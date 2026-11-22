//! WebSocket (RFC 6455), the server's side, over an upgraded HTTP/1.1
//! connection. Frames are read into one buffer and unmasked in place; what's
//! sent is framed straight into one buffer, an EVENT message's JSON copied
//! once, and written at once when flushed. No extensions are taken: a
//! client offering compression is answered without it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::FutureExt;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Notify;

/// What's read from the socket at a time, at least.
pub(super) const READ_AHEAD: usize = 16 << 10;

/// How much is read at first of what a quiet connection sends.
const QUIET_READ: usize = 256;

/// A written buffer kept past this is let go, rather than kept for the
/// next message.
const KEEP_BUFFER: usize = 1 << 20;

const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xa;

/// A request to upgrade to a WebSocket.
pub struct Upgrade {
    on_upgrade: OnUpgrade,
    accept: HeaderValue,
}

impl<S: Send + Sync> FromRequestParts<S> for Upgrade {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;
        let has = |name, token: &str| {
            headers.get_all(name).iter().any(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case(token))
                })
            })
        };
        if parts.method != Method::GET
            || !has(header::CONNECTION, "upgrade")
            || !has(header::UPGRADE, "websocket")
            || headers
                .get(header::SEC_WEBSOCKET_VERSION)
                .map(HeaderValue::as_bytes)
                != Some(b"13")
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let key = headers
            .get(header::SEC_WEBSOCKET_KEY)
            .ok_or(StatusCode::BAD_REQUEST)?;
        let on_upgrade = parts
            .extensions
            .remove::<OnUpgrade>()
            .ok_or(StatusCode::UPGRADE_REQUIRED)?;
        Ok(Upgrade {
            on_upgrade,
            accept: accept(key.as_bytes()),
        })
    }
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`.
fn accept(key: &[u8]) -> HeaderValue {
    let mut sha1 = Sha1::new();
    sha1.update(key);
    sha1.update(GUID);
    HeaderValue::from_str(&STANDARD.encode(sha1.finalize())).expect("base64 is a header value")
}

impl Upgrade {
    /// Switch protocols, then run `f` with the socket, messages of up to
    /// `max` bytes.
    pub fn on_upgrade<F, Fut>(self, max: usize, f: F) -> Response
    where
        F: FnOnce(Reader, Writer) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let Upgrade { on_upgrade, accept } = self;
        tokio::spawn(async move {
            if let Ok(upgraded) = on_upgrade.await {
                let (reader, writer) = split(upgraded, max);
                f(reader, writer).await;
            }
        });
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::SEC_WEBSOCKET_ACCEPT, accept);
        (StatusCode::SWITCHING_PROTOCOLS, headers).into_response()
    }
}

/// The connection's halves: a TCP stream's own, which share no lock, or
/// any other stream's, split.
fn split(upgraded: hyper::upgrade::Upgraded, max: usize) -> (Reader, Writer) {
    let (read, write, buffered): (Box<dyn Read>, Box<dyn Write>, Bytes) =
        match upgraded.downcast::<TokioIo<TcpStream>>() {
            Ok(parts) => {
                let (read, write) = parts.io.into_inner().into_split();
                (Box::new(read), Box::new(write), parts.read_buf)
            }
            Err(upgraded) => {
                let (read, write) = tokio::io::split(TokioIo::new(upgraded));
                (Box::new(read), Box::new(write), Bytes::new())
            }
        };
    let mut buf = BytesMut::with_capacity(READ_AHEAD.max(buffered.len()));
    buf.extend_from_slice(&buffered);
    let reader = Reader {
        io: read,
        buf,
        max,
        partial: None,
    };
    (reader, Writer::new(write))
}

trait Read: AsyncRead + Send + Unpin {}
impl<T: AsyncRead + Send + Unpin> Read for T {}
pub(super) trait Write: AsyncWrite + Send + Unpin {}
impl<T: AsyncWrite + Send + Unpin> Write for T {}

/// A text message, its bytes UTF-8.
#[derive(Clone, Debug)]
pub struct Text(Bytes);

impl std::ops::Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        // SAFETY: checked to be UTF-8 when it was read.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

/// A message from the client.
#[derive(Debug)]
pub enum Message {
    Text(Text),
    Binary,
    Ping(Bytes),
    Pong,
    /// The client is closing.
    Close,
}

/// What breaks the protocol, or the limits.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(&'static str),
    /// A message past the limit.
    TooBig,
    /// Text that isn't UTF-8.
    NotUtf8,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "reading its socket failed: {err}"),
            Error::Protocol(why) => write!(f, "it broke the WebSocket protocol: {why}"),
            Error::TooBig => write!(f, "it sent a message too big"),
            Error::NotUtf8 => write!(f, "it sent text that isn't UTF-8"),
        }
    }
}

impl Error {
    /// The close code to say it with.
    pub fn code(&self) -> u16 {
        match self {
            Error::Io(_) | Error::Protocol(_) => 1002,
            Error::TooBig => 1009,
            Error::NotUtf8 => 1007,
        }
    }
}

/// Reads the client's messages.
pub struct Reader {
    io: Box<dyn Read>,
    buf: BytesMut,
    max: usize,
    /// A message coming in fragments: its opcode, and what's come so far.
    partial: Option<(u8, BytesMut)>,
}

/// A frame read: whether it's the last of its message, its opcode, and
/// its payload, unmasked.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: BytesMut,
}

impl Reader {
    /// The next message, or `None` once the stream ends. Cancel safe: what's
    /// read is kept for the next call.
    pub async fn next(&mut self) -> Option<Result<Message, Error>> {
        loop {
            match self.message() {
                Ok(Some(message)) => return Some(Ok(message)),
                Ok(None) => {}
                Err(err) => return Some(Err(err)),
            }
            if self.buf.capacity() - self.buf.len() < READ_AHEAD / 4 {
                self.buf.reserve(READ_AHEAD);
            }
            let read = match self.buf.is_empty() {
                false => self.io.read_buf(&mut self.buf).await,
                true => match self.io.read_buf(&mut self.buf).now_or_never() {
                    Some(read) => read,
                    // Nothing to read: a quiet connection holds no buffer
                    // while it waits.
                    None => {
                        self.buf = BytesMut::new();
                        let mut first = [0; QUIET_READ];
                        let read = self.io.read(&mut first).await;
                        if let Ok(n) = read {
                            self.buf.reserve(READ_AHEAD);
                            self.buf.extend_from_slice(&first[..n]);
                        }
                        read
                    }
                },
            };
            match read {
                Ok(0) => return None,
                Ok(_) => {}
                Err(err) => return Some(Err(Error::Io(err))),
            }
        }
    }

    /// The next message, if it's been read whole already, or what breaks
    /// the protocol. Doesn't read.
    pub fn try_next(&mut self) -> Option<Result<Message, Error>> {
        self.message().transpose()
    }

    /// A whole message, if what's read holds one.
    fn message(&mut self) -> Result<Option<Message>, Error> {
        while let Some(Frame {
            fin,
            opcode,
            payload,
        }) = self.frame()?
        {
            match opcode {
                CLOSE | PING | PONG => {
                    if !fin {
                        return Err(Error::Protocol("a fragmented control frame"));
                    }
                    let payload = payload.freeze();
                    return Ok(Some(match opcode {
                        CLOSE => Message::Close,
                        PING => Message::Ping(payload),
                        _ => Message::Pong,
                    }));
                }
                TEXT | BINARY if self.partial.is_some() => {
                    return Err(Error::Protocol("a new message before the last's end"));
                }
                TEXT | BINARY if fin => return finish(opcode, payload).map(Some),
                TEXT | BINARY => self.partial = Some((opcode, payload)),
                CONTINUATION => {
                    let Some((first, mut message)) = self.partial.take() else {
                        return Err(Error::Protocol("a continuation of no message"));
                    };
                    if message.len() + payload.len() > self.max {
                        return Err(Error::TooBig);
                    }
                    message.extend_from_slice(&payload);
                    match fin {
                        true => return finish(first, message).map(Some),
                        false => self.partial = Some((first, message)),
                    }
                }
                _ => return Err(Error::Protocol("an unknown opcode")),
            }
        }
        Ok(None)
    }

    /// The next frame, if it's all been read.
    fn frame(&mut self) -> Result<Option<Frame>, Error> {
        let buf = &self.buf[..];
        let [first, second, ..] = *buf else {
            return Ok(None);
        };
        if first & 0x70 != 0 {
            return Err(Error::Protocol("reserved bits set"));
        }
        if second & 0x80 == 0 {
            return Err(Error::Protocol("an unmasked frame from a client"));
        }
        let (len, at) = match second & 0x7f {
            126 => match buf.get(2..4) {
                Some(len) => (u64::from(u16::from_be_bytes([len[0], len[1]])), 4),
                None => return Ok(None),
            },
            127 => match buf.get(2..10) {
                Some(len) => (u64::from_be_bytes(len.try_into().expect("8 bytes")), 10),
                None => return Ok(None),
            },
            len => (u64::from(len), 2),
        };
        let opcode = first & 0x0f;
        if opcode >= CLOSE && len > 125 {
            return Err(Error::Protocol("a control frame over 125 bytes"));
        }
        if len > self.max as u64 {
            return Err(Error::TooBig);
        }
        let len = len as usize;
        let Some(mask) = buf.get(at..at + 4) else {
            return Ok(None);
        };
        let mask: [u8; 4] = mask.try_into().expect("4 bytes");
        let whole = at + 4 + len;
        if buf.len() < whole {
            self.buf.reserve(whole - buf.len());
            return Ok(None);
        }
        let mut payload = self.buf.split_to(whole);
        payload.advance(at + 4);
        unmask(&mut payload, mask);
        Ok(Some(Frame {
            fin: first & 0x80 != 0,
            opcode,
            payload,
        }))
    }
}

/// A message, all of it come.
fn finish(opcode: u8, payload: BytesMut) -> Result<Message, Error> {
    match opcode {
        TEXT => match is_utf8(&payload) {
            true => Ok(Message::Text(Text(payload.freeze()))),
            false => Err(Error::NotUtf8),
        },
        _ => Ok(Message::Binary),
    }
}

fn is_utf8(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

/// XOR the payload with the mask, eight bytes at a time.
fn unmask(payload: &mut [u8], mask: [u8; 4]) {
    let word = u64::from_ne_bytes([
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ]);
    let (words, rest) = payload.as_chunks_mut::<8>();
    let done = words.len() * 8;
    for chunk in words {
        *chunk = (u64::from_ne_bytes(*chunk) ^ word).to_ne_bytes();
    }
    for (i, byte) in rest.iter_mut().enumerate() {
        *byte ^= mask[(done + i) % 4];
    }
}

/// Writes messages to the client: framed into a buffer, sent when flushed.
/// The connection's task writes, and so may a [`Direct`] of it.
pub struct Writer {
    out: Arc<Out>,
}

/// What's framed to send, and where to.
struct Out {
    state: Mutex<OutState>,
    /// Notified when a [`Direct`] left what it framed for the connection
    /// to send.
    wanted: Notify,
}

struct OutState {
    io: Box<dyn Write>,
    buf: Vec<u8>,
    /// How much of `buf` is sent.
    sent: usize,
}

/// The most a [`Direct`] lets wait unsent before it refuses more.
const MAX_UNSENT: usize = 16 << 20;

impl OutState {
    fn header(&mut self, opcode: u8, len: usize) {
        self.buf.push(0x80 | opcode);
        match len {
            0..=125 => self.buf.push(len as u8),
            126..=0xffff => {
                self.buf.push(126);
                self.buf.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                self.buf.push(127);
                self.buf.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
    }

    fn event(&mut self, sub_id: &str, json: &str) {
        const OPEN: &[u8] = b"[\"EVENT\",";
        self.header(TEXT, OPEN.len() + sub_id.len() + 1 + json.len() + 1);
        self.buf.extend_from_slice(OPEN);
        self.buf.extend_from_slice(sub_id.as_bytes());
        self.buf.push(b',');
        self.buf.extend_from_slice(json.as_bytes());
        self.buf.push(b']');
    }

    fn unsent(&self) -> usize {
        self.buf.len() - self.sent
    }

    /// Send what it can of what's framed: ready once it's all sent, and
    /// flushed from any layer between, as TLS.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.buf.len() {
            let OutState { io, buf, sent } = self;
            match Pin::new(&mut **io).poll_write(cx, &buf[*sent..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => *sent += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.sent > 0 {
            self.buf.clear();
            self.sent = 0;
            if self.buf.capacity() > KEEP_BUFFER {
                self.buf = Vec::new();
            }
        }
        Pin::new(&mut *self.io).poll_flush(cx)
    }
}

impl Writer {
    pub(super) fn new(io: Box<dyn Write>) -> Writer {
        let state = OutState {
            io,
            buf: Vec::new(),
            sent: 0,
        };
        Writer {
            out: Arc::new(Out {
                state: Mutex::new(state),
                wanted: Notify::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, OutState> {
        self.out.state.lock().expect("unpoisoned")
    }

    /// A text message.
    pub fn text(&mut self, text: &str) {
        let mut state = self.state();
        state.header(TEXT, text.len());
        state.buf.extend_from_slice(text.as_bytes());
    }

    /// `["EVENT", sub_id, event]`, the subscription id [quoted](super::quoted)
    /// and the event serialized.
    pub fn event(&mut self, sub_id: &str, json: &str) {
        self.state().event(sub_id, json);
    }

    pub fn ping(&mut self) {
        self.state().header(PING, 0);
    }

    /// Answer a ping, with its payload.
    pub fn pong(&mut self, payload: &[u8]) {
        let mut state = self.state();
        state.header(PONG, payload.len());
        state.buf.extend_from_slice(payload);
    }

    /// A close frame, with a status code.
    pub fn close(&mut self, code: u16) {
        let mut state = self.state();
        state.header(CLOSE, 2);
        state.buf.extend_from_slice(&code.to_be_bytes());
    }

    /// Send what's framed.
    pub async fn flush(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.state().poll_send(cx)).await
    }

    /// Send what's framed, and end the stream.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.flush().await?;
        std::future::poll_fn(|cx| Pin::new(&mut *self.state().io).poll_shutdown(cx)).await
    }

    /// Once a [`Direct`] left something for the connection to send.
    pub async fn wanted(&self) {
        self.out.wanted.notified().await
    }

    /// A way for another thread to send the client events.
    pub fn direct(&self) -> Direct {
        Direct(self.out.clone())
    }
}

/// Sends a connection's client events from any thread, along with what the
/// connection sends: see [`Direct::event`].
#[derive(Clone)]
pub struct Direct(Arc<Out>);

impl Direct {
    /// Send `["EVENT", sub_id, event]` now, as much as the socket takes at
    /// once, if nothing else waits to be: the rest is left to the
    /// connection, as is all of it if something else waits, to send with
    /// that. Returns false, and sends nothing, if too much waits already.
    pub fn event(&self, sub_id: &str, json: &str) -> bool {
        let mut state = self.0.state.lock().expect("unpoisoned");
        let unsent = state.unsent();
        if unsent > MAX_UNSENT {
            return false;
        }
        state.event(sub_id, json);
        // Something else waiting is being sent, or will be, by a task
        // that's to be woken when it can: polling here would take its
        // place.
        if unsent == 0 {
            let mut cx = Context::from_waker(Waker::noop());
            let sent = state.poll_send(&mut cx);
            if !matches!(sent, Poll::Ready(Ok(()))) {
                self.0.wanted.notify_one();
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A client's frame of `payload`, masked with `mask`.
    fn masked(first: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![first];
        match payload.len() {
            len @ 0..=125 => frame.push(0x80 | len as u8),
            len @ 126..=0xffff => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    fn reader(bytes: Vec<u8>, max: usize) -> Reader {
        Reader {
            io: Box::new(std::io::Cursor::new(bytes)),
            buf: BytesMut::new(),
            max,
            partial: None,
        }
    }

    async fn all(mut reader: Reader) -> Vec<Result<Message, Error>> {
        let mut out = Vec::new();
        while let Some(message) = reader.next().await {
            let stop = message.is_err();
            out.push(message);
            if stop {
                break;
            }
        }
        out
    }

    fn texts(messages: &[Result<Message, Error>]) -> Vec<String> {
        messages
            .iter()
            .map(|message| match message {
                Ok(Message::Text(text)) => text.to_string(),
                Ok(other) => format!("{other:?}"),
                Err(err) => format!("{err:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn reads_what_comes_after_waiting_without_a_buffer() {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let mut reader = Reader {
            io: Box::new(server),
            buf: BytesMut::new(),
            max: 1 << 20,
            partial: None,
        };
        let mask = [1, 2, 3, 4];
        let long = "y".repeat(QUIET_READ * 3);
        for text in ["short", long.as_str(), "after"] {
            let read = tokio::spawn(async move {
                let message = reader.next().await;
                (reader, message)
            });
            tokio::task::yield_now().await;
            client
                .write_all(&masked(0x81, text.as_bytes(), mask))
                .await
                .unwrap();
            let message;
            (reader, message) = read.await.unwrap();
            assert_eq!(texts(&[message.unwrap()]), [text]);
        }
        // Two at once: the second is read with the first.
        let mut both = masked(0x81, long.as_bytes(), mask);
        both.extend(masked(0x81, b"two", mask));
        client.write_all(&both).await.unwrap();
        drop(client);
        assert_eq!(texts(&all(reader).await), [long, "two".to_string()]);
    }

    #[tokio::test]
    async fn reads_frames_whole_fragmented_and_controls_between() {
        let mask = [1, 2, 3, 4];
        let long = "x".repeat(70_000);
        let mut bytes = masked(0x81, b"hello", mask);
        bytes.extend(masked(0x81, long.as_bytes(), [9, 8, 7, 6]));
        bytes.extend(masked(0x01, "fr".as_bytes(), mask));
        bytes.extend(masked(0x89, b"hi", mask));
        bytes.extend(masked(0x00, "ag".as_bytes(), mask));
        bytes.extend(masked(0x80, "ment ✓".as_bytes(), mask));
        bytes.extend(masked(0x81, b"", mask));
        bytes.extend(masked(0x82, b"\x00\xff", mask));
        bytes.extend(masked(0x88, &1000u16.to_be_bytes(), mask));
        let messages = all(reader(bytes, 1 << 20)).await;
        assert_eq!(
            texts(&messages),
            [
                "hello".to_string(),
                long,
                "Ping(b\"hi\")".to_string(),
                "fragment ✓".to_string(),
                "".to_string(),
                "Binary".to_string(),
                "Close".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn refuses_what_breaks_the_protocol_or_the_limits() {
        let mask = [5, 6, 7, 8];
        let unmasked = vec![0x81, 2, b'h', b'i'];
        let reserved = masked(0xc1, b"hi", mask);
        let unknown = masked(0x83, b"hi", mask);
        let fragmented_ping = masked(0x09, b"hi", mask);
        let long_ping = masked(0x89, &[0; 126], mask);
        let stray = masked(0x80, b"hi", mask);
        let mut interleaved = masked(0x01, b"a", mask);
        interleaved.extend(masked(0x81, b"b", mask));
        let big = masked(0x81, &[b'a'; 101], mask);
        let mut big_in_pieces = masked(0x01, &[b'a'; 60], mask);
        big_in_pieces.extend(masked(0x80, &[b'a'; 60], mask));
        let not_utf8 = masked(0x81, b"\xff\xfe", mask);
        for (bytes, code) in [
            (unmasked, 1002),
            (reserved, 1002),
            (unknown, 1002),
            (fragmented_ping, 1002),
            (long_ping, 1002),
            (stray, 1002),
            (interleaved, 1002),
            (big, 1009),
            (big_in_pieces, 1009),
            (not_utf8, 1007),
        ] {
            let messages = all(reader(bytes.clone(), 100)).await;
            match messages.last() {
                Some(Err(err)) => assert_eq!(err.code(), code, "{bytes:?}"),
                other => panic!("{bytes:?}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn reads_a_frame_however_it_arrives() {
        let frame = masked(0x81, "split ✓ across reads".as_bytes(), [3, 1, 4, 1]);
        for cut in 1..frame.len() {
            let (a, b) = frame.split_at(cut);
            let (mut client, server) = tokio::io::duplex(64);
            let mut reader = Reader {
                io: Box::new(server),
                buf: BytesMut::new(),
                max: 1 << 10,
                partial: None,
            };
            let (a, b) = (a.to_vec(), b.to_vec());
            let writing = tokio::spawn(async move {
                client.write_all(&a).await.unwrap();
                tokio::task::yield_now().await;
                client.write_all(&b).await.unwrap();
                client
            });
            match reader.next().await {
                Some(Ok(Message::Text(text))) => assert_eq!(&*text, "split ✓ across reads"),
                other => panic!("cut at {cut}: {other:?}"),
            }
            drop(writing.await.unwrap());
        }
    }

    #[test]
    fn unmasks_as_a_byte_at_a_time_does() {
        for len in 0..40 {
            let mask = [0x12, 0x34, 0x56, 0x78];
            let plain: Vec<u8> = (0..len as u8).collect();
            let mut payload: Vec<u8> = plain
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i % 4])
                .collect();
            unmask(&mut payload, mask);
            assert_eq!(payload, plain);
        }
    }

    #[tokio::test]
    async fn frames_what_it_writes() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let mut writer = Writer::new(Box::new(server));
        let long = "y".repeat(60_000);
        writer.text("short");
        writer.event("\"sub\"", "{\"id\":1}");
        writer.text(&long);
        writer.ping();
        writer.pong(b"pp");
        writer.close(1001);
        writer.shutdown().await.unwrap();
        let mut read = Vec::new();
        let mut client = client;
        client.read_to_end(&mut read).await.unwrap();
        let mut expect = vec![0x81, 5];
        expect.extend_from_slice(b"short");
        let event = b"[\"EVENT\",\"sub\",{\"id\":1}]";
        expect.extend_from_slice(&[0x81, event.len() as u8]);
        expect.extend_from_slice(event);
        expect.extend_from_slice(&[0x81, 126]);
        expect.extend_from_slice(&60_000u16.to_be_bytes());
        expect.extend_from_slice(long.as_bytes());
        expect.extend_from_slice(&[0x89, 0, 0x8a, 2, b'p', b'p', 0x88, 2]);
        expect.extend_from_slice(&1001u16.to_be_bytes());
        assert_eq!(read, expect);
    }

    #[tokio::test]
    async fn sends_directly_or_leaves_it_to_the_connection() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut writer = Writer::new(Box::new(server));
        let direct = writer.direct();
        let frame = |sub: &str, json: &str| {
            let text = format!("[\"EVENT\",{sub},{json}]");
            let mut frame = vec![0x81];
            match text.len() {
                len @ 0..=125 => frame.push(len as u8),
                len => {
                    frame.push(126);
                    frame.extend_from_slice(&(len as u16).to_be_bytes());
                }
            }
            frame.extend_from_slice(text.as_bytes());
            frame
        };
        async fn read(
            mut client: tokio::io::DuplexStream,
            len: usize,
        ) -> (tokio::io::DuplexStream, Vec<u8>) {
            let mut got = vec![0; len];
            client.read_exact(&mut got).await.unwrap();
            (client, got)
        }

        // Sent at once, nothing waiting.
        assert!(direct.event("\"a\"", "1"));
        let (c, got) = read(client, frame("\"a\"", "1").len()).await;
        assert_eq!(got, frame("\"a\"", "1"));
        client = c;

        // What the connection framed goes first, then this, both sent when
        // it flushes.
        writer.text("t");
        assert!(direct.event("\"b\"", "2"));
        writer.flush().await.unwrap();
        let mut expect = vec![0x81, 1, b't'];
        expect.extend(frame("\"b\"", "2"));
        let (c, got) = read(client, expect.len()).await;
        assert_eq!(got, expect);
        client = c;

        // More than the socket takes: the rest is the connection's to send.
        let long = "x".repeat(200);
        assert!(direct.event("\"c\"", &long));
        tokio::time::timeout(std::time::Duration::from_secs(1), writer.wanted())
            .await
            .unwrap();
        let reading = tokio::spawn(read(client, frame("\"c\"", &long).len()));
        writer.flush().await.unwrap();
        let (_, got) = reading.await.unwrap();
        assert_eq!(got, frame("\"c\"", &long));
    }

    #[test]
    fn accepts_keys_as_the_rfc_says() {
        // RFC 6455 §1.3's example.
        assert_eq!(
            accept(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
