//! Events as the relay stores them: one compact binary record each, read in
//! place from the map.
//!
//! ```text
//! flags      u8         bit 0: an expiration follows the fixed header
//!                       bit 1: the content is base64, kept as its bytes
//! id         [u8; 32]
//! pubkey     [u8; 32]
//! sig        [u8; 64]
//! created_at u32 LE
//! kind       u16 LE
//! expiration u32 LE     if flagged
//! tags_len   varint     bytes of tags that follow
//! tags       varint count, then per tag: varint count, then per element
//!            varint (len << 1 | hex), then the bytes
//! content    the rest: UTF-8, or the bytes base64 content decodes to
//! ```
//!
//! Ids, keys, and signatures are raw bytes rather than hex, and so is any
//! tag element that is exactly 64 lowercase hex digits — event and pubkey
//! references, mostly — flagged so it reads back as the same text. Content
//! that is base64 is kept as the bytes it spells, a quarter smaller. Either
//! only applies when the text written back is exactly what was signed.
//! Nothing is kept twice: the JSON is written from the record when it's sent.
//!
//! The NIP-40 expiration is recorded but not yet acted on.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::event::{Event, is_hex64};

const FLAG_EXPIRATION: u8 = 1;
const FLAG_BASE64: u8 = 2;
const FIXED: usize = 1 + 32 + 32 + 64 + 4 + 2;

/// Encode an event. It must already be valid: ids and keys hex, numbers in
/// range (see [`Event::verify`]).
pub fn encode(event: &Event) -> Vec<u8> {
    let expiration = expiration(event);
    let mut out = Vec::with_capacity(FIXED + 8 + event.content.len() + event.tags.len() * 40);
    let base64 = decode_base64(&event.content);
    out.push(
        if expiration.is_some() {
            FLAG_EXPIRATION
        } else {
            0
        } | if base64.is_some() { FLAG_BASE64 } else { 0 },
    );
    push_hex(&mut out, &event.id);
    push_hex(&mut out, &event.pubkey);
    push_hex(&mut out, &event.sig);
    out.extend_from_slice(&(event.created_at as u32).to_le_bytes());
    out.extend_from_slice(&event.kind.to_le_bytes());
    if let Some(expiration) = expiration {
        out.extend_from_slice(&expiration.to_le_bytes());
    }

    let mut tags = Vec::new();
    put_varint(&mut tags, event.tags.len() as u64);
    for tag in &event.tags {
        put_varint(&mut tags, tag.len() as u64);
        for element in tag {
            if is_hex64(element) {
                put_varint(&mut tags, 32 << 1 | 1);
                push_hex(&mut tags, element);
            } else {
                put_varint(&mut tags, (element.len() as u64) << 1);
                tags.extend_from_slice(element.as_bytes());
            }
        }
    }
    put_varint(&mut out, tags.len() as u64);
    out.extend_from_slice(&tags);
    match base64 {
        Some(bytes) => out.extend_from_slice(&bytes),
        None => out.extend_from_slice(event.content.as_bytes()),
    }
    out
}

/// The bytes `content` spells, if it's base64 that encodes back to exactly
/// itself: padded, with no stray bits, and not empty.
fn decode_base64(content: &str) -> Option<Vec<u8>> {
    if content.is_empty() || !content.len().is_multiple_of(4) {
        return None;
    }
    let bytes = STANDARD.decode(content).ok()?;
    (STANDARD.encode(&bytes) == content).then_some(bytes)
}

/// The NIP-40 expiration, if the event has one that will ever arrive.
/// Beyond 2106 it may as well not.
fn expiration(event: &Event) -> Option<u32> {
    let value = event.tag("expiration")?;
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| u32::try_from(value).ok())
}

fn push_hex(out: &mut Vec<u8>, hex: &str) {
    let start = out.len();
    out.resize(start + hex.len() / 2, 0);
    hex::decode_to_slice(hex, &mut out[start..]).expect("validated hex");
}

fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn get_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut n = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        n |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some(n);
        }
    }
    None
}

/// A stored event, read in place.
#[derive(Clone, Copy, Debug)]
pub struct EventView<'a> {
    fixed: &'a [u8; FIXED],
    #[cfg_attr(not(test), expect(dead_code, reason = "read once NIP-40 is enforced"))]
    expiration: Option<u32>,
    tags: &'a [u8],
    content: Content<'a>,
}

/// An event's content, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content<'a> {
    Text(&'a str),
    /// Base64, as the bytes it spells.
    Base64(&'a [u8]),
}

impl<'a> EventView<'a> {
    /// `None` if the bytes aren't a record.
    pub fn new(buf: &'a [u8]) -> Option<EventView<'a>> {
        let fixed: &[u8; FIXED] = buf.get(..FIXED)?.try_into().ok()?;
        let mut rest = &buf[FIXED..];
        let expiration = if fixed[0] & FLAG_EXPIRATION != 0 {
            let (value, tail) = rest.split_first_chunk::<4>()?;
            rest = tail;
            Some(u32::from_le_bytes(*value))
        } else {
            None
        };
        let tags_len = usize::try_from(get_varint(&mut rest)?).ok()?;
        let tags = rest.get(..tags_len)?;
        let content = &rest[tags_len..];
        let content = if fixed[0] & FLAG_BASE64 != 0 {
            Content::Base64(content)
        } else {
            Content::Text(std::str::from_utf8(content).ok()?)
        };
        Some(EventView {
            fixed,
            expiration,
            tags,
            content,
        })
    }

    pub fn id(&self) -> &'a [u8; 32] {
        self.fixed[1..33].try_into().unwrap()
    }

    pub fn pubkey(&self) -> &'a [u8; 32] {
        self.fixed[33..65].try_into().unwrap()
    }

    pub fn sig(&self) -> &'a [u8; 64] {
        self.fixed[65..129].try_into().unwrap()
    }

    pub fn created_at(&self) -> u32 {
        u32::from_le_bytes(self.fixed[129..133].try_into().unwrap())
    }

    pub fn kind(&self) -> u16 {
        u16::from_le_bytes(self.fixed[133..135].try_into().unwrap())
    }

    #[cfg(test)]
    pub fn expiration(&self) -> Option<u32> {
        self.expiration
    }

    #[cfg(test)]
    pub fn content(&self) -> Content<'a> {
        self.content
    }

    pub fn tags(&self) -> Tags<'a> {
        let mut buf = self.tags;
        let remaining = get_varint(&mut buf).unwrap_or(0);
        Tags { buf, remaining }
    }

    /// Each single-letter tag's name and first value: what's indexed and
    /// what filters match against.
    pub fn indexed_tags(&self) -> impl Iterator<Item = (u8, Element<'a>)> {
        self.tags().filter_map(|tag| {
            let mut elements = tag;
            let Some(Element::Text(name)) = elements.next() else {
                return None;
            };
            let &[letter] = name.as_bytes() else {
                return None;
            };
            if !letter.is_ascii_alphabetic() {
                return None;
            }
            Some((letter, elements.next()?))
        })
    }

    /// The first value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<Element<'a>> {
        self.tags().find_map(|mut tag| match tag.next()? {
            Element::Text(n) if n == name => tag.next(),
            _ => None,
        })
    }

    /// The event as NIP-01 JSON.
    pub fn to_json(self) -> String {
        let content_len = match self.content {
            Content::Text(text) => text.len(),
            Content::Base64(bytes) => bytes.len().div_ceil(3) * 4,
        };
        let mut out = String::with_capacity(FIXED * 2 + content_len + self.tags.len() * 2 + 96);
        out.push_str("{\"id\":\"");
        push_hex_str(&mut out, self.id());
        out.push_str("\",\"pubkey\":\"");
        push_hex_str(&mut out, self.pubkey());
        out.push_str("\",\"created_at\":");
        out.push_str(&self.created_at().to_string());
        out.push_str(",\"kind\":");
        out.push_str(&self.kind().to_string());
        out.push_str(",\"tags\":[");
        for (i, tag) in self.tags().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('[');
            for (j, element) in tag.enumerate() {
                if j > 0 {
                    out.push(',');
                }
                match element {
                    Element::Text(text) => push_json_str(&mut out, text),
                    Element::Hex(bytes) => {
                        out.push('"');
                        push_hex_str(&mut out, bytes);
                        out.push('"');
                    }
                }
            }
            out.push(']');
        }
        out.push_str("],\"content\":");
        match self.content {
            Content::Text(text) => push_json_str(&mut out, text),
            Content::Base64(bytes) => {
                // Nothing in base64 needs escaping.
                out.push('"');
                STANDARD.encode_string(bytes, &mut out);
                out.push('"');
            }
        }
        out.push_str(",\"sig\":\"");
        push_hex_str(&mut out, self.sig());
        out.push_str("\"}");
        out
    }
}

fn push_hex_str(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0xf)] as char);
    }
}

fn push_json_str(out: &mut String, value: &str) {
    // serde_json escapes exactly what JSON requires, and nothing more.
    out.push_str(&serde_json::to_string(value).expect("strings serialize"));
}

/// The tags of an event.
pub struct Tags<'a> {
    buf: &'a [u8],
    remaining: u64,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Elements<'a>;

    fn next(&mut self) -> Option<Elements<'a>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let count = get_varint(&mut self.buf)?;
        // Measure the tag by walking it, so the next starts where it ends.
        let start = self.buf;
        let mut walk = Elements {
            buf: start,
            remaining: count,
        };
        while walk.next().is_some() {}
        let len = start.len() - walk.buf.len();
        self.buf = &start[len..];
        Some(Elements {
            buf: &start[..len],
            remaining: count,
        })
    }
}

/// The elements of one tag.
#[derive(Clone)]
pub struct Elements<'a> {
    buf: &'a [u8],
    remaining: u64,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let header = get_varint(&mut self.buf)?;
        let len = usize::try_from(header >> 1).ok()?;
        let bytes = self.buf.get(..len)?;
        self.buf = &self.buf[len..];
        if header & 1 == 1 {
            Some(Element::Hex(bytes.try_into().ok()?))
        } else {
            Some(Element::Text(std::str::from_utf8(bytes).ok()?))
        }
    }
}

/// One element of a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element<'a> {
    Text(&'a str),
    /// 64 lowercase hex digits, as the bytes they spell.
    Hex(&'a [u8; 32]),
}

impl Element<'_> {
    /// The form tag values are indexed and compared in. See [`tag_value`].
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Element::Hex(bytes) => {
                out.push(1);
                out.extend_from_slice(*bytes);
            }
            Element::Text(text) => {
                out.push(0);
                out.extend_from_slice(text.as_bytes());
            }
        }
    }

    /// Whether this is the value `encoded` (in [`tag_value`] form).
    #[cfg(test)]
    pub fn is(&self, encoded: &[u8]) -> bool {
        match (self, encoded.split_first()) {
            (Element::Hex(bytes), Some((1, rest))) => rest == bytes.as_slice(),
            (Element::Text(text), Some((0, rest))) => rest == text.as_bytes(),
            _ => false,
        }
    }

    pub fn encoded_len(&self) -> usize {
        1 + match self {
            Element::Hex(_) => 32,
            Element::Text(text) => text.len(),
        }
    }
}

/// A tag value from a filter, in the form stored elements compare in: hex
/// as its bytes, flagged 1, and any other text flagged 0.
pub fn tag_value(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    if is_hex64(value) {
        out.push(1);
        push_hex(&mut out, value);
    } else {
        out.push(0);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;

    fn roundtrip(event: &Event) -> Event {
        let record = encode(event);
        let view = EventView::new(&record).unwrap();
        serde_json::from_str(&view.to_json()).unwrap()
    }

    #[test]
    fn roundtrips() {
        let hex = "ab".repeat(32);
        let upper = hex.to_uppercase();
        let event = signed(
            2,
            1_700_000_000,
            30_023,
            vec![
                vec!["d", "a \"quoted\"\nname"],
                vec!["e", &hex, "wss://relay.example.com", "root"],
                // Not lowercase hex, so kept as text, and read back as written.
                vec!["p", &upper],
                vec![],
                vec![""],
                vec!["expiration", "1800000000"],
            ],
            "héllo\u{1}\u{2028} 🎉",
        );
        let back = roundtrip(&event);
        assert_eq!(back, event);
        assert_eq!(back.verify(), Ok(()));

        let record = encode(&event);
        let view = EventView::new(&record).unwrap();
        assert_eq!(view.kind(), 30_023);
        assert_eq!(view.content(), Content::Text(&event.content));
        assert_eq!(view.created_at(), 1_700_000_000);
        assert_eq!(view.expiration(), Some(1_800_000_000));
        assert_eq!(view.tag("d"), Some(Element::Text("a \"quoted\"\nname")));

        let indexed: Vec<_> = view.indexed_tags().collect();
        assert_eq!(indexed.len(), 3);
        assert_eq!(indexed[1].0, b'e');
        assert!(indexed[1].1.is(&tag_value(&hex)));
        assert!(!indexed[2].1.is(&tag_value(&hex)));
        assert!(indexed[2].1.is(&tag_value(&upper)));
    }

    #[test]
    fn is_smaller_than_json() {
        let hex = "cd".repeat(32);
        let tags = (0..10).map(|_| vec!["p", hex.as_str()]).collect();
        let event = signed(2, 1_700_000_000, 3, tags, "");
        let json = serde_json::to_string(&event).unwrap();
        let record = encode(&event);
        assert!(
            record.len() * 2 < json.len(),
            "{} vs {}",
            record.len(),
            json.len()
        );
        assert_eq!(roundtrip(&event), event);
    }

    #[test]
    fn keeps_base64_content_as_bytes() {
        let payload = STANDARD.encode((0..1000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>());
        let hex = "cd".repeat(32);
        let event = signed(2, 1_700_000_000, 1059, vec![vec!["p", &hex]], &payload);
        let record = encode(&event);
        let view = EventView::new(&record).unwrap();
        assert_eq!(
            view.content(),
            Content::Base64(&STANDARD.decode(&payload).unwrap())
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            record.len() * 10 < json.len() * 7,
            "{} vs {}",
            record.len(),
            json.len()
        );
        let back = roundtrip(&event);
        assert_eq!(back, event);
        assert_eq!(back.verify(), Ok(()));

        // Only base64 that reads back exactly as it was signed.
        for content in [
            "",
            "aGk=",
            "aGk",
            "aGl=",
            "abc=",
            "YQ==",
            "YQ",
            "hi there",
            "AAAA\n",
            "😀😀😀😀",
        ] {
            let event = signed(2, 1_700_000_000, 1, vec![], content);
            let record = encode(&event);
            let base64 = matches!(
                EventView::new(&record).unwrap().content(),
                Content::Base64(_)
            );
            assert_eq!(
                base64,
                matches!(content, "aGk=" | "abc=" | "YQ=="),
                "{content:?}"
            );
            assert_eq!(roundtrip(&event), event, "{content:?}");
        }
    }

    #[test]
    fn refuses_garbage() {
        assert!(EventView::new(&[0; 10]).is_none());
        let mut record = encode(&signed(2, 1, 1, vec![], "x"));
        *record.last_mut().unwrap() = 0xff;
        assert!(EventView::new(&record).is_none());
    }
}
