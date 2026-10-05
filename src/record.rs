//! Events as the relay stores them: one compact binary record each, read in
//! place from the map.
//!
//! ```text
//! flags      u8         bit 0: an expiration follows the fixed header
//!                       bit 1: the content is base64, kept as its bytes
//!                       bit 2: an analysis follows the fixed header
//!                       bit 3: the content is NIP-04, kept as its bytes
//! id         [u8; 32]
//! pubkey     [u8; 32]
//! sig        [u8; 64]
//! created_at u32 LE
//! kind       u16 LE
//! expiration u32 LE     if flagged
//! analysis   [u8; 3]    if flagged: language (ISO 639-1, or zeros), then
//!                       sentiment (see `Sentiment::to_byte`, or 0)
//! tags_len   varint     bytes of tags that follow
//! tags       varint count, then per tag: varint count, then per element
//!            varint (len << 1 | packed), then the bytes: UTF-8, or if
//!            packed, 32 bytes of hex, or an address (kind u16 BE, pubkey
//!            [u8; 32], then the `d` tag's UTF-8)
//! content    the rest: UTF-8, the bytes base64 content decodes to, or
//!            NIP-04's ciphertext bytes then its 16-byte IV
//! ```
//!
//! Ids, keys, and signatures are raw bytes rather than hex, and so is any
//! tag element that is exactly 64 lowercase hex digits — event and pubkey
//! references, mostly — flagged so it reads back as the same text. So is the
//! pubkey of one that is an address, `kind:pubkey:d`. Content that is base64
//! is kept as the bytes it spells, a quarter smaller, and so is NIP-04's
//! `base64?iv=base64`. Each only applies when the text written back is
//! exactly what was signed.
//! Nothing is kept twice: the JSON is written from the record when it's sent.
//!
//! The NIP-40 expiration is in the header so that checking it, which every
//! read does, needn't walk the tags. So is the event's [analysis], guessed
//! once when it's encoded, so it's the same guess every time it's read.

use std::borrow::Cow;
use std::cmp::Ordering;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::analysis::{self, Analysis, Sentiment};
use crate::event::{Event, is_hex64};

const FLAG_EXPIRATION: u8 = 1;
const FLAG_BASE64: u8 = 2;
const FLAG_ANALYSIS: u8 = 4;
const FLAG_NIP04: u8 = 8;
const FIXED: usize = 1 + 32 + 32 + 64 + 4 + 2;
/// A packed address's kind and pubkey, before its `d` tag.
const ADDRESS_FIXED: usize = 2 + 32;
const NIP04_IV: &str = "?iv=";
const NIP04_IV_LEN: usize = 16;

/// Encode an event, with its [analysis]. It must already be valid: ids and
/// keys hex, numbers in range (see [`Event::verify`]).
pub fn encode(event: &Event) -> Vec<u8> {
    let plain = encode_with(event, Analysis::default());
    let analysis = analysis::analyze(&EventView::new(&plain).expect("an encoded record"));
    match analysis.is_empty() {
        true => plain,
        false => encode_with(event, analysis),
    }
}

fn encode_with(event: &Event, analysis: Analysis) -> Vec<u8> {
    let expiration = expiration(event);
    let mut out = Vec::with_capacity(FIXED + 8 + event.content.len() + event.tags.len() * 40);
    let (content_flag, content) = match decode_base64(&event.content) {
        Some(bytes) => (FLAG_BASE64, Some(bytes)),
        None => match decode_nip04(&event.content) {
            Some(bytes) => (FLAG_NIP04, Some(bytes)),
            None => (0, None),
        },
    };
    let mut flags = content_flag;
    if expiration.is_some() {
        flags |= FLAG_EXPIRATION;
    }
    if !analysis.is_empty() {
        flags |= FLAG_ANALYSIS;
    }
    out.push(flags);
    push_hex(&mut out, &event.id);
    push_hex(&mut out, &event.pubkey);
    push_hex(&mut out, &event.sig);
    out.extend_from_slice(&(event.created_at as u32).to_le_bytes());
    out.extend_from_slice(&event.kind.to_le_bytes());
    if let Some(expiration) = expiration {
        out.extend_from_slice(&expiration.to_le_bytes());
    }
    if !analysis.is_empty() {
        out.extend_from_slice(&analysis.language.unwrap_or_default());
        out.push(analysis.sentiment.map_or(0, Sentiment::to_byte));
    }

    let mut tags = Vec::new();
    put_varint(&mut tags, event.tags.len() as u64);
    for tag in &event.tags {
        put_varint(&mut tags, tag.len() as u64);
        for element in tag {
            if is_hex64(element) {
                put_varint(&mut tags, 32 << 1 | 1);
                push_hex(&mut tags, element);
            } else if let Some((kind, pubkey, d)) = parse_address(element) {
                put_varint(&mut tags, ((ADDRESS_FIXED + d.len()) as u64) << 1 | 1);
                tags.extend_from_slice(&kind.to_be_bytes());
                push_hex(&mut tags, pubkey);
                tags.extend_from_slice(d.as_bytes());
            } else {
                put_varint(&mut tags, (element.len() as u64) << 1);
                tags.extend_from_slice(element.as_bytes());
            }
        }
    }
    put_varint(&mut out, tags.len() as u64);
    out.extend_from_slice(&tags);
    match content {
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

/// NIP-04 content, `base64?iv=base64`, as the ciphertext's bytes then the
/// IV's, if both parts are base64 that encodes back to exactly itself.
fn decode_nip04(content: &str) -> Option<Vec<u8>> {
    let (ciphertext, iv) = content.split_once(NIP04_IV)?;
    let mut bytes = decode_base64(ciphertext)?;
    let iv = decode_base64(iv)?;
    if iv.len() != NIP04_IV_LEN {
        return None;
    }
    bytes.extend_from_slice(&iv);
    Some(bytes)
}

/// The kind, pubkey, and `d` tag of an address, `kind:pubkey:d`, if it
/// reads back as exactly itself: the kind in plain decimal, the pubkey in
/// lowercase hex.
fn parse_address(text: &str) -> Option<(u16, &str, &str)> {
    let (kind_text, rest) = text.split_once(':')?;
    let (pubkey, d) = rest.split_once(':')?;
    let kind: u16 = kind_text.parse().ok()?;
    (kind.to_string() == kind_text && is_hex64(pubkey)).then_some((kind, pubkey, d))
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
    expiration: Option<u32>,
    analysis: Analysis,
    tags: &'a [u8],
    content: Content<'a>,
}

/// An event's content, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content<'a> {
    Text(&'a str),
    /// Base64, as the bytes it spells.
    Base64(&'a [u8]),
    /// NIP-04's `base64?iv=base64`, as the bytes each part spells.
    Nip04 {
        ciphertext: &'a [u8],
        iv: &'a [u8; NIP04_IV_LEN],
    },
}

impl<'a> Content<'a> {
    /// The content as it was signed.
    pub fn to_text(self) -> Cow<'a, str> {
        match self {
            Content::Text(text) => Cow::Borrowed(text),
            _ => {
                let mut out = String::with_capacity(self.text_len());
                self.push_text(&mut out);
                Cow::Owned(out)
            }
        }
    }

    fn push_text(self, out: &mut String) {
        match self {
            Content::Text(text) => out.push_str(text),
            Content::Base64(bytes) => STANDARD.encode_string(bytes, out),
            Content::Nip04 { ciphertext, iv } => {
                STANDARD.encode_string(ciphertext, out);
                out.push_str(NIP04_IV);
                STANDARD.encode_string(iv, out);
            }
        }
    }

    /// The length of [`to_text`](Content::to_text), without making it.
    fn text_len(self) -> usize {
        match self {
            Content::Text(text) => text.len(),
            Content::Base64(bytes) => bytes.len().div_ceil(3) * 4,
            Content::Nip04 { ciphertext, iv } => {
                ciphertext.len().div_ceil(3) * 4 + NIP04_IV.len() + iv.len().div_ceil(3) * 4
            }
        }
    }
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
        let analysis = if fixed[0] & FLAG_ANALYSIS != 0 {
            let (&[a, b, sentiment], tail) = rest.split_first_chunk::<3>()?;
            rest = tail;
            Analysis {
                language: (a != 0).then_some([a, b]),
                sentiment: Sentiment::from_byte(sentiment),
            }
        } else {
            Analysis::default()
        };
        let tags_len = usize::try_from(get_varint(&mut rest)?).ok()?;
        let tags = rest.get(..tags_len)?;
        let content = &rest[tags_len..];
        let content = if fixed[0] & FLAG_BASE64 != 0 {
            Content::Base64(content)
        } else if fixed[0] & FLAG_NIP04 != 0 {
            let (ciphertext, iv) = content.split_last_chunk::<NIP04_IV_LEN>()?;
            Content::Nip04 { ciphertext, iv }
        } else {
            Content::Text(std::str::from_utf8(content).ok()?)
        };
        Some(EventView {
            fixed,
            expiration,
            analysis,
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

    /// The NIP-40 expiration.
    pub fn expiration(&self) -> Option<u32> {
        self.expiration
    }

    /// Its language and sentiment, as guessed when it was encoded.
    pub fn analysis(&self) -> Analysis {
        self.analysis
    }

    /// Whether the event has expired by `now`.
    pub fn is_expired(&self, now: u32) -> bool {
        self.expiration.is_some_and(|at| at <= now)
    }

    pub fn content(&self) -> Content<'a> {
        self.content
    }

    pub fn tags(&self) -> Tags<'a> {
        let mut buf = self.tags;
        let remaining = get_varint(&mut buf).unwrap_or(0);
        Tags { buf, remaining }
    }

    /// Each tag's name and first value: what's indexed, for the names that
    /// are, and what filters match against.
    pub fn tag_values(&self) -> impl Iterator<Item = (&'a str, Element<'a>)> {
        self.tags().filter_map(|mut tag| {
            let Some(Element::Text(name)) = tag.next() else {
                return None;
            };
            Some((name, tag.next()?))
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
        let content_len = self.content.text_len();
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
                    Element::Address { .. } => push_json_str(&mut out, &element.to_text()),
                }
            }
            out.push(']');
        }
        out.push_str("],\"content\":");
        match self.content {
            Content::Text(text) => push_json_str(&mut out, text),
            // Nothing in base64 needs escaping.
            content => {
                out.push('"');
                content.push_text(&mut out);
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
        match (header & 1 == 1, len) {
            (true, 32) => Some(Element::Hex(bytes.try_into().ok()?)),
            (true, _) => address_element(bytes),
            (false, _) => Some(Element::Text(std::str::from_utf8(bytes).ok()?)),
        }
    }
}

/// One element of a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element<'a> {
    Text(&'a str),
    /// 64 lowercase hex digits, as the bytes they spell.
    Hex(&'a [u8; 32]),
    /// An address, `kind:pubkey:d`, its pubkey as the bytes it spells.
    Address {
        kind: u16,
        pubkey: &'a [u8; 32],
        d: &'a str,
    },
}

impl<'a> Element<'a> {
    const TEXT: u8 = 0;
    const HEX: u8 = 1;
    const ADDRESS: u8 = 2;

    /// The form tag values are indexed and compared in. See [`tag_value`].
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Element::Hex(bytes) => {
                out.push(Self::HEX);
                out.extend_from_slice(*bytes);
            }
            Element::Address { kind, pubkey, d } => {
                out.push(Self::ADDRESS);
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(*pubkey);
                out.extend_from_slice(d.as_bytes());
            }
            Element::Text(text) => {
                out.push(Self::TEXT);
                out.extend_from_slice(text.as_bytes());
            }
        }
    }

    /// Compare a value in [`tag_value`] form with this one, as if it were
    /// encoded too.
    pub fn compare(&self, encoded: &[u8]) -> Ordering {
        let Some((&flag, rest)) = encoded.split_first() else {
            return Ordering::Less;
        };
        match self {
            Element::Text(text) => flag
                .cmp(&Self::TEXT)
                .then_with(|| rest.cmp(text.as_bytes())),
            Element::Hex(bytes) => flag.cmp(&Self::HEX).then_with(|| rest.cmp(&bytes[..])),
            Element::Address { kind, pubkey, d } => flag.cmp(&Self::ADDRESS).then_with(|| {
                let parts = [&kind.to_be_bytes()[..], &pubkey[..], d.as_bytes()];
                rest.iter().cmp(parts.into_iter().flatten())
            }),
        }
    }

    /// Whether this is the value `encoded` (in [`tag_value`] form).
    #[cfg(test)]
    pub fn is(&self, encoded: &[u8]) -> bool {
        self.compare(encoded) == Ordering::Equal
    }

    pub fn encoded_len(&self) -> usize {
        1 + match self {
            Element::Hex(_) => 32,
            Element::Address { d, .. } => ADDRESS_FIXED + d.len(),
            Element::Text(text) => text.len(),
        }
    }

    /// The element as it was signed.
    pub fn to_text(self) -> Cow<'a, str> {
        match self {
            Element::Text(text) => Cow::Borrowed(text),
            Element::Hex(bytes) => Cow::Owned(hex::encode(bytes)),
            Element::Address { kind, pubkey, d } => {
                Cow::Owned(format!("{kind}:{}:{d}", hex::encode(pubkey)))
            }
        }
    }
}

/// A packed address: kind, pubkey, then the `d` tag.
fn address_element(bytes: &[u8]) -> Option<Element<'_>> {
    let (kind, rest) = bytes.split_first_chunk::<2>()?;
    let (pubkey, d) = rest.split_first_chunk::<32>()?;
    Some(Element::Address {
        kind: u16::from_be_bytes(*kind),
        pubkey,
        d: std::str::from_utf8(d).ok()?,
    })
}

/// A value in [`tag_value`] form, as the element it is.
pub fn tag_value_element(encoded: &[u8]) -> Option<Element<'_>> {
    match encoded.split_first()? {
        (&Element::TEXT, text) => Some(Element::Text(std::str::from_utf8(text).ok()?)),
        (&Element::HEX, bytes) => Some(Element::Hex(bytes.try_into().ok()?)),
        (&Element::ADDRESS, bytes) => address_element(bytes),
        _ => None,
    }
}

/// A tag value from a filter, in the form stored elements compare in: hex
/// as its bytes, flagged 1, an address with its pubkey as bytes, flagged 2,
/// and any other text flagged 0.
pub fn tag_value(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    if is_hex64(value) {
        out.push(Element::HEX);
        push_hex(&mut out, value);
    } else if let Some((kind, pubkey, d)) = parse_address(value) {
        out.push(Element::ADDRESS);
        out.extend_from_slice(&kind.to_be_bytes());
        push_hex(&mut out, pubkey);
        out.extend_from_slice(d.as_bytes());
    } else {
        out.push(Element::TEXT);
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

        // Tags with no value have none to give.
        let values: Vec<_> = view.tag_values().collect();
        assert_eq!(values.len(), 4);
        assert_eq!(values[1].0, "e");
        assert!(values[1].1.is(&tag_value(&hex)));
        assert!(!values[2].1.is(&tag_value(&hex)));
        assert!(values[2].1.is(&tag_value(&upper)));
        assert_eq!(values[3], ("expiration", Element::Text("1800000000")));
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
    fn keeps_nip04_content_as_bytes() {
        let ciphertext = STANDARD.encode((0..160u32).map(|i| (i * 13) as u8).collect::<Vec<_>>());
        let iv = STANDARD.encode([7u8; 16]);
        let content = format!("{ciphertext}?iv={iv}");
        let event = signed(2, 1_700_000_000, 4, vec![], &content);
        let record = encode(&event);
        let view = EventView::new(&record).unwrap();
        assert_eq!(
            view.content(),
            Content::Nip04 {
                ciphertext: &STANDARD.decode(&ciphertext).unwrap(),
                iv: &[7; 16],
            }
        );
        assert_eq!(view.content().to_text(), content);
        assert!(record.len() < FIXED + 1 + 160 + 16 + 4);
        let back = roundtrip(&event);
        assert_eq!(back, event);
        assert_eq!(back.verify(), Ok(()));

        // Only NIP-04 that reads back exactly as it was signed.
        for content in [
            format!("{ciphertext}?iv={}", STANDARD.encode([7u8; 15])),
            format!("{ciphertext}?iv={iv}?iv={iv}"),
            format!("{ciphertext}?iv={iv}\n"),
            format!("{}?iv={iv}", ciphertext.trim_end_matches('=')),
            format!("?iv={iv}"),
            format!("{ciphertext}?IV={iv}"),
        ] {
            let event = signed(2, 1_700_000_000, 4, vec![], &content);
            let record = encode(&event);
            assert!(
                matches!(EventView::new(&record).unwrap().content(), Content::Text(_)),
                "{content:?}"
            );
            assert_eq!(roundtrip(&event), event, "{content:?}");
        }
    }

    #[test]
    fn packs_addresses() {
        let hex = "ef".repeat(32);
        let address = format!("30023:{hex}:my:article");
        let event = signed(
            2,
            1_700_000_000,
            7,
            vec![
                vec!["a", &address],
                vec!["a", &format!("10000:{hex}:")],
                vec!["client", "Ditto", &format!("31990:{hex}:ditto")],
                // Not as it would read back, so kept as text.
                vec!["a", &format!("030023:{hex}:x")],
                vec!["a", &format!("+1:{hex}:x")],
                vec!["a", &format!("70000:{hex}:x")],
                vec!["a", &format!("1:{}:x", hex.to_uppercase())],
                vec!["a", &format!("1:{hex}")],
            ],
            "",
        );
        let back = roundtrip(&event);
        assert_eq!(back, event);
        assert_eq!(back.verify(), Ok(()));

        let record = encode(&event);
        let view = EventView::new(&record).unwrap();
        let values: Vec<_> = view.tag_values().map(|(_, value)| value).collect();
        let pubkey: [u8; 32] = hex::decode(&hex).unwrap().try_into().unwrap();
        assert_eq!(
            values[0],
            Element::Address {
                kind: 30_023,
                pubkey: &pubkey,
                d: "my:article"
            }
        );
        assert_eq!(values[0].to_text(), address);
        assert!(values[0].is(&tag_value(&address)));
        assert_eq!(values[0].encoded_len(), tag_value(&address).len());
        assert!(!values[0].is(&tag_value(&format!("30023:{hex}:my"))));
        assert!(matches!(values[1], Element::Address { d: "", .. }));
        assert!(values[3..].iter().all(|v| matches!(v, Element::Text(_))));
        assert!(values[3].is(&tag_value(&format!("030023:{hex}:x"))));

        // Comparison agrees with the encoded bytes' order.
        let mut encoded: Vec<_> = values
            .iter()
            .map(|v| {
                let mut out = Vec::new();
                v.encode(&mut out);
                out
            })
            .collect();
        encoded.sort();
        for value in &values {
            for other in &encoded {
                let mut mine = Vec::new();
                value.encode(&mut mine);
                assert_eq!(value.compare(other), other.cmp(&mine));
            }
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
