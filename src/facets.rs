//! NIP-50 search extensions: `key:value` conditions on what an event is
//! rather than on its text, like `pow:20` or `media:true`.
//!
//! Each is derived from the event alone, the same way when it's stored as
//! when a live event or a search hit is checked, so the two never disagree.
//! Those selective enough to look up are indexed in the `facets` table,
//! keyed like tags: facet ‖ value length ‖ value ‖ kind. Only what narrows
//! a search down is filed there — a proof of work, media, a protocol — and
//! the rest, `media:false` or `nsfw:false`, are checked by hand.
//!
//! Any extension can be negated: `-media:true` is `media:false`, `-pow:20`
//! is less than 20, `-tag:content-warning` lacks the tag. Conditions on the
//! same key don't replace each other; an event must meet all of them.

use std::sync::OnceLock;

use crate::record::{Content, Element, EventView};
use crate::store::{IndexedTags, MAX_INDEXED_TAG};

/// NIP-13 proof of work, as a u16 (BE): see [`pow`].
pub const POW: u8 = 0;
/// Media attached: see [`media`]. No value.
pub const MEDIA: u8 = 1;
/// Only video attached. No value.
pub const VIDEO: u8 = 2;
/// The NIP-48 protocol an event was bridged from.
pub const PROTOCOL: u8 = 3;
/// The NIP-89 address of the client that published an event.
pub const CLIENT: u8 = 4;
/// The name of an indexed tag an event has.
pub const TAG: u8 = 5;

/// The most bytes of a note's content scanned for media links.
const MAX_CONTENT_SCAN: usize = 32 * 1024;

/// File extensions of media links, and what they're of.
const MEDIA_EXTENSIONS: &[(&str, &str)] = &[
    ("jpg", "image"),
    ("jpeg", "image"),
    ("png", "image"),
    ("gif", "image"),
    ("webp", "image"),
    ("svg", "image"),
    ("avif", "image"),
    ("bmp", "image"),
    ("ico", "image"),
    ("tiff", "image"),
    ("mp4", "video"),
    ("webm", "video"),
    ("mov", "video"),
    ("avi", "video"),
    ("mkv", "video"),
    ("ogv", "video"),
    ("m4v", "video"),
    ("mp3", "audio"),
    ("ogg", "audio"),
    ("wav", "audio"),
    ("flac", "audio"),
    ("aac", "audio"),
    ("m4a", "audio"),
    ("opus", "audio"),
];

/// Hashtags that mark media as adult, unless configured otherwise.
pub const DEFAULT_NSFW_HASHTAGS: &[&str] = &[
    "nsfw", "adult", "nude", "nudes", "nudity", "sex", "xxx", "onlyfans", "porn", "porno", "boobs",
    "tits", "pussy", "cock", "milf", "slut", "fetish", "hentai", "loli",
];

static NSFW_HASHTAGS: OnceLock<Vec<String>> = OnceLock::new();

/// Set the hashtags that mark media as adult, once, before any are checked.
pub fn set_nsfw_hashtags(tags: impl IntoIterator<Item = String>) {
    let mut tags: Vec<String> = tags.into_iter().map(|t| t.to_lowercase()).collect();
    tags.sort_unstable();
    tags.dedup();
    let _ = NSFW_HASHTAGS.set(tags);
}

fn nsfw_hashtags() -> &'static [String] {
    NSFW_HASHTAGS.get_or_init(|| {
        let mut tags: Vec<String> = DEFAULT_NSFW_HASHTAGS
            .iter()
            .map(|t| t.to_string())
            .collect();
        tags.sort_unstable();
        tags
    })
}

/// A key of the `facets` table. Without a kind, the prefix every kind's
/// key for the value starts with.
pub fn key(facet: u8, value: &[u8], kind: Option<u16>) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + value.len() + 2);
    key.push(facet);
    key.push(value.len() as u8);
    key.extend_from_slice(value);
    if let Some(kind) = kind {
        key.extend_from_slice(&kind.to_be_bytes());
    }
    key
}

/// Every `facets` key an event is filed under.
pub fn keys(view: &EventView, indexed: &IndexedTags) -> Vec<Vec<u8>> {
    let kind = Some(view.kind());
    let mut keys = Vec::new();
    let pow = pow(view);
    if pow > 0 {
        keys.push(key(POW, &pow.to_be_bytes(), kind));
    }
    let media = media(view);
    if media.media {
        keys.push(key(MEDIA, &[], kind));
    }
    if media.video {
        keys.push(key(VIDEO, &[], kind));
    }
    for (facet, value) in [(PROTOCOL, protocol(view)), (CLIENT, client(view))] {
        if let Some(value) = value.filter(|v| v.len() <= MAX_INDEXED_TAG) {
            keys.push(key(facet, value.as_bytes(), kind));
        }
    }
    for mut tag in view.tags() {
        if let Some(Element::Text(name)) = tag.next()
            && indexed.contains(name)
        {
            keys.push(key(TAG, name.as_bytes(), kind));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// NIP-13 difficulty: the leading zero bits of the id, of an event with a
/// `nonce` tag, and no more than the target it commits to, if it does.
/// An event that wasn't mined has none, however its id happens to start.
pub fn pow(view: &EventView) -> u16 {
    let Some(mut nonce) = view
        .tags()
        .find(|tag| matches!(tag.clone().next(), Some(Element::Text("nonce"))))
    else {
        return 0;
    };
    let mut zeros = 0u16;
    for &byte in view.id() {
        zeros += byte.leading_zeros() as u16;
        if byte != 0 {
            break;
        }
    }
    match nonce.nth(2) {
        Some(Element::Text(target))
            if !target.is_empty() && target.bytes().all(|b| b.is_ascii_digit()) =>
        {
            zeros.min(target.parse().unwrap_or(u16::MAX))
        }
        _ => zeros,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Media {
    /// Whether anything is attached.
    pub media: bool,
    /// Whether everything attached is video.
    pub video: bool,
}

/// What an event has attached: what its NIP-92 `imeta` tags with a URL
/// describe, or for a note without any, media its content links to.
pub fn media(view: &EventView) -> Media {
    // Whether each attachment is video.
    let mut attached = Vec::new();
    for mut tag in view.tags() {
        if tag.next() != Some(Element::Text("imeta")) {
            continue;
        }
        let (mut url, mut video) = (false, false);
        for element in tag {
            let Element::Text(entry) = element else {
                continue;
            };
            match entry.split_once(' ') {
                Some(("url", value)) => url |= !value.is_empty(),
                Some(("m", value)) => video = value.starts_with("video/"),
                _ => {}
            }
        }
        if url {
            attached.push(video);
        }
    }
    if attached.is_empty()
        && view.kind() == 1
        && let Content::Text(content) = view.content()
    {
        let scanned = &content.as_bytes()[..content.len().min(MAX_CONTENT_SCAN)];
        for word in scanned.split(u8::is_ascii_whitespace) {
            if let Some(base) = media_link(word) {
                attached.push(base == "video");
            }
        }
    }
    Media {
        media: !attached.is_empty(),
        video: !attached.is_empty() && attached.iter().all(|&video| video),
    }
}

/// What a link is to, by its file extension, if it's to media.
fn media_link(word: &[u8]) -> Option<&'static str> {
    let rest = word
        .strip_prefix(b"https://")
        .or_else(|| word.strip_prefix(b"http://"))?;
    let path_end = rest
        .iter()
        .position(|&b| b == b'?' || b == b'#')
        .unwrap_or(rest.len());
    let path = &rest[..path_end];
    let dot = path.iter().rposition(|&b| b == b'.')?;
    let extension = &path[dot + 1..];
    if dot == 0
        || extension.is_empty()
        || !extension
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return None;
    }
    MEDIA_EXTENSIONS
        .iter()
        .find(|(ext, _)| ext.as_bytes().eq_ignore_ascii_case(extension))
        .map(|(_, base)| *base)
}

/// Whether an event is adult media: media with a hashtag marking it so.
/// NIP-36 content warnings don't count; `-tag:content-warning` is for those.
pub fn is_nsfw(view: &EventView) -> bool {
    let tags = nsfw_hashtags();
    !tags.is_empty() && view.tag_values().any(|(name, value)| {
        name == "t"
            && matches!(value, Element::Text(t) if tags.binary_search(&t.to_lowercase()).is_ok())
    }) && media(view).media
}

/// The third element of the first tag named `name` with one.
fn third<'a>(view: &EventView<'a>, name: &str) -> Option<&'a str> {
    view.tags().find_map(|mut tag| {
        if tag.next()? != Element::Text(name) {
            return None;
        }
        match tag.nth(1)? {
            Element::Text(text) => Some(text),
            Element::Hex(_) => None,
        }
    })
}

/// The protocol a NIP-48 `proxy` tag says an event was bridged from.
pub fn protocol<'a>(view: &EventView<'a>) -> Option<&'a str> {
    third(view, "proxy")
}

/// The NIP-89 address of the client a `client` tag names.
pub fn client<'a>(view: &EventView<'a>) -> Option<&'a str> {
    third(view, "client")
}

/// Whether an event has a tag named `name`, with a value or without.
pub fn has_tag(view: &EventView, name: &str) -> bool {
    view.tags()
        .any(|mut tag| tag.next() == Some(Element::Text(name)))
}

/// One extension of a search, negated if it was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    /// At least this much proof of work, or with `negated`, less.
    Pow { min: u16, negated: bool },
    /// Media attached, or not.
    Media(bool),
    /// Only video attached, or not.
    Video(bool),
    /// `nsfw:true` lets adult media in, as it is anyway; `nsfw:false` keeps
    /// it out.
    Nsfw(bool),
    /// Bridged from this protocol, or `nostr` for not bridged.
    Protocol { protocol: String, negated: bool },
    /// Published by the client at this NIP-89 address.
    Client { address: String, negated: bool },
    /// Has a tag with this name, or not.
    Tag { name: String, negated: bool },
}

/// A `bool` extension's value.
fn boolean(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

impl Condition {
    /// The condition an extension sets, if it's one this relay knows.
    /// Its key may start with `-` to negate it.
    pub fn parse(key: &str, value: &str) -> Option<Condition> {
        let (key, negated) = match key.strip_prefix('-') {
            Some(key) => (key, true),
            None => (key, false),
        };
        let condition = match key {
            "pow" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let min = value.parse().unwrap_or(u16::MAX);
                Condition::Pow { min, negated }
            }
            "media" => Condition::Media(boolean(value)? != negated),
            "video" => Condition::Video(boolean(value)? != negated),
            "nsfw" => Condition::Nsfw(boolean(value)? != negated),
            "protocol" => Condition::Protocol {
                protocol: value.to_string(),
                negated,
            },
            "client" => Condition::Client {
                address: value.to_string(),
                negated,
            },
            "tag" => Condition::Tag {
                name: value.to_string(),
                negated,
            },
            _ => return None,
        };
        Some(condition)
    }

    pub fn matches(&self, view: &EventView) -> bool {
        match self {
            Condition::Pow { min, negated } => (pow(view) >= *min) != *negated,
            Condition::Media(want) => media(view).media == *want,
            Condition::Video(want) => media(view).video == *want,
            Condition::Nsfw(true) => true,
            Condition::Nsfw(false) => !is_nsfw(view),
            Condition::Protocol {
                protocol: p,
                negated,
            } => {
                let is = match protocol(view) {
                    None => p == "nostr",
                    Some(found) => found == p,
                };
                is != *negated
            }
            Condition::Client { address, negated } => {
                (client(view) == Some(address.as_str())) != *negated
            }
            Condition::Tag { name, negated } => has_tag(view, name) != *negated,
        }
    }

    /// Where in the `facets` table the events meeting this condition are
    /// filed, if they all are: the key to start at, and the prefix every
    /// key from there that's for it starts with.
    pub fn lookup(&self, indexed: &IndexedTags) -> Option<(Vec<u8>, Vec<u8>)> {
        let exact = |facet, value: &[u8]| {
            let key = key(facet, value, None);
            Some((key.clone(), key))
        };
        match self {
            Condition::Pow {
                min,
                negated: false,
            } if *min > 0 => Some((key(POW, &min.to_be_bytes(), None), vec![POW])),
            Condition::Media(true) => exact(MEDIA, &[]),
            Condition::Video(true) => exact(VIDEO, &[]),
            Condition::Protocol {
                protocol,
                negated: false,
            } if protocol != "nostr" && protocol.len() <= MAX_INDEXED_TAG => {
                exact(PROTOCOL, protocol.as_bytes())
            }
            // Bridged at all.
            Condition::Protocol {
                protocol,
                negated: true,
            } if protocol == "nostr" => Some((vec![PROTOCOL], vec![PROTOCOL])),
            Condition::Client {
                address,
                negated: false,
            } if address.len() <= MAX_INDEXED_TAG => exact(CLIENT, address.as_bytes()),
            Condition::Tag {
                name,
                negated: false,
            } if indexed.contains(name) => exact(TAG, name.as_bytes()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record;

    fn with<T>(event: &Event, f: impl FnOnce(&EventView) -> T) -> T {
        let record = record::encode(event);
        f(&EventView::new(&record).unwrap())
    }

    /// An event with at least `bits` of work, committing to `target`.
    fn mine(bits: u16, target: &str) -> Event {
        (0u32..)
            .map(|n| {
                let nonce = n.to_string();
                signed(1, 100, 1, vec![vec!["nonce", &nonce, target]], "")
            })
            .find(|e| {
                let id = hex::decode(&e.id).unwrap();
                let zeros: u32 = id
                    .iter()
                    .scan(true, |go, &b| {
                        let z = if *go { b.leading_zeros() } else { 0 };
                        *go &= b == 0;
                        Some(z)
                    })
                    .sum();
                zeros >= u32::from(bits)
            })
            .unwrap()
    }

    #[test]
    fn measures_committed_work() {
        let mined = mine(6, "6");
        with(&mined, |v| assert_eq!(pow(v), 6));
        let lucky = mine(6, "2");
        with(&lucky, |v| assert_eq!(pow(v), 2));
        let uncommitted = mine(5, "");
        with(&uncommitted, |v| assert!(pow(v) >= 5));
        // Not mined, so no work, whatever the id.
        let plain = signed(1, 100, 1, vec![], "");
        with(&plain, |v| assert_eq!(pow(v), 0));
    }

    #[test]
    fn finds_media() {
        let media_of =
            |kind, tags: Vec<Vec<&str>>, content| with(&signed(1, 100, kind, tags, content), media);
        let both = Media {
            media: true,
            video: true,
        };
        let image = Media {
            media: true,
            video: false,
        };
        let none = Media::default();
        let imeta = |url, m| vec!["imeta", url, m];

        assert_eq!(
            media_of(20, vec![imeta("url https://x/a", "m image/png")], ""),
            image
        );
        assert_eq!(
            media_of(1, vec![imeta("url https://x/a", "m video/mp4")], ""),
            both
        );
        // All of it video, or it's not video.
        assert_eq!(
            media_of(
                1,
                vec![
                    imeta("url https://x/a", "m video/mp4"),
                    imeta("url https://x/b", "m image/png")
                ],
                ""
            ),
            image
        );
        assert_eq!(media_of(1, vec![imeta("url https://x/a", "")], ""), image);
        assert_eq!(media_of(1, vec![imeta("m image/png", "")], ""), none);

        // Links in a note's content, if it has no imeta.
        assert_eq!(media_of(1, vec![], "look https://x.com/a.JPG?s=1 !"), image);
        assert_eq!(media_of(1, vec![], "https://x.com/clip.mp4"), both);
        assert_eq!(media_of(1, vec![], "https://x.com/page.html"), none);
        assert_eq!(media_of(1, vec![], "https://x.com/a.jpg/"), none);
        assert_eq!(media_of(1, vec![], "see:https://x.com/a.jpg"), none);
        assert_eq!(media_of(1111, vec![], "https://x.com/a.jpg"), none);
        let far = format!("{} https://x.com/a.jpg", "x".repeat(MAX_CONTENT_SCAN));
        assert_eq!(media_of(1, vec![], &far), none);
    }

    #[test]
    fn marks_adult_media() {
        let nsfw = |tags: Vec<Vec<&str>>, content| with(&signed(1, 100, 1, tags, content), is_nsfw);
        let pic = "https://x.com/a.png";
        assert!(nsfw(vec![vec!["t", "NSFW"]], pic));
        assert!(!nsfw(vec![vec!["t", "nsfw"]], "words"));
        assert!(!nsfw(vec![vec!["t", "cats"]], pic));
        assert!(!nsfw(vec![vec!["content-warning", "nudity"]], pic));
    }

    #[test]
    fn reads_proxies_and_clients() {
        let event = signed(
            1,
            100,
            1,
            vec![
                vec!["proxy", "https://x"],
                vec!["proxy", "https://y", "activitypub"],
                vec!["client", "Ditto", "31990:ab:ditto"],
                vec!["content-warning"],
            ],
            "",
        );
        with(&event, |v| {
            assert_eq!(protocol(v), Some("activitypub"));
            assert_eq!(client(v), Some("31990:ab:ditto"));
            assert!(has_tag(v, "content-warning") && !has_tag(v, "t"));
        });
    }

    #[test]
    fn parses_and_negates() {
        let parse = |k, v| Condition::parse(k, v);
        assert_eq!(parse("media", "true"), Some(Condition::Media(true)));
        assert_eq!(parse("-media", "true"), Some(Condition::Media(false)));
        assert_eq!(parse("-nsfw", "true"), Some(Condition::Nsfw(false)));
        assert_eq!(parse("media", "yes"), None);
        assert_eq!(parse("pow", "-1"), None);
        assert_eq!(parse("spam", "true"), None);
        assert_eq!(
            parse("-pow", "99999"),
            Some(Condition::Pow {
                min: u16::MAX,
                negated: true
            })
        );

        let bridged = signed(1, 100, 1, vec![vec!["proxy", "x", "activitypub"]], "");
        let native = signed(1, 100, 1, vec![], "");
        let nostr = parse("protocol", "nostr").unwrap();
        let ap = parse("protocol", "activitypub").unwrap();
        let not_nostr = parse("-protocol", "nostr").unwrap();
        with(&bridged, |v| {
            assert!(!nostr.matches(v) && ap.matches(v) && not_nostr.matches(v))
        });
        with(&native, |v| {
            assert!(nostr.matches(v) && !ap.matches(v) && !not_nostr.matches(v))
        });
    }
}
