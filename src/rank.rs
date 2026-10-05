//! `sort:top`, `sort:hot`, `sort:controversial`, `sort:rising`, and
//! `sort:zaps`: events ranked by how the people the relay
//! [trusts](crate::wot) have engaged with them.
//!
//! # Scores
//!
//! An event's *score* is the sum of the weights of everyone who's engaged
//! with it, each once however often, the author aside: who's reacted to it
//! (other than negatively), reposted it, replied to it (as NIP-10 has it),
//! commented on it (NIP-22), or quoted it. Only regular events engage.
//! Beside it are kept the same sum over only those who've replied or
//! commented, and over only those who've reacted, negatively too, for
//! `sort:controversial`; and for `sort:zaps`, the msats zapped to it, each
//! zap's times its sender's weight.
//!
//! A NIP-57 zap receipt is signed by the recipient's wallet, which anyone
//! can pretend to be, so its sender is whoever signed the zap request it
//! carries, which is checked, and what it zaps is what that request names.
//! Its amount is its invoice's, at most what the request asked for. A kind
//! 8333 onchain zap's sender is its author, and its amount what it says.
//! Neither can be checked further, which is why a zap counts only as much
//! as its sender is trusted. Still, a trusted sender's zap request can be
//! replayed in receipts for payments never made.
//!
//! A zap also counts toward what its recipients have received in all, kept
//! like an event's score under an id of their own ([`recipient`]), so that
//! profiles can be ranked by it. A zap to several splits evenly among them.
//!
//! Apart from all that, `zaps` tallies every zap to an event or an address
//! at face value, whoever sent it, for [NIP-85](crate::nip85) assertions.
//!
//! `engagement` keeps each pair of engager and target, with [`Counts`] of
//! how the engager's events engage the target, so the pair counts until the
//! last of them goes. It's keyed engager first, so everything someone has
//! engaged with is one walk. `scores` keeps each target's score by id —
//! engagement often arrives before what it's for — with what's known of
//! the target: its author once it's been seen, and while it's stored, its
//! sequence number, kind, and `created_at`.
//!
//! # Weights
//!
//! Weights change all the time as trust moves, so a score counts each
//! engager at the weight *applied* to them, kept in `applied`, and an
//! engager's weight is applied again only when it's moved at least a
//! [step](Rank::new) from it, or to or from nothing. Then the engager is
//! queued, and a turn of the writer walks what they've engaged with,
//! moving each score by the difference — a budget at a time, so a walk of
//! someone who's engaged with a great deal is spread over turns, and
//! engagement arriving meanwhile counts at the weight applied on its side
//! of the walk. Every score is therefore exactly the sum of its engagers'
//! applied weights, in thousandths. Walks wait while trust is still being
//! pushed, so a weight is applied once it's settled.
//!
//! Without a web of trust, everyone weighs 1, and a score is a count.
//!
//! # Ranks
//!
//! `ranked` files each stored event with a score under its mode and kind:
//! by score for `sort:top`; for `sort:hot` by
//! `log2(score) + created_at / half_life`, which orders events as
//! `score * 2^-(age / half_life)` does at any moment, so it needn't change
//! as time passes; for `sort:controversial` by
//! `min(comments, reactions) * sqrt(comments + reactions)`; and for
//! `sort:zaps` by zaps. Profiles are ranked instead by their author's
//! trust, and for `sort:zaps` by what their author has received.
//!
//! `sort:rising` is score per second of age, and only for the past week's
//! events. That changes as time passes, so it isn't filed: events are
//! taken from the top of `sort:hot` until none further down could rise
//! faster than those found (see [`walk_rising`]). For `sort:rising` and
//! `sort:controversial`, profiles are ranked as their authors' best events
//! are.
//!
//! A search with no text finds the best by walking `ranked` from the top
//! (or, for a filter naming authors, ids, or tags, by ranking all it
//! matches); one with text ranks what the search index finds.

use std::collections::{BinaryHeap, HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::analysis::Sentiment;
use crate::event::{Event, KindClass, decode_hex};
use crate::filter::{Filter, Sort};
use crate::lmdb::{Cursor, Result, RwTxn, Txn};
use crate::metrics::METRICS;
use crate::query::MAX_EXAMINED;
use crate::record::{Element, EventView};
use crate::store::{Store, address};
use crate::wot;

/// `ranked` modes.
const TOP: u8 = 0;
const HOT: u8 = 1;
const PROFILE: u8 = 2;
const CONTROVERSIAL: u8 = 3;
const ZAPS: u8 = 4;
/// Profiles, by what their authors have been zapped.
const RECEIVED: u8 = 5;
/// Not filed: see [`walk_rising`].
const RISING: u8 = 6;

/// A weight of 1, in the thousandths weights and scores are kept in.
const FULL: i64 = 1000;

/// The `meta` keys of what scores were computed with, and the walk under
/// way.
const PARAMS: &[u8] = b"rank_params";
const WALK: &[u8] = b"rank_walk";

/// The most entries rebuilt per write transaction.
const REBUILD_CHUNK: usize = 10_000;

/// `sort:rising` ranks only events this new, in seconds,
const RISING_WINDOW: u32 = 7 * 86_400;
/// and takes any newer than this to be this old.
const RISING_MIN_AGE: u32 = 360;

/// How many authors' best events rank profiles, where their authors' events
/// do.
const RANKED_AUTHORS: usize = 1000;

const ZAP_RECEIPT: u16 = 9735;
const ZAP_REQUEST: u16 = 9734;
const ONCHAIN_ZAP: u16 = 8333;

/// The most msats a zap can be: all the bitcoin there will ever be.
const MAX_MSATS: u128 = 21_000_000 * 100_000_000_000;

/// How events are ranked.
#[derive(Debug, Clone)]
pub struct Rank {
    /// Seconds.
    half_life: u32,
    /// In thousandths.
    step: i64,
    /// About how many targets to walk per turn.
    budget: usize,
}

impl Default for Rank {
    fn default() -> Rank {
        Rank::new(86_400, 0.05, 10_000)
    }
}

impl Rank {
    /// `sort:hot` halves a score's worth every `half_life` seconds. An
    /// engager's weight is applied again once it's moved by `step`.
    pub fn new(half_life: u32, step: f64, budget: usize) -> Rank {
        Rank {
            half_life: half_life.max(1),
            step: ((step * FULL as f64).round() as i64).max(1),
            budget: budget.max(1),
        }
    }
}

/// What NIP-10 says a note replies to: its `e` tag marked `reply`, or
/// failing that `root`, or with no markers, its last `e` tag.
fn parent<'a>(view: &EventView<'a>) -> Option<&'a [u8; 32]> {
    let (mut reply, mut root, mut last, mut marked) = (None, None, None, false);
    for mut tag in view.tags() {
        if tag.next() != Some(Element::Text("e")) {
            continue;
        }
        let Some(Element::Hex(id)) = tag.next() else {
            continue;
        };
        match tag.nth(1) {
            Some(Element::Text("reply")) => (reply, marked) = (Some(id), true),
            Some(Element::Text("root")) => (root, marked) = (Some(id), true),
            Some(Element::Text("mention")) => marked = true,
            _ => last = Some(id),
        }
    }
    match marked {
        true => reply.or(root),
        false => last,
    }
}

/// The first or last value of the `name` tags that's an id.
fn id_tag<'a>(view: &EventView<'a>, name: &str, last: bool) -> Option<&'a [u8; 32]> {
    let mut ids = ids(view, name);
    match last {
        true => ids.last(),
        false => ids.next(),
    }
}

/// The values of the `name` tags that are ids or pubkeys.
fn ids<'a>(view: &EventView<'a>, name: &str) -> impl Iterator<Item = &'a [u8; 32]> {
    view.tag_values().filter_map(move |(n, value)| match value {
        Element::Hex(id) if n == name => Some(id),
        _ => None,
    })
}

/// How one engager's events engage one target, summed over them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Those that count toward its score: all but negative reactions and
    /// zaps.
    pub engages: u32,
    /// Replies and comments.
    pub comments: u32,
    /// Reactions, negative ones too.
    pub reactions: u32,
    /// Msats zapped.
    pub msats: u128,
}

impl Counts {
    fn encode(&self) -> [u8; 28] {
        let mut out = [0; 28];
        out[..4].copy_from_slice(&self.engages.to_le_bytes());
        out[4..8].copy_from_slice(&self.comments.to_le_bytes());
        out[8..12].copy_from_slice(&self.reactions.to_le_bytes());
        out[12..].copy_from_slice(&self.msats.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Counts> {
        let bytes: &[u8; 28] = bytes.try_into().ok()?;
        Some(Counts {
            engages: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            comments: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            reactions: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            msats: u128::from_le_bytes(bytes[12..].try_into().unwrap()),
        })
    }

    fn is_empty(&self) -> bool {
        *self == Counts::default()
    }

    /// These and `other` together.
    pub fn plus(&self, other: &Counts) -> Option<Counts> {
        Some(Counts {
            engages: self.engages.checked_add(other.engages)?,
            comments: self.comments.checked_add(other.comments)?,
            reactions: self.reactions.checked_add(other.reactions)?,
            msats: self.msats.checked_add(other.msats)?,
        })
    }

    /// These less `other`, if that's not less than nothing.
    fn minus(&self, other: &Counts) -> Option<Counts> {
        Some(Counts {
            engages: self.engages.checked_sub(other.engages)?,
            comments: self.comments.checked_sub(other.comments)?,
            reactions: self.reactions.checked_sub(other.reactions)?,
            msats: self.msats.checked_sub(other.msats)?,
        })
    }

    /// The most of each.
    fn max(&self, other: &Counts) -> Counts {
        Counts {
            engages: self.engages.max(other.engages),
            comments: self.comments.max(other.comments),
            reactions: self.reactions.max(other.reactions),
            msats: self.msats.max(other.msats),
        }
    }
}

/// What's engaged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    Event([u8; 32]),
    /// Everyone zapped this pubkey.
    Recipient([u8; 32]),
}

impl Target {
    /// What its score is kept under.
    pub fn id(&self) -> [u8; 32] {
        match self {
            Target::Event(id) => *id,
            Target::Recipient(pubkey) => recipient(pubkey),
        }
    }
}

/// The id what's been zapped to a pubkey is scored under: no event's.
pub fn recipient(pubkey: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"zaps received by ")
        .chain_update(pubkey)
        .finalize()
        .into()
}

/// What's zapped to an event, or to an address, is tallied in `zaps` under.
pub enum Zapped<'a> {
    Event(&'a [u8; 32]),
    Address(&'a str),
}

impl Zapped<'_> {
    fn key(&self) -> [u8; 32] {
        match self {
            Zapped::Event(id) => **id,
            Zapped::Address(address) => Sha256::new()
                .chain_update(b"zaps of address ")
                .chain_update(address.as_bytes())
                .finalize()
                .into(),
        }
    }
}

/// How many zaps something has had, and their msats, whoever sent them.
pub fn zaps(store: &Store, txn: &Txn, zapped: Zapped) -> Result<(u64, u128)> {
    zaps_under(store, txn, &zapped.key())
}

fn zaps_under(store: &Store, txn: &Txn, key: &[u8; 32]) -> Result<(u64, u128)> {
    Ok(txn
        .get(store.tables.zaps, key)?
        .and_then(|v| <&[u8; 24]>::try_from(v).ok())
        .map(|v| {
            let count = u64::from_le_bytes(v[..8].try_into().unwrap());
            (count, u128::from_le_bytes(v[8..].try_into().unwrap()))
        })
        .unwrap_or_default())
}

/// Tally, or with `add` false take back, a zap in `zaps`.
fn tally(store: &Store, txn: &mut RwTxn, zap: &Zap, add: bool) -> Result<()> {
    let event = zap.event.as_ref().map(Zapped::Event);
    let address = zap.address.as_deref().map(Zapped::Address);
    for zapped in event.into_iter().chain(address) {
        let key = zapped.key();
        let (count, msats) = zaps_under(store, txn, &key)?;
        let (count, msats) = match add {
            true => (count + 1, msats.wrapping_add(zap.msats)),
            false => (count.saturating_sub(1), msats.wrapping_sub(zap.msats)),
        };
        if count == 0 {
            txn.del(store.tables.zaps, &key, None)?;
        } else {
            let mut value = [0; 24];
            value[..8].copy_from_slice(&count.to_le_bytes());
            value[8..].copy_from_slice(&msats.to_le_bytes());
            txn.put(store.tables.zaps, &key, &value)?;
        }
    }
    Ok(())
}

/// One engager's engagement with one target, by one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engagement {
    pub engager: [u8; 32],
    pub target: Target,
    pub counts: Counts,
}

#[cfg(test)]
fn engagements(view: &EventView) -> Vec<Engagement> {
    engagements_with(view, zap(view).as_ref())
}

/// How an event engages with others, given its [`zap`]. See the [module
/// docs].
///
/// [module docs]: self
fn engagements_with(view: &EventView, zap: Option<&Zap>) -> Vec<Engagement> {
    if KindClass::of(view.kind()) != KindClass::Regular {
        return Vec::new();
    }
    let author = *view.pubkey();
    let engagement = |engager, target, counts| Engagement {
        engager,
        target,
        counts,
    };
    let engages = Counts {
        engages: 1,
        ..Counts::default()
    };
    let comments = Counts {
        comments: 1,
        ..engages
    };
    let mut out = Vec::new();
    let direct = match view.kind() {
        // NIP-25: the last `e` tag.
        7 => id_tag(view, "e", true).map(|id| {
            let negative = view.analysis().sentiment == Some(Sentiment::Negative);
            let counts = Counts {
                engages: (!negative).into(),
                reactions: 1,
                ..Counts::default()
            };
            (id, counts)
        }),
        6 | 16 => id_tag(view, "e", false).map(|id| (id, engages)),
        1 => parent(view).map(|id| (id, comments)),
        // NIP-22: the parent, when it's an event.
        1111 => id_tag(view, "e", false).map(|id| (id, comments)),
        _ => None,
    };
    if let Some((id, counts)) = direct {
        out.push(engagement(author, Target::Event(*id), counts));
    }
    if let Some(zap) = zap {
        let counts = |msats| Counts {
            msats,
            ..Counts::default()
        };
        if let Some(id) = zap.event {
            out.push(engagement(zap.sender, Target::Event(id), counts(zap.msats)));
        }
        // What each was paid isn't said.
        let each = zap.msats / zap.recipients.len().max(1) as u128;
        for pubkey in zap.recipients.iter().filter(|_| each > 0) {
            out.push(engagement(
                zap.sender,
                Target::Recipient(*pubkey),
                counts(each),
            ));
        }
    }
    // A receipt's author is a wallet.
    if view.kind() != ZAP_RECEIPT {
        for id in ids(view, "q") {
            out.push(engagement(author, Target::Event(*id), engages));
        }
    }
    // One event engages a target once, however many ways.
    out.sort_unstable_by_key(|e| (e.engager, e.target));
    out.dedup_by(|later, kept| {
        let same = (later.engager, later.target) == (kept.engager, kept.target);
        if same {
            kept.counts = kept.counts.max(&later.counts);
        }
        same
    });
    out
}

/// A zap: who sent it, how much, and to what.
struct Zap {
    sender: [u8; 32],
    msats: u128,
    event: Option<[u8; 32]>,
    /// The address of the addressable event zapped, as its `a` tag has it.
    address: Option<String>,
    /// Sorted.
    recipients: Vec<[u8; 32]>,
}

/// An event's zap, if it's one that zaps something. See the [module docs].
///
/// [module docs]: self
fn zap(view: &EventView) -> Option<Zap> {
    let mut zap = match view.kind() {
        ZAP_RECEIPT => {
            let Some(Element::Text(description)) = view.tag("description") else {
                return None;
            };
            let request: Event = serde_json::from_str(description).ok()?;
            if request.kind != ZAP_REQUEST || request.verify().is_err() {
                return None;
            }
            let Some(Element::Text(invoice)) = view.tag("bolt11") else {
                return None;
            };
            let mut msats = invoice_msats(invoice)?;
            if let Some(asked) = request.tag("amount").and_then(|a| a.parse().ok()) {
                msats = msats.min(asked);
            }
            Zap {
                sender: decode_hex(&request.pubkey)?,
                msats,
                event: request.tag("e").and_then(decode_hex),
                address: request.tag("a").map(String::from),
                recipients: request.tag("p").and_then(decode_hex).into_iter().collect(),
            }
        }
        ONCHAIN_ZAP => {
            let Some(Element::Text(sats)) = view.tag("amount") else {
                return None;
            };
            if !sats.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Zap {
                sender: *view.pubkey(),
                msats: sats.parse::<u128>().ok()?.checked_mul(1000)?,
                event: id_tag(view, "e", false).copied(),
                address: match view.tag("a") {
                    Some(address @ (Element::Text(_) | Element::Address { .. })) => {
                        Some(address.to_text().into_owned())
                    }
                    _ => None,
                },
                recipients: ids(view, "p").copied().collect(),
            }
        }
        _ => return None,
    };
    zap.recipients.sort_unstable();
    zap.recipients.dedup();
    // Paying yourself is free.
    if zap.recipients.contains(&zap.sender) {
        return None;
    }
    zap.msats = zap.msats.min(MAX_MSATS);
    (zap.msats > 0).then_some(zap)
}

/// The msats a BOLT 11 invoice on bitcoin's mainnet is for, if it says.
fn invoice_msats(invoice: &str) -> Option<u128> {
    let invoice = invoice.to_ascii_lowercase();
    // No `1` is in the data that follows it.
    let prefix = &invoice[..invoice.rfind('1')?];
    let amount = prefix.strip_prefix("lnbc")?;
    let (digits, multiplier) = match amount.as_bytes().last()? {
        b'0'..=b'9' => (amount, None),
        &multiplier => (&amount[..amount.len() - 1], Some(multiplier)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u128 = digits.parse().ok()?;
    // A bitcoin is 10^11 msats.
    match multiplier {
        None => n.checked_mul(100_000_000_000),
        Some(b'm') => n.checked_mul(100_000_000),
        Some(b'u') => n.checked_mul(100_000),
        Some(b'n') => n.checked_mul(100),
        Some(b'p') => Some(n / 10),
        Some(_) => None,
    }
}

/// What's kept of something engaged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Score {
    /// Its engagers' applied weights, in thousandths.
    score: i64,
    /// Likewise, of those who've replied or commented,
    comments: i64,
    /// and of those who've reacted.
    reactions: i64,
    /// The msats zapped to it, each zap's times its sender's applied
    /// weight. It wraps, so that taking a zap back is always exact.
    zaps: i128,
    /// While it's stored and current, its sequence number; 0 otherwise.
    seq: u64,
    created_at: u32,
    kind: u16,
    /// Once it's been seen.
    author: Option<[u8; 32]>,
    /// It's what's been zapped to its author: see [`recipient`]. Its
    /// whereabouts are their profile's.
    recipient: bool,
}

impl Score {
    fn encode(&self) -> [u8; 87] {
        let mut out = [0; 87];
        out[..8].copy_from_slice(&self.score.to_le_bytes());
        out[8..16].copy_from_slice(&self.comments.to_le_bytes());
        out[16..24].copy_from_slice(&self.reactions.to_le_bytes());
        out[24..40].copy_from_slice(&self.zaps.to_le_bytes());
        out[40..48].copy_from_slice(&self.seq.to_le_bytes());
        out[48..52].copy_from_slice(&self.created_at.to_le_bytes());
        out[52..54].copy_from_slice(&self.kind.to_le_bytes());
        out[54] = u8::from(self.recipient) << 1;
        if let Some(author) = self.author {
            out[54] |= 1;
            out[55..].copy_from_slice(&author);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Option<Score> {
        let bytes: &[u8; 87] = bytes.try_into().ok()?;
        Some(Score {
            score: i64::from_le_bytes(bytes[..8].try_into().unwrap()),
            comments: i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            reactions: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            zaps: i128::from_le_bytes(bytes[24..40].try_into().unwrap()),
            seq: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            created_at: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            kind: u16::from_le_bytes(bytes[52..54].try_into().unwrap()),
            author: (bytes[54] & 1 == 1).then(|| bytes[55..].try_into().unwrap()),
            recipient: bytes[54] & 2 == 2,
        })
    }

    /// Count an engager's engagement at `weight`, or with a negative one,
    /// stop counting it.
    fn credit(&mut self, counts: &Counts, weight: i64) {
        let at = |count: u32| if count > 0 { weight } else { 0 };
        self.score += at(counts.engages);
        self.comments += at(counts.comments);
        self.reactions += at(counts.reactions);
        let zaps = i128::from(weight).wrapping_mul(counts.msats as i128);
        self.zaps = self.zaps.wrapping_add(zaps);
    }

    /// Where `ranked` files it: nowhere unless it's stored and scored.
    fn ranks(&self, half_life: u32) -> Vec<(u8, u64)> {
        let mut out = Vec::new();
        if self.seq == 0 {
            return out;
        }
        if self.recipient {
            out.extend((self.zaps > 0).then(|| (RECEIVED, ordered(self.zaps as f64))));
            return out;
        }
        if self.score > 0 {
            out.push((TOP, self.score as u64));
            out.push((HOT, hot(self.score, self.created_at, half_life)));
        }
        if let Some(rank) = controversial(self.comments, self.reactions) {
            out.push((CONTROVERSIAL, rank));
        }
        if self.zaps > 0 {
            out.push((ZAPS, ordered(self.zaps as f64)));
        }
        out
    }
}

/// A float as a u64 that sorts the same.
fn ordered(x: f64) -> u64 {
    let bits = x.to_bits();
    match bits >> 63 {
        1 => !bits,
        _ => bits | 1 << 63,
    }
}

/// The float an [`ordered`] u64 is.
fn unordered(rank: u64) -> f64 {
    f64::from_bits(match rank >> 63 {
        1 => rank & !(1 << 63),
        _ => !rank,
    })
}

/// `log2(score) + created_at / half_life`, [ordered].
fn hot(score: i64, created_at: u32, half_life: u32) -> u64 {
    ordered((score as f64 / FULL as f64).log2() + f64::from(created_at) / f64::from(half_life))
}

/// `min(comments, reactions) * sqrt(comments + reactions)`, [ordered], if
/// it's been both commented on and reacted to.
fn controversial(comments: i64, reactions: i64) -> Option<u64> {
    if comments <= 0 || reactions <= 0 {
        return None;
    }
    let balance = comments.min(reactions) as f64;
    Some(ordered(balance * ((comments + reactions) as f64).sqrt()))
}

/// A score per second of age at `now`, if the event's new enough to rise.
fn rising(score: i64, created_at: u32, now: u32) -> Option<f64> {
    if score <= 0 || created_at.saturating_add(RISING_WINDOW) < now {
        return None;
    }
    let age = now.saturating_sub(created_at).max(RISING_MIN_AGE);
    Some(score as f64 / f64::from(age))
}

fn ranked_key(mode: u8, kind: u16) -> [u8; 3] {
    let kind = kind.to_be_bytes();
    [mode, kind[0], kind[1]]
}

/// A `ranked` value: rank, then the sequence number in 48 bits.
fn ranked_value(rank: u64, seq: u64) -> [u8; 14] {
    let mut out = [0; 14];
    out[..8].copy_from_slice(&rank.to_be_bytes());
    out[8..].copy_from_slice(&seq.to_be_bytes()[2..]);
    out
}

fn ranked_rank(value: &[u8]) -> u64 {
    u64::from_be_bytes(value[..8].try_into().unwrap())
}

fn ranked_seq(value: &[u8]) -> u64 {
    let mut seq = [0; 8];
    seq[2..].copy_from_slice(&value[8..14]);
    u64::from_be_bytes(seq)
}

fn score_of(store: &Store, txn: &Txn, id: &[u8; 32]) -> Result<Option<Score>> {
    Ok(txn.get(store.tables.scores, id)?.and_then(Score::decode))
}

/// An event's score: its engagers' applied weights, in whole engagers.
pub fn score(store: &Store, txn: &Txn, id: &[u8; 32]) -> Result<f64> {
    let score = score_of(store, txn, id)?.map_or(0, |s| s.score);
    Ok(score as f64 / FULL as f64)
}

/// Keep a target's new score, refiling it in `ranked`.
fn set_score(
    store: &Store,
    txn: &mut RwTxn,
    id: &[u8; 32],
    old: &Score,
    new: &Score,
) -> Result<()> {
    let t = store.tables;
    let half_life = store.rank().half_life;
    if old.seq != 0 {
        for (mode, rank) in old.ranks(half_life) {
            let value = ranked_value(rank, old.seq);
            txn.del(t.ranked, &ranked_key(mode, old.kind), Some(&value))?;
        }
    }
    for (mode, rank) in new.ranks(half_life) {
        let value = ranked_value(rank, new.seq);
        txn.put_dup(t.ranked, &ranked_key(mode, new.kind), &value)?;
    }
    txn.put(t.scores, id, &new.encode()).map(drop)
}

/// An engager's weight now, in thousandths.
fn weight(store: &Store, txn: &Txn, engager: &[u8; 32]) -> Result<i64> {
    match store.wot() {
        Some(wot) => Ok((f64::from(wot.weight(store, txn, engager)?) * FULL as f64).round() as i64),
        None => Ok(FULL),
    }
}

/// The weight applied to an engager, walk aside.
fn stored_applied(store: &Store, txn: &Txn, engager: &[u8; 32]) -> Result<i64> {
    if store.wot().is_none() {
        return Ok(FULL);
    }
    Ok(txn
        .get(store.tables.applied, engager)?
        .and_then(|v| v.try_into().ok())
        .map_or(0, i64::from_le_bytes))
}

/// The weight an engager's engagement with `target` counts at.
fn applied(store: &Store, txn: &Txn, engager: &[u8; 32], target: &[u8; 32]) -> Result<i64> {
    if let Some(walk) = Walk::load(store, txn)?
        && walk.engager == *engager
    {
        let walked = walk.done.is_some_and(|done| *target <= done);
        return Ok(if walked { walk.new } else { walk.old });
    }
    stored_applied(store, txn, engager)
}

/// What an engager's engagement with a target counts at.
fn contribution(
    store: &Store,
    txn: &Txn,
    engager: &[u8; 32],
    target: &[u8; 32],
    score: &Score,
) -> Result<i64> {
    match score.author == Some(*engager) {
        true => Ok(0),
        false => applied(store, txn, engager, target),
    }
}

/// A walk of an engager's engagement, applying a new weight.
#[derive(Debug, Clone, Copy)]
struct Walk {
    engager: [u8; 32],
    old: i64,
    new: i64,
    /// The last target walked.
    done: Option<[u8; 32]>,
}

impl Walk {
    fn load(store: &Store, txn: &Txn) -> Result<Option<Walk>> {
        let Some(bytes) = txn.get(store.tables.meta, WALK)? else {
            return Ok(None);
        };
        let Ok::<&[u8; 81], _>(bytes) = bytes.try_into() else {
            return Ok(None);
        };
        Ok(Some(Walk {
            engager: bytes[..32].try_into().unwrap(),
            old: i64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            new: i64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            done: (bytes[48] == 1).then(|| bytes[49..].try_into().unwrap()),
        }))
    }

    fn save(&self, store: &Store, txn: &mut RwTxn) -> Result<()> {
        let mut out = [0; 81];
        out[..32].copy_from_slice(&self.engager);
        out[32..40].copy_from_slice(&self.old.to_le_bytes());
        out[40..48].copy_from_slice(&self.new.to_le_bytes());
        if let Some(done) = self.done {
            out[48] = 1;
            out[49..].copy_from_slice(&done);
        }
        txn.put(store.tables.meta, WALK, &out).map(drop)
    }
}

/// How an engager's events engage a target.
fn pair(store: &Store, txn: &Txn, engager: &[u8; 32], target: &[u8; 32]) -> Result<Counts> {
    let key = [&engager[..], &target[..]].concat();
    Ok(txn
        .get(store.tables.engagement, &key)?
        .and_then(Counts::decode)
        .unwrap_or_default())
}

/// Count, or with `add` false stop counting, one event's engagement.
fn engage(store: &Store, txn: &mut RwTxn, engagement: &Engagement, add: bool) -> Result<()> {
    let t = store.tables;
    let (engager, id) = (&engagement.engager, engagement.target.id());
    let count = pair(store, txn, engager, &id)?;
    let next = match add {
        true => count.plus(&engagement.counts),
        false => count.minus(&engagement.counts),
    };
    let Some(next) = next else {
        return Ok(());
    };
    let kept = score_of(store, txn, &id)?;
    let old = match kept {
        Some(score) => score,
        None => seen(store, txn, &engagement.target)?,
    };
    let weight = contribution(store, txn, engager, &id, &old)?;
    let mut new = old;
    new.credit(&next, weight);
    new.credit(&count, -weight);
    if kept.is_none() || new != old {
        set_score(store, txn, &id, &old, &new)?;
    }
    let key = [&engager[..], &id[..]].concat();
    match next.is_empty() {
        true => txn.del(t.engagement, &key, None).map(drop),
        false => txn.put(t.engagement, &key, &next.encode()).map(drop),
    }
}

/// What's known of something not engaged with before. Of an event: if
/// it's stored, its author, and if it's current, where it is. Of a
/// recipient: where their profile is.
fn seen(store: &Store, txn: &Txn, target: &Target) -> Result<Score> {
    match target {
        Target::Event(id) => {
            let Some(seq) = store.seq_of(txn, id)? else {
                return Ok(Score::default());
            };
            let Some(view) = store.load(txn, seq)? else {
                return Ok(Score::default());
            };
            let current = store.is_current(txn, seq, &view)?;
            Ok(Score {
                seq: if current { seq } else { 0 },
                created_at: view.created_at(),
                kind: view.kind(),
                author: Some(*view.pubkey()),
                ..Score::default()
            })
        }
        Target::Recipient(pubkey) => {
            let mut score = Score {
                author: Some(*pubkey),
                recipient: true,
                ..Score::default()
            };
            if let Some(seq) = profile(store, txn, pubkey)?
                && let Some(view) = store.load(txn, seq)?
            {
                (score.seq, score.created_at) = (seq, view.created_at());
            }
            Ok(score)
        }
    }
}

/// The current kind 0 of an author.
fn profile(store: &Store, txn: &Txn, author: &[u8; 32]) -> Result<Option<u64>> {
    Ok(txn
        .get(store.tables.replaceable, &address(author, 0, &[0]))?
        .and_then(|v| v.try_into().ok())
        .map(u64::from_be_bytes))
}

/// An event has been stored, current, under `seq`: rank it if it's been
/// engaged with, count what it engages with, and rank it if it's a profile.
pub fn index(store: &Store, txn: &mut RwTxn, seq: u64, view: &EventView) -> Result<()> {
    let (id, author) = (view.id(), view.pubkey());
    if let Some(old) = score_of(store, txn, id)? {
        let mut new = Score {
            seq,
            created_at: view.created_at(),
            kind: view.kind(),
            author: Some(*author),
            ..old
        };
        // Its author's engagement counted until now it was known as theirs.
        if old.author.is_none() {
            let counts = pair(store, txn, author, id)?;
            new.credit(&counts, -applied(store, txn, author, id)?);
        }
        set_score(store, txn, id, &old, &new)?;
    }
    let zap = zap(view);
    for engagement in engagements_with(view, zap.as_ref()) {
        engage(store, txn, &engagement, true)?;
    }
    if let Some(zap) = &zap {
        tally(store, txn, zap, true)?;
    }
    if view.kind() == 0 {
        let received = recipient(author);
        if let Some(old) = score_of(store, txn, &received)? {
            let new = Score {
                seq,
                created_at: view.created_at(),
                ..old
            };
            set_score(store, txn, &received, &old, &new)?;
        }
        if store.wot().is_some() {
            let score = wot::score(store, txn, author)?;
            if score > 0 {
                let value = ranked_value(score as u64, seq);
                txn.put_dup(store.tables.ranked, &ranked_key(PROFILE, 0), &value)?;
            }
        }
    }
    Ok(())
}

/// An event under `seq` has been taken out of the indexes: undo [`index`].
pub fn unindex(store: &Store, txn: &mut RwTxn, seq: u64, view: &EventView) -> Result<()> {
    let (id, author) = (view.id(), view.pubkey());
    let mut kept = vec![*id];
    if view.kind() == 0 {
        kept.push(recipient(author));
    }
    for id in &kept {
        if let Some(old) = score_of(store, txn, id)?
            && old.seq == seq
        {
            let new = Score { seq: 0, ..old };
            set_score(store, txn, id, &old, &new)?;
        }
    }
    let zap = zap(view);
    for engagement in engagements_with(view, zap.as_ref()) {
        engage(store, txn, &engagement, false)?;
    }
    if let Some(zap) = &zap {
        tally(store, txn, zap, false)?;
    }
    if view.kind() == 0 && store.wot().is_some() {
        let score = wot::score(store, txn, author)?;
        if score > 0 {
            let value = ranked_value(score as u64, seq);
            txn.del(store.tables.ranked, &ranked_key(PROFILE, 0), Some(&value))?;
        }
    }
    Ok(())
}

/// An author's trust score has changed, as of the write transaction: refile
/// their profile, and queue their engagement to be walked if their weight
/// has moved far enough from what's applied.
pub fn trust_changed(
    store: &Store,
    txn: &mut RwTxn,
    author: &[u8; 32],
    old: i64,
    new: i64,
) -> Result<()> {
    if old != new
        && let Some(seq) = profile(store, txn, author)?
    {
        let key = ranked_key(PROFILE, 0);
        if old > 0 {
            txn.del(
                store.tables.ranked,
                &key,
                Some(&ranked_value(old as u64, seq)),
            )?;
        }
        if new > 0 {
            txn.put_dup(store.tables.ranked, &key, &ranked_value(new as u64, seq))?;
        }
    }
    let (now, applied) = (
        weight(store, txn, author)?,
        stored_applied(store, txn, author)?,
    );
    if (now - applied).abs() >= store.rank().step || (now == 0) != (applied == 0) {
        requeue(store, txn, author)?;
    }
    Ok(())
}

/// Queue an engager to have their weight applied again.
pub fn requeue(store: &Store, txn: &mut RwTxn, engager: &[u8; 32]) -> Result<()> {
    txn.put(store.tables.rank_queue, engager, &[]).map(drop)
}

/// Whether there's walking to do.
pub fn due(store: &Store, txn: &Txn) -> Result<bool> {
    Ok(
        Walk::load(store, txn)?.is_some()
            || txn.cursor(store.tables.rank_queue)?.first()?.is_some(),
    )
}

/// Walk a budget's worth of an engager's engagement, starting the next
/// walk if none is under way.
pub fn turn(store: &Store, txn: &mut RwTxn) -> Result<()> {
    let t = store.tables;
    let mut walk = match Walk::load(store, txn)? {
        Some(walk) => walk,
        None => {
            let next: Option<[u8; 32]> = {
                let mut cursor = txn.cursor(t.rank_queue)?;
                cursor.first()?.and_then(|(key, _)| key.try_into().ok())
            };
            let Some(engager) = next else {
                return Ok(());
            };
            txn.del(t.rank_queue, &engager, None)?;
            let walk = Walk {
                engager,
                old: stored_applied(store, txn, &engager)?,
                new: weight(store, txn, &engager)?,
                done: None,
            };
            if walk.old == walk.new {
                return Ok(());
            }
            walk
        }
    };
    let budget = store.rank().budget;
    let targets: Vec<([u8; 32], Counts)> = {
        let mut cursor = txn.cursor(t.engagement)?;
        let start = [&walk.engager[..], &walk.done.unwrap_or_default()[..]].concat();
        let mut entry = cursor.set_range(&start)?;
        let mut out = Vec::new();
        while let Some((key, value)) = entry
            && key.starts_with(&walk.engager)
            && out.len() < budget
        {
            let target: [u8; 32] = key[32..].try_into().unwrap_or_default();
            if walk.done != Some(target) {
                out.push((target, Counts::decode(value).unwrap_or_default()));
            }
            entry = cursor.next()?;
        }
        out
    };
    for (target, counts) in &targets {
        if let Some(old) = score_of(store, txn, target)?
            && old.author != Some(walk.engager)
        {
            let mut new = old;
            new.credit(counts, walk.new - walk.old);
            set_score(store, txn, target, &old, &new)?;
        }
        walk.done = Some(*target);
    }
    if targets.len() < budget {
        match walk.new {
            0 => txn.del(t.applied, &walk.engager, None)?,
            new => txn.put(t.applied, &walk.engager, &new.to_le_bytes())?,
        };
        txn.del(t.meta, WALK, None)?;
    } else {
        walk.save(store, txn)?;
    }
    Ok(())
}

/// Rebuild scores and ranks from `engagement` if the parameters they're
/// computed with have changed, when the store opens: before it serves anything, a chunk per
/// transaction, and over again if interrupted.
pub fn open(store: &Store) -> anyhow::Result<()> {
    let t = store.tables;
    let rank = store.rank();
    let params = [
        &rank.half_life.to_be_bytes()[..],
        &rank.step.to_be_bytes(),
        &store.wot().map(|wot| wot.params()).unwrap_or_default(),
    ]
    .concat();
    if store.read()?.get(t.meta, PARAMS)? == Some(&params[..]) {
        return Ok(());
    }
    tracing::info!("rebuilding scores for ranked sorts");
    let mut txn = store.write()?;
    for db in [t.ranked, t.applied, t.rank_queue] {
        txn.clear(db)?;
    }
    txn.del(t.meta, WALK, None)?;
    txn.del(t.meta, PARAMS, None)?;
    txn.commit()?;

    chunks(store, t.scores, |txn, id, value| {
        if let Some(score) = Score::decode(value) {
            let zeroed = Score {
                score: 0,
                comments: 0,
                reactions: 0,
                zaps: 0,
                ..score
            };
            txn.put(t.scores, id, &zeroed.encode())?;
        }
        Ok(())
    })?;
    chunks(store, t.engagement, |txn, key, value| {
        let (engager, target): ([u8; 32], [u8; 32]) =
            (key[..32].try_into().unwrap(), key[32..].try_into().unwrap());
        let weight = weight(store, txn, &engager)?;
        if store.wot().is_some() && weight > 0 {
            txn.put(t.applied, &engager, &weight.to_le_bytes())?;
        }
        if let Some(mut score) = score_of(store, txn, &target)?
            && score.author != Some(engager)
        {
            score.credit(&Counts::decode(value).unwrap_or_default(), weight);
            txn.put(t.scores, &target, &score.encode())?;
        }
        Ok(())
    })?;
    chunks(store, t.scores, |txn, _, value| {
        if let Some(score) = Score::decode(value) {
            for (mode, rank) in score.ranks(rank.half_life) {
                txn.put_dup(
                    t.ranked,
                    &ranked_key(mode, score.kind),
                    &ranked_value(rank, score.seq),
                )?;
            }
        }
        Ok(())
    })?;
    if store.wot().is_some() {
        chunks(store, t.wot, |txn, author, _| {
            let author: [u8; 32] = author.try_into().unwrap_or_default();
            let score = wot::score(store, txn, &author)?;
            if score > 0
                && let Some(seq) = profile(store, txn, &author)?
            {
                let value = ranked_value(score as u64, seq);
                txn.put_dup(t.ranked, &ranked_key(PROFILE, 0), &value)?;
            }
            Ok(())
        })?;
    }
    let mut txn = store.write()?;
    txn.put(t.meta, PARAMS, &params)?;
    txn.commit()?;
    Ok(())
}

/// Call `f` with every entry of a plain table, [`REBUILD_CHUNK`] to a
/// write transaction.
fn chunks(
    store: &Store,
    db: crate::lmdb::Db,
    mut f: impl FnMut(&mut RwTxn, &[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let mut after: Option<Vec<u8>> = None;
    loop {
        let mut txn = store.write()?;
        let entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut cursor = txn.cursor(db)?;
            let mut entry = match &after {
                None => cursor.first()?,
                Some(key) => match cursor.set_range(key)? {
                    Some((k, _)) if k == key.as_slice() => cursor.next()?,
                    other => other,
                },
            };
            let mut out = Vec::new();
            while let Some((key, value)) = entry
                && out.len() < REBUILD_CHUNK
            {
                out.push((key.to_vec(), value.to_vec()));
                entry = cursor.next()?;
            }
            out
        };
        for (key, value) in &entries {
            f(&mut txn, key, value)?;
        }
        txn.commit()?;
        match entries.len() < REBUILD_CHUNK {
            true => return Ok(()),
            false => after = entries.last().map(|(key, _)| key.clone()),
        }
    }
}

/// Which ranks a ranked search goes by. Profiles are ranked by their
/// author's trust, if there's a web of trust, or by what they've been
/// zapped; anything else by engagement.
fn mode(store: &Store, filter: &Filter, sort: Sort) -> u8 {
    let profiles = filter.kinds.as_deref() == Some(&[0]);
    match sort {
        Sort::Top | Sort::Hot if profiles && store.wot().is_some() => PROFILE,
        Sort::Hot => HOT,
        Sort::Controversial => CONTROVERSIAL,
        Sort::Rising => RISING,
        Sort::Zaps if profiles => RECEIVED,
        Sort::Zaps => ZAPS,
        _ => TOP,
    }
}

/// Whether profiles are ranked by their authors' best events, having no
/// ranks of their own in the mode.
fn by_author(filter: &Filter, mode: u8) -> bool {
    filter.kinds.as_deref() == Some(&[0]) && matches!(mode, CONTROVERSIAL | RISING)
}

/// An event's rank in a mode at `now`: 0 for none.
fn rank_of(store: &Store, txn: &Txn, mode: u8, view: &EventView, now: u32) -> Result<u64> {
    let id = match mode {
        PROFILE => return Ok(wot::score(store, txn, view.pubkey())?.max(0) as u64),
        RECEIVED => recipient(view.pubkey()),
        _ => *view.id(),
    };
    let Some(score) = score_of(store, txn, &id)? else {
        return Ok(0);
    };
    Ok(match mode {
        TOP => score.score.max(0) as u64,
        HOT if score.score > 0 => hot(score.score, view.created_at(), store.rank().half_life),
        CONTROVERSIAL => controversial(score.comments, score.reactions).unwrap_or(0),
        RISING => rising(score.score, view.created_at(), now).map_or(0, ordered),
        ZAPS | RECEIVED if score.zaps > 0 => ordered(score.zaps as f64),
        _ => 0,
    })
}

/// Order events found best first, then newest first.
pub fn sort<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    sort: Sort,
    found: &mut Vec<(u64, EventView<'t>)>,
) -> Result<()> {
    let mode = mode(store, filter, sort);
    let now = crate::event::now();
    // The best authors first.
    let authors: Option<HashMap<[u8; 32], u64>> = match by_author(filter, mode) {
        true => {
            let authors = ranked_authors(store, txn, mode)?;
            let n = authors.len() as u64;
            Some((0..).zip(authors).map(|(i, a)| (a, n - i)).collect())
        }
        false => None,
    };
    let mut ranked = Vec::with_capacity(found.len());
    for (seq, view) in found.drain(..) {
        let rank = match &authors {
            Some(authors) => authors.get(view.pubkey()).copied().unwrap_or(0),
            None => rank_of(store, txn, mode, &view, now)?,
        };
        ranked.push((rank, seq, view));
    }
    ranked.sort_by(|(x, _, a), (y, _, b)| y.cmp(x).then_with(|| crate::search::newest_first(a, b)));
    found.extend(ranked.into_iter().map(|(_, seq, view)| (seq, view)));
    Ok(())
}

/// Run a ranked filter whose search has no text to look up. One naming
/// ids, authors, or tags has its matches ranked; any other walks `ranked`
/// from the top, then makes up its limit from the newest unranked.
pub fn run<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    limit: usize,
) -> anyhow::Result<Vec<(u64, EventView<'t>)>> {
    let search = filter.search.as_ref().expect("a ranked search");
    let mode = mode(store, filter, search.sort);
    // The filter as a plain one, newest first.
    let mut plain = filter.clone();
    plain.search = match search.has_text() || !search.conditions.is_empty() {
        true => Some(crate::filter::Search {
            sort: Sort::New,
            distinct_author: false,
            ..search.clone()
        }),
        false => None,
    };
    let narrow = filter.ids.is_some() || filter.authors.is_some() || !filter.tags.is_empty();
    let mut found = if narrow {
        let mut found = crate::query::run_filter(store, txn, &plain, MAX_EXAMINED)?;
        sort(store, txn, filter, search.sort, &mut found)?;
        found
    } else {
        let mut found = match by_author(filter, mode) {
            true => {
                let authors = ranked_authors(store, txn, mode)?;
                profiles(store, txn, filter, &authors, limit)?
            }
            false => best(store, txn, filter, mode, limit, search.distinct_author)?,
        };
        if found.len() < limit {
            let seen: HashSet<u64> = found.iter().map(|(seq, _)| *seq).collect();
            let newest = crate::query::run_filter(store, txn, &plain, limit + seen.len())?;
            found.extend(newest.into_iter().filter(|(seq, _)| !seen.contains(seq)));
        }
        found
    };
    if search.distinct_author {
        let mut authors = HashSet::new();
        found.retain(|(_, view)| authors.insert(*view.pubkey()));
    }
    found.truncate(limit);
    Ok(found)
}

/// The authors of the best events of any kind in a mode, the best first.
fn ranked_authors(store: &Store, txn: &Txn, mode: u8) -> Result<Vec<[u8; 32]>> {
    let any = Filter {
        until: u32::MAX,
        ..Filter::default()
    };
    let found = best(store, txn, &any, mode, RANKED_AUTHORS, true)?;
    Ok(found.iter().map(|(_, view)| *view.pubkey()).collect())
}

/// The current profiles of `authors` a filter matches, in their order.
fn profiles<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    authors: &[[u8; 32]],
    limit: usize,
) -> Result<Vec<(u64, EventView<'t>)>> {
    let mut found = Vec::new();
    for author in authors {
        if found.len() >= limit {
            break;
        }
        if let Some(seq) = profile(store, txn, author)?
            && let Some(view) = store.load(txn, seq)?
            && filter.matches(&view)
        {
            found.push((seq, view));
        }
    }
    Ok(found)
}

/// The best events a filter matches in a mode, with `distinct`, only each
/// author's best.
fn best<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    mode: u8,
    limit: usize,
    distinct: bool,
) -> Result<Vec<(u64, EventView<'t>)>> {
    match mode {
        RISING => walk_rising(store, txn, filter, limit, distinct, crate::event::now()),
        _ => walk(store, txn, filter, mode, limit, distinct),
    }
}

/// A mode's `ranked` entries of the kinds a filter wants, from the top.
struct Ranked<'t> {
    cursors: Vec<Cursor<'t>>,
    /// Each cursor's entry, by which is next.
    heap: BinaryHeap<(Vec<u8>, usize)>,
}

impl<'t> Ranked<'t> {
    fn new(store: &Store, txn: &'t Txn, filter: &Filter, mode: u8) -> Result<Ranked<'t>> {
        let t = store.tables;
        let kinds: Vec<u16> = match &filter.kinds {
            Some(kinds) => kinds.clone(),
            None => {
                let mut kinds = Vec::new();
                let mut cursor = txn.cursor(t.ranked)?;
                let mut entry = cursor.set_range(&[mode])?;
                while let Some((key, _)) = entry
                    && key.first() == Some(&mode)
                {
                    kinds.push(u16::from_be_bytes([key[1], key[2]]));
                    entry = cursor.next_nodup()?;
                }
                kinds
            }
        };
        let mut cursors = Vec::new();
        let mut heap = BinaryHeap::new();
        for kind in kinds.into_iter().filter(|&kind| filter.wants_kind(kind)) {
            let mut cursor = txn.cursor(t.ranked)?;
            if cursor.set(&ranked_key(mode, kind))?.is_some()
                && let Some((_, value)) = cursor.last_dup()?
            {
                heap.push((value.to_vec(), cursors.len()));
                cursors.push(cursor);
            }
        }
        Ok(Ranked { cursors, heap })
    }

    /// The next entry's rank and sequence number.
    fn next(&mut self) -> Result<Option<(u64, u64)>> {
        let Some((value, i)) = self.heap.pop() else {
            return Ok(None);
        };
        if let Some((_, next)) = self.cursors[i].prev_dup()? {
            self.heap.push((next.to_vec(), i));
        }
        Ok(Some((ranked_rank(&value), ranked_seq(&value))))
    }
}

/// The best ranked events a filter matches, from `ranked`.
fn walk<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    mode: u8,
    limit: usize,
    distinct: bool,
) -> Result<Vec<(u64, EventView<'t>)>> {
    let mut ranked = Ranked::new(store, txn, filter, mode)?;
    let mut authors = HashSet::new();
    let mut found = Vec::new();
    let mut examined = 0;
    while found.len() < limit
        && let Some((_, seq)) = ranked.next()?
    {
        examined += 1;
        if examined > MAX_EXAMINED {
            METRICS.filters_cut_short.inc();
            break;
        }
        if let Some(view) = store.load(txn, seq)?
            && filter.matches(&view)
            && (!distinct || authors.insert(*view.pubkey()))
        {
            found.push((seq, view));
        }
    }
    Ok(found)
}

/// The fastest rising events a filter matches at `now`, walking `sort:hot`
/// from the top. An event filed there at `x` (see [`hot`]) and `age` seconds old has
/// a score of `2^(x - created_at / half_life)`, so it rises at
/// `2^(x - now / half_life) * 2^(age / half_life) / age`. The last factor
/// is largest at the youngest or oldest an event can be to rise, so once
/// that bound is below the `limit`th fastest found, nothing further down
/// can be among them.
fn walk_rising<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    limit: usize,
    distinct: bool,
    now: u32,
) -> Result<Vec<(u64, EventView<'t>)>> {
    let half_life = f64::from(store.rank().half_life);
    let factor = |age: u32| f64::from(age) / half_life - f64::from(age).log2();
    // Less `x`, the log2 of the fastest an event at `x` can rise, in
    // thousandths per second.
    let slack = (FULL as f64).log2() - f64::from(now) / half_life
        + factor(RISING_MIN_AGE).max(factor(RISING_WINDOW));
    let mut ranked = Ranked::new(store, txn, filter, HOT)?;
    let mut found: Vec<(f64, u64, EventView<'t>)> = Vec::new();
    // The log2 of the `limit`th fastest found, as of the last look.
    let mut threshold = f64::NEG_INFINITY;
    let mut examined = 0usize;
    while let Some((rank, seq)) = ranked.next()? {
        examined += 1;
        if examined > MAX_EXAMINED {
            METRICS.filters_cut_short.inc();
            break;
        }
        if unordered(rank) + slack < threshold {
            break;
        }
        let Some(view) = store.load(txn, seq)?.filter(|view| filter.matches(view)) else {
            continue;
        };
        let Some(rise) = score_of(store, txn, view.id())?
            .and_then(|score| rising(score.score, view.created_at(), now))
        else {
            continue;
        };
        found.push((rise, seq, view));
        if found.len() == limit || (found.len() > limit && examined.is_multiple_of(64)) {
            threshold = nth_fastest(&found, limit, distinct).log2();
        }
    }
    found.sort_by(|(x, _, a), (y, _, b)| {
        y.total_cmp(x)
            .then_with(|| crate::search::newest_first(a, b))
    });
    let mut authors = HashSet::new();
    Ok(found
        .into_iter()
        .filter(|(_, _, view)| !distinct || authors.insert(*view.pubkey()))
        .take(limit)
        .map(|(_, seq, view)| (seq, view))
        .collect())
}

/// How fast the `n`th fastest rises, with `distinct` counting only each
/// author's fastest: 0 if fewer have been found.
fn nth_fastest(found: &[(f64, u64, EventView)], n: usize, distinct: bool) -> f64 {
    let mut rises: Vec<f64> = match distinct {
        true => {
            let mut fastest: HashMap<[u8; 32], f64> = HashMap::new();
            for (rise, _, view) in found {
                let best = fastest.entry(*view.pubkey()).or_insert(0.0);
                *best = best.max(*rise);
            }
            fastest.into_values().collect()
        }
        false => found.iter().map(|(rise, _, _)| *rise).collect(),
    };
    rises.sort_by(|x, y| y.total_cmp(x));
    rises.get(n.wrapping_sub(1)).copied().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::{sign, signed};
    use crate::record;
    use crate::store::History;
    use crate::store::tests::{MAX_VALUES, test_tags};
    use crate::wot::Wot;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use serde_json::{Value, json};
    use std::collections::HashMap;

    const DAY: u32 = 86_400;

    fn secret(n: u32) -> [u8; 32] {
        let mut secret = [9; 32];
        secret[28..].copy_from_slice(&n.to_be_bytes());
        secret
    }

    fn pubkey(n: u32) -> [u8; 32] {
        let keypair = secp256k1::Keypair::from_secret_bytes(secret(n)).unwrap();
        keypair.x_only_public_key().0.to_byte_array()
    }

    fn event(n: u32, at: u32, kind: u16, tags: Vec<Vec<&str>>, content: &str) -> Event {
        let tags = tags
            .into_iter()
            .map(|t| t.into_iter().map(String::from).collect())
            .collect();
        sign(secret(n), at.into(), kind, tags, content)
    }

    fn follows(n: u32, at: u32, whom: &[u32]) -> Event {
        let hexes: Vec<String> = whom.iter().map(|&w| hex::encode(pubkey(w))).collect();
        event(
            n,
            at,
            3,
            hexes.iter().map(|h| vec!["p", h.as_str()]).collect(),
            "",
        )
    }

    fn open(dir: &std::path::Path, wot: Option<Wot>, rank: Rank) -> Store {
        let history = History::new(true, vec![], 20);
        Store::open(dir, 1 << 28, test_tags(), history, wot, rank).unwrap()
    }

    fn put(store: &Store, event: &Event) {
        crate::store::tests::put(store, event);
    }

    fn settle(store: &Store) {
        while store.turn().unwrap() {}
    }

    fn ids(store: &Store, filter: Value) -> Vec<String> {
        let filter = Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();
        crate::query::run(store, None, None, &[filter], 100, 500)
            .unwrap()
            .events
            .iter()
            .map(|json| serde_json::from_str::<Event>(json).unwrap().id)
            .collect()
    }

    fn of(events: &[&Event]) -> Vec<String> {
        events.iter().map(|e| e.id.clone()).collect()
    }

    fn id(event: &Event) -> [u8; 32] {
        hex::decode(&event.id).unwrap().try_into().unwrap()
    }

    fn react(n: u32, to: &Event, content: &str) -> Event {
        event(n, 1, 7, vec![vec!["e", &to.id]], content)
    }

    /// Who signs zap receipts.
    const WALLET: u32 = 99;

    /// A receipt for `n` zapping an event, by its tags, `msats` (a
    /// multiple of 100). The request asks for `asked`.
    fn zap_with(n: u32, at: u32, tags: Vec<Vec<&str>>, msats: u64, asked: u64) -> Event {
        let asked = asked.to_string();
        let mut request_tags = tags.clone();
        request_tags.push(vec!["amount", &asked]);
        let request = event(n, at, 9734, request_tags, "");
        let invoice = format!("lnbc{}n1pfake", msats / 100);
        let description = serde_json::to_string(&request).unwrap();
        let mut tags = tags;
        tags.extend([vec!["bolt11", &invoice], vec!["description", &description]]);
        event(WALLET, at, 9735, tags, "")
    }

    fn zap(n: u32, at: u32, to: &Event, msats: u64) -> Event {
        let tags = vec![vec!["e", to.id.as_str()], vec!["p", to.pubkey.as_str()]];
        zap_with(n, at, tags, msats, msats)
    }

    fn onchain(n: u32, at: u32, to: &Event, sats: u64) -> Event {
        let sats = sats.to_string();
        let tags = vec![
            vec!["i", "bitcoin:tx:0000"],
            vec!["p", to.pubkey.as_str()],
            vec!["amount", &sats],
            vec!["e", to.id.as_str()],
        ];
        event(n, at, 8333, tags, "")
    }

    fn score(store: &Store, event: &Event) -> i64 {
        scores(store, &id(event)).score
    }

    fn scores(store: &Store, id: &[u8; 32]) -> Score {
        let txn = store.read().unwrap();
        score_of(store, &txn, id).unwrap().unwrap_or_default()
    }

    fn table(store: &Store, db: crate::lmdb::Db) -> Vec<(Vec<u8>, Vec<u8>)> {
        let txn = store.read().unwrap();
        let mut cursor = txn.cursor(db).unwrap();
        let mut out = Vec::new();
        let mut entry = cursor.first().unwrap();
        while let Some((key, value)) = entry {
            out.push((key.to_vec(), value.to_vec()));
            entry = cursor.next().unwrap();
        }
        out
    }

    /// Random notes, engagement, zaps, deletions, vanishing, new profiles,
    /// and follow lists, with the background work done a little at a time,
    /// checked against counting it all up again.
    #[test]
    fn agrees_with_brute_force() {
        let dir = tempfile::tempdir().unwrap();
        let wot = Wot::new(vec![pubkey(0)], 0.85, 20, 0.01, 15).unwrap();
        let rank = Rank::new(DAY, 0.05, 3);
        let store = open(dir.path(), Some(wot), rank);
        let mut rng = StdRng::seed_from_u64(4);
        // People post and may be trusted; strangers only engage, and may
        // vanish.
        let people: Vec<u32> = (0..12).collect();
        let strangers: Vec<u32> = (20..25).collect();
        let mut posts: Vec<Event> = Vec::new();
        for (i, &n) in people.iter().enumerate() {
            for j in 0..3 {
                let post = event(n, 1000 + (i * 3 + j) as u32 * 600, 1, vec![], "a post");
                put(&store, &post);
                posts.push(post);
            }
            if i % 3 == 0 {
                put(&store, &event(n, 500, 0, vec![], "{}"));
            }
        }
        let missing = event(5, 99_999, 1, vec![], "never stored");
        let late = event(6, 99_998, 1, vec![], "stored last");
        let mut pool: Vec<&Event> = posts.iter().collect();
        pool.extend([&missing, &late]);
        let mut engagement: Vec<Event> = Vec::new();
        for step in 0..400u32 {
            let at = 10_000 + step;
            let everyone = [&people[..], &strangers[..]].concat();
            let n = everyone[rng.random_range(0..everyone.len())];
            let to = pool[rng.random_range(0..pool.len())];
            let to_id = to.id.as_str();
            let new = match rng.random_range(0..15) {
                0 => Some(event(n, at, 7, vec![vec!["e", to_id]], "-")),
                1 | 2 => Some(event(n, at, 7, vec![vec!["e", to_id]], "+")),
                3 => Some(event(n, at, 6, vec![vec!["e", to_id]], "")),
                4 => Some(event(n, at, 1, vec![vec!["e", to_id, "", "root"]], "re")),
                5 => Some(event(n, at, 1111, vec![vec!["e", to_id]], "hm")),
                6 => Some(event(n, at, 1, vec![vec!["q", to_id]], "look")),
                9 => Some(zap(n, at, to, rng.random_range(1..10_000) * 100)),
                10 => Some(onchain(n, at, to, rng.random_range(1..10_000))),
                11 => {
                    let m = people[rng.random_range(0..people.len())];
                    put(&store, &event(m, at, 0, vec![], "{\"name\":\"x\"}"));
                    None
                }
                7 if !engagement.is_empty() => {
                    let old = &engagement[rng.random_range(0..engagement.len())];
                    let author = (0..100).find(|&m| hex::encode(pubkey(m)) == old.pubkey);
                    if let Some(m) = author {
                        put(&store, &event(m, at, 5, vec![vec!["e", &old.id]], ""));
                    }
                    None
                }
                8 if step % 5 == 0 => {
                    let m = strangers[rng.random_range(0..strangers.len())];
                    put(&store, &event(m, at, 62, vec![], ""));
                    None
                }
                _ => {
                    let m = people[rng.random_range(0..people.len())];
                    let whom: Vec<u32> = (0..rng.random_range(0..4))
                        .map(|_| everyone[rng.random_range(0..everyone.len())])
                        .collect();
                    put(&store, &follows(m, at, &whom));
                    None
                }
            };
            if let Some(new) = new {
                put(&store, &new);
                engagement.push(new);
            }
            if rng.random_bool(0.5) {
                store.turn().unwrap();
            }
        }
        // Someone trusted engages with their own post before it arrives:
        // until then it's not known to be theirs.
        put(&store, &follows(0, 20_000, &[6, 1, 2]));
        put(&store, &event(6, 20_001, 7, vec![vec!["e", &late.id]], "+"));
        settle(&store);
        assert!(score(&store, &late) > 0);
        put(&store, &late);
        settle(&store);

        let txn = store.read().unwrap();
        // What's engaged with what, from every indexed event.
        let mut pairs: HashMap<([u8; 32], [u8; 32]), Counts> = HashMap::new();
        let mut targets: HashMap<[u8; 32], Target> = HashMap::new();
        for (key, record) in table(&store, store.tables.events) {
            let seq = u64::from_ne_bytes(key.try_into().unwrap());
            let view = EventView::new(&record).unwrap();
            if store.is_current(&txn, seq, &view).unwrap() {
                for e in engagements(&view) {
                    let counts = pairs.entry((e.engager, e.target.id())).or_default();
                    *counts = counts.plus(&e.counts).unwrap();
                    targets.insert(e.target.id(), e.target);
                }
            }
        }
        let kept: HashMap<([u8; 32], [u8; 32]), Counts> = table(&store, store.tables.engagement)
            .into_iter()
            .map(|(k, v)| {
                let pair = (k[..32].try_into().unwrap(), k[32..].try_into().unwrap());
                (pair, Counts::decode(&v).unwrap())
            })
            .collect();
        assert_eq!(kept, pairs);
        // Every way to engage, some of it trusted.
        let some = |f: fn(&Counts) -> bool| pairs.values().any(f);
        assert!(some(|c| c.engages > 0 && c.comments > 0));
        assert!(some(|c| c.engages == 0 && c.reactions > 0));
        assert!(some(|c| c.msats > 0));
        assert!(targets.values().any(|t| matches!(t, Target::Recipient(_))));

        // Weights applied are within a step of where they are now.
        let applied = |x: &[u8; 32]| stored_applied(&store, &txn, x).unwrap();
        for (x, _) in pairs.keys() {
            let (now, applied) = (weight(&store, &txn, x).unwrap(), applied(x));
            assert!(
                (now - applied).abs() < 50 && (now == 0) == (applied == 0),
                "{now} {applied}"
            );
        }
        assert!(pairs.keys().any(|(x, _)| applied(x) > 0));

        // Each score is its engagers' applied weights, authors aside; its
        // author is known once it's been stored. A recipient's is known
        // from the start, and its whereabouts are their profile's.
        let mut want: HashMap<[u8; 32], Score> = HashMap::new();
        for ((x, target), counts) in &pairs {
            let author = match targets[target] {
                Target::Recipient(pubkey) => Some(pubkey),
                Target::Event(_) if *target == id(&missing) => None,
                Target::Event(_) => {
                    let event = pool.iter().find(|e| id(e) == *target).unwrap();
                    Some(hex::decode(&event.pubkey).unwrap().try_into().unwrap())
                }
            };
            if author != Some(*x) {
                want.entry(*target).or_default().credit(counts, applied(x));
            }
        }
        assert!(want.values().any(|s| s.comments > 0 && s.reactions > 0));
        assert!(want.values().any(|s| s.zaps > 0));
        let mut expected_ranks = Vec::new();
        for (key, value) in table(&store, store.tables.scores) {
            let target: [u8; 32] = key.try_into().unwrap();
            let s = Score::decode(&value).unwrap();
            let w = want.get(&target).copied().unwrap_or_default();
            assert_eq!(
                (s.score, s.comments, s.reactions, s.zaps),
                (w.score, w.comments, w.reactions, w.zaps)
            );
            assert_eq!(s.author.is_some(), target != id(&missing));
            if let Target::Recipient(pubkey) = targets[&target] {
                assert!(s.recipient && s.author == Some(pubkey));
                let seq = profile(&store, &txn, &pubkey).unwrap();
                assert_eq!(s.seq, seq.unwrap_or(0));
            }
            for (mode, rank) in s.ranks(DAY) {
                expected_ranks.push((
                    ranked_key(mode, s.kind).to_vec(),
                    ranked_value(rank, s.seq).to_vec(),
                ));
            }
        }
        // And every stored, scored event is filed by its ranks, and every
        // profile of someone with a score by it.
        for n in &people {
            let score = wot::score(&store, &txn, &pubkey(*n)).unwrap();
            if score > 0
                && let Some(seq) = profile(&store, &txn, &pubkey(*n)).unwrap()
            {
                expected_ranks.push((
                    ranked_key(PROFILE, 0).to_vec(),
                    ranked_value(score as u64, seq).to_vec(),
                ));
            }
        }
        let mut ranks = Vec::new();
        let mut cursor = txn.cursor(store.tables.ranked).unwrap();
        let mut entry = cursor.first().unwrap();
        while let Some((key, value)) = entry {
            ranks.push((key.to_vec(), value.to_vec()));
            entry = cursor.next().unwrap();
        }
        ranks.sort();
        expected_ranks.sort();
        assert_eq!(ranks, expected_ranks);
        drop(cursor);
        drop(txn);

        // Rebuilt from scratch, the same.
        let scores = table(&store, store.tables.scores);
        drop(store);
        let store = open(dir.path(), None, Rank::new(DAY, 0.05, 3));
        drop(store);
        let wot = Wot::new(vec![pubkey(0)], 0.85, 20, 0.01, 15).unwrap();
        let store = open(dir.path(), Some(wot), Rank::new(DAY, 0.05, 3));
        settle(&store);
        let rebuilt = table(&store, store.tables.scores);
        // Weights may land elsewhere within a step, so compare who's scored.
        let scored = |t: &[(Vec<u8>, Vec<u8>)]| -> Vec<(Vec<u8>, [bool; 4])> {
            t.iter()
                .map(|(k, v)| {
                    let s = Score::decode(v).unwrap();
                    let scored = [s.score > 0, s.comments > 0, s.reactions > 0, s.zaps > 0];
                    (k.clone(), scored)
                })
                .collect()
        };
        assert_eq!(scored(&rebuilt), scored(&scores));
    }

    /// What scoring costs the writer: storing engagement in batches, and
    /// the longest turn while weights settle and are applied. Slow to set
    /// up, so run by hand:
    /// `cargo test --release scoring_speed -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn scoring_speed() {
        let dir = tempfile::tempdir().unwrap();
        let wot = Wot::new(vec![pubkey(0)], 0.85, 1000, 0.01, 10_000).unwrap();
        let store = open(dir.path(), Some(wot), Rank::default());
        let mut rng = StdRng::seed_from_u64(8);
        let people = 2000u32;
        let posts: Vec<Event> = (0..5000)
            .map(|i| event(rng.random_range(1..people), i, 1, vec![], "post"))
            .collect();
        let mut events: Vec<Event> = posts.clone();
        for n in 0..people {
            let whom: Vec<u32> = (0..50).map(|_| rng.random_range(0..people)).collect();
            events.push(follows(n, 10, &whom));
        }
        for i in 0..100_000u32 {
            let to = &posts[rng.random_range(0..posts.len())];
            events.push(event(
                rng.random_range(1..people),
                20 + i,
                7,
                vec![vec!["e", &to.id]],
                "+",
            ));
        }
        let records: Vec<Vec<u8>> = events.iter().map(record::encode).collect();
        let start = std::time::Instant::now();
        for chunk in records.chunks(1000) {
            store
                .write_batch(chunk.iter().map(Vec::as_slice), 1 << 30)
                .unwrap();
        }
        let stored = start.elapsed();
        let start = std::time::Instant::now();
        let (mut turns, mut longest) = (0, std::time::Duration::ZERO);
        loop {
            let turn = std::time::Instant::now();
            let more = store.turn().unwrap();
            longest = longest.max(turn.elapsed());
            turns += 1;
            if !more {
                break;
            }
        }
        eprintln!(
            "{} events stored in {stored:?}; {turns} turns in {:?}, the longest {longest:?}; {} scored",
            records.len(),
            start.elapsed(),
            table(&store, store.tables.ranked).len() / 2,
        );
    }

    #[test]
    fn ranks_top_and_hot() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), None, Rank::new(DAY, 0.05, 100));
        // Old and much engaged with, newer and less, and newest and none.
        let old = event(1, 10 * DAY, 1, vec![], "old");
        let mid = event(2, 11 * DAY, 1, vec![], "mid");
        let new = event(3, 13 * DAY + DAY / 2, 1, vec![], "new");
        let quiet = event(1, 14 * DAY, 1, vec![], "quiet");
        for e in [&old, &mid, &new, &quiet] {
            put(&store, e);
        }
        for n in 10..18 {
            put(&store, &react(n, &old, "+"));
        }
        // Twice by one person counts once; their own, and dislikes, not
        // at all.
        put(&store, &react(10, &mid, "+"));
        put(
            &store,
            &event(10, 2, 1111, vec![vec!["e", &mid.id]], "agreed"),
        );
        put(&store, &react(11, &mid, "🔥"));
        put(&store, &react(2, &mid, "+"));
        put(&store, &react(12, &mid, "👎"));
        put(&store, &react(10, &new, "+"));
        assert_eq!((score(&store, &old), score(&store, &mid)), (8000, 2000));

        // The unranked fill up the limit, newest first.
        let top = ids(&store, json!({"search": "sort:top", "kinds": [1]}));
        assert_eq!(top, of(&[&old, &mid, &new, &quiet]));
        // Hot, in days: log2(8) + 10 = 13 for the old, log2(2) + 11 = 12,
        // and log2(1) + 13.5 for the new.
        let hot = ids(&store, json!({"search": "sort:hot", "kinds": [1]}));
        assert_eq!(hot, of(&[&new, &old, &mid, &quiet]));
        // Any kind; limits, kinds, and narrow filters.
        let all = ids(&store, json!({"search": "sort:top"}));
        assert_eq!(all[..3], of(&[&old, &mid, &new]));
        assert_eq!(all.len(), 4 + 8 + 6);
        assert_eq!(
            ids(&store, json!({"search": "sort:top", "limit": 2})),
            of(&[&old, &mid])
        );
        assert!(ids(&store, json!({"search": "sort:top", "kinds": [30023]})).is_empty());
        let author = hex::encode(pubkey(1));
        let by = json!({"search": "sort:top", "authors": [author]});
        assert_eq!(ids(&store, by), of(&[&old, &quiet]));
        let distinct = json!({"search": "sort:top distinct:author", "kinds": [1]});
        assert_eq!(ids(&store, distinct), of(&[&old, &mid, &new]));
        // Fewer as engagement goes.
        let reaction = react(13, &old, "+");
        let deletion = event(13, 3, 5, vec![vec!["e", &reaction.id]], "");
        put(&store, &deletion);
        assert_eq!(score(&store, &old), 7000);
    }

    #[test]
    fn follows_trust() {
        let dir = tempfile::tempdir().unwrap();
        // Full trust is an eighth of it all: 1 gets 0.1275, and 2 0.108.
        let wot = Wot::new(vec![pubkey(0)], 0.85, 8, 0.01, 1000).unwrap();
        let store = open(dir.path(), Some(wot), Rank::default());
        // The seed trusts 1 directly, and 2 through 1.
        put(&store, &follows(0, 100, &[1]));
        put(&store, &follows(1, 100, &[2]));
        let post = event(5, 100, 1, vec![], "hello");
        put(&store, &post);
        put(&store, &react(1, &post, "+"));
        put(&store, &react(2, &post, "+"));
        put(&store, &react(9, &post, "+"));
        settle(&store);
        let txn = store.read().unwrap();
        let weights = [1, 2].map(|n| weight(&store, &txn, &pubkey(n)).unwrap());
        drop(txn);
        assert!(weights[0] > weights[1] && weights[1] > 0, "{weights:?}");
        assert_eq!(score(&store, &post), weights[0] + weights[1]);

        // Unfollowed, their engagement stops counting.
        put(&store, &follows(0, 200, &[]));
        settle(&store);
        assert_eq!(score(&store, &post), 0);
        assert!(table(&store, store.tables.ranked).is_empty());
        // Still found, after any ranked.
        assert_eq!(
            ids(&store, json!({"search": "sort:hot", "kinds": [1]})),
            of(&[&post])
        );
    }

    #[test]
    fn ranks_profiles_by_trust() {
        let dir = tempfile::tempdir().unwrap();
        let wot = Wot::new(vec![pubkey(0)], 0.85, 100, 0.01, 1000).unwrap();
        let store = open(dir.path(), Some(wot), Rank::default());
        // 1 is followed by the seed and by 2; 2 only by the seed; 3 by no
        // one.
        put(&store, &follows(0, 100, &[1, 2]));
        put(&store, &follows(2, 100, &[1]));
        let profiles: Vec<Event> = (1..=3).map(|n| event(n, 100, 0, vec![], "{}")).collect();
        for p in &profiles {
            put(&store, p);
        }
        settle(&store);
        let want = of(&[&profiles[0], &profiles[1], &profiles[2]]);
        assert_eq!(
            ids(&store, json!({"kinds": [0], "search": "sort:top"})),
            want
        );
        // Replaced, ranked as it was.
        let newer = event(2, 200, 0, vec![], "{\"name\":\"two\"}");
        put(&store, &newer);
        let want = of(&[&profiles[0], &newer, &profiles[2]]);
        assert_eq!(
            ids(&store, json!({"kinds": [0], "search": "sort:hot"})),
            want
        );
        assert_eq!(table(&store, store.tables.ranked).len(), 2);
    }

    fn engagements_of(event: &Event) -> Vec<Engagement> {
        let record = record::encode(event);
        engagements(&EventView::new(&record).unwrap())
    }

    /// The events an event engages with toward their scores.
    fn targets_of(kind: u16, tags: Vec<Vec<&str>>, content: &str) -> Vec<[u8; 32]> {
        engagements_of(&signed(1, 100, kind, tags, content))
            .into_iter()
            .filter(|e| e.counts.engages > 0)
            .map(|e| e.target.id())
            .collect()
    }

    fn counts_of(kind: u16, tags: Vec<Vec<&str>>, content: &str) -> Vec<Counts> {
        let found = engagements_of(&signed(1, 100, kind, tags, content));
        found.into_iter().map(|e| e.counts).collect()
    }

    fn counts(engages: u32, comments: u32, reactions: u32, msats: u128) -> Counts {
        Counts {
            engages,
            comments,
            reactions,
            msats,
        }
    }

    #[test]
    fn finds_what_events_engage() {
        let [a, b, c] = ["aa", "bb", "cc"].map(|x| x.repeat(32));
        let id = |hex: &String| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
        // Reactions: the last `e`, unless negative.
        let tags = || vec![vec!["e", &a], vec!["e", &b]];
        assert_eq!(targets_of(7, tags(), "+"), [id(&b)]);
        assert_eq!(targets_of(7, tags(), "🤙"), [id(&b)]);
        assert!(targets_of(7, tags(), "-").is_empty());
        assert!(targets_of(7, tags(), "👎").is_empty());
        // Reposts.
        assert_eq!(
            targets_of(6, vec![vec!["e", &a], vec!["p", &b]], ""),
            [id(&a)]
        );
        // Replies, marked or by position, but not mentions.
        let marked = vec![vec!["e", &a, "", "root"], vec!["e", &b, "", "reply"]];
        assert_eq!(targets_of(1, marked, "x"), [id(&b)]);
        assert_eq!(
            targets_of(1, vec![vec!["e", &a, "", "root"]], "x"),
            [id(&a)]
        );
        assert!(targets_of(1, vec![vec!["e", &a, "", "mention"]], "x").is_empty());
        assert_eq!(targets_of(1, tags(), "x"), [id(&b)]);
        // Comments, by their parent; quotes by anything, once.
        assert_eq!(
            targets_of(1111, vec![vec!["E", &a], vec!["e", &b]], "x"),
            [id(&b)]
        );
        let quote = vec![vec!["q", &c], vec!["e", &c, "", "reply"], vec!["q", &a]];
        assert_eq!(targets_of(1, quote, "x"), [id(&a), id(&c)]);
        // Nothing else, nor anything replaceable.
        assert!(targets_of(9735, tags(), "").is_empty());
        assert!(targets_of(30023, vec![vec!["q", &a]], "").is_empty());

        // Which are comments and reactions, negative or not.
        assert_eq!(counts_of(7, tags(), "+"), [counts(1, 0, 1, 0)]);
        assert_eq!(counts_of(7, tags(), "👎"), [counts(0, 0, 1, 0)]);
        assert_eq!(counts_of(6, tags(), ""), [counts(1, 0, 0, 0)]);
        let reply = vec![vec!["e", &a, "", "reply"], vec!["q", &a]];
        assert_eq!(counts_of(1, reply, "x"), [counts(1, 1, 0, 0)]);
        assert_eq!(counts_of(1111, tags(), "x"), [counts(1, 1, 0, 0)]);
    }

    #[test]
    fn finds_what_zaps_zap() {
        let post = event(1, 100, 1, vec![], "zap me");
        let author = pubkey(1);
        let to = |target: Target, msats| (pubkey(2), target, counts(0, 0, 0, msats));
        let found = |zap: &Event| -> Vec<_> {
            let found = engagements_of(zap);
            found
                .into_iter()
                .map(|e| (e.engager, e.target, e.counts))
                .collect()
        };
        // By the request's signer, to what it names, never mind the
        // receipt's tags; the event, and its author too.
        let receipt = zap(2, 200, &post, 21_000);
        let both = [
            to(Target::Event(id(&post)), 21_000),
            to(Target::Recipient(author), 21_000),
        ];
        assert_eq!(found(&receipt), both);
        let elsewhere = "ab".repeat(32);
        let tags = vec![
            vec!["e", &elsewhere],
            vec!["p", &elsewhere],
            vec!["bolt11", receipt.tag("bolt11").unwrap()],
            vec!["description", receipt.tag("description").unwrap()],
        ];
        assert_eq!(found(&event(WALLET, 200, 9735, tags, "")), both);
        // At most what was asked.
        let tags = vec![vec!["p", post.pubkey.as_str()]];
        let greedy = zap_with(2, 200, tags.clone(), 50_000, 30_000);
        assert_eq!(found(&greedy), [to(Target::Recipient(author), 30_000)]);
        // Not to yourself, nor with a request that isn't signed.
        assert!(found(&zap(1, 200, &post, 1000)).is_empty());
        let mut forged: Event = serde_json::from_str(receipt.tag("description").unwrap()).unwrap();
        forged.pubkey = hex::encode(pubkey(3));
        let description = serde_json::to_string(&forged).unwrap();
        let tags = vec![
            vec!["bolt11", receipt.tag("bolt11").unwrap()],
            vec!["description", &description],
        ];
        assert!(found(&event(WALLET, 200, 9735, tags, "")).is_empty());

        // Onchain, by its author, split among recipients.
        let others = [pubkey(4), pubkey(5)].map(hex::encode);
        let batch = event(
            2,
            200,
            8333,
            vec![
                vec!["p", &others[0]],
                vec!["p", &others[1]],
                vec!["amount", "1001"],
            ],
            "",
        );
        let mut split = [4, 5].map(|n| to(Target::Recipient(pubkey(n)), 500_500));
        split.sort_unstable_by_key(|(_, target, _)| *target);
        assert_eq!(found(&batch), split);
        let single = onchain(2, 200, &post, 7);
        assert_eq!(found(&single).len(), 2);
        assert!(found(&onchain(1, 200, &post, 7)).is_empty());
        let tags = vec![vec!["p", post.pubkey.as_str()], vec!["amount", "-7"]];
        assert!(found(&event(2, 200, 8333, tags, "")).is_empty());
    }

    #[test]
    fn reads_invoice_amounts() {
        for (invoice, msats) in [
            (
                "lnbc210n1p5e2srfpp5x4fd3rjklja8fhvn3y5vjnrc00775805hts9rewjl2v3g8ma7d5q",
                Some(21_000),
            ),
            ("lnbc10u1p5", Some(1_000_000)),
            ("lnbc1m1p5", Some(100_000_000)),
            ("lnbc100p1p5", Some(10)),
            ("lnbc2500u1pvjluez", Some(250_000_000)),
            ("LNBC10N1P5", Some(1000)),
            ("lnbc31pvjluez", Some(300_000_000_000)),
            // No amount, another network, or nonsense.
            ("lnbc1pvjluez", None),
            ("lntb10n1p5", None),
            ("lnbcrt10n1p5", None),
            ("lnbc10x1p5", None),
            ("not-a-bolt11", None),
            ("", None),
        ] {
            assert_eq!(invoice_msats(invoice), msats, "{invoice}");
        }
    }

    #[test]
    fn ranks_controversial_and_zaps() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), None, Rank::default());
        let [heated, mild, liked, quiet] =
            [1, 2, 3, 4].map(|n| event(n, 100 * n, 1, vec![], "post"));
        for e in [&heated, &mild, &liked, &quiet] {
            put(&store, e);
        }
        let profiles = [1, 2, 3, 4].map(|n| event(n, 50 + n, 0, vec![], "{}"));
        // Some profiles before they're zapped, some after.
        put(&store, &profiles[0]);
        put(&store, &profiles[1]);
        let reply =
            |n: u32, to: &Event| event(n, 200, 1, vec![vec!["e", &to.id, "", "root"]], "no");
        // Argued over; a little of both; only liked.
        for n in 10..13 {
            put(&store, &reply(n, &heated));
            put(&store, &react(n + 10, &heated, "👎"));
        }
        put(&store, &reply(10, &mild));
        put(&store, &react(11, &mild, "+"));
        for n in 10..20 {
            put(&store, &react(n, &liked, "+"));
        }
        let s = scores(&store, &id(&heated));
        assert_eq!((s.score, s.comments, s.reactions), (3000, 3000, 3000));
        let search = |text: &str, kinds: Value, limit: usize| {
            ids(
                &store,
                json!({"search": text, "kinds": kinds, "limit": limit}),
            )
        };
        assert_eq!(
            search("sort:controversial", json!([1]), 2),
            of(&[&heated, &mild])
        );

        put(&store, &zap(30, 300, &liked, 21_000));
        put(&store, &zap(31, 300, &liked, 21_000));
        put(&store, &zap(30, 300, &quiet, 50_000));
        put(&store, &onchain(32, 300, &mild, 10));
        assert_eq!(scores(&store, &id(&quiet)).zaps, 50_000_000);
        assert_eq!(
            search("sort:zaps", json!([1]), 3),
            of(&[&quiet, &liked, &mild])
        );
        // Taken back as it goes.
        let big = zap(33, 301, &mild, 100_000);
        put(&store, &big);
        assert_eq!(search("sort:zaps", json!([1]), 1), of(&[&mild]));
        put(&store, &event(WALLET, 302, 5, vec![vec!["e", &big.id]], ""));
        assert_eq!(search("sort:zaps", json!([1]), 1), of(&[&quiet]));

        // Profiles, by all their authors have been zapped, to their
        // profiles too.
        put(&store, &profiles[2]);
        put(&store, &profiles[3]);
        let to_two = vec![vec!["p", mild.pubkey.as_str()]];
        put(&store, &zap_with(34, 400, to_two, 1_000_000, 1_000_000));
        assert_eq!(
            search("sort:zaps", json!([0]), 4),
            of(&[&profiles[1], &profiles[3], &profiles[2], &profiles[0]])
        );
        // Controversial as their authors' events are.
        assert_eq!(
            search("sort:controversial", json!([0]), 2),
            of(&[&profiles[0], &profiles[1]])
        );
        let named = json!({
            "kinds": [0],
            "authors": [mild.pubkey, heated.pubkey, liked.pubkey],
            "search": "sort:controversial",
        });
        assert_eq!(
            ids(&store, named),
            of(&[&profiles[0], &profiles[1], &profiles[2]])
        );
        // Replaced, ranked as it was.
        let newer = event(2, 500, 0, vec![], "{\"name\":\"two\"}");
        put(&store, &newer);
        assert_eq!(search("sort:zaps", json!([0]), 1), of(&[&newer]));

        // Two orders: nothing.
        assert!(search("sort:zaps sort:top", json!([1]), 10).is_empty());
    }

    #[test]
    fn ranks_rising() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path(), None, Rank::default());
        let now = crate::event::now();
        let new = event(1, now - 3600, 1, vec![], "new");
        let mid = event(2, now - 3 * DAY, 1, vec![], "mid");
        let old = event(3, now - 10 * DAY, 1, vec![], "old");
        for (e, n) in [(&new, 2), (&mid, 20), (&old, 100)] {
            put(&store, e);
            for m in 0..n {
                put(&store, &react(100 + m, e, "+"));
            }
        }
        // Too old to rise, so after those that are.
        let rising = json!({"search": "sort:rising", "kinds": [1]});
        assert_eq!(ids(&store, rising), of(&[&new, &mid, &old]));
        let hot = json!({"search": "sort:hot", "kinds": [1]});
        assert_eq!(ids(&store, hot), of(&[&mid, &new, &old]));
    }

    /// Random posts and reactions, ranked by how fast they're rising, the
    /// walk stopping where it may, checked against ranking them all.
    #[test]
    fn rises_as_brute_force_does() {
        const NOW: u32 = 100 * DAY;
        for half_life in [DAY, 3600, 30 * DAY] {
            let dir = tempfile::tempdir().unwrap();
            let store = open(dir.path(), None, Rank::new(half_life, 0.05, 100));
            let mut rng = StdRng::seed_from_u64(half_life.into());
            let posts: Vec<Event> = (0..80)
                .map(|i| {
                    let at = NOW - rng.random_range(0..9 * DAY);
                    event(1 + i % 9, at, 1, vec![], &format!("post {i}"))
                })
                .collect();
            for post in &posts {
                put(&store, post);
            }
            for _ in 0..600 {
                let to = &posts[rng.random_range(0..posts.len())];
                put(&store, &react(rng.random_range(100..160), to, "+"));
            }
            let txn = store.read().unwrap();
            let filter = Filter::parse(&json!({"kinds": [1]}), &test_tags(), MAX_VALUES).unwrap();
            for distinct in [false, true] {
                let mut want: Vec<(f64, &Event)> = posts
                    .iter()
                    .filter_map(|post| {
                        let score = score_of(&store, &txn, &id(post)).unwrap();
                        let score = score.map_or(0, |s| s.score);
                        rising(score, post.created_at as u32, NOW).map(|r| (r, post))
                    })
                    .collect();
                want.sort_by(|(x, a), (y, b)| {
                    y.total_cmp(x)
                        .then(b.created_at.cmp(&a.created_at))
                        .then(a.id.cmp(&b.id))
                });
                let mut authors = HashSet::new();
                want.retain(|(_, post)| !distinct || authors.insert(post.pubkey.clone()));
                for limit in [1, 3, 10, 40] {
                    let got = walk_rising(&store, &txn, &filter, limit, distinct, NOW).unwrap();
                    let got: Vec<String> = got.iter().map(|(_, v)| hex::encode(v.id())).collect();
                    let want: Vec<String> =
                        want.iter().take(limit).map(|(_, e)| e.id.clone()).collect();
                    assert_eq!(got, want, "{half_life} {limit} {distinct}");
                }
            }
        }
    }

    #[test]
    fn orders_hot_as_decay_does() {
        let day = 86_400;
        // (score, created_at): at any moment, score * 2^-(age / day).
        let events = [
            (1000, 10 * day),
            (4000, 8 * day),
            (3000, 9 * day),
            (500, 11 * day),
        ];
        let mut by_rank = events;
        by_rank.sort_by_key(|&(s, at)| std::cmp::Reverse(hot(s, at, day)));
        for now in [12 * day, 20 * day, 100 * day] {
            let mut by_decay = events;
            let worth =
                |(s, at): (i64, u32)| s as f64 * 0.5f64.powf(f64::from(now - at) / f64::from(day));
            by_decay.sort_by(|x, y| worth(*y).total_cmp(&worth(*x)));
            assert_eq!(by_rank, by_decay);
        }
    }
}
