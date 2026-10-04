//! `sort:top` and `sort:hot`: events ranked by how many people the relay
//! [trusts](crate::wot) have engaged with them.
//!
//! # Scores
//!
//! An event's *score* is the sum of the weights of everyone who's engaged
//! with it, each once however often, the author aside: who's reacted to it
//! (other than negatively), reposted it, replied to it (as NIP-10 has it),
//! commented on it (NIP-22), or quoted it. Only regular events engage, and
//! a zap's sender can't be told from its receipt, so zaps don't.
//!
//! `engagement` keeps each pair of engager and target, with how many of
//! the engager's events engage the target, so the pair counts until the
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
//! by score for `sort:top`, and for `sort:hot` by
//! `log2(score) + created_at / half_life`. The latter orders events as
//! `score * 2^-(age / half_life)` does at any moment, so it needn't change
//! as time passes. Profiles are ranked by their author's trust instead.
//! A search with no text finds the best by walking `ranked` from the top
//! (or, for a filter naming authors, ids, or tags, by ranking all it
//! matches); one with text ranks what the search index finds.

use std::collections::{BinaryHeap, HashSet};

use crate::analysis::Sentiment;
use crate::event::KindClass;
use crate::filter::{Filter, Sort};
use crate::lmdb::{Result, RwTxn, Txn};
use crate::metrics::METRICS;
use crate::query::MAX_EXAMINED;
use crate::record::{Element, EventView};
use crate::store::{Store, address};
use crate::wot;

/// `ranked` modes.
const TOP: u8 = 0;
const HOT: u8 = 1;
const PROFILE: u8 = 2;

/// A weight of 1, in the thousandths weights and scores are kept in.
const FULL: i64 = 1000;

/// Bumped when how scores are kept changes. They're then rebuilt.
const VERSION: u32 = 1;

/// The `meta` keys of what scores were computed with, and the walk under
/// way.
const PARAMS: &[u8] = b"rank_params";
const WALK: &[u8] = b"rank_walk";

/// The most entries rebuilt per write transaction.
const REBUILD_CHUNK: usize = 10_000;

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
    let mut ids = view.tag_values().filter_map(|(n, value)| match value {
        Element::Hex(id) if n == name => Some(id),
        _ => None,
    });
    match last {
        true => ids.last(),
        false => ids.next(),
    }
}

/// The ids of the events an event engages with. See the [module docs].
///
/// [module docs]: self
pub fn targets(view: &EventView) -> Vec<[u8; 32]> {
    if KindClass::of(view.kind()) != KindClass::Regular {
        return Vec::new();
    }
    let mut out: Vec<[u8; 32]> = match view.kind() {
        // NIP-25: the last `e` tag.
        7 if view.analysis().sentiment != Some(Sentiment::Negative) => id_tag(view, "e", true),
        6 | 16 => id_tag(view, "e", false),
        1 => parent(view),
        // NIP-22: the parent, when it's an event.
        1111 => id_tag(view, "e", false),
        _ => None,
    }
    .into_iter()
    .copied()
    .collect();
    out.extend(view.tag_values().filter_map(|(name, value)| match value {
        Element::Hex(id) if name == "q" => Some(*id),
        _ => None,
    }));
    out.sort_unstable();
    out.dedup();
    out
}

/// What's kept of an event engaged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Score {
    /// Its engagers' applied weights, in thousandths.
    score: i64,
    /// While it's stored and current, its sequence number; 0 otherwise.
    seq: u64,
    created_at: u32,
    kind: u16,
    /// Once it's been seen.
    author: Option<[u8; 32]>,
}

impl Score {
    fn encode(&self) -> [u8; 55] {
        let mut out = [0; 55];
        out[..8].copy_from_slice(&self.score.to_le_bytes());
        out[8..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16..20].copy_from_slice(&self.created_at.to_le_bytes());
        out[20..22].copy_from_slice(&self.kind.to_le_bytes());
        if let Some(author) = self.author {
            out[22] = 1;
            out[23..].copy_from_slice(&author);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Option<Score> {
        let bytes: &[u8; 55] = bytes.try_into().ok()?;
        Some(Score {
            score: i64::from_le_bytes(bytes[..8].try_into().unwrap()),
            seq: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            created_at: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            kind: u16::from_le_bytes(bytes[20..22].try_into().unwrap()),
            author: (bytes[22] == 1).then(|| bytes[23..].try_into().unwrap()),
        })
    }

    /// Where `ranked` files it: nowhere unless it's stored and scored.
    fn ranks(&self, half_life: u32) -> Vec<(u8, u64)> {
        if self.seq == 0 || self.score <= 0 {
            return Vec::new();
        }
        vec![
            (TOP, self.score as u64),
            (HOT, hot(self.score, self.created_at, half_life)),
        ]
    }
}

/// `log2(score) + created_at / half_life`, in an order-preserving u64.
fn hot(score: i64, created_at: u32, half_life: u32) -> u64 {
    let x = (score as f64 / FULL as f64).log2() + f64::from(created_at) / f64::from(half_life);
    let bits = x.to_bits();
    match bits >> 63 {
        1 => !bits,
        _ => bits | 1 << 63,
    }
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

fn ranked_seq(value: &[u8]) -> u64 {
    let mut seq = [0; 8];
    seq[2..].copy_from_slice(&value[8..14]);
    u64::from_be_bytes(seq)
}

fn score_of(store: &Store, txn: &Txn, id: &[u8; 32]) -> Result<Option<Score>> {
    Ok(txn.get(store.tables.scores, id)?.and_then(Score::decode))
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

/// What an engager adds to a target's score.
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

/// Count, or with `delta` -1 stop counting, one of an engager's events
/// engaging a target.
fn engage(
    store: &Store,
    txn: &mut RwTxn,
    engager: &[u8; 32],
    target: &[u8; 32],
    delta: i32,
) -> Result<()> {
    let t = store.tables;
    let key = [&engager[..], &target[..]].concat();
    let count = txn
        .get(t.engagement, &key)?
        .and_then(|v| v.try_into().ok())
        .map_or(0, u32::from_le_bytes);
    let Some(next) = count.checked_add_signed(delta) else {
        return Ok(());
    };
    if count == 0 || next == 0 {
        let old = match score_of(store, txn, target)? {
            Some(score) => score,
            None => seen(store, txn, target)?,
        };
        let mut new = old;
        let amount = contribution(store, txn, engager, target, &old)?;
        new.score += if delta > 0 { amount } else { -amount };
        set_score(store, txn, target, &old, &new)?;
    }
    match next {
        0 => txn.del(t.engagement, &key, None).map(drop),
        _ => txn.put(t.engagement, &key, &next.to_le_bytes()).map(drop),
    }
}

/// What's known of an event not engaged with before: if it's stored, its
/// author, and if it's current, where it is.
fn seen(store: &Store, txn: &Txn, id: &[u8; 32]) -> Result<Score> {
    let Some(seq) = store.seq_of(txn, id)? else {
        return Ok(Score::default());
    };
    let Some(view) = store.load(txn, seq)? else {
        return Ok(Score::default());
    };
    let current = store.is_current(txn, seq, &view)?;
    Ok(Score {
        score: 0,
        seq: if current { seq } else { 0 },
        created_at: view.created_at(),
        kind: view.kind(),
        author: Some(*view.pubkey()),
    })
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
        if old.author.is_none() && engaged(store, txn, author, id)? {
            new.score -= applied(store, txn, author, id)?;
        }
        set_score(store, txn, id, &old, &new)?;
    }
    for target in targets(view) {
        engage(store, txn, author, &target, 1)?;
    }
    if view.kind() == 0 && store.wot().is_some() {
        let score = wot::score(store, txn, author)?;
        if score > 0 {
            let value = ranked_value(score as u64, seq);
            txn.put_dup(store.tables.ranked, &ranked_key(PROFILE, 0), &value)?;
        }
    }
    Ok(())
}

/// An event under `seq` has been taken out of the indexes: undo [`index`].
pub fn unindex(store: &Store, txn: &mut RwTxn, seq: u64, view: &EventView) -> Result<()> {
    let (id, author) = (view.id(), view.pubkey());
    if let Some(old) = score_of(store, txn, id)?
        && old.seq == seq
    {
        let new = Score { seq: 0, ..old };
        set_score(store, txn, id, &old, &new)?;
    }
    for target in targets(view) {
        engage(store, txn, author, &target, -1)?;
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

fn engaged(store: &Store, txn: &Txn, engager: &[u8; 32], target: &[u8; 32]) -> Result<bool> {
    let key = [&engager[..], &target[..]].concat();
    Ok(txn.get(store.tables.engagement, &key)?.is_some())
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
    let targets: Vec<[u8; 32]> = {
        let mut cursor = txn.cursor(t.engagement)?;
        let start = [&walk.engager[..], &walk.done.unwrap_or_default()[..]].concat();
        let mut entry = cursor.set_range(&start)?;
        let mut out = Vec::new();
        while let Some((key, _)) = entry
            && key.starts_with(&walk.engager)
            && out.len() < budget
        {
            let target: [u8; 32] = key[32..].try_into().unwrap_or_default();
            if walk.done != Some(target) {
                out.push(target);
            }
            entry = cursor.next()?;
        }
        out
    };
    for target in &targets {
        if let Some(old) = score_of(store, txn, target)?
            && old.author != Some(walk.engager)
        {
            let new = Score {
                score: old.score + walk.new - walk.old,
                ..old
            };
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

/// Rebuild scores and ranks from `engagement` if how they're computed has
/// changed, when the store opens: before it serves anything, a chunk per
/// transaction, and over again if interrupted.
pub fn open(store: &Store) -> anyhow::Result<()> {
    let t = store.tables;
    let rank = store.rank();
    let params = [
        &VERSION.to_be_bytes()[..],
        &rank.half_life.to_be_bytes(),
        &rank.step.to_be_bytes(),
        &store.wot().map(|wot| wot.params()).unwrap_or_default(),
    ]
    .concat();
    if store.read()?.get(t.meta, PARAMS)? == Some(&params[..]) {
        return Ok(());
    }
    tracing::info!("rebuilding scores for sort:top and sort:hot");
    let mut txn = store.write()?;
    for db in [t.ranked, t.applied, t.rank_queue] {
        txn.clear(db)?;
    }
    txn.del(t.meta, WALK, None)?;
    txn.del(t.meta, PARAMS, None)?;
    txn.commit()?;

    chunks(store, t.scores, |txn, id, value| {
        if let Some(score) = Score::decode(value) {
            txn.put(t.scores, id, &Score { score: 0, ..score }.encode())?;
        }
        Ok(())
    })?;
    chunks(store, t.engagement, |txn, key, _| {
        let (engager, target): ([u8; 32], [u8; 32]) =
            (key[..32].try_into().unwrap(), key[32..].try_into().unwrap());
        let weight = weight(store, txn, &engager)?;
        if store.wot().is_some() && weight > 0 {
            txn.put(t.applied, &engager, &weight.to_le_bytes())?;
        }
        if let Some(mut score) = score_of(store, txn, &target)?
            && score.author != Some(engager)
        {
            score.score += weight;
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

/// Which ranks a ranked search goes by: profiles by their author's trust,
/// anything else by engagement.
fn mode(store: &Store, filter: &Filter, sort: Sort) -> u8 {
    match (filter.kinds.as_deref(), store.wot(), sort) {
        (Some([0]), Some(_), _) => PROFILE,
        (_, _, Sort::Hot) => HOT,
        _ => TOP,
    }
}

/// An event's rank in a mode: 0 for none.
fn rank_of(store: &Store, txn: &Txn, mode: u8, view: &EventView) -> Result<u64> {
    if mode == PROFILE {
        return Ok(wot::score(store, txn, view.pubkey())?.max(0) as u64);
    }
    let Some(score) = score_of(store, txn, view.id())?.filter(|s| s.score > 0) else {
        return Ok(0);
    };
    Ok(match mode {
        TOP => score.score as u64,
        _ => hot(score.score, view.created_at(), store.rank().half_life),
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
    let mut ranked = Vec::with_capacity(found.len());
    for (seq, view) in found.drain(..) {
        ranked.push((rank_of(store, txn, mode, &view)?, seq, view));
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
        let mut found = walk(store, txn, filter, mode(store, filter, search.sort), limit)?;
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

/// The best ranked events a filter matches, from `ranked`.
fn walk<'t>(
    store: &Store,
    txn: &'t Txn,
    filter: &Filter,
    mode: u8,
    limit: usize,
) -> Result<Vec<(u64, EventView<'t>)>> {
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
    let distinct = filter.search.as_ref().is_some_and(|s| s.distinct_author);
    let mut authors = HashSet::new();
    let mut found = Vec::new();
    let mut examined = 0;
    while let Some((value, i)) = heap.pop() {
        if let Some((_, next)) = cursors[i].prev_dup()? {
            heap.push((next.to_vec(), i));
        }
        examined += 1;
        if found.len() >= limit {
            break;
        }
        if examined > MAX_EXAMINED {
            METRICS.filters_cut_short.inc();
            break;
        }
        let seq = ranked_seq(&value);
        if let Some(view) = store.load(txn, seq)?
            && filter.matches(&view)
            && (!distinct || authors.insert(*view.pubkey()))
        {
            found.push((seq, view));
        }
    }
    Ok(found)
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
        crate::query::run(store, None, &[filter], 100, 500, |_| true)
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

    fn score(store: &Store, event: &Event) -> i64 {
        let txn = store.read().unwrap();
        score_of(store, &txn, &id(event))
            .unwrap()
            .map_or(0, |s| s.score)
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

    /// Random notes, engagement, deletions, vanishing, and follow lists,
    /// with the background work done a little at a time, checked against
    /// counting it all up again.
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
            let new = match rng.random_range(0..12) {
                0 => Some(event(n, at, 7, vec![vec!["e", to_id]], "-")),
                1 | 2 => Some(event(n, at, 7, vec![vec!["e", to_id]], "+")),
                3 => Some(event(n, at, 6, vec![vec!["e", to_id]], "")),
                4 => Some(event(n, at, 1, vec![vec!["e", to_id, "", "root"]], "re")),
                5 => Some(event(n, at, 1111, vec![vec!["e", to_id]], "hm")),
                6 => Some(event(n, at, 1, vec![vec!["q", to_id]], "look")),
                7 if !engagement.is_empty() => {
                    let old = &engagement[rng.random_range(0..engagement.len())];
                    let author = (0..30).find(|&m| hex::encode(pubkey(m)) == old.pubkey);
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
        let mut pairs: HashMap<([u8; 32], [u8; 32]), u32> = HashMap::new();
        for (key, record) in table(&store, store.tables.events) {
            let seq = u64::from_ne_bytes(key.try_into().unwrap());
            let view = EventView::new(&record).unwrap();
            if store.is_current(&txn, seq, &view).unwrap() {
                for target in targets(&view) {
                    *pairs.entry((*view.pubkey(), target)).or_default() += 1;
                }
            }
        }
        let kept: HashMap<([u8; 32], [u8; 32]), u32> = table(&store, store.tables.engagement)
            .into_iter()
            .map(|(k, v)| {
                let pair = (k[..32].try_into().unwrap(), k[32..].try_into().unwrap());
                (pair, u32::from_le_bytes(v.try_into().unwrap()))
            })
            .collect();
        assert_eq!(kept, pairs);
        assert!(!pairs.is_empty());

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
        // author is known once it's been stored.
        let mut want: HashMap<[u8; 32], i64> = HashMap::new();
        for (x, target) in pairs.keys() {
            let author = pool
                .iter()
                .find(|e| id(e) == *target)
                .unwrap()
                .pubkey
                .clone();
            let known = id(&missing) != *target;
            if !(known && hex::encode(x) == author) {
                *want.entry(*target).or_default() += applied(x);
            }
        }
        let mut expected_ranks = Vec::new();
        for (key, value) in table(&store, store.tables.scores) {
            let target: [u8; 32] = key.try_into().unwrap();
            let s = Score::decode(&value).unwrap();
            assert_eq!(s.score, want.get(&target).copied().unwrap_or(0));
            assert_eq!(s.author.is_some(), target != id(&missing));
            for (mode, rank) in s.ranks(DAY) {
                expected_ranks.push((
                    ranked_key(mode, s.kind).to_vec(),
                    ranked_value(rank, s.seq).to_vec(),
                ));
            }
        }
        // And every stored, scored event is filed by its ranks, and every
        // profile of someone with a score by it.
        for n in people.iter().step_by(3) {
            let score = wot::score(&store, &txn, &pubkey(*n)).unwrap();
            if score > 0 {
                let seq = profile(&store, &txn, &pubkey(*n)).unwrap().unwrap();
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
        let scored = |t: &[(Vec<u8>, Vec<u8>)]| -> Vec<(Vec<u8>, bool)> {
            t.iter()
                .map(|(k, v)| (k.clone(), Score::decode(v).unwrap().score > 0))
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

    fn targets_of(kind: u16, tags: Vec<Vec<&str>>, content: &str) -> Vec<[u8; 32]> {
        let record = record::encode(&signed(1, 100, kind, tags, content));
        targets(&EventView::new(&record).unwrap())
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
