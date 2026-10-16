//! A web of trust: how much the relay trusts each author, from who follows
//! whom, so that engagement can count by who it's from.
//!
//! Trust is personalized PageRank over kind 3 follow lists, rooted at the
//! operator's seed pubkeys: a walk that starts at a seed, follows someone
//! its current account follows with probability `d` (the damping), and
//! otherwise stops. An author's *score* is the chance the walk stops at
//! them. One unit of trust is shared out in all, so a crowd of fresh keys
//! following each other gets only what trusted accounts' follows hand it,
//! however many keys there are. A walk that reaches someone who follows
//! nobody goes no further: the trust they'd pass on is *leaked*.
//!
//! An author's *weight*, what their engagement counts for, is their score
//! over [`Wot::tau`] — the score of one of `full_trust` equally trusted
//! people — at most 1, and nothing below `min_weight`. The seeds weigh 1.
//!
//! # Computing it
//!
//! Scores are computed by *local push*, which only ever touches authors
//! trust reaches, so the work depends on the precision asked for, not on
//! how many pubkeys exist. Each author has a settled score and a pending
//! *residual*; at first the seeds hold all of it. Pushing an author settles
//! `1 - d` of their residual into their score and shares the rest equally
//! among those they follow. An author is pushed only while their residual
//! is at least [`Wot::epsilon`] per follow, which settles at least so much
//! trust each time, so pushing it all takes at most about
//! `1 / (epsilon (1 - d))` follows visited in all. A score is never more
//! than the sum of every residual short of exact.
//!
//! The scores keep up with follow lists as they change, with no recompute:
//! when an author with a score replaces their list, what they've passed on
//! is taken back from residuals of those they followed and given to those
//! they follow now, and pushing then spreads it, negative residuals too.
//! The store does that in the same transaction that changes the list, when
//! it has both versions in hand ([`relist`]), so it never needs an old list
//! back. For an author without a score that's one lookup; it's only
//! trusted authors' changes that spread.
//!
//! Pushing runs on the writer's thread a [budget](Wot::budget) at a time,
//! between batches of events, so it never holds up storing them for long.
//! Authors due a push wait in `wot_queue`. On first start the seeds are
//! queued with all the trust, and weights fill in from there.
//!
//! # Arithmetic
//!
//! Trust is fixed-point, [`ONE`] being all of it, so nothing is lost to
//! rounding: what doesn't divide evenly among an author's follows stays
//! with them as residual. Every score, every residual, and what's leaked
//! always add up to exactly [`ONE`]; [`check`] confirms it.

use crate::lmdb::{Result, RwTxn, Txn};
use crate::record::{Element, EventView};
use crate::store::{Store, address};

/// All the trust there is.
pub const ONE: i64 = 1 << 52;

/// Follow lists.
pub const FOLLOWS: u16 = 3;

/// The damping is kept in millionths.
const MILLION: i64 = 1_000_000;

/// An author whose follow list hasn't been read.
const UNKNOWN: u32 = u32::MAX;

/// The `meta` keys of what the state was computed with, the seeds it was
/// rooted at, and how much trust has leaked.
const PARAMS: &[u8] = b"wot_params";
const SEEDS: &[u8] = b"wot_seeds";
const LEAKED: &[u8] = b"wot_leaked";

/// How the web of trust is computed. Without seeds, there's none, and
/// everyone weighs 1.
#[derive(Debug, Clone)]
pub struct Wot {
    /// Sorted.
    seeds: Vec<[u8; 32]>,
    /// In millionths.
    damping: i64,
    /// The score of full trust.
    tau: i64,
    /// The residual per follow an author must have to be pushed.
    epsilon: i64,
    min_weight: f64,
    /// About how many follows to visit per turn.
    budget: usize,
}

impl Wot {
    /// `damping` is in (0, 1); `full_trust` at least 1; `min_weight` in
    /// (0, 1]. `None` without seeds.
    pub fn new(
        mut seeds: Vec<[u8; 32]>,
        damping: f64,
        full_trust: u64,
        min_weight: f64,
        budget: usize,
    ) -> Option<Wot> {
        seeds.sort_unstable();
        seeds.dedup();
        if seeds.is_empty() {
            return None;
        }
        let damping = ((damping * MILLION as f64).round() as i64).clamp(1, MILLION - 1);
        let tau = (ONE / full_trust.max(1) as i64).max(1);
        let min_weight = min_weight.clamp(f64::MIN_POSITIVE, 1.0);
        Some(Wot {
            seeds,
            damping,
            tau,
            epsilon: ((tau as f64 * min_weight) as i64).max(1),
            min_weight,
            budget: budget.max(1),
        })
    }

    /// What, if it changes, means starting over.
    pub fn params(&self) -> Vec<u8> {
        [&self.damping.to_be_bytes()[..], &self.epsilon.to_be_bytes()].concat()
    }

    /// Whether an author is due a push.
    fn due(&self, node: &Node) -> bool {
        let follows = match node.degree {
            UNKNOWN | 0 => 1,
            n => i64::from(n),
        };
        node.residual.unsigned_abs() >= (self.epsilon as u64).saturating_mul(follows as u64)
    }

    /// Of `amount`, what's passed on rather than settled.
    fn passed(&self, amount: i64) -> i64 {
        (i128::from(amount) * i128::from(self.damping) / i128::from(MILLION)) as i64
    }

    /// What an author with `score` has passed on: `d / (1 - d)` of it.
    fn passed_on(&self, score: i64) -> i64 {
        (i128::from(score) * i128::from(self.damping) / i128::from(MILLION - self.damping)) as i64
    }

    /// The least weight counted.
    pub fn min_weight(&self) -> f64 {
        self.min_weight
    }

    /// An author's weight.
    pub fn weight(&self, store: &Store, txn: &Txn, pubkey: &[u8; 32]) -> Result<f32> {
        if self.seeds.binary_search(pubkey).is_ok() {
            return Ok(1.0);
        }
        let score = node(store, txn, pubkey)?.map_or(0, |node| node.score);
        let weight = (score as f64 / self.tau as f64).min(1.0);
        Ok(match weight >= self.min_weight {
            true => weight as f32,
            false => 0.0,
        })
    }

    /// Each seed's share of the trust: equal, and the first gets what
    /// doesn't divide evenly.
    fn shares(seeds: &[[u8; 32]]) -> Vec<([u8; 32], i64)> {
        let Some(n) = i64::try_from(seeds.len()).ok().filter(|&n| n > 0) else {
            return Vec::new();
        };
        let each = ONE / n;
        seeds
            .iter()
            .enumerate()
            .map(|(i, seed)| (*seed, if i == 0 { ONE - each * (n - 1) } else { each }))
            .collect()
    }
}

/// What's kept of an author: `wot` maps their pubkey to these, 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Node {
    score: i64,
    residual: i64,
    /// How many they followed when last looked, or [`UNKNOWN`].
    degree: u32,
}

impl Default for Node {
    fn default() -> Node {
        Node {
            score: 0,
            residual: 0,
            degree: UNKNOWN,
        }
    }
}

impl Node {
    fn encode(&self) -> [u8; 20] {
        let mut out = [0; 20];
        out[..8].copy_from_slice(&self.score.to_le_bytes());
        out[8..16].copy_from_slice(&self.residual.to_le_bytes());
        out[16..].copy_from_slice(&self.degree.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Node> {
        let bytes: &[u8; 20] = bytes.try_into().ok()?;
        Some(Node {
            score: i64::from_le_bytes(bytes[..8].try_into().unwrap()),
            residual: i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            degree: u32::from_le_bytes(bytes[16..].try_into().unwrap()),
        })
    }
}

/// An author's trust score, of [`ONE`].
pub fn score(store: &Store, txn: &Txn, pubkey: &[u8; 32]) -> Result<i64> {
    Ok(node(store, txn, pubkey)?.map_or(0, |node| node.score))
}

fn node(store: &Store, txn: &Txn, pubkey: &[u8; 32]) -> Result<Option<Node>> {
    Ok(txn.get(store.tables.wot, pubkey)?.and_then(Node::decode))
}

/// Keep an author's state, or forget it if there's nothing to keep.
fn put_node(store: &Store, txn: &mut RwTxn, pubkey: &[u8; 32], node: &Node) -> Result<()> {
    match node.score == 0 && node.residual == 0 {
        true => txn.del(store.tables.wot, pubkey, None).map(drop),
        false => txn.put(store.tables.wot, pubkey, &node.encode()).map(drop),
    }
}

fn leaked(store: &Store, txn: &Txn) -> Result<i64> {
    Ok(txn
        .get(store.tables.meta, LEAKED)?
        .and_then(|v| v.try_into().ok())
        .map_or(0, i64::from_le_bytes))
}

fn leak(store: &Store, txn: &mut RwTxn, amount: i64) -> Result<()> {
    let total = leaked(store, txn)? + amount;
    txn.put(store.tables.meta, LEAKED, &total.to_le_bytes())
        .map(drop)
}

/// The pubkeys a follow list follows: its `p` tags, once each, not its
/// author.
pub fn follows(view: &EventView) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = view
        .tag_values()
        .filter_map(|(name, value)| match (name, value) {
            ("p", Element::Hex(pubkey)) if pubkey != view.pubkey() => Some(*pubkey),
            _ => None,
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Whom an author's current follow list follows. One that has expired but
/// not been swept still counts, as it did when trust was pushed along it.
fn current_follows(store: &Store, txn: &Txn, pubkey: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let t = store.tables;
    let Some(seq) = txn
        .get(t.replaceable, &address(pubkey, FOLLOWS, &[0]))?
        .and_then(|v| v.try_into().ok())
        .map(u64::from_be_bytes)
    else {
        return Ok(Vec::new());
    };
    Ok(txn
        .get(t.events, &seq.to_ne_bytes())?
        .and_then(EventView::new)
        .map_or_else(Vec::new, |view| follows(&view)))
}

/// Add to an author's residual, queueing them if they're due a push.
fn add(store: &Store, txn: &mut RwTxn, wot: &Wot, pubkey: &[u8; 32], amount: i64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let mut node = node(store, txn, pubkey)?.unwrap_or_default();
    node.residual += amount;
    put_node(store, txn, pubkey, &node)?;
    if wot.due(&node) {
        txn.put(store.tables.wot_queue, pubkey, &[])?;
    }
    Ok(())
}

/// Share `amount` equally among `targets`' residuals, or leak it if there
/// are none. Returns what didn't divide evenly.
fn share(
    store: &Store,
    txn: &mut RwTxn,
    wot: &Wot,
    targets: &[[u8; 32]],
    amount: i64,
) -> Result<i64> {
    if targets.is_empty() {
        leak(store, txn, amount)?;
        return Ok(0);
    }
    let each = amount / targets.len() as i64;
    for target in targets {
        add(store, txn, wot, target, each)?;
    }
    Ok(amount - each * targets.len() as i64)
}

/// An author's follow list has gone from following `old` to `new`, in the
/// write transaction that changed it: move what they've passed on from the
/// one to the other. See the [module docs](self).
pub fn relist(
    store: &Store,
    txn: &mut RwTxn,
    wot: &Wot,
    author: &[u8; 32],
    old: &[[u8; 32]],
    new: &[[u8; 32]],
) -> Result<()> {
    let Some(mut node) = node(store, txn, author)? else {
        return Ok(());
    };
    node.degree = new.len() as u32;
    if old != new && node.score != 0 {
        let amount = wot.passed_on(node.score);
        // What doesn't divide evenly stays with the author, so nothing's
        // lost.
        node.residual += share(store, txn, wot, old, -amount)?;
        node.residual += share(store, txn, wot, new, amount)?;
    }
    put_node(store, txn, author, &node)?;
    if wot.due(&node) {
        txn.put(store.tables.wot_queue, author, &[])?;
    }
    Ok(())
}

/// Push an author, if they're still due it. Returns about how much work
/// that was.
fn push(store: &Store, txn: &mut RwTxn, wot: &Wot, pubkey: &[u8; 32]) -> Result<usize> {
    txn.del(store.tables.wot_queue, pubkey, None)?;
    let Some(mut node) = node(store, txn, pubkey)? else {
        return Ok(1);
    };
    let follows = current_follows(store, txn, pubkey)?;
    node.degree = follows.len() as u32;
    let before = node.score;
    if wot.due(&node) {
        let residual = std::mem::take(&mut node.residual);
        let passed = wot.passed(residual);
        node.score += residual - passed;
        node.residual = share(store, txn, wot, &follows, passed)?;
    }
    put_node(store, txn, pubkey, &node)?;
    if node.score != before {
        crate::rank::trust_changed(store, txn, pubkey, before, node.score)?;
    }
    Ok(follows.len() + 1)
}

/// Push authors due it until about a budget's worth of follows have been
/// visited. Returns whether any are still due.
pub fn turn(store: &Store, txn: &mut RwTxn, wot: &Wot) -> Result<bool> {
    let first = |txn: &RwTxn| -> Result<Option<[u8; 32]>> {
        let mut cursor = txn.cursor(store.tables.wot_queue)?;
        Ok(cursor.first()?.and_then(|(key, _)| key.try_into().ok()))
    };
    let mut spent = 0;
    while spent < wot.budget {
        let Some(pubkey) = first(txn)? else {
            return Ok(false);
        };
        spent += push(store, txn, wot, &pubkey)?;
    }
    Ok(first(txn)?.is_some())
}

/// Bring the state in line with how it's to be computed, when the store
/// opens: start over if the damping or precision changed, move the trust
/// from the old seeds to the new, or with no web of trust, drop it all.
pub fn open(store: &Store, wot: Option<&Wot>) -> anyhow::Result<()> {
    let t = store.tables;
    let mut txn = store.write()?;
    let params = txn.get(t.meta, PARAMS)?.map(<[u8]>::to_vec);
    let Some(wot) = wot else {
        if params.is_some() {
            reset(store, &mut txn)?;
            txn.commit()?;
        }
        return Ok(());
    };
    let mut old_seeds = Vec::new();
    if params.as_deref() == Some(&wot.params()[..]) {
        if let Some(seeds) = txn.get(t.meta, SEEDS)? {
            old_seeds = seeds.as_chunks::<32>().0.to_vec();
        }
    } else {
        if params.is_some() {
            tracing::warn!("rebuilding the web of trust");
        }
        reset(store, &mut txn)?;
        txn.put(t.meta, PARAMS, &wot.params())?;
    }
    if old_seeds != wot.seeds {
        // Linear in the seeds, so it's a change of residuals.
        for (seed, share) in Wot::shares(&old_seeds) {
            add(store, &mut txn, wot, &seed, -share)?;
        }
        for (seed, share) in Wot::shares(&wot.seeds) {
            add(store, &mut txn, wot, &seed, share)?;
        }
        txn.put(t.meta, SEEDS, &wot.seeds.concat())?;
        // Seeds weigh 1 whatever their score.
        for seed in old_seeds.iter().chain(&wot.seeds) {
            crate::rank::requeue(store, &mut txn, seed)?;
        }
    }
    txn.commit()?;
    if let Err(err) = check(store) {
        tracing::error!("the web of trust doesn't add up: {err}");
    }
    Ok(())
}

fn reset(store: &Store, txn: &mut RwTxn) -> Result<()> {
    let t = store.tables;
    txn.clear(t.wot)?;
    txn.clear(t.wot_queue)?;
    for key in [PARAMS, SEEDS, LEAKED] {
        txn.del(t.meta, key, None)?;
    }
    Ok(())
}

/// Confirm that every score and residual, and what's leaked, add up to
/// exactly [`ONE`].
pub fn check(store: &Store) -> anyhow::Result<()> {
    let txn = store.read()?;
    if txn.get(store.tables.meta, PARAMS)?.is_none() {
        return Ok(());
    }
    let mut total = i128::from(leaked(store, &txn)?);
    let mut cursor = txn.cursor(store.tables.wot)?;
    let mut entry = cursor.first()?;
    while let Some((_, value)) = entry {
        let node = Node::decode(value).ok_or_else(|| anyhow::anyhow!("a malformed node"))?;
        total += i128::from(node.score) + i128::from(node.residual);
        entry = cursor.next()?;
    }
    anyhow::ensure!(total == i128::from(ONE), "{total} rather than {ONE}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::sign;
    use crate::store::History;
    use crate::store::tests::test_tags;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::collections::HashMap;
    use std::path::Path;

    const DAMPING: f64 = 0.85;

    fn secret(n: u32) -> [u8; 32] {
        let mut secret = [7; 32];
        secret[28..].copy_from_slice(&n.to_be_bytes());
        secret
    }

    fn pubkey(n: u32) -> [u8; 32] {
        let keypair = secp256k1::Keypair::from_secret_bytes(secret(n)).unwrap();
        keypair.x_only_public_key().0.to_byte_array()
    }

    fn follow_list(n: u32, at: u64, follows: &[[u8; 32]]) -> Event {
        let tags = follows
            .iter()
            .map(|pk| vec!["p".to_string(), hex::encode(pk)])
            .collect();
        sign(secret(n), at, FOLLOWS, tags, "")
    }

    fn wot(seeds: Vec<[u8; 32]>, budget: usize) -> Wot {
        // Fine enough to compare with exact scores.
        Wot::new(seeds, DAMPING, 100, 0.0001, budget).unwrap()
    }

    fn open_at(dir: &Path, wot: Option<Wot>) -> Store {
        let history = History::new(true, vec![], 20);
        Store::open(
            dir,
            1 << 28,
            crate::lmdb::Opening::SYNC,
            test_tags(),
            history,
            wot,
            Default::default(),
        )
        .unwrap()
    }

    fn put(store: &Store, event: &Event) {
        crate::store::tests::put(store, event);
    }

    fn settle(store: &Store) {
        while store.turn().unwrap() {}
    }

    /// Every author's state, and the sum of every residual's size.
    fn state(store: &Store) -> (HashMap<[u8; 32], Node>, f64) {
        let txn = store.read().unwrap();
        let mut cursor = txn.cursor(store.tables.wot).unwrap();
        let mut nodes = HashMap::new();
        let mut entry = cursor.first().unwrap();
        while let Some((key, value)) = entry {
            nodes.insert(key.try_into().unwrap(), Node::decode(value).unwrap());
            entry = cursor.next().unwrap();
        }
        let residual = nodes
            .values()
            .map(|n| n.residual.unsigned_abs() as f64)
            .sum::<f64>()
            / ONE as f64;
        (nodes, residual)
    }

    /// The follow graph as the store has it now.
    fn graph(store: &Store, people: &[[u8; 32]]) -> HashMap<[u8; 32], Vec<[u8; 32]>> {
        let txn = store.read().unwrap();
        people
            .iter()
            .map(|pk| (*pk, current_follows(store, &txn, pk).unwrap()))
            .collect()
    }

    /// Personalized PageRank by power iteration.
    fn exact(
        graph: &HashMap<[u8; 32], Vec<[u8; 32]>>,
        seeds: &[[u8; 32]],
    ) -> HashMap<[u8; 32], f64> {
        let teleport: HashMap<[u8; 32], f64> = seeds
            .iter()
            .map(|s| (*s, 1.0 / seeds.len() as f64))
            .collect();
        let mut rank = teleport.clone();
        for _ in 0..300 {
            let mut next: HashMap<[u8; 32], f64> = teleport
                .iter()
                .map(|(k, v)| (*k, (1.0 - DAMPING) * v))
                .collect();
            for (from, score) in &rank {
                let follows = graph.get(from).map_or(&[][..], Vec::as_slice);
                for to in follows {
                    *next.entry(*to).or_default() += DAMPING * score / follows.len() as f64;
                }
            }
            rank = next;
        }
        rank
    }

    /// Scores agree with exact ones, as closely as the residuals left say
    /// they must, and all trust is accounted for.
    fn assert_exact(store: &Store, people: &[[u8; 32]], seeds: &[[u8; 32]]) {
        check(store).unwrap();
        let want = exact(&graph(store, people), seeds);
        let (nodes, residual) = state(store);
        let tolerance = residual + 1e-9;
        for pk in want.keys().chain(nodes.keys()) {
            let got = nodes.get(pk).map_or(0, |n| n.score) as f64 / ONE as f64;
            let exact = want.get(pk).copied().unwrap_or(0.0);
            assert!(
                (got - exact).abs() <= tolerance,
                "{}: {got} vs {exact}, within {tolerance}",
                hex::encode(pk)
            );
        }
    }

    fn random_follows(rng: &mut StdRng, people: &[[u8; 32]]) -> Vec<[u8; 32]> {
        (0..rng.random_range(0..6))
            .map(|_| people[rng.random_range(0..people.len())])
            .collect()
    }

    #[test]
    fn matches_exact_pagerank() {
        let dir = tempfile::tempdir().unwrap();
        let people: Vec<[u8; 32]> = (0..60).map(pubkey).collect();
        let seeds = vec![people[0], people[1]];
        let store = open_at(dir.path(), Some(wot(seeds.clone(), 1000)));
        let mut rng = StdRng::seed_from_u64(3);
        for n in 0..60 {
            put(
                &store,
                &follow_list(n, 100, &random_follows(&mut rng, &people)),
            );
        }
        settle(&store);
        assert_exact(&store, &people, &seeds);
    }

    #[test]
    fn keeps_up_with_changing_follow_lists() {
        let dir = tempfile::tempdir().unwrap();
        let people: Vec<[u8; 32]> = (0..40).map(pubkey).collect();
        let seeds = vec![people[0], people[1], people[2]];
        // A small budget, so lists change while trust is still spreading.
        let store = open_at(dir.path(), Some(wot(seeds.clone(), 20)));
        let mut rng = StdRng::seed_from_u64(5);
        let mut lists: HashMap<u32, Vec<Event>> = HashMap::new();
        for step in 0..400u64 {
            let n = rng.random_range(0..40);
            match rng.random_range(0..10) {
                // Delete the current list by id: the one before comes back.
                0 => {
                    if let Some(event) = lists.get(&n).and_then(|l| l.last()) {
                        let tags = vec![vec!["e".to_string(), event.id.clone()]];
                        put(&store, &sign(secret(n), 1000 + step, 5, tags, ""));
                    }
                }
                // Vanish: every list gone.
                1 if step % 7 == 0 => {
                    put(&store, &sign(secret(n), 1000 + step, 62, vec![], ""));
                }
                _ => {
                    let event = follow_list(n, 1000 + step, &random_follows(&mut rng, &people));
                    put(&store, &event);
                    lists.entry(n).or_default().push(event);
                }
            }
            store.turn().unwrap();
            check(&store).unwrap();
        }
        settle(&store);
        assert_exact(&store, &people, &seeds);
    }

    #[test]
    fn moves_trust_to_new_seeds() {
        let dir = tempfile::tempdir().unwrap();
        let people: Vec<[u8; 32]> = (0..30).map(pubkey).collect();
        let first = vec![people[0]];
        let store = open_at(dir.path(), Some(wot(first.clone(), 1000)));
        let mut rng = StdRng::seed_from_u64(9);
        for n in 0..30 {
            put(
                &store,
                &follow_list(n, 100, &random_follows(&mut rng, &people)),
            );
        }
        settle(&store);
        assert_exact(&store, &people, &first);
        drop(store);

        let second = vec![people[3], people[4]];
        let store = open_at(dir.path(), Some(wot(second.clone(), 1000)));
        settle(&store);
        assert_exact(&store, &people, &second);
        drop(store);

        // Other damping: from scratch.
        let other = Wot::new(second.clone(), 0.5, 100, 0.0001, 1000).unwrap();
        let store = open_at(dir.path(), Some(other));
        assert_eq!(state(&store).0.len(), 2);
        drop(store);

        // Off: nothing kept, and everyone counts.
        let store = open_at(dir.path(), None);
        assert!(state(&store).0.is_empty());
        let txn = store.read().unwrap();
        assert_eq!(store.trust(&txn, &people[9]).unwrap(), 1.0);
    }

    #[test]
    fn limits_what_sybils_get() {
        let dir = tempfile::tempdir().unwrap();
        let seed = pubkey(0);
        let store = open_at(dir.path(), Some(wot(vec![seed], 100_000)));
        let real: Vec<[u8; 32]> = (1..=10).map(pubkey).collect();
        let bots: Vec<[u8; 32]> = (1000..1300).map(pubkey).collect();
        put(&store, &follow_list(0, 100, &real));
        // One careless real account follows a bot.
        put(&store, &follow_list(1, 100, &[real[1], real[2], bots[0]]));
        let mut rng = StdRng::seed_from_u64(1);
        for (i, n) in (1000..1300).enumerate() {
            let mut follows: Vec<[u8; 32]> = (0..5)
                .map(|_| bots[rng.random_range(0..bots.len())])
                .collect();
            follows.push(bots[(i + 1) % bots.len()]);
            put(&store, &follow_list(n, 100, &follows));
        }
        settle(&store);
        let (nodes, residual) = state(&store);
        let score = |pk: &[u8; 32]| nodes.get(pk).map_or(0, |n| n.score) as f64 / ONE as f64;
        // What flows in along the one follow, staying 1 / (1 - d) steps on
        // average, is all they can have.
        let inflow = DAMPING * score(&real[0]) / 3.0;
        let bots_total: f64 = bots.iter().map(score).sum();
        assert!(bots_total > 0.0);
        assert!(
            bots_total <= inflow / (1.0 - DAMPING) + residual,
            "{bots_total} vs {inflow}"
        );
    }

    #[test]
    fn ignores_the_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let seed = pubkey(0);
        let store = open_at(dir.path(), Some(wot(vec![seed], 1000)));
        put(&store, &follow_list(0, 100, &[pubkey(1), pubkey(2)]));
        settle(&store);
        let before = state(&store).0;
        // Strangers following each other and the trusted change nothing.
        for n in 100..400 {
            put(
                &store,
                &follow_list(n, 100, &[pubkey(n + 1), pubkey(1), seed]),
            );
        }
        assert!(!store.turn().unwrap());
        assert_eq!(state(&store).0, before);
    }

    /// How long pushing takes, and how long a turn holds the writer, with
    /// the default precision. Slow to set up, so run by hand:
    /// `cargo test --release pushing_speed -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn pushing_speed() {
        let dir = tempfile::tempdir().unwrap();
        let people: Vec<[u8; 32]> = (0..20_000).map(pubkey).collect();
        let wot = Wot::new(vec![people[0]], DAMPING, 100_000, 0.01, 20_000).unwrap();
        let store = open_at(dir.path(), Some(wot));
        let mut rng = StdRng::seed_from_u64(2);
        for n in 0..20_000 {
            let follows: Vec<[u8; 32]> = (0..rng.random_range(10..300))
                .map(|_| people[rng.random_range(0..people.len())])
                .collect();
            put(&store, &follow_list(n, 100, &follows));
        }
        let start = std::time::Instant::now();
        let (mut turns, mut longest) = (0, std::time::Duration::ZERO);
        loop {
            let turn = std::time::Instant::now();
            let more = store.turn().unwrap();
            turns += 1;
            longest = longest.max(turn.elapsed());
            if !more {
                break;
            }
        }
        let (nodes, residual) = state(&store);
        eprintln!(
            "{} authors in {:?}, {turns} turns, the longest {longest:?}, residual {residual}",
            nodes.len(),
            start.elapsed()
        );
        check(&store).unwrap();
    }

    #[test]
    fn weighs_by_score() {
        let dir = tempfile::tempdir().unwrap();
        let seed = pubkey(0);
        // Full trust is a fiftieth of all of it: those the seed follows
        // directly get more than that, and the next hop less.
        let wot = Wot::new(vec![seed], DAMPING, 50, 0.05, 1000).unwrap();
        let store = open_at(dir.path(), Some(wot));
        let near: Vec<[u8; 32]> = (1..=4).map(pubkey).collect();
        let far: Vec<[u8; 32]> = (10..30).map(pubkey).collect();
        put(&store, &follow_list(0, 100, &near));
        put(&store, &follow_list(1, 100, &far));
        settle(&store);
        let txn = store.read().unwrap();
        let weight = |pk: &[u8; 32]| store.trust(&txn, pk).unwrap();
        assert_eq!(weight(&seed), 1.0);
        assert_eq!(weight(&near[0]), 1.0);
        let w = weight(&far[0]);
        assert!((0.05..1.0).contains(&w), "{w}");
        assert_eq!(weight(&pubkey(999)), 0.0);
    }
}
