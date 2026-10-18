//! Deletions asked for and not yet carried out: NIP-09 deletions, NIP-62
//! requests to vanish, and what `ditto-relay delete` asks for.
//!
//! What a deletion covers is hidden from the moment it's asked for, before
//! anything is removed: every event the store reads for a client is checked
//! against the pending deletions, in memory (see [`Store::load`]). Removing
//! what they cover from disk is left to [`crate::purge`], which takes as long
//! as it takes, between the writer's other work. Counts answered from the
//! indexes alone include what's hidden until then.
//!
//! A deletion covers only events stored before it was asked for: those
//! under a sequence number below its *watermark*, the store's next one then.
//! Events stored later aren't checked against it, so storing an event costs
//! nothing more for what's pending, and what a deletion covers never changes
//! while it's carried out. (NIP-09 and NIP-62 refuse what they name if it
//! arrives later, by the deletion or request kept.)
//!
//! What `ditto-relay delete` asks for is a filter, matched as a REQ's are,
//! search text and extensions too. One that picks rather than matches, with
//! a limit or `distinct:author`, is picked when it's asked for, and covers
//! the events picked.
//!
//! Each is kept in `pending`, under its id (u64 BE) and a byte: [`SPEC`],
//! what it covers, as JSON; [`PLAN`], the sequence numbers of what it
//! removes, once they've been found, as a Roaring bitmap; and [`PROGRESS`],
//! how far removing them has got. All are loaded into memory when the store
//! is opened, and removed once it's done.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use roaring::RoaringTreemap;
use serde::{Deserialize, Serialize};

use crate::filter::Filter;
use crate::lmdb::{Result, RwTxn, Txn};
use crate::record::{Element, EventView};
use crate::store::{GIFT_WRAP, IndexedTags, Store, address_of, may_delete};

/// The `pending` field of what a deletion covers.
pub const SPEC: u8 = 0;
/// The field of the sequence numbers it removes.
pub const PLAN: u8 = 1;
/// The field of how far removing them has got.
pub const PROGRESS: u8 = 2;

/// The `meta` key of the next deletion's id.
const NEXT_ID: &[u8] = b"next_pending";

/// What a pending deletion covers.
pub enum Target {
    /// What a filter matches, as `ditto-relay delete` asks: the filter, the
    /// JSON it was parsed from, and the `until` its `--age` made.
    Filter {
        filter: Box<Filter>,
        json: String,
        until: Option<u32>,
    },
    /// These events, picked by a filter when it was asked for.
    Seqs(Arc<RoaringTreemap>),
    /// What a NIP-09 deletion names.
    Deletion(Deletion),
    /// What a NIP-62 request to vanish covers: everything its author
    /// published up to `until`, and the gift wraps addressed to them.
    Vanish { author: [u8; 32], until: u32 },
}

/// What a NIP-09 deletion by `author`, made at `until`, names.
pub struct Deletion {
    pub author: [u8; 32],
    /// By id, those its author [may delete](may_delete). Sorted.
    pub ids: Vec<[u8; 32]>,
    /// Every version of these addresses of its author's, up to `until`.
    /// Sorted.
    pub addresses: Vec<Vec<u8>>,
    pub until: u32,
}

impl Deletion {
    /// What a stored NIP-09 deletion names.
    pub fn of(view: &EventView) -> Deletion {
        let author = *view.pubkey();
        let (mut ids, mut addresses) = (Vec::new(), Vec::new());
        for (name, value) in view.tag_values() {
            match (name, value) {
                ("e", Element::Hex(id)) => ids.push(*id),
                ("a", value) => {
                    addresses.extend(crate::store::parse_address(&value.to_text(), &author))
                }
                _ => {}
            }
        }
        ids.sort_unstable();
        ids.dedup();
        addresses.sort_unstable();
        addresses.dedup();
        Deletion {
            author,
            ids,
            addresses,
            until: view.created_at(),
        }
    }

    fn covers(&self, view: &EventView) -> bool {
        if self.ids.binary_search(view.id()).is_ok() && may_delete(&self.author, view) {
            return true;
        }
        !self.addresses.is_empty()
            && view.pubkey() == &self.author
            && view.created_at() <= self.until
            && address_of(view).is_some_and(|a| self.addresses.binary_search(&a).is_ok())
    }
}

/// A deletion asked for, not yet carried out.
pub struct Pending {
    pub id: u64,
    /// It covers only events under lower sequence numbers.
    pub watermark: u64,
    pub target: Target,
}

impl Pending {
    /// Whether it covers the event stored under `seq`.
    pub fn covers(&self, seq: u64, view: &EventView) -> bool {
        seq < self.watermark
            && match &self.target {
                Target::Filter { filter, .. } => filter.matches(view),
                Target::Seqs(seqs) => seqs.contains(seq),
                Target::Deletion(deletion) => deletion.covers(view),
                Target::Vanish { author, until } => {
                    view.created_at() <= *until
                        && (view.pubkey() == author || is_wrapped_for(view, author))
                }
            }
    }

    /// What it is, to say in the log.
    pub fn describe(&self) -> String {
        match &self.target {
            Target::Filter { json, .. } => format!("deletion {} of what {json} matches", self.id),
            Target::Seqs(seqs) => format!("deletion {} of {} events picked", self.id, seqs.len()),
            Target::Deletion(_) => format!("NIP-09 deletion {}", self.id),
            Target::Vanish { author, .. } => {
                format!("request to vanish {} by {}", self.id, hex::encode(author))
            }
        }
    }
}

/// Whether an event is a gift wrap addressed to `recipient`.
fn is_wrapped_for(view: &EventView, recipient: &[u8; 32]) -> bool {
    view.kind() == GIFT_WRAP
        && view
            .tag_values()
            .any(|(name, value)| name == "p" && value == Element::Hex(recipient))
}

/// The pending deletions, indexed so that checking an event against
/// thousands of NIP-09 deletions is a lookup or two: by the ids they name,
/// and by the authors whose addresses they name or who vanish. Filters and
/// picked events are checked one by one; there are seldom more than a few.
#[derive(Default)]
pub struct Hidden {
    all: Vec<Arc<Pending>>,
    by_id: HashMap<[u8; 32], Vec<usize>>,
    by_author: HashMap<[u8; 32], Vec<usize>>,
    others: Vec<usize>,
    /// Whether any is a request to vanish, so gift wraps' recipients are
    /// looked up too.
    vanishing: bool,
    /// The highest watermark: nothing under a higher sequence number is
    /// covered.
    below: u64,
}

impl Hidden {
    fn new(all: Vec<Arc<Pending>>) -> Hidden {
        let mut hidden = Hidden::default();
        for (i, pending) in all.iter().enumerate() {
            hidden.below = hidden.below.max(pending.watermark);
            match &pending.target {
                Target::Deletion(deletion) => {
                    for id in &deletion.ids {
                        hidden.by_id.entry(*id).or_default().push(i);
                    }
                    if !deletion.addresses.is_empty() {
                        hidden.by_author.entry(deletion.author).or_default().push(i);
                    }
                }
                Target::Vanish { author, .. } => {
                    hidden.by_author.entry(*author).or_default().push(i);
                    hidden.vanishing = true;
                }
                Target::Filter { .. } | Target::Seqs(_) => hidden.others.push(i),
            }
        }
        hidden.all = all;
        hidden
    }

    /// These and `pending` too.
    pub fn with(&self, pending: Arc<Pending>) -> Hidden {
        let mut all = self.all.clone();
        all.push(pending);
        Hidden::new(all)
    }

    /// These but the one with `id`.
    pub fn without(&self, id: u64) -> Hidden {
        Hidden::new(
            self.all
                .iter()
                .filter(|pending| pending.id != id)
                .cloned()
                .collect(),
        )
    }

    pub fn all(&self) -> &[Arc<Pending>] {
        &self.all
    }

    /// Whether anything under `seq` may be hidden, without reading it.
    pub fn may_hide(&self, seq: u64) -> bool {
        seq < self.below
    }

    /// Whether a pending deletion covers the event stored under `seq`.
    pub fn hides(&self, seq: u64, view: &EventView) -> bool {
        if !self.may_hide(seq) {
            return false;
        }
        let covers = |list: Option<&Vec<usize>>| {
            list.is_some_and(|list| list.iter().any(|&i| self.all[i].covers(seq, view)))
        };
        if covers(self.by_id.get(view.id())) || covers(self.by_author.get(view.pubkey())) {
            return true;
        }
        if self.vanishing && view.kind() == GIFT_WRAP {
            for (name, value) in view.tag_values() {
                if let ("p", Element::Hex(recipient)) = (name, value)
                    && covers(self.by_author.get(recipient))
                {
                    return true;
                }
            }
        }
        self.others.iter().any(|&i| self.all[i].covers(seq, view))
    }
}

/// What a pending deletion covers, as kept.
#[derive(Serialize, Deserialize)]
struct Spec {
    watermark: u64,
    #[serde(flatten)]
    target: SpecTarget,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SpecTarget {
    Filter {
        filter: String,
        until: Option<u32>,
    },
    /// Picked: the events are its plan.
    Seqs,
    Deletion {
        author: String,
        ids: Vec<String>,
        addresses: Vec<String>,
        until: u32,
    },
    Vanish {
        author: String,
        until: u32,
    },
}

/// How far removing what a deletion covers has got, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Progress {
    /// Removing them one at a time: done up to and including `after`.
    Each { after: Option<u64> },
    /// Sweeping: see [`crate::purge`]. The records undone up to `after`.
    Records { after: Option<u64> },
    /// The index table `table` swept up to this key and value, in hex.
    Table {
        table: usize,
        at: Option<(String, String)>,
    },
    /// The records forgotten up to `after`.
    Forget { after: Option<u64> },
}

/// A pending deletion as `ditto-relay deletions` lists it.
#[derive(Debug, Serialize)]
pub struct Listed {
    pub id: u64,
    /// `filter`, `picked`, `nip09` or `vanish`.
    pub kind: &'static str,
    /// What it covers, to say.
    pub covers: String,
    /// It covers only events stored under lower sequence numbers.
    pub watermark: u64,
    /// How many events it removes, once that's been found.
    pub events: Option<u64>,
    #[serde(flatten)]
    pub stage: Stage,
    /// How many of `events` the stage is done with.
    pub done: u64,
}

/// How far removing what a deletion covers has got.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "stage", rename_all = "lowercase")]
pub enum Stage {
    /// What it removes is still to be found.
    Finding,
    /// Found, and waiting its turn.
    Queued,
    /// Being removed one at a time.
    Removing,
    /// Being swept (see [`crate::purge`]): undoing what the events counted
    /// toward,
    Undoing,
    /// sweeping each index table in turn,
    Sweeping { table: &'static str },
    /// and removing their records.
    Forgetting,
    /// What it covers can't be read, as with a tag no longer indexed.
    Unreadable,
}

impl Listed {
    fn new(pending: &Pending, plan: Option<&RoaringTreemap>, progress: Option<Progress>) -> Listed {
        let (kind, covers) = match &pending.target {
            Target::Filter { json, until, .. } => (
                "filter",
                match until {
                    Some(until) => format!("what {json} matches, up to {until}"),
                    None => format!("what {json} matches"),
                },
            ),
            Target::Seqs(seqs) => ("picked", format!("{} events picked", seqs.len())),
            Target::Deletion(deletion) => (
                "nip09",
                format!(
                    "a NIP-09 deletion by {} of {} ids and {} addresses",
                    hex::encode(deletion.author),
                    deletion.ids.len(),
                    deletion.addresses.len()
                ),
            ),
            Target::Vanish { author, until } => (
                "vanish",
                format!(
                    "a request to vanish by {}, up to {until}",
                    hex::encode(author)
                ),
            ),
        };
        let rank = |after: Option<u64>| match (plan, after) {
            (Some(plan), Some(after)) => plan.rank(after),
            _ => 0,
        };
        let (stage, done) = match (plan, progress) {
            (None, _) => (Stage::Finding, 0),
            (Some(_), None) => (Stage::Queued, 0),
            (Some(_), Some(Progress::Each { after })) => (Stage::Removing, rank(after)),
            (Some(_), Some(Progress::Records { after })) => (Stage::Undoing, rank(after)),
            (Some(_), Some(Progress::Table { table, .. })) => (
                Stage::Sweeping {
                    table: crate::purge::swept_name(table),
                },
                0,
            ),
            (Some(_), Some(Progress::Forget { after })) => (Stage::Forgetting, rank(after)),
        };
        Listed {
            id: pending.id,
            kind,
            covers,
            watermark: pending.watermark,
            events: plan.map(RoaringTreemap::len),
            stage,
            done,
        }
    }

    /// How far it's got, to say.
    pub fn progress(&self) -> String {
        let events = self.events.unwrap_or(0);
        match &self.stage {
            Stage::Finding => "finding what it removes".into(),
            Stage::Queued => format!("{events} events to remove, waiting its turn"),
            Stage::Removing => format!("removed {} of {events} events", self.done),
            Stage::Undoing => format!(
                "sweeping {events} events: undoing what {} of them counted toward",
                self.done
            ),
            Stage::Sweeping { table } => {
                format!("sweeping {events} events: walking the {table} index")
            }
            Stage::Forgetting => format!(
                "sweeping {events} events: removed {} of their records",
                self.done
            ),
            Stage::Unreadable => "unreadable: the relay drops it when it starts".into(),
        }
    }
}

/// A filter as kept: as `ditto-relay delete` would take it, with `until`
/// from its `--age`, if it had one.
pub fn parse_filter(
    json: &str,
    until: Option<u32>,
    indexed: &IndexedTags,
) -> anyhow::Result<Filter> {
    let value: serde_json::Value = serde_json::from_str(json).context("the filter isn't JSON")?;
    let mut filter = Filter::parse(&value, indexed, usize::MAX).map_err(anyhow::Error::msg)?;
    if let Some(until) = until {
        filter.until = until;
        filter.never |= filter.since > filter.until;
    }
    Ok(filter)
}

fn key(id: u64, field: u8) -> [u8; 9] {
    let mut key = [0; 9];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key[8] = field;
    key
}

fn hex32(text: &str) -> anyhow::Result<[u8; 32]> {
    crate::event::decode_hex::<32>(text).context("not 32 bytes of hex")
}

impl Store {
    /// Ask, in `txn`, for what `target` covers below `watermark` to be
    /// deleted. It's hidden at once, before `txn` commits; if it doesn't,
    /// [`forget_uncommitted`](Self::forget_uncommitted) unhides it.
    pub fn queue_deletion(
        &self,
        txn: &mut RwTxn,
        watermark: u64,
        target: Target,
    ) -> Result<Arc<Pending>> {
        let t = self.tables;
        let id = txn
            .get(t.meta, NEXT_ID)?
            .map_or(1, |v| u64::from_be_bytes(v.try_into().unwrap_or_default()));
        txn.put(t.meta, NEXT_ID, &(id + 1).to_be_bytes())?;
        let spec = Spec {
            watermark,
            target: match &target {
                Target::Filter { json, until, .. } => SpecTarget::Filter {
                    filter: json.clone(),
                    until: *until,
                },
                Target::Seqs(_) => SpecTarget::Seqs,
                Target::Deletion(deletion) => SpecTarget::Deletion {
                    author: hex::encode(deletion.author),
                    ids: deletion.ids.iter().map(hex::encode).collect(),
                    addresses: deletion.addresses.iter().map(hex::encode).collect(),
                    until: deletion.until,
                },
                Target::Vanish { author, until } => SpecTarget::Vanish {
                    author: hex::encode(author),
                    until: *until,
                },
            },
        };
        let json = serde_json::to_vec(&spec).expect("a spec serializes");
        txn.put(t.pending, &key(id, SPEC), &json)?;
        if let Target::Seqs(seqs) = &target {
            self.put_plan(txn, id, seqs)?;
        }
        let pending = Arc::new(Pending {
            id,
            watermark,
            target,
        });
        self.hidden
            .rcu(|hidden| Arc::new(hidden.with(pending.clone())));
        self.uncommitted.lock().expect("unpoisoned").push(id);
        Ok(pending)
    }

    /// Unhide the deletions queued since the last write committed, as it
    /// didn't.
    pub fn forget_uncommitted(&self) {
        let ids = std::mem::take(&mut *self.uncommitted.lock().expect("unpoisoned"));
        for id in ids {
            self.unhide(id);
        }
    }

    /// The deletions queued since the last write committed did.
    pub fn committed_queued(&self) {
        self.uncommitted.lock().expect("unpoisoned").clear();
    }

    /// Stop hiding what the deletion `id` covered, once it's gone.
    pub fn unhide(&self, id: u64) {
        self.hidden.rcu(|hidden| Arc::new(hidden.without(id)));
    }

    /// The pending deletions, oldest first.
    pub fn pending(&self) -> Vec<Arc<Pending>> {
        self.hidden.load().all().to_vec()
    }

    /// Whether a pending deletion covers the event stored under `seq`.
    pub fn hides(&self, seq: u64, view: &EventView) -> bool {
        self.hidden.load().hides(seq, view)
    }

    /// Whether anything under `seq` may be hidden, without reading it.
    pub fn may_hide(&self, seq: u64) -> bool {
        self.hidden.load().may_hide(seq)
    }

    /// Load the pending deletions kept, to hide what they cover. One whose
    /// filter can no longer be parsed, as with a tag no longer indexed, is
    /// dropped, saying so.
    pub(crate) fn load_pending(&self) -> anyhow::Result<()> {
        let txn = self.read()?;
        let (all, unreadable) = self.read_pending(&txn)?;
        drop(txn);
        for (id, err) in &unreadable {
            tracing::error!("dropping pending deletion {id}, unreadable: {err:#}");
        }
        let unreadable: Vec<u64> = unreadable.into_iter().map(|(id, _)| id).collect();
        if !unreadable.is_empty() {
            let mut txn = self.write()?;
            for id in unreadable {
                self.drop_pending(&mut txn, id)?;
            }
            txn.commit()?;
        }
        if !all.is_empty() {
            tracing::info!("{} deletions pending, hiding what they cover", all.len());
        }
        self.hidden.store(Arc::new(Hidden::new(all)));
        Ok(())
    }

    /// Hide what the pending deletions kept cover, in a store opened [only
    /// to read](Store::open_read_only), as the relay hides it: the relay
    /// drops one that's unreadable, and here it's left out.
    pub fn hide_pending(&self) -> anyhow::Result<()> {
        let txn = self.read()?;
        let (all, _) = self.read_pending(&txn)?;
        self.hidden.store(Arc::new(Hidden::new(all)));
        Ok(())
    }

    /// The pending deletions kept, oldest first, and the ids of those that
    /// can't be read, with why.
    #[allow(clippy::type_complexity)]
    fn read_pending(
        &self,
        txn: &Txn,
    ) -> anyhow::Result<(Vec<Arc<Pending>>, Vec<(u64, anyhow::Error)>)> {
        let mut all = Vec::new();
        let mut unreadable = Vec::new();
        let mut cursor = txn.cursor(self.tables.pending)?;
        let mut entry = cursor.first()?;
        while let Some((key, value)) = entry {
            if key.len() == 9 && key[8] == SPEC {
                let id = u64::from_be_bytes(key[..8].try_into().expect("8 bytes"));
                match self.parse_spec(txn, id, value) {
                    Ok(pending) => all.push(Arc::new(pending)),
                    Err(err) => unreadable.push((id, err)),
                }
            }
            entry = cursor.next()?;
        }
        Ok((all, unreadable))
    }

    /// The pending deletions kept, oldest first, and how far each has got,
    /// for `ditto-relay deletions`.
    pub fn list_pending(&self) -> anyhow::Result<Vec<Listed>> {
        let txn = self.read()?;
        let (all, unreadable) = self.read_pending(&txn)?;
        let mut listed = Vec::new();
        for pending in all {
            let plan = self.plan_of(&txn, pending.id)?;
            let progress = self.progress_of(&txn, pending.id)?;
            listed.push(Listed::new(&pending, plan.as_ref(), progress));
        }
        for (id, err) in unreadable {
            listed.push(Listed {
                id,
                kind: "unreadable",
                covers: format!("{err:#}"),
                watermark: 0,
                events: None,
                stage: Stage::Unreadable,
                done: 0,
            });
        }
        listed.sort_by_key(|listed| listed.id);
        Ok(listed)
    }

    fn parse_spec(&self, txn: &Txn, id: u64, value: &[u8]) -> anyhow::Result<Pending> {
        let spec: Spec = serde_json::from_slice(value)?;
        let target = match spec.target {
            SpecTarget::Filter { filter, until } => Target::Filter {
                filter: Box::new(parse_filter(&filter, until, &self.indexed_tags)?),
                json: filter,
                until,
            },
            SpecTarget::Seqs => Target::Seqs(Arc::new(
                self.plan_of(txn, id)?
                    .context("the events picked are missing")?,
            )),
            SpecTarget::Deletion {
                author,
                ids,
                addresses,
                until,
            } => Target::Deletion(Deletion {
                author: hex32(&author)?,
                ids: ids
                    .iter()
                    .map(|id| hex32(id))
                    .collect::<anyhow::Result<_>>()?,
                addresses: addresses
                    .iter()
                    .map(hex::decode)
                    .collect::<std::result::Result<_, _>>()?,
                until,
            }),
            SpecTarget::Vanish { author, until } => Target::Vanish {
                author: hex32(&author)?,
                until,
            },
        };
        Ok(Pending {
            id,
            watermark: spec.watermark,
            target,
        })
    }

    /// The sequence numbers of what deletion `id` removes, if found yet.
    pub fn plan_of(&self, txn: &Txn, id: u64) -> anyhow::Result<Option<RoaringTreemap>> {
        match txn.get(self.tables.pending, &key(id, PLAN))? {
            Some(bytes) => Ok(Some(RoaringTreemap::deserialize_from(bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_plan(&self, txn: &mut RwTxn, id: u64, plan: &RoaringTreemap) -> Result<()> {
        let mut bytes = Vec::with_capacity(plan.serialized_size());
        plan.serialize_into(&mut bytes).expect("writing to memory");
        txn.put(self.tables.pending, &key(id, PLAN), &bytes)
            .map(drop)
    }

    pub fn progress_of(&self, txn: &Txn, id: u64) -> Result<Option<Progress>> {
        Ok(txn
            .get(self.tables.pending, &key(id, PROGRESS))?
            .and_then(|bytes| serde_json::from_slice(bytes).ok()))
    }

    pub fn put_progress(&self, txn: &mut RwTxn, id: u64, progress: &Progress) -> Result<()> {
        let json = serde_json::to_vec(progress).expect("progress serializes");
        txn.put(self.tables.pending, &key(id, PROGRESS), &json)
            .map(drop)
    }

    /// Forget deletion `id`, done.
    pub fn drop_pending(&self, txn: &mut RwTxn, id: u64) -> Result<()> {
        for field in [SPEC, PLAN, PROGRESS] {
            txn.del(self.tables.pending, &key(id, field), None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::record::encode;
    use crate::store::tests::{open, open_in, put, settle, test_tags};
    use serde_json::json;
    use tokio_util::sync::CancellationToken;

    /// Queue a deletion of what `filter` matches, as `ditto-relay delete`
    /// would, without carrying it out.
    fn queue(store: &Store, filter: serde_json::Value) -> Arc<Pending> {
        let json = filter.to_string();
        let parsed = crate::delete::filter(Some(&json), None, 0, &test_tags()).unwrap();
        let target = crate::delete::target(store, parsed, Some(&json), None).unwrap();
        let mut txn = store.write().unwrap();
        let watermark = store.next_seq(&txn).unwrap();
        let pending = store.queue_deletion(&mut txn, watermark, target).unwrap();
        txn.commit().unwrap();
        store.committed_queued();
        pending
    }

    /// Stored without carrying out any deletion it asks for.
    fn store_only(store: &Store, event: &crate::event::Event) {
        store.write_batch([encode(event).as_slice()], 0).unwrap();
    }

    /// The sequence numbers a query of `filter` finds, newest first.
    fn found(store: &Store, filter: serde_json::Value) -> Vec<u64> {
        let filter = Filter::parse(&filter, &test_tags(), 1000).unwrap();
        let txn = store.read().unwrap();
        crate::query::run_filter(store, &txn, &filter, 100, &CancellationToken::new())
            .unwrap()
            .into_iter()
            .map(|(seq, _)| seq)
            .collect()
    }

    #[test]
    fn hides_at_once_what_it_covers_of_what_was_stored() {
        let (dir, store) = open();
        for (seed, at, topic) in [(1, 100, "spam"), (2, 200, "fine"), (3, 300, "spam")] {
            put(&store, &signed(seed, at, 1, vec![vec!["t", topic]], "x"));
        }
        let pending = queue(&store, json!({"#t": ["spam"]}));
        assert_eq!(pending.watermark, 4);
        // Stored after, it's not covered.
        store_only(&store, &signed(4, 400, 1, vec![vec!["t", "spam"]], "x"));
        assert_eq!(found(&store, json!({"kinds": [1]})), [4, 2]);
        assert_eq!(found(&store, json!({"#t": ["spam"]})), [4]);
        let txn = store.read().unwrap();
        assert!(store.header(&txn, 1).unwrap().is_none());
        assert!(store.header(&txn, 2).unwrap().is_some());
        // Still there, to be removed.
        assert!(store.stored(&txn, 1).unwrap().is_some());
        drop(txn);

        // Still hidden once the store's opened again.
        drop(store);
        let store = open_in(dir.path());
        assert_eq!(found(&store, json!({"kinds": [1]})), [4, 2]);
        settle(&store);
        assert!(store.pending().is_empty());
        assert_eq!(found(&store, json!({"kinds": [1]})), [4, 2]);
        assert!(store.stored(&store.read().unwrap(), 1).unwrap().is_none());
    }

    /// Picked by its sort and limit, as of when it was asked for.
    #[test]
    fn hides_what_a_limit_picks() {
        let (_dir, store) = open();
        for at in [100, 200, 300] {
            put(&store, &signed(1, at, 1, vec![], "x"));
        }
        queue(&store, json!({"kinds": [1], "limit": 2}));
        store_only(&store, &signed(1, 400, 1, vec![], "x"));
        assert_eq!(found(&store, json!({"kinds": [1]})), [4, 1]);
    }

    /// Listed, with how far each has got, from a store opened only to
    /// read, as `ditto-relay deletions` does beside the relay; which hides
    /// what they cover once asked to.
    #[test]
    fn lists_what_is_pending() {
        let (dir, store) = open();
        for at in [100, 200, 300] {
            put(&store, &signed(1, at, 1, vec![vec!["t", "spam"]], "x"));
        }
        let filter = queue(&store, json!({"#t": ["spam"]}));
        let picked = queue(&store, json!({"kinds": [1], "limit": 2}));
        let read_only = || {
            Store::open_read_only(
                dir.path(),
                1 << 30,
                test_tags(),
                crate::store::History::new(true, vec![], 20),
                None,
                crate::rank::Rank::default(),
            )
            .unwrap()
        };
        let listed = read_only().list_pending().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(
            (
                listed[0].id,
                listed[0].kind,
                &listed[0].stage,
                listed[0].events
            ),
            (filter.id, "filter", &Stage::Finding, None)
        );
        assert_eq!(listed[0].covers, r##"what {"#t":["spam"]} matches"##);
        assert_eq!(
            (listed[1].kind, &listed[1].stage, listed[1].events),
            ("picked", &Stage::Queued, Some(2))
        );

        let mut txn = store.write().unwrap();
        let plan: RoaringTreemap = [1, 2, 3].into_iter().collect();
        store.put_plan(&mut txn, filter.id, &plan).unwrap();
        let after = Some(2);
        store
            .put_progress(&mut txn, filter.id, &Progress::Each { after })
            .unwrap();
        let table = Progress::Table { table: 5, at: None };
        store.put_progress(&mut txn, picked.id, &table).unwrap();
        txn.commit().unwrap();
        let listed = read_only().list_pending().unwrap();
        assert_eq!(listed[0].progress(), "removed 2 of 3 events");
        assert_eq!(
            listed[1].progress(),
            "sweeping 2 events: walking the tags index"
        );
        let json = serde_json::to_value(&listed[1]).unwrap();
        assert_eq!(
            (&json["stage"], &json["table"]),
            (&json!("sweeping"), &json!("tags"))
        );

        let read_only = read_only();
        let txn = read_only.read().unwrap();
        assert!(read_only.load(&txn, 1).unwrap().is_some());
        drop(txn);
        read_only.hide_pending().unwrap();
        let txn = read_only.read().unwrap();
        assert!(read_only.load(&txn, 1).unwrap().is_none());
    }

    /// Queued in a write that doesn't commit, nothing's hidden.
    #[test]
    fn unhides_what_wasnt_committed() {
        let (_dir, store) = open();
        put(&store, &signed(1, 100, 1, vec![], "x"));
        let parsed = crate::delete::filter(Some("{}"), None, 0, &test_tags()).unwrap();
        let target = crate::delete::target(&store, parsed, Some("{}"), None).unwrap();
        let mut txn = store.write().unwrap();
        store.queue_deletion(&mut txn, 2, target).unwrap();
        assert!(found(&store, json!({})).is_empty());
        drop(txn);
        store.forget_uncommitted();
        assert_eq!(found(&store, json!({})), [1]);
        assert!(store.pending().is_empty());
    }

    /// NIP-09 deletions and requests to vanish are looked up by id and
    /// author, however many are pending.
    #[test]
    fn looks_deletions_up_by_id_and_author() {
        let (_dir, store) = open();
        let notes: Vec<_> = (1..=20u8)
            .map(|seed| signed(seed, 100, 1, vec![], "note"))
            .collect();
        for note in &notes {
            put(&store, note);
        }
        for (seed, note) in (1..=10u8).zip(&notes) {
            store_only(&store, &signed(seed, 200, 5, vec![vec!["e", &note.id]], ""));
        }
        // Not their author's: refused.
        store_only(
            &store,
            &signed(1, 200, 5, vec![vec!["e", &notes[15].id]], ""),
        );
        store_only(&store, &signed(12, 200, 62, vec![], ""));
        let left: Vec<u64> = found(&store, json!({"kinds": [1]}));
        let mut want: Vec<u64> = (11..=20).filter(|&seq| seq != 12).collect();
        want.reverse();
        assert_eq!(left.len(), want.len());
        let mut left = left;
        left.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(left, want);
        assert_eq!(store.pending().len(), 12);
        settle(&store);
        assert!(store.pending().is_empty());
    }
}
