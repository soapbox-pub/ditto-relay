//! The events queries returned lately, by sequence number: each one's
//! record, so that whether a query may return it again is decided without
//! looking it up in the store, and its JSON, so that it's sent without
//! being written out again. The newest events and busy inboxes are asked
//! for over and over.
//!
//! A sequence number names one record for good: records are only ever
//! appended, under numbers never given out before, or removed. So what's
//! kept is never stale, only kept after its event's gone, until it's
//! pushed out: nothing finds a removed event's number to ask for it.
//!
//! It holds up to so many bytes, split among shards by number, each
//! pushing out what it took in first.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{Arc, Mutex};

const SHARDS: usize = 16;

/// How many bytes of records and JSON are kept, all shards together.
pub const BYTES: usize = 128 << 20;

/// An event kept: its record and its JSON.
pub struct Kept {
    pub record: Box<[u8]>,
    pub json: Arc<String>,
}

impl Kept {
    fn size(&self) -> usize {
        self.record.len() + self.json.len()
    }
}

pub struct JsonCache {
    shards: Box<[Mutex<Shard>]>,
    /// Each shard's share of the bytes.
    budget: usize,
}

#[derive(Default)]
struct Shard {
    kept: HashMap<u64, Arc<Kept>, BuildHasherDefault<SeqHasher>>,
    /// In the order they were taken in.
    order: VecDeque<u64>,
    bytes: usize,
}

impl Default for JsonCache {
    fn default() -> Self {
        Self::new(BYTES)
    }
}

impl JsonCache {
    pub fn new(bytes: usize) -> Self {
        JsonCache {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            budget: bytes / SHARDS,
        }
    }

    fn shard(&self, seq: u64) -> &Mutex<Shard> {
        &self.shards[seq as usize % SHARDS]
    }

    /// The event numbered `seq`, if it's kept.
    pub fn get(&self, seq: u64) -> Option<Arc<Kept>> {
        self.shard(seq)
            .lock()
            .expect("unpoisoned")
            .kept
            .get(&seq)
            .cloned()
    }

    /// Keep the event numbered `seq`, whose record is `record` and JSON
    /// `json`, pushing out the oldest kept past the budget.
    pub fn keep(&self, seq: u64, record: &[u8], json: String) -> Arc<Kept> {
        let kept = Arc::new(Kept {
            record: record.into(),
            json: Arc::new(json),
        });
        if kept.size() > self.budget {
            return kept;
        }
        let mut shard = self.shard(seq).lock().expect("unpoisoned");
        if shard.kept.insert(seq, kept.clone()).is_none() {
            shard.order.push_back(seq);
            shard.bytes += kept.size();
        }
        while shard.bytes > self.budget
            && let Some(oldest) = shard.order.pop_front()
        {
            if let Some(gone) = shard.kept.remove(&oldest) {
                shard.bytes -= gone.size();
            }
        }
        kept
    }
}

/// Sequence numbers are counted out one by one, so spread over the table
/// by multiplying, rather than hashed.
#[derive(Default)]
struct SeqHasher(u64);

impl Hasher for SeqHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_to_its_budget() {
        let cache = JsonCache::new(SHARDS * 100);
        let keep = |seq: u64| cache.keep(seq, &[seq as u8; 10], format!("{seq:0>30}"));
        assert_eq!(&*keep(1).json, &format!("{:0>30}", 1));
        assert_eq!(&*cache.get(1).unwrap().record, &[1; 10]);
        // Two fit in a shard's 100 bytes; a third pushes out the first.
        keep(17);
        keep(33);
        assert!(cache.get(1).is_none());
        assert!(cache.get(17).is_some() && cache.get(33).is_some());
        assert!(cache.get(2).is_none());
        let shard = cache.shards[1].lock().unwrap();
        assert!(shard.bytes <= 100 && shard.kept.len() == shard.order.len());
    }
}
