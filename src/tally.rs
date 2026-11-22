//! About how many times each of many keys has been seen, in fixed memory:
//! a count-min sketch. Each key is counted in a cell of each of a few rows,
//! picked by hashing it a different way in each; its tally is the least of
//! those cells. Other keys hashed to the same cells only add to them, so a
//! tally is never less than the times its key was counted, only sometimes
//! more: a key whose tally is short of a number was counted fewer times.
//!
//! The store's writer counts the `tags` keys it files events under, so as
//! to look a key's events up in the store, to see whether it has enough for
//! a HyperLogLog, only once its tally says it may.

use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU16, Ordering};

/// Rows, each hashed with a seed of its own.
const ROWS: usize = 4;

/// Cells a row, a power of two: 2 MB of them a row.
const CELLS: usize = 1 << 20;

pub struct Tally {
    cells: Box<[AtomicU16]>,
}

impl Default for Tally {
    fn default() -> Self {
        Tally {
            // SAFETY: zeroed is a valid AtomicU16, of 0. Allocated zeroed,
            // the cells cost no memory till counted in.
            cells: unsafe { Box::new_zeroed_slice(ROWS * CELLS).assume_init() },
        }
    }
}

impl Tally {
    fn cells(&self, key: &[u8]) -> impl Iterator<Item = &AtomicU16> {
        (0..ROWS).map(move |row| {
            let hash = foldhash::fast::FixedState::with_seed(row as u64).hash_one(key);
            &self.cells[row * CELLS + (hash as usize & (CELLS - 1))]
        })
    }

    /// Count `key` once more, returning its tally after. Counted by one
    /// thread at a time.
    pub fn add(&self, key: &[u8]) -> usize {
        self.cells(key)
            .map(|cell| {
                let n = cell.load(Ordering::Relaxed).saturating_add(1);
                cell.store(n, Ordering::Relaxed);
                usize::from(n)
            })
            .min()
            .unwrap_or_default()
    }

    /// `key`'s tally: at least the times it's been counted.
    pub fn get(&self, key: &[u8]) -> usize {
        self.cells(key)
            .map(|cell| usize::from(cell.load(Ordering::Relaxed)))
            .min()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tallies_at_least_what_was_counted() {
        let tally = Tally::default();
        let keys: Vec<Vec<u8>> = (0u32..200_000).map(|n| n.to_be_bytes().to_vec()).collect();
        for (n, key) in keys.iter().enumerate() {
            for _ in 0..n % 7 {
                tally.add(key);
            }
        }
        let mut over = 0;
        for (n, key) in keys.iter().enumerate() {
            let got = tally.get(key);
            assert!(got >= n % 7, "{n}: {got}");
            over += usize::from(got > n % 7);
        }
        // Rarely more, with so few keys for its cells.
        assert!(over < keys.len() / 100, "{over}");
        assert_eq!(tally.add(b"new"), tally.get(b"new"));
    }
}
