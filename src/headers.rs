//! Each stored event's header (see [`crate::store::Tables`]): its id,
//! `created_at`, expiration and author, in a file of rows of
//! [`ROW`] bytes, the row of sequence number `n` at `n * ROW`, read
//! through a map. Reading many events' headers, as a sync or a sketch
//! does, is a read of memory each, where a table would be a search.
//!
//! A row of zeroes is none: the event's read from its record. The writer
//! writes an event's row before its transaction commits, and readers only
//! look up the rows of events the indexes have as of their transaction,
//! so a row written by a transaction that didn't commit, or left by a crash
//! past the last commit, is never read: its sequence number is stored
//! again, and its row written again. The file is synced before each
//! [checkpoint](crate::checkpoint) is saved, so that the rows of what it
//! keeps are on disk.
//!
//! Row 0, of no sequence number, holds an id the database's `meta` keeps
//! too, so that a file left beside another database, as one restored from
//! a backup, is known not to be its.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{MmapOptions, MmapRaw};

/// The bytes of a row.
pub const ROW: usize = 72;

/// The most bytes mapped: rows past it are read as none.
const MAPPED: u64 = 1 << 36;

/// How much the file grows by at a time.
const GROW: u64 = 1 << 26;

const MAGIC: &[u8; 8] = b"dittohdr";

pub struct Headers {
    file: File,
    map: MmapRaw,
    /// The file's length, past which nothing's read.
    len: AtomicU64,
    writable: bool,
    /// Held while the file grows.
    growing: Mutex<()>,
}

impl Headers {
    /// Open the file at `path`, of the database whose id is `id`, making
    /// it if `writable`: with whether it was there, and the database's.
    /// Only to read, `None` if it's not.
    pub fn open(path: &Path, id: u64, writable: bool) -> io::Result<Option<(Headers, bool)>> {
        let file = match OpenOptions::new()
            .read(true)
            .write(writable)
            .create(writable)
            .truncate(false)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if !writable && err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut head = [0u8; ROW];
        let len = file.metadata()?.len();
        let ours = len >= ROW as u64
            && std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).is_ok()
            && &head[..8] == MAGIC
            && head[8..16] == id.to_le_bytes();
        if !ours {
            if !writable {
                return Ok(None);
            }
            // Another database's, or none: begun again.
            file.set_len(0)?;
            head = [0; ROW];
            head[..8].copy_from_slice(MAGIC);
            head[8..16].copy_from_slice(&id.to_le_bytes());
            file.set_len(GROW)?;
            std::os::unix::fs::FileExt::write_all_at(&file, &head, 0)?;
            file.sync_all()?;
        }
        let options = {
            let mut options = MmapOptions::new();
            options.len(MAPPED as usize);
            options
        };
        let map = match writable {
            true => options.map_raw(&file)?,
            false => options.map_raw_read_only(&file)?,
        };
        let headers = Headers {
            len: AtomicU64::new(file.metadata()?.len()),
            file,
            map,
            writable,
            growing: Mutex::default(),
        };
        Ok(Some((headers, ours)))
    }

    fn offset(seq: u64) -> Option<u64> {
        let offset = seq.checked_mul(ROW as u64)?;
        (seq > 0 && offset + ROW as u64 <= MAPPED).then_some(offset)
    }

    /// The row of `seq`, if there's one.
    pub fn get(&self, seq: u64) -> Option<[u8; ROW]> {
        let offset = Self::offset(seq)?;
        if offset + ROW as u64 > self.len.load(Ordering::Acquire) {
            // Only to read, the relay may have grown it since.
            if self.writable {
                return None;
            }
            let len = self.file.metadata().ok()?.len();
            self.len.fetch_max(len, Ordering::AcqRel);
            if offset + ROW as u64 > len {
                return None;
            }
        }
        let mut row = [0u8; ROW];
        // SAFETY: within the file, and the map; a row being written is of
        // an event no reader looks up yet, so it's copied out, not borrowed.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.map.as_ptr().add(offset as usize),
                row.as_mut_ptr(),
                ROW,
            );
        }
        (row != [0; ROW]).then_some(row)
    }

    /// Ask for the row of `seq` to be read into the cache, to be read soon.
    pub fn prefetch(&self, seq: u64) {
        if let Some(offset) = Self::offset(seq)
            && offset + ROW as u64 <= self.len.load(Ordering::Relaxed)
        {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: a hint, of an address within the map.
            unsafe {
                use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                let at = self.map.as_ptr().add(offset as usize) as *const i8;
                _mm_prefetch::<_MM_HINT_T0>(at);
                _mm_prefetch::<_MM_HINT_T0>(at.add(ROW - 1));
            }
        }
    }

    /// Write the row of `seq`. Only by the store's writer.
    pub fn put(&self, seq: u64, row: &[u8; ROW]) -> io::Result<()> {
        let Some(offset) = Self::offset(seq) else {
            return Ok(());
        };
        if offset + ROW as u64 > self.len.load(Ordering::Acquire) {
            let _growing = self.growing.lock().expect("unpoisoned");
            let len = (offset + ROW as u64).next_multiple_of(GROW).min(MAPPED);
            if len > self.len.load(Ordering::Acquire) {
                self.file.set_len(len)?;
                self.len.store(len, Ordering::Release);
            }
        }
        // SAFETY: within the file, grown to hold it, and the map, writable.
        unsafe {
            std::ptr::copy_nonoverlapping(
                row.as_ptr(),
                self.map.as_mut_ptr().add(offset as usize),
                ROW,
            );
        }
        Ok(())
    }

    /// Clear the row of `seq`: its event's gone.
    pub fn clear(&self, seq: u64) {
        if let Some(offset) = Self::offset(seq)
            && offset + ROW as u64 <= self.len.load(Ordering::Acquire)
        {
            // SAFETY: as in `put`.
            unsafe {
                std::ptr::write_bytes(self.map.as_mut_ptr().add(offset as usize), 0, ROW);
            }
        }
    }

    /// Make what's written durable.
    pub fn sync(&self) -> io::Result<()> {
        if !self.writable {
            return Ok(());
        }
        let len = self.len.load(Ordering::Acquire) as usize;
        self.map.flush_range(0, len)?;
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(n: u8) -> [u8; ROW] {
        [n; ROW]
    }

    #[test]
    fn reads_what_it_writes_again_and_only_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers");
        assert!(Headers::open(&path, 7, false).unwrap().is_none());
        let (headers, ours) = Headers::open(&path, 7, true).unwrap().unwrap();
        assert!(!ours);
        let far = GROW / ROW as u64 * 3 + 5;
        for seq in [1, 2, 100, far] {
            headers.put(seq, &row(seq as u8 | 1)).unwrap();
        }
        headers.clear(2);
        let check = |headers: &Headers| {
            assert_eq!(headers.get(0), None);
            assert_eq!(headers.get(1), Some(row(1)));
            assert_eq!(headers.get(2), None);
            assert_eq!(headers.get(3), None);
            assert_eq!(headers.get(100), Some(row(101)));
            assert_eq!(headers.get(far), Some(row(far as u8 | 1)));
            assert_eq!(headers.get(far * 10), None);
        };
        check(&headers);
        headers.sync().unwrap();
        // A reader opened before grows with the file.
        let (reader, _) = Headers::open(&path, 7, false).unwrap().unwrap();
        check(&reader);
        headers.put(far * 2, &row(9)).unwrap();
        assert_eq!(reader.get(far * 2), Some(row(9)));
        drop((headers, reader));

        let (headers, ours) = Headers::open(&path, 7, true).unwrap().unwrap();
        assert!(ours);
        check(&headers);
        drop(headers);
        // Another database's: not read, and begun again by a writer.
        assert!(Headers::open(&path, 8, false).unwrap().is_none());
        let (headers, ours) = Headers::open(&path, 8, true).unwrap().unwrap();
        assert!(!ours);
        assert_eq!(headers.get(1), None);
    }
}
