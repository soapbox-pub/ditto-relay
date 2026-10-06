//! A Bloom filter of the keys under which the store finds NIP-09 deletions
//! and NIP-62 requests to vanish, so that checking whether an event has been
//! deleted, which almost always finds it hasn't, needn't search LMDB to say
//! so. It never answers that a key has nothing when it has: LMDB is still
//! asked whenever the filter can't rule a key out.
//!
//! It's a fixed size, whatever the number of keys: past what it's sized for,
//! it rules out fewer keys, and more checks fall through to LMDB. Nor can it
//! forget, so a deletion that's gone leaves its bits behind; that costs a
//! lookup now and then, never a wrong answer.
//!
//! It's kept in a file beside the database, with the sequence number it's
//! complete below, so that a restart only reads the deletions stored since.
//!
//! ```text
//! magic   [u8; 8]
//! bits    u64 LE
//! hashes  u64 LE
//! covered u64 LE   every deletion stored under a lower seq is in it
//! keys    u64 LE   how many keys have been added, for metrics
//! words   u64 LE each, bits / 64 of them
//! ```

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DRRDEL01";
const HEADER: usize = 40;

/// Bits set per key. With ten bits a key, about 1% of the keys not in the
/// filter aren't ruled out.
const HASHES: u64 = 7;

/// Words written to the file at once; runs of zero words are left as holes.
const CHUNK: usize = 8192;

pub struct Filter {
    bits: Box<[AtomicU64]>,
    keys: AtomicU64,
    /// Whether every deletion stored so far is in it. Until then it rules
    /// nothing out.
    ready: AtomicBool,
    /// One save at a time.
    saving: Mutex<()>,
}

impl Filter {
    /// An empty filter of `bits` bits, a power of two. Its memory is only
    /// taken up as keys land on it.
    pub fn new(bits: u64) -> Filter {
        assert!(bits.is_power_of_two() && bits >= 64);
        const { assert!(align_of::<u64>() == align_of::<AtomicU64>()) };
        // Zeroed memory from the allocator is untouched pages, unlike
        // building the atomics one by one.
        let words = vec![0u64; (bits / 64) as usize].into_boxed_slice();
        // SAFETY: AtomicU64 has the same size, alignment (asserted above),
        // and representation as u64.
        let bits = unsafe { Box::from_raw(Box::into_raw(words) as *mut [AtomicU64]) };
        Filter {
            bits,
            keys: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            saving: Mutex::new(()),
        }
    }

    fn len(&self) -> u64 {
        self.bits.len() as u64 * 64
    }

    fn positions(&self, key: &[u8]) -> impl Iterator<Item = usize> {
        let hash = Sha256::digest(key);
        let a = u64::from_le_bytes(hash[..8].try_into().unwrap());
        let b = u64::from_le_bytes(hash[8..16].try_into().unwrap()) | 1;
        let mask = self.len() - 1;
        (0..HASHES).map(move |i| (a.wrapping_add(i.wrapping_mul(b)) & mask) as usize)
    }

    pub fn add(&self, key: &[u8]) {
        for bit in self.positions(key) {
            self.bits[bit / 64].fetch_or(1 << (bit % 64), Ordering::Relaxed);
        }
        self.keys.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether a key certainly has nothing under it.
    pub fn rules_out(&self, key: &[u8]) -> bool {
        self.ready.load(Ordering::Acquire)
            && self
                .positions(key)
                .any(|bit| self.bits[bit / 64].load(Ordering::Relaxed) & (1 << (bit % 64)) == 0)
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Say every deletion stored so far has been added.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub fn keys(&self) -> u64 {
        self.keys.load(Ordering::Relaxed)
    }

    /// Fill it from a file saved by [`save`](Self::save), returning the
    /// sequence number it's complete below, or None if there's no file, or
    /// it's of a filter shaped differently.
    pub fn load(&self, path: &Path) -> std::io::Result<Option<u64>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut header = [0; HEADER];
        file.read_exact(&mut header)?;
        let field =
            |n: usize| u64::from_le_bytes(header[8 + n * 8..16 + n * 8].try_into().unwrap());
        if &header[..8] != MAGIC || field(0) != self.len() || field(1) != HASHES {
            return Ok(None);
        }
        let mut buf = vec![0; CHUNK * 8];
        for chunk in self.bits.chunks(CHUNK) {
            let bytes = &mut buf[..chunk.len() * 8];
            file.read_exact(bytes)?;
            for (word, bytes) in chunk.iter().zip(bytes.as_chunks::<8>().0) {
                let value = u64::from_le_bytes(*bytes);
                // Zero words are left untouched, and so is their memory.
                if value != 0 {
                    word.fetch_or(value, Ordering::Relaxed);
                }
            }
        }
        self.keys.store(field(3), Ordering::Relaxed);
        Ok(Some(field(2)))
    }

    /// Save it, as complete below `covered`, replacing the file at `path`
    /// once it's all written. Keys may be added meanwhile: any that make it
    /// in only rule out less.
    pub fn save(&self, path: &Path, covered: u64) -> std::io::Result<()> {
        let _saving = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = path.with_extension("tmp");
        let mut file = File::create(&tmp)?;
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(MAGIC);
        for field in [self.len(), HASHES, covered, self.keys()] {
            header.extend_from_slice(&field.to_le_bytes());
        }
        file.write_all(&header)?;
        file.set_len(HEADER as u64 + self.len() / 8)?;
        let mut buf = Vec::with_capacity(CHUNK * 8);
        for (n, chunk) in self.bits.chunks(CHUNK).enumerate() {
            buf.clear();
            for word in chunk {
                buf.extend_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
            }
            if buf.iter().any(|&b| b != 0) {
                file.write_all_at(&buf, (HEADER + n * CHUNK * 8) as u64)?;
            }
        }
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_out_only_what_it_lacks_once_ready() {
        let filter = Filter::new(1 << 16);
        filter.add(b"deleted");
        assert!(!filter.rules_out(b"anything"));
        filter.set_ready();
        assert!(!filter.rules_out(b"deleted"));
        let ruled_out = (0..1000u32)
            .filter(|n| filter.rules_out(&n.to_be_bytes()))
            .count();
        assert!(ruled_out > 990, "{ruled_out}");
    }

    #[test]
    fn saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deletions.bloom");
        let filter = Filter::new(1 << 20);
        assert_eq!(filter.load(&path).unwrap(), None);
        for n in 0..100u32 {
            filter.add(&n.to_be_bytes());
        }
        filter.save(&path, 42).unwrap();

        let loaded = Filter::new(1 << 20);
        assert_eq!(loaded.load(&path).unwrap(), Some(42));
        assert_eq!(loaded.keys(), 100);
        loaded.set_ready();
        assert!((0..100u32).all(|n| !loaded.rules_out(&n.to_be_bytes())));
        assert!(loaded.rules_out(b"never added"));

        // Not into a filter of another size.
        assert_eq!(Filter::new(1 << 21).load(&path).unwrap(), None);
    }
}
