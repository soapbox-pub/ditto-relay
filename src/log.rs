//! The event log: every stored event's record, appended in sequence-number
//! order to segment files, and where each is, by sequence number.
//!
//! A record is framed as its length (u32 LE), a CRC-32 of its sequence
//! number and bytes (u32 LE), its sequence number (u64 LE), then the
//! record. A segment holds up to [`SEGMENT_SIZE`] bytes; it's mapped whole
//! and read through the map, and written with `pwrite`, a batch at a time.
//!
//! Where each record is goes in `locs`, eight bytes a sequence number: its
//! segment in the top 16 bits and its offset in the rest, 0 for none, as a
//! sequence number never stored, or removed. It's kept in memory, in chunks
//! read without a lock, and in a file, written after the segment.
//!
//! [`Log::sync`] makes what's appended durable. A crash can leave the last
//! records of either file without the other's: opening checks the newest
//! entries of `locs` against the records they point to, dropping those that
//! don't match, then reads on from the last good record for any `locs` is
//! missing, and the log goes on from the end of the last one intact.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use memmap2::{Mmap, MmapOptions};

/// The most bytes a segment holds.
pub const SEGMENT_SIZE: u64 = 1 << 30;

/// A record's frame: length, CRC, sequence number.
const FRAME: usize = 16;

/// Sequence numbers in a chunk of `locs` in memory.
const CHUNK: usize = 1 << 16;

const OFFSET_BITS: u32 = 48;

pub struct Log {
    dir: PathBuf,
    segment_size: u64,
    segments: ArcSwap<Vec<Arc<Segment>>>,
    locs: Locs,
    locs_file: File,
    tail: Mutex<Tail>,
}

struct Segment {
    file: File,
    map: Mmap,
}

/// Where the next record goes.
struct Tail {
    segment: u16,
    offset: u64,
    /// The next sequence number, one past the last appended.
    next: u64,
    /// The segments written to since the last sync.
    dirty: Vec<u16>,
}

/// `locs` in memory: chunks of atomics, swapped for a longer list as the
/// log grows past them.
struct Locs {
    chunks: ArcSwap<Vec<Arc<[AtomicU64]>>>,
}

impl Locs {
    fn new() -> Locs {
        Locs {
            chunks: ArcSwap::from_pointee(Vec::new()),
        }
    }

    fn get(&self, seq: u64) -> u64 {
        let (chunk, at) = (seq as usize / CHUNK, seq as usize % CHUNK);
        self.chunks
            .load()
            .get(chunk)
            .map_or(0, |chunk| chunk[at].load(Ordering::Acquire))
    }

    /// Only from the one thread that appends.
    fn set(&self, seq: u64, loc: u64) {
        let chunk = seq as usize / CHUNK;
        if self.chunks.load().len() <= chunk {
            let mut chunks = Vec::clone(&self.chunks.load());
            while chunks.len() <= chunk {
                chunks.push((0..CHUNK).map(|_| AtomicU64::new(0)).collect());
            }
            self.chunks.store(Arc::new(chunks));
        }
        self.chunks.load()[chunk][seq as usize % CHUNK].store(loc, Ordering::Release);
    }
}

fn loc(segment: u16, offset: u64) -> u64 {
    // Offset 0 of segment 0 is a record's too: 1 past it, so 0 is none.
    (u64::from(segment) << OFFSET_BITS) | (offset + 1)
}

fn unloc(loc: u64) -> (u16, u64) {
    (
        (loc >> OFFSET_BITS) as u16,
        (loc & ((1 << OFFSET_BITS) - 1)) - 1,
    )
}

fn segment_path(dir: &Path, segment: u16) -> PathBuf {
    dir.join(format!("{segment:05}.seg"))
}

fn checksum(seq: u64, record: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&seq.to_le_bytes());
    hasher.update(record);
    hasher.finalize()
}

impl Segment {
    fn open(dir: &Path, segment: u16, size: u64) -> io::Result<Segment> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(segment_path(dir, segment))?;
        // SAFETY: mapped only to read, and records are written once, past
        // what any reader is given, and never moved while it's mapped.
        let map = unsafe { MmapOptions::new().len(size as usize).map(&file)? };
        Ok(Segment { file, map })
    }

    /// The record framed at `offset`, if one intact is within the
    /// segment's first `len_limit` bytes: past the file's end, reading the
    /// map faults.
    fn record(&self, offset: u64, len_limit: u64) -> Option<(u64, &[u8])> {
        let at = offset as usize;
        if offset + FRAME as u64 > len_limit {
            return None;
        }
        let frame = self.map.get(at..at + FRAME)?;
        let len = u32::from_le_bytes(frame[..4].try_into().ok()?) as usize;
        let crc = u32::from_le_bytes(frame[4..8].try_into().ok()?);
        let seq = u64::from_le_bytes(frame[8..].try_into().ok()?);
        if (at + FRAME + len) as u64 > len_limit {
            return None;
        }
        let record = self.map.get(at + FRAME..at + FRAME + len)?;
        (len > 0 && checksum(seq, record) == crc).then_some((seq, record))
    }
}

impl Log {
    /// Open the log in `dir`, making it if there's none.
    pub fn open(dir: &Path) -> io::Result<Log> {
        Self::open_with(dir, SEGMENT_SIZE)
    }

    /// Open the log in `dir`, with segments of up to `segment_size` bytes.
    pub fn open_with(dir: &Path, segment_size: u64) -> io::Result<Log> {
        std::fs::create_dir_all(dir)?;
        let mut ids: Vec<u16> = std::fs::read_dir(dir)?
            .filter_map(|entry| {
                entry
                    .ok()?
                    .file_name()
                    .to_str()?
                    .strip_suffix(".seg")?
                    .parse()
                    .ok()
            })
            .collect();
        ids.sort_unstable();
        if ids.is_empty() {
            ids.push(0);
        }
        // Numbered from 0 with no gaps, as rolled over.
        if ids.iter().enumerate().any(|(i, &id)| usize::from(id) != i) {
            return Err(io::Error::other(format!(
                "{} has a segment missing",
                dir.display()
            )));
        }
        let segments: Vec<Arc<Segment>> = ids
            .iter()
            .map(|&id| Segment::open(dir, id, segment_size).map(Arc::new))
            .collect::<io::Result<_>>()?;
        let sizes: Vec<u64> = segments
            .iter()
            .map(|segment| Ok(segment.file.metadata()?.len()))
            .collect::<io::Result<_>>()?;

        let locs_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("locs"))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut &locs_file, &mut bytes)?;
        let locs = Locs::new();
        let mut highest = 0;
        for (seq, entry) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let entry = u64::from_le_bytes(*entry);
            if entry != 0 {
                locs.set(seq as u64, entry);
                highest = seq as u64;
            }
        }

        // The newest entries that point to intact records of theirs, back
        // from the end: the rest never reached the disk whole.
        let intact = |seq: u64, entry: u64| {
            let (segment, offset) = unloc(entry);
            segments
                .get(usize::from(segment))
                .and_then(|s| s.record(offset, sizes[usize::from(segment)]))
                .is_some_and(|(at, _)| at == seq)
        };
        let mut last = None;
        let mut seq = highest;
        while seq > 0 {
            let entry = locs.get(seq);
            if entry != 0 {
                if intact(seq, entry) {
                    last = Some((seq, entry));
                    break;
                }
                locs.set(seq, 0);
            }
            seq -= 1;
        }
        // On from there, for records `locs` is missing.
        let (mut segment, mut offset, mut next) = match last {
            Some((seq, entry)) => {
                let (segment, offset) = unloc(entry);
                let len = segments[usize::from(segment)]
                    .record(offset, sizes[usize::from(segment)])
                    .expect("intact")
                    .1
                    .len();
                (segment, offset + (FRAME + len) as u64, seq + 1)
            }
            None => (0, 0, 1),
        };
        loop {
            let at = usize::from(segment);
            match segments[at].record(offset, sizes[at]) {
                Some((seq, record)) if seq >= next => {
                    locs.set(seq, loc(segment, offset));
                    offset += (FRAME + record.len()) as u64;
                    next = seq + 1;
                }
                _ if at + 1 < segments.len() => {
                    segment += 1;
                    offset = 0;
                }
                _ => break,
            }
        }
        // Whatever's past it is garbage of a write cut short.
        let tail_segment = &segments[usize::from(segment)];
        tail_segment.file.set_len(offset)?;
        for later in &segments[usize::from(segment) + 1..] {
            later.file.set_len(0)?;
        }
        let log = Log {
            dir: dir.to_path_buf(),
            segment_size,
            segments: ArcSwap::from_pointee(segments),
            locs,
            locs_file,
            tail: Mutex::new(Tail {
                segment,
                offset,
                next,
                dirty: Vec::new(),
            }),
        };
        // Bring the file in line with what's in memory.
        let entries = log.locs.chunks.load().len() * CHUNK;
        let mut fixed = vec![0u8; entries * 8];
        for seq in 0..entries as u64 {
            let entry = log.locs.get(seq);
            fixed[seq as usize * 8..][..8].copy_from_slice(&entry.to_le_bytes());
        }
        log.locs_file.set_len(0)?;
        log.locs_file
            .write_all_at(&fixed[..(next as usize * 8).min(fixed.len())], 0)?;
        log.locs_file.sync_data()?;
        Ok(log)
    }

    /// The sequence number the next record appended must have, or later.
    pub fn next(&self) -> u64 {
        self.tail.lock().expect("unpoisoned").next
    }

    /// Append records, each with its sequence number, which must be past
    /// every one appended before, and rise. Durable once [synced](Self::sync).
    pub fn append<'a>(&self, records: impl IntoIterator<Item = (u64, &'a [u8])>) -> io::Result<()> {
        let mut tail = self.tail.lock().expect("unpoisoned");
        let mut buf = Vec::new();
        let mut start = tail.offset;
        let mut placed = Vec::new();
        for (seq, record) in records {
            if seq < tail.next || record.is_empty() {
                return Err(io::Error::other(format!(
                    "can't append {seq} after {}",
                    tail.next
                )));
            }
            let size = (FRAME + record.len()) as u64;
            if size > self.segment_size {
                return Err(io::Error::other("a record bigger than a segment"));
            }
            if tail.offset + size > self.segment_size {
                self.write(&mut tail, &buf, start)?;
                buf.clear();
                self.roll(&mut tail)?;
                start = 0;
            }
            buf.extend_from_slice(&(record.len() as u32).to_le_bytes());
            buf.extend_from_slice(&checksum(seq, record).to_le_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(record);
            placed.push((seq, loc(tail.segment, tail.offset)));
            tail.offset += size;
            tail.next = seq + 1;
        }
        self.write(&mut tail, &buf, start)?;
        // Readers find a record only once it's written.
        let Some(&(first, _)) = placed.first() else {
            return Ok(());
        };
        let mut entries = vec![0u8; (tail.next - first) as usize * 8];
        for &(seq, entry) in &placed {
            self.locs.set(seq, entry);
            entries[(seq - first) as usize * 8..][..8].copy_from_slice(&entry.to_le_bytes());
        }
        self.locs_file.write_all_at(&entries, first * 8)?;
        Ok(())
    }

    fn write(&self, tail: &mut Tail, buf: &[u8], at: u64) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.segments.load()[usize::from(tail.segment)]
            .file
            .write_all_at(buf, at)?;
        if !tail.dirty.contains(&tail.segment) {
            tail.dirty.push(tail.segment);
        }
        Ok(())
    }

    fn roll(&self, tail: &mut Tail) -> io::Result<()> {
        let segment = tail
            .segment
            .checked_add(1)
            .ok_or_else(|| io::Error::other("the log has run out of segments"))?;
        let mut segments = Vec::clone(&self.segments.load());
        segments.push(Arc::new(Segment::open(
            &self.dir,
            segment,
            self.segment_size,
        )?));
        self.segments.store(Arc::new(segments));
        tail.segment = segment;
        tail.offset = 0;
        Ok(())
    }

    /// Make everything appended durable.
    pub fn sync(&self) -> io::Result<()> {
        let dirty = std::mem::take(&mut self.tail.lock().expect("unpoisoned").dirty);
        let segments = self.segments.load();
        for segment in dirty {
            segments[usize::from(segment)].file.sync_data()?;
        }
        self.locs_file.sync_data()
    }

    /// Forget where a record is, so it reads as gone.
    pub fn remove(&self, seq: u64) -> io::Result<()> {
        let _tail = self.tail.lock().expect("unpoisoned");
        if self.locs.get(seq) != 0 {
            self.locs.set(seq, 0);
            self.locs_file.write_all_at(&0u64.to_le_bytes(), seq * 8)?;
        }
        Ok(())
    }

    /// The log's records as they are now, to read.
    pub fn view(&self) -> View<'_> {
        View {
            log: self,
            segments: self.segments.load_full(),
        }
    }
}

/// The log as of when it was taken: the records read through it live as
/// long as it does.
pub struct View<'l> {
    log: &'l Log,
    segments: Arc<Vec<Arc<Segment>>>,
}

impl View<'_> {
    /// The record of `seq`, if one's stored.
    pub fn get(&self, seq: u64) -> Option<&[u8]> {
        let entry = self.log.locs.get(seq);
        if entry == 0 {
            return None;
        }
        let (segment, offset) = unloc(entry);
        let map = &self.segments.get(usize::from(segment))?.map;
        let at = offset as usize;
        let len = u32::from_le_bytes(map.get(at..at + 4)?.try_into().ok()?) as usize;
        map.get(at + FRAME..at + FRAME + len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64) -> Vec<u8> {
        format!("record {seq} ")
            .repeat((seq % 7 + 1) as usize)
            .into_bytes()
    }

    #[test]
    fn reads_what_it_appends_and_again_when_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path()).unwrap();
        assert_eq!(log.next(), 1);
        let records: Vec<(u64, Vec<u8>)> =
            (1..=500).map(|seq| (seq * 2, record(seq * 2))).collect();
        for chunk in records.chunks(37) {
            log.append(chunk.iter().map(|(seq, r)| (*seq, r.as_slice())))
                .unwrap();
        }
        log.sync().unwrap();
        log.remove(20).unwrap();
        let check = |log: &Log| {
            let view = log.view();
            for (seq, r) in &records {
                match *seq {
                    20 => assert_eq!(view.get(20), None),
                    _ => assert_eq!(view.get(*seq), Some(r.as_slice()), "{seq}"),
                }
                assert_eq!(view.get(seq + 1), None);
            }
            assert_eq!(log.next(), 1001);
        };
        check(&log);
        drop(log);
        check(&Log::open(dir.path()).unwrap());
        // Appending only after.
        let log = Log::open(dir.path()).unwrap();
        assert!(log.append([(1000, &b"x"[..])]).is_err());
        log.append([(1001, &b"x"[..])]).unwrap();
        assert_eq!(log.view().get(1001), Some(&b"x"[..]));
    }

    #[test]
    fn recovers_from_writes_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path()).unwrap();
        for seq in 1..=100 {
            log.append([(seq, record(seq).as_slice())]).unwrap();
        }
        log.sync().unwrap();
        drop(log);
        let seg = segment_path(dir.path(), 0);
        let len = std::fs::metadata(&seg).unwrap().len();

        // locs lost its last entries: read back from the segment.
        let locs = dir.path().join("locs");
        let full = std::fs::read(&locs).unwrap();
        std::fs::write(&locs, &full[..50 * 8]).unwrap();
        let log = Log::open(dir.path()).unwrap();
        assert_eq!(log.next(), 101);
        assert_eq!(log.view().get(100), Some(record(100).as_slice()));
        drop(log);

        // The segment lost its last bytes: the torn record, and locs' entry
        // for it, are dropped, and the log goes on from the last intact.
        let file = OpenOptions::new().write(true).open(&seg).unwrap();
        file.set_len(len - 3).unwrap();
        let log = Log::open(dir.path()).unwrap();
        assert_eq!(log.next(), 100);
        assert_eq!(log.view().get(100), None);
        assert_eq!(log.view().get(99), Some(record(99).as_slice()));
        log.append([(100, &b"again"[..])]).unwrap();
        log.sync().unwrap();
        drop(log);

        // A last record written wrong is dropped too.
        let log = Log::open(dir.path()).unwrap();
        assert_eq!(log.view().get(100), Some(&b"again"[..]));
        let loc = unloc(log.locs.get(100));
        drop(log);
        let file = OpenOptions::new().write(true).open(&seg).unwrap();
        file.write_all_at(b"!", loc.1 + FRAME as u64 + 2).unwrap();
        let log = Log::open(dir.path()).unwrap();
        assert_eq!(log.next(), 100);
        assert_eq!(log.view().get(100), None);
        assert_eq!(log.view().get(99), Some(record(99).as_slice()));
    }

    #[test]
    fn rolls_over_to_new_segments() {
        // Records of a third of a segment each: three segments for seven.
        const SIZE: u64 = 1 << 20;
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open_with(dir.path(), SIZE).unwrap();
        let big = |seq: u64| vec![seq as u8; (SIZE / 3) as usize - FRAME];
        for seq in 1..=7 {
            log.append([(seq, big(seq).as_slice())]).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.segments.load().len(), 3);
        drop(log);
        let log = Log::open_with(dir.path(), SIZE).unwrap();
        assert_eq!(log.next(), 8);
        for seq in 1..=7 {
            assert_eq!(log.view().get(seq), Some(big(seq).as_slice()));
        }
    }
}
