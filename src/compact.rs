//! `ditto-relay compact`: a copy of the main environment holding only what's
//! live, packed in order.
//!
//! LMDB never shrinks its file, and reuses what's freed only page by page,
//! wherever it is. After a big delete the main environment's live pages are
//! scattered thinly through a file many times their size, so far fewer of
//! them stay in memory, and every walk of an index reads the disk at random.
//! A copy written table by table, each in key order, holds them together.
//!
//! `mdb_copy -c` does that, but reads one page at a time, waiting on the
//! disk for each, as the pages of a scattered file are out of order. Here
//! each table is first split into many key ranges, and threads walk the
//! ranges ahead of the one that copies, only to bring their pages into
//! memory, so that the disk has many reads to do at once. The copy itself
//! is a single cursor per table, appended to the new file in order: what the
//! threads do changes how fast it goes, never what it writes. A key with
//! too many values to read one page at a time, as the author of millions of
//! events has, is split into pieces of its values for the threads to read.
//!
//! Only the main environment is copied: `bodies` is written in order, its
//! freed pages filled by the records that come after them, so it stays
//! packed.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};

use crate::lmdb::{Cursor, Db, DbFlags, Env, Txn};

/// The most ranges a table is split into.
const MAX_RANGES: usize = 1 << 16;

/// How many values a key has at least for its values to be read ahead in
/// [pieces](Piece).
const BIG_KEY: usize = if cfg!(test) { 500 } else { 1 << 16 };

/// How many pieces a big key's values are read ahead in, at most.
const PIECES: usize = 256;

/// How many ranges ahead of the copy each thread may read.
const AHEAD_PER_THREAD: usize = 4;

/// About how much is copied in one write transaction.
const COMMIT_BYTES: u64 = 64 << 20;

/// The main environment's data file, in a database's directory.
const DATA_FILE: &str = "data.mdb";

/// Where [`in_place`] keeps the database's file it replaced.
pub const OLD_FILE: &str = "data.mdb.old";

/// Where [`in_place`] writes its copy, in the database's directory.
const COPY_DIR: &str = "compact";

/// How a copy's going.
pub struct Progress<'a> {
    /// The table being copied.
    pub table: &'a str,
    /// Entries copied, of them all, counting each duplicate.
    pub entries: u64,
    pub total: u64,
    /// Bytes of keys and values copied.
    pub bytes: u64,
    pub elapsed: Duration,
}

/// What a copy did.
pub struct Copied {
    /// Every table copied, and how many entries it has.
    pub tables: Vec<(String, u64)>,
    /// The size of the environment copied, and of its copy.
    pub before: u64,
    pub after: u64,
    /// How long splitting the tables into ranges took.
    pub split: Duration,
    pub elapsed: Duration,
}

/// A run of one table's keys: from `start`, to before `end` or to the last.
struct Range {
    table: usize,
    start: Vec<u8>,
    end: Option<Vec<u8>>,
}

/// Some of a big key's values, to be read ahead: from `start`, to `end` or
/// to the last.
struct Piece {
    table: usize,
    key: Vec<u8>,
    start: Vec<u8>,
    end: Option<Vec<u8>>,
}

/// One table of the environment copied from.
struct Table {
    name: String,
    db: Db,
    flags: DbFlags,
}

/// What a walk of a range comes across.
enum Item<'t> {
    Entry(&'t [u8], &'t [u8]),
    /// In a `DUP_FIXED` table, a page of a key's values, packed, each
    /// `size` bytes; `first` if it's the key's first.
    Dups {
        key: &'t [u8],
        values: &'t [u8],
        size: usize,
        first: bool,
    },
}

/// Copy the main environment in the directory `from`, which nothing may
/// write meanwhile, into the directory `into`, which mustn't hold one, as
/// [compacted](self), reading ahead on `threads` threads. The copy is on
/// disk when this returns.
pub fn copy(
    from: &Path,
    into: &Path,
    map_size: usize,
    threads: usize,
    progress: &mut dyn FnMut(&Progress),
) -> anyhow::Result<Copied> {
    let start = Instant::now();
    ensure!(
        from.join(DATA_FILE).exists(),
        "there's no database at {}",
        from.display()
    );
    ensure!(
        !into.join(DATA_FILE).exists(),
        "{} holds a database already",
        into.display()
    );
    let source = Env::open_read_only(from, map_size, 64, 1024)
        .with_context(|| format!("Could not open the database at {}", from.display()))?;
    let tables: Vec<Table> = source
        .tables()?
        .into_iter()
        .map(|(name, db, flags)| Table { name, db, flags })
        .collect();
    std::fs::create_dir_all(into)
        .with_context(|| format!("Could not create {}", into.display()))?;
    let dest = Env::open(into, map_size, 64, 16)
        .with_context(|| format!("Could not create a database at {}", into.display()))?;
    let dests = tables
        .iter()
        .map(|table| dest.create_db(&table.name, table.flags))
        .collect::<Result<Vec<_>, _>>()?;

    let mut ranges = Vec::new();
    for (n, table) in tables.iter().enumerate() {
        let bounds = split(&source, table, threads.max(1))?;
        let ends = bounds.iter().skip(1).map(|end| Some(end.clone()));
        // The last bound is the table's last key, in the last range.
        let ends: Vec<_> = ends
            .take(bounds.len().saturating_sub(2))
            .chain([None])
            .collect();
        for (start, end) in bounds.into_iter().zip(ends) {
            ranges.push(Range {
                table: n,
                start,
                end,
            });
        }
    }
    let split = start.elapsed();

    let reading = source.read_txn()?;
    let total: u64 = tables
        .iter()
        .map(|table| reading.len(table.db).map(|n| n as u64))
        .sum::<Result<u64, _>>()?;
    // The range the copy is in, and the next a thread is to read.
    let copying = AtomicUsize::new(0);
    let next = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let pieces = Mutex::new(VecDeque::new());
    let reader = Reader {
        env: &source,
        tables: &tables,
        ranges: &ranges,
        copying: &copying,
        next: &next,
        ahead: threads * AHEAD_PER_THREAD,
        pieces: &pieces,
        done: &done,
    };
    std::thread::scope(|scope| -> anyhow::Result<()> {
        for _ in 0..threads {
            scope.spawn(|| reader.run());
        }
        let copied = (|| -> anyhow::Result<()> {
            let (mut entries, mut bytes, mut uncommitted) = (0u64, 0u64, 0u64);
            let mut said = Instant::now();
            let mut txn = dest.write_txn()?;
            for (n, range) in ranges.iter().enumerate() {
                copying.store(n, Ordering::Relaxed);
                let table = &tables[range.table];
                let mut appender = txn.appender(dests[range.table])?;
                walk(&reading, table, range, None, |item| {
                    match item {
                        Item::Entry(key, value) => {
                            appender.append(key, value)?;
                            entries += 1;
                            uncommitted += (key.len() + value.len()) as u64;
                        }
                        Item::Dups {
                            key,
                            values,
                            size,
                            first,
                        } => {
                            appender.append_dups(key, values, size, first)?;
                            entries += (values.len() / size) as u64;
                            uncommitted += values.len() as u64;
                        }
                    }
                    // From within a range, as one key can take minutes.
                    if said.elapsed() >= Duration::from_secs(1) {
                        progress(&Progress {
                            table: &table.name,
                            entries,
                            total,
                            bytes: bytes + uncommitted,
                            elapsed: start.elapsed(),
                        });
                        said = Instant::now();
                    }
                    Ok(())
                })
                .with_context(|| format!("Could not copy the table {}", table.name))?;
                drop(appender);
                if uncommitted >= COMMIT_BYTES {
                    txn.commit()?;
                    txn = dest.write_txn()?;
                    bytes += std::mem::take(&mut uncommitted);
                }
            }
            txn.commit()?;
            Ok(())
        })();
        done.store(true, Ordering::Relaxed);
        copied
    })?;

    // Read from what's been written, not what was meant to be.
    let check = dest.read_txn()?;
    let mut counts = Vec::new();
    for (table, &db) in tables.iter().zip(&dests) {
        let (want, got) = (reading.len(table.db)?, check.len(db)?);
        ensure!(
            want == got,
            "the copy of the table {} has {got} entries, not {want}",
            table.name
        );
        counts.push((table.name.clone(), got as u64));
    }
    drop(check);
    dest.sync()?;
    let (before, after) = (source.usage(0)?.used, dest.usage(0)?.used);
    Ok(Copied {
        tables: counts,
        before,
        after,
        split,
        elapsed: start.elapsed(),
    })
}

/// Compact the database in the directory `dir`, whose main environment
/// nothing may use meanwhile, and which must be on disk as it is: see
/// [`copy`]. The file replaced is kept, as [`OLD_FILE`], for whoever runs
/// it to remove once the copy's known good; there mustn't be one already.
/// The database's checkpoint, of the file replaced, is removed, so a crash
/// of the machine before the relay makes its own leaves the copy alone.
pub fn in_place(
    dir: &Path,
    map_size: usize,
    threads: usize,
    progress: &mut dyn FnMut(&Progress),
) -> anyhow::Result<Copied> {
    let old = dir.join(OLD_FILE);
    if old.exists() {
        bail!(
            "{} is there, left by an earlier compact: remove it once the database is known good",
            old.display()
        );
    }
    let into = dir.join(COPY_DIR);
    // Left by a compact that didn't finish, and of no use.
    match std::fs::remove_dir_all(&into) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return Err(err).with_context(|| format!("Could not remove {}", into.display()));
        }
        _ => {}
    }
    let copied = copy(dir, &into, map_size, threads, progress)?;
    let swap = || -> std::io::Result<()> {
        std::fs::rename(dir.join(DATA_FILE), &old)?;
        std::fs::rename(into.join(DATA_FILE), dir.join(DATA_FILE))?;
        std::fs::File::open(dir)?.sync_all()?;
        for gone in [dir.join(crate::checkpoint::FILE), dir.join("lock.mdb")] {
            match std::fs::remove_file(gone) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
                _ => {}
            }
        }
        std::fs::remove_dir_all(&into)?;
        std::fs::File::open(dir)?.sync_all()
    };
    swap().with_context(|| format!("Could not put the copy in place in {}", dir.display()))?;
    Ok(copied)
}

/// Split `table` into ranges of keys, returning where each begins, then
/// its last key: none if it's empty. Each split is a key about midway
/// between two others, so the ranges follow how the keys are spread.
fn split(env: &Env, table: &Table, threads: usize) -> anyhow::Result<Vec<Vec<u8>>> {
    let txn = env.read_txn()?;
    let mut cursor = txn.cursor(table.db)?;
    let Some((first, _)) = cursor.first()? else {
        return Ok(Vec::new());
    };
    let first = first.to_vec();
    let last = cursor.last()?.expect("a last key, as there's a first").0;
    if first == last {
        return Ok(vec![first]);
    }
    let last = last.to_vec();
    drop(cursor);
    // Each bound, and whether there may be keys between it and the next.
    let mut bounds = vec![(first, true), (last, false)];
    while bounds.len() < MAX_RANGES {
        let pairs: Vec<(usize, &[u8], &[u8])> = bounds
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| pair[0].1)
            .map(|(n, pair)| (n, &pair[0].0[..], &pair[1].0[..]))
            .collect();
        if pairs.is_empty() {
            break;
        }
        let chunk = pairs.len().div_ceil(threads);
        let found = std::thread::scope(|scope| {
            let workers: Vec<_> = pairs
                .chunks(chunk)
                .map(|pairs| {
                    scope.spawn(move || -> anyhow::Result<Vec<(usize, Option<Vec<u8>>)>> {
                        let txn = env.read_txn()?;
                        let mut cursor = txn.cursor(table.db)?;
                        let mut found = Vec::new();
                        for &(n, a, b) in pairs {
                            let key = between(&txn, &mut cursor, table, a, b)?;
                            found.push((n, key));
                        }
                        Ok(found)
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("splitting doesn't panic"))
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        let mut found = found.into_iter().flatten().peekable();
        let mut split = Vec::with_capacity(bounds.len() * 2);
        for (n, (bound, open)) in bounds.into_iter().enumerate() {
            match found.next_if(|(at, _)| *at == n) {
                Some((_, Some(key))) => {
                    split.push((bound, true));
                    split.push((key, true));
                }
                Some((_, None)) => split.push((bound, false)),
                None => split.push((bound, open)),
            }
        }
        bounds = split;
    }
    Ok(bounds.into_iter().map(|(bound, _)| bound).collect())
}

/// A key of `table` after `a` and before `b`, about midway, if there's one.
fn between<'t>(
    txn: &'t Txn,
    cursor: &mut crate::lmdb::Cursor<'t>,
    table: &Table,
    a: &[u8],
    b: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    let inside =
        |key: &[u8]| txn.cmp(table.db, key, a).is_gt() && txn.cmp(table.db, key, b).is_lt();
    let middle = midpoint(a, b, table.flags.integer_key);
    if let Some((key, _)) = cursor.set_range(&middle)?
        && inside(key)
    {
        return Ok(Some(key.to_vec()));
    }
    // None from the middle on: the last before it, as keys may be bunched
    // in a corner of the space between, as digits are in a byte's.
    let before = match cursor.set_range(b)? {
        Some(_) => cursor.prev()?,
        None => cursor.last()?,
    };
    Ok(before
        .map(|(key, _)| key)
        .filter(|key| inside(key))
        .map(<[u8]>::to_vec))
}

/// A key at least `a` and at most `b`, about halfway between: as numbers,
/// for integer keys of the same size, else as byte strings, in the order
/// LMDB compares them.
fn midpoint(a: &[u8], b: &[u8], integer: bool) -> Vec<u8> {
    if integer && a.len() == b.len() {
        match a.len() {
            8 => {
                let a = u64::from_ne_bytes(a.try_into().expect("8 bytes"));
                let b = u64::from_ne_bytes(b.try_into().expect("8 bytes"));
                return (a / 2 + b / 2 + (a % 2 + b % 2) / 2).to_ne_bytes().to_vec();
            }
            4 => {
                let a = u32::from_ne_bytes(a.try_into().expect("4 bytes"));
                let b = u32::from_ne_bytes(b.try_into().expect("4 bytes"));
                return (a / 2 + b / 2 + (a % 2 + b % 2) / 2).to_ne_bytes().to_vec();
            }
            _ => {}
        }
    }
    // Both as fractions, a byte a digit, one digit longer than the longer.
    let len = a.len().max(b.len()) + 1;
    let digit = |key: &[u8], n: usize| u16::from(key.get(n).copied().unwrap_or(0));
    let mut sum = vec![0u16; len];
    let mut carry = 0;
    for n in (0..len).rev() {
        let total = digit(a, n) + digit(b, n) + carry;
        sum[n] = total & 0xff;
        carry = total >> 8;
    }
    let mut half = Vec::with_capacity(len);
    let mut rest = carry;
    for digit in sum {
        let total = (rest << 8) | digit;
        half.push((total >> 1) as u8);
        rest = total & 1;
    }
    half
}

/// Told of a big key, its first value and its last, by [`walk`].
type BigKey<'a> = &'a mut dyn FnMut(&[u8], &[u8], &[u8]);

/// Walk `range` of `table`, in order, handing `visit` what's there. With
/// `big`, a key with [`BIG_KEY`] values or more is handed to it instead,
/// with its first and last values, and its values aren't walked.
fn walk<'t>(
    txn: &'t Txn,
    table: &Table,
    range: &Range,
    mut big: Option<BigKey>,
    mut visit: impl FnMut(Item<'t>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut cursor = txn.cursor(table.db)?;
    let mut entry = cursor.set_range(&range.start)?;
    while let Some((key, value)) = entry {
        if let Some(end) = &range.end
            && txn.cmp(table.db, key, end).is_ge()
        {
            break;
        }
        if !table.flags.dup_fixed {
            visit(Item::Entry(key, value))?;
            entry = cursor.next()?;
            continue;
        }
        let size = value.len();
        if let Some(big) = &mut big
            && cursor.count()? >= BIG_KEY
        {
            let last = cursor.last_dup()?.map_or(value, |(_, last)| last);
            big(key, value, last);
            entry = cursor.next_nodup()?;
            continue;
        }
        // At the key's first value, so its first page is its first values.
        let page = cursor.get_multiple()?;
        if page.is_empty() {
            visit(Item::Dups {
                key,
                values: value,
                size,
                first: true,
            })?;
        } else {
            let (mut page, mut first) = (Some(page), true);
            while let Some(values) = page {
                visit(Item::Dups {
                    key,
                    values,
                    size,
                    first,
                })?;
                first = false;
                page = cursor.next_multiple()?;
            }
        }
        entry = cursor.next_nodup()?;
    }
    Ok(())
}

/// The threads that read ahead of the copy.
struct Reader<'a> {
    env: &'a Env,
    tables: &'a [Table],
    ranges: &'a [Range],
    /// The range being copied.
    copying: &'a AtomicUsize,
    /// The next range for a thread to read.
    next: &'a AtomicUsize,
    /// How many ranges ahead of the copy a thread may read.
    ahead: usize,
    /// Pieces of big keys, in order, read before any more ranges.
    pieces: &'a Mutex<VecDeque<Piece>>,
    done: &'a AtomicBool,
}

impl Reader<'_> {
    /// Read ranges, and pieces of big keys in them, ahead of the one being
    /// copied, so their pages are in memory when it gets to them, until
    /// it's done.
    fn run(&self) {
        let Ok(txn) = self.env.read_txn() else {
            return;
        };
        while !self.done.load(Ordering::Relaxed) {
            let piece = self.pieces.lock().expect("unpoisoned").pop_front();
            if let Some(piece) = piece {
                if let Err(err) = read_piece(&txn, &self.tables[piece.table], &piece) {
                    tracing::debug!("reading ahead failed: {err:#}");
                }
                continue;
            }
            let n = self.next.load(Ordering::Relaxed);
            let copying = self.copying.load(Ordering::Relaxed);
            // None left, or far enough ahead: big keys' pieces may come.
            if n >= self.ranges.len() || n > copying + self.ahead {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            if self
                .next
                .compare_exchange(n, n + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            // Copied already: reading it now is no help.
            if n < copying {
                continue;
            }
            let range = &self.ranges[n];
            let table = &self.tables[range.table];
            let mut big = |key: &[u8], first: &[u8], last: &[u8]| {
                let bounds = spread(first, last);
                let mut pieces = self.pieces.lock().expect("unpoisoned");
                for (n, start) in bounds.iter().enumerate() {
                    pieces.push_back(Piece {
                        table: range.table,
                        key: key.to_vec(),
                        start: start.clone(),
                        end: bounds.get(n + 1).cloned(),
                    });
                }
            };
            let read = walk(&txn, table, range, Some(&mut big), |item| {
                let bytes = match item {
                    Item::Entry(_, value) => value,
                    Item::Dups { values, .. } => values,
                };
                touch(bytes);
                Ok(())
            });
            if let Err(err) = read {
                tracing::debug!("reading ahead failed: {err:#}");
            }
        }
    }
}

/// Read a byte of each page of `bytes`, as values may span several.
fn touch(bytes: &[u8]) {
    std::hint::black_box(bytes.iter().step_by(4096).fold(0u8, |a, &b| a ^ b));
}

/// Where the [pieces](Piece) of a key whose values run from `first` to
/// `last` begin: `first`, then values about evenly spread up to `last`.
fn spread(first: &[u8], last: &[u8]) -> Vec<Vec<u8>> {
    let mut bounds = vec![first.to_vec(), last.to_vec()];
    // Each round doubles the pieces, bounds.len() - 1, at most.
    while 2 * (bounds.len() - 1) <= PIECES {
        let mut split = Vec::with_capacity(bounds.len() * 2);
        for pair in bounds.windows(2) {
            split.push(pair[0].clone());
            let mut middle = midpoint(&pair[0], &pair[1], false);
            // The size values are; still not before the first.
            middle.truncate(first.len());
            if middle > pair[0] && middle < pair[1] {
                split.push(middle);
            }
        }
        split.push(bounds[bounds.len() - 1].clone());
        if split.len() == bounds.len() {
            break;
        }
        bounds = split;
    }
    bounds.pop();
    bounds
}

/// Read `piece` of a big key's values, returning how many it read.
fn read_piece(txn: &Txn, table: &Table, piece: &Piece) -> anyhow::Result<usize> {
    let mut cursor: Cursor = txn.cursor(table.db)?;
    if cursor.get_both_range(&piece.key, &piece.start)?.is_none() {
        return Ok(0);
    }
    let size = piece.start.len();
    let mut read = 0;
    let mut page = Some(cursor.get_multiple()?);
    while let Some(values) = page {
        touch(values);
        read += values.len() / size;
        let past = values.len().checked_sub(size).map(|last| &values[last..]);
        if let (Some(end), Some(last)) = (&piece.end, past)
            && last >= &end[..]
        {
            break;
        }
        page = cursor.next_multiple()?;
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb::DbFlags;

    #[test]
    fn finds_keys_between() {
        let cases: [(&[u8], &[u8]); 5] = [
            (b"a", b"c"),
            (b"a", b"b"),
            (b"ab", b"abc"),
            (b"\x00", b"\xff\xff"),
            (b"", b"\x01"),
        ];
        for (a, b) in cases {
            let m = midpoint(a, b, false);
            assert!(a <= &m[..] && &m[..] <= b, "{a:?} {m:?} {b:?}");
        }
        assert_eq!(midpoint(b"a", b"c", false), b"b\0");
        let (a, b) = (1000u64.to_ne_bytes(), u64::MAX.to_ne_bytes());
        let m = u64::from_ne_bytes(midpoint(&a, &b, true).try_into().unwrap());
        assert_eq!(m, 1000 / 2 + u64::MAX / 2);
    }

    type Contents = Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>;

    /// Every entry of every table of the environment in `dir`, in order.
    fn contents(dir: &Path) -> Contents {
        let env = Env::open_read_only(dir, 1 << 30, 64, 16).unwrap();
        let tables = env.tables().unwrap();
        let txn = env.read_txn().unwrap();
        tables
            .into_iter()
            .map(|(name, db, _)| {
                let mut cursor = txn.cursor(db).unwrap();
                let mut entries = Vec::new();
                let mut entry = cursor.first().unwrap();
                while let Some((key, value)) = entry {
                    entries.push((key.to_vec(), value.to_vec()));
                    entry = cursor.next().unwrap();
                }
                (name, entries)
            })
            .collect()
    }

    /// An environment with every kind of table, much of it deleted.
    fn fill(dir: &Path) {
        let env = Env::open(dir, 1 << 28, 8, 16).unwrap();
        let plain = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let dups = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
        let ints = env.create_db("ints", DbFlags::INTEGER_KEY).unwrap();
        env.create_db("empty", DbFlags::DUP_FIXED).unwrap();
        let one = env.create_db("one", DbFlags::PLAIN).unwrap();
        let mut txn = env.write_txn().unwrap();
        txn.put(one, b"only", b"value").unwrap();
        txn.commit().unwrap();
        // Written out of order, so pages split and scatter.
        for round in 0..20u64 {
            let mut txn = env.write_txn().unwrap();
            for i in 0..2000u64 {
                let n = (i * 7919 + round * 104_729) % 40_000;
                let key = format!("key:{:x}", n.wrapping_mul(0x9e37_79b9) % 10_007);
                txn.put(
                    plain,
                    key.as_bytes(),
                    &vec![n as u8; 1 + (n % 300) as usize],
                )
                .unwrap();
                // Some keys with thousands of values, some with one.
                let dup = match n % 3 {
                    0 => b"big".to_vec(),
                    _ => format!("d{}", n % 500).into_bytes(),
                };
                txn.put_dup(dups, &dup, &n.to_be_bytes()).unwrap();
                txn.put(ints, &(n * 1_000_003).to_ne_bytes(), &[1; 40])
                    .unwrap();
                // Now and then, a value too big for a page.
                if n % 997 == 0 {
                    txn.put(plain, format!("big:{n}").as_bytes(), &vec![7; 9000])
                        .unwrap();
                }
            }
            txn.commit().unwrap();
        }
        let mut txn = env.write_txn().unwrap();
        for n in 0..40_000u64 {
            if n % 4 != 0 {
                txn.del(ints, &(n * 1_000_003).to_ne_bytes(), None).unwrap();
                txn.del(dups, b"big", Some(&n.to_be_bytes())).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    #[test]
    fn copies_every_table_smaller() {
        let from = tempfile::tempdir().unwrap();
        fill(from.path());
        let mut copies = Vec::new();
        for threads in [0, 1, 8] {
            let into = tempfile::tempdir().unwrap();
            let copied = copy(from.path(), into.path(), 1 << 28, threads, &mut |_| {}).unwrap();
            assert!(
                copied.after < copied.before / 2,
                "{} {}",
                copied.after,
                copied.before
            );
            let names: Vec<_> = copied
                .tables
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(names, ["dups", "empty", "ints", "one", "plain"]);
            assert_eq!(contents(into.path()), contents(from.path()));
            copies.push(std::fs::read(into.path().join(DATA_FILE)).unwrap());
            // And it's written to as usual.
            let env = Env::open(into.path(), 1 << 28, 8, 16).unwrap();
            let dups = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
            let mut txn = env.write_txn().unwrap();
            txn.put_dup(dups, b"big", &1u64.to_be_bytes()).unwrap();
            txn.put_dup(dups, b"a", &1u64.to_be_bytes()).unwrap();
            txn.commit().unwrap();
        }
        // However many threads read ahead, the copy's the same.
        assert!(copies.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn splits_tables_by_their_keys() {
        let dir = tempfile::tempdir().unwrap();
        fill(dir.path());
        let env = Env::open_read_only(dir.path(), 1 << 28, 8, 16).unwrap();
        for (name, db, flags) in env.tables().unwrap() {
            let table = Table { name, db, flags };
            let bounds = split(&env, &table, 4).unwrap();
            let txn = env.read_txn().unwrap();
            assert!(bounds.windows(2).all(|w| txn.cmp(db, &w[0], &w[1]).is_lt()));
            let expected = match table.name.as_str() {
                "empty" => 0..1,
                "one" => 1..2,
                "dups" => 100..600,
                _ => 1000..MAX_RANGES + 1,
            };
            assert!(
                expected.contains(&bounds.len()),
                "{} {}",
                table.name,
                bounds.len()
            );
        }
    }

    /// A big key's pieces cover its values, from the first to the last.
    #[test]
    fn reads_a_big_key_in_pieces() {
        let first = 5u64.to_be_bytes();
        let last = 1_000_000u64.to_be_bytes();
        let bounds = spread(&first, &last);
        assert!(bounds.len() > PIECES / 2 && bounds.len() <= PIECES);
        assert_eq!(bounds[0], first);
        assert!(bounds.windows(2).all(|w| w[0] < w[1] && w[1].len() == 8));
        assert!(bounds.last().unwrap() < &last.to_vec());
        assert_eq!(spread(&first, &6u64.to_be_bytes()), [first.to_vec()]);

        let dir = tempfile::tempdir().unwrap();
        fill(dir.path());
        let env = Env::open_read_only(dir.path(), 1 << 28, 8, 16).unwrap();
        let (name, db, flags) = env
            .tables()
            .unwrap()
            .into_iter()
            .find(|(name, ..)| name == "dups")
            .unwrap();
        let table = Table { name, db, flags };
        let txn = env.read_txn().unwrap();
        let mut cursor = txn.cursor(db).unwrap();
        let (_, first) = cursor.set(b"big").unwrap().unwrap();
        let count = cursor.count().unwrap();
        assert!(count >= BIG_KEY, "{count}");
        let last = cursor.last_dup().unwrap().unwrap().1;
        let bounds = spread(first, last);
        assert!(bounds.len() > 4);
        let read: usize = bounds
            .iter()
            .enumerate()
            .map(|(n, start)| {
                let piece = Piece {
                    table: 0,
                    key: b"big".to_vec(),
                    start: start.clone(),
                    end: bounds.get(n + 1).cloned(),
                };
                read_piece(&txn, &table, &piece).unwrap()
            })
            .sum();
        // Whole pages, so some twice.
        assert!(read >= count, "{read} {count}");
    }

    #[test]
    fn refuses_to_copy_over_a_database() {
        let from = tempfile::tempdir().unwrap();
        fill(from.path());
        let into = tempfile::tempdir().unwrap();
        copy(from.path(), into.path(), 1 << 28, 2, &mut |_| {}).unwrap();
        assert!(copy(from.path(), into.path(), 1 << 28, 2, &mut |_| {}).is_err());
        let nothing = tempfile::tempdir().unwrap();
        assert!(copy(nothing.path(), into.path(), 1 << 28, 2, &mut |_| {}).is_err());
    }

    #[test]
    fn compacts_a_store_in_place() {
        use crate::event::tests::signed;
        use crate::store::tests::{open_in, put};
        let dir = tempfile::tempdir().unwrap();
        let topics: Vec<String> = (0..7).map(|n| format!("t{n}")).collect();
        let events: Vec<_> = (0..300)
            .map(|n| {
                signed(
                    1,
                    1000 + n,
                    1,
                    vec![vec!["t", &topics[n as usize % 7]]],
                    "hi",
                )
            })
            .collect();
        let store = open_in(dir.path());
        for event in &events {
            put(&store, event);
        }
        let id = store.id(&store.read().unwrap()).unwrap();
        assert!(id.is_some());
        store.checkpoint().unwrap();
        drop(store);
        let before = contents(dir.path());

        in_place(dir.path(), 1 << 30, 4, &mut |_| {}).unwrap();
        assert!(dir.path().join(OLD_FILE).exists());
        assert!(!dir.path().join(COPY_DIR).exists());
        assert!(!dir.path().join(crate::checkpoint::FILE).exists());
        assert_eq!(contents(dir.path()), before);
        let store = open_in(dir.path());
        let txn = store.read().unwrap();
        assert_eq!(store.id(&txn).unwrap(), id);
        assert_eq!(store.len(&txn).unwrap(), events.len());
        drop(txn);
        drop(store);

        // Not again, until the old file's gone.
        assert!(in_place(dir.path(), 1 << 30, 4, &mut |_| {}).is_err());
        std::fs::remove_file(dir.path().join(OLD_FILE)).unwrap();
        in_place(dir.path(), 1 << 30, 4, &mut |_| {}).unwrap();
    }
}
