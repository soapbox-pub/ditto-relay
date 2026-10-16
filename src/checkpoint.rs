//! Checkpoints: how the store survives a crash of the machine.
//!
//! Commits aren't flushed to disk one by one: the kernel writes them when it
//! likes, in any order, so after a crash of the machine the latest commit may
//! point to pages that never reached the disk, or that a later commit had
//! started to overwrite. Which commits survive depends on the filesystem and
//! on luck, and LMDB trusts the pages it reads, so a corrupt one can crash
//! the relay rather than fail.
//!
//! So every so often the relay makes one commit durable on purpose. It pins
//! the latest commit with a read transaction, so that LMDB reuses none of
//! its pages, keeps a copy of each environment's meta pages, which point to
//! them, flushes the environments' files to disk, and only then writes the
//! copies, with the machine's boot id, to the `checkpoint` file beside them.
//! The pin is let go once the next checkpoint is durable.
//!
//! When the store opens, if the machine has booted since the checkpoint was
//! made, its meta pages are written back: the store is as it was at the
//! checkpoint, every page of which is on disk untouched. What was committed
//! since, a few seconds of writes, is lost, and nothing else. If the machine
//! hasn't booted since, only the relay stopped, and every commit it made is
//! in the kernel's page cache, so nothing is lost. A store that's been
//! replaced since, as by a compacted copy, has a file of its own, and its
//! checkpoint isn't used.
//!
//! What's kept beside the store copes with it going back in time: see
//! [`crate::store`] for the records `bodies` may have that the main
//! environment doesn't, and [`crate::search`] for an index ahead of it.

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::lmdb::{Env, Meta};

/// The checkpoint's file, in the database's directory.
pub const FILE: &str = "checkpoint";

/// How often the writer makes a checkpoint: about as many seconds of writes
/// as a crash of the machine can lose.
pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

const MAGIC: &[u8; 8] = b"DRCKPT02";

/// LMDB's meta page: where in it its magic number and the id of the
/// transaction that wrote it are.
const META_MAGIC_AT: usize = 16;
const META_TXNID_AT: usize = 144;
const LMDB_MAGIC: u32 = 0xBEEF_C0DE;

/// This boot of the machine's id, which changes when it restarts.
pub fn boot_id() -> Option<String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(id.trim().to_string()).filter(|id| !id.is_empty())
}

/// One environment's part of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Saved {
    /// Which file it is, by inode and when it was made (0 if the
    /// filesystem doesn't say): not by device, which ZFS numbers anew each
    /// time it mounts a dataset.
    ino: u64,
    born: u64,
    meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Checkpoint {
    boot_id: String,
    envs: Vec<Saved>,
}

impl Checkpoint {
    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let put = |out: &mut Vec<u8>, n: u64| out.extend_from_slice(&n.to_le_bytes());
        put(&mut out, self.boot_id.len() as u64);
        out.extend_from_slice(self.boot_id.as_bytes());
        put(&mut out, self.envs.len() as u64);
        for env in &self.envs {
            put(&mut out, env.ino);
            put(&mut out, env.born);
            put(&mut out, env.meta.txnid);
            put(&mut out, env.meta.page_size as u64);
            put(&mut out, env.meta.pages.len() as u64);
            out.extend_from_slice(&env.meta.pages);
        }
        let sum = Sha256::digest(&out);
        out.extend_from_slice(&sum);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Checkpoint> {
        let (body, sum) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
        if Sha256::digest(body)[..] != *sum || !body.starts_with(MAGIC) {
            return None;
        }
        let mut reader = Reader(&body[MAGIC.len()..]);
        let len = reader.num()? as usize;
        let boot_id = String::from_utf8(reader.take(len)?.to_vec()).ok()?;
        let mut envs = Vec::new();
        for _ in 0..reader.num()? {
            let (ino, born, txnid) = (reader.num()?, reader.num()?, reader.num()?);
            let page_size = reader.num()? as usize;
            let len = reader.num()? as usize;
            if len != 2 * page_size || page_size < META_TXNID_AT + 8 {
                return None;
            }
            let pages = reader.take(len)?.to_vec();
            envs.push(Saved {
                ino,
                born,
                meta: Meta {
                    txnid,
                    page_size,
                    pages,
                },
            });
        }
        Some(Checkpoint { boot_id, envs })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn num(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

/// The newest commit either meta page in `pages` is of, skipping any that
/// isn't a meta page.
fn newest_txnid(pages: &[u8], page_size: usize) -> Option<u64> {
    pages
        .chunks_exact(page_size)
        .filter(|page| {
            page.get(META_MAGIC_AT..META_MAGIC_AT + 4)
                .is_some_and(|magic| magic == LMDB_MAGIC.to_le_bytes())
        })
        .filter_map(|page| {
            Some(u64::from_le_bytes(
                page.get(META_TXNID_AT..META_TXNID_AT + 8)?
                    .try_into()
                    .ok()?,
            ))
        })
        .max()
}

/// When a file was made, in nanoseconds since the epoch, or 0 if its
/// filesystem doesn't say.
fn born(stat: &std::fs::Metadata) -> u64 {
    stat.created()
        .ok()
        .and_then(|born| born.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |born| born.as_nanos() as u64)
}

/// Whether `meta`'s pages hold its commit's meta page: they may not, if
/// they were read as two more commits were made.
fn holds(meta: &Meta) -> bool {
    meta.pages
        .chunks_exact(meta.page_size)
        .any(|page| newest_txnid(page, meta.page_size) == Some(meta.txnid))
}

/// Begin a checkpoint of `env`'s latest commit, pinning it: see
/// [`Env::begin_checkpoint`]. Call it between write transactions.
pub fn begin(env: &Env) -> anyhow::Result<Vec<Meta>> {
    let metas = env.begin_checkpoint()?;
    anyhow::ensure!(
        metas.iter().all(holds),
        "the store was written to as its checkpoint began"
    );
    Ok(metas)
}

/// Make a checkpoint [begun](begin) durable: flush `env`, whose data files
/// are `files`, to disk, then save its meta pages in `dir`, and let the
/// checkpoint before go. Writes may go on meanwhile.
pub fn finish(
    env: &Env,
    dir: &Path,
    files: &[PathBuf],
    boot_id: Option<&str>,
    metas: &[Meta],
) -> anyhow::Result<()> {
    env.sync()?;
    save(dir, boot_id, files, metas)?;
    env.confirm_checkpoint();
    Ok(())
}

/// The data files of the environments of the store in `dir`, in the order
/// they're opened.
pub fn files(dir: &Path, others: &[&Path]) -> Vec<PathBuf> {
    std::iter::once(dir)
        .chain(others.iter().copied())
        .map(|dir| dir.join("data.mdb"))
        .collect()
}

/// Write a checkpoint of `files`' environments, whose meta pages `metas`
/// are, to `dir`, durably. The pinned commits must be on disk already.
pub fn save(
    dir: &Path,
    boot_id: Option<&str>,
    files: &[PathBuf],
    metas: &[Meta],
) -> io::Result<()> {
    let mut envs = Vec::new();
    for (file, meta) in files.iter().zip(metas) {
        let stat = std::fs::metadata(file)?;
        envs.push(Saved {
            ino: stat.ino(),
            born: born(&stat),
            meta: meta.clone(),
        });
    }
    let checkpoint = Checkpoint {
        boot_id: boot_id.unwrap_or_default().to_string(),
        envs,
    };
    let tmp = dir.join(format!("{FILE}.tmp"));
    let mut file = File::create(&tmp)?;
    file.write_all(&checkpoint.encode())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, dir.join(FILE))?;
    File::open(dir)?.sync_all()
}

/// What [`recover`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Recovered {
    /// There was no checkpoint, so the store's as it was left.
    Nothing,
    /// The machine hasn't booted since the checkpoint, so every commit is
    /// in the page cache, and the store's as it was left.
    SameBoot,
    /// The machine has booted since: the store's back at the checkpoint,
    /// the commits since dropped unread, intact or not. For each
    /// environment, in order, the checkpoint's commit and the latest found.
    Restored(Vec<(u64, Option<u64>)>),
    /// The checkpoint isn't this store's, or is unreadable, so the store's
    /// as it was left. Why.
    Ignored(String),
}

/// Before the store in `dir`, whose data files are `files`, is opened: if
/// the machine has booted since its checkpoint, put it back as it was then.
pub fn recover(dir: &Path, files: &[PathBuf], boot_id: Option<&str>) -> io::Result<Recovered> {
    let bytes = match std::fs::read(dir.join(FILE)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Recovered::Nothing),
        Err(err) => return Err(err),
    };
    let Some(checkpoint) = Checkpoint::decode(&bytes) else {
        return Ok(Recovered::Ignored("it can't be read".into()));
    };
    if boot_id.is_some_and(|id| id == checkpoint.boot_id) {
        return Ok(Recovered::SameBoot);
    }
    if checkpoint.envs.len() != files.len() {
        return Ok(Recovered::Ignored(
            "it has another number of environments".into(),
        ));
    }
    let mut opened = Vec::new();
    for (path, saved) in files.iter().zip(&checkpoint.envs) {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(Recovered::Ignored(format!("{} is gone", path.display())));
            }
            Err(err) => return Err(err),
        };
        let stat = file.metadata()?;
        if (stat.ino(), born(&stat)) != (saved.ino, saved.born) {
            return Ok(Recovered::Ignored(format!(
                "{} has been replaced",
                path.display()
            )));
        }
        let mut current = vec![0; saved.meta.pages.len()];
        file.read_exact_at(&mut current, 0)?;
        // Written over in place, as by restoring a backup: the meta pages
        // that survive a crash are of the checkpoint's commit or later.
        let newest = newest_txnid(&current, saved.meta.page_size);
        if newest.is_some_and(|newest| newest < saved.meta.txnid) {
            return Ok(Recovered::Ignored(format!(
                "{} is at commit {}, before the checkpoint's {}",
                path.display(),
                newest.unwrap_or_default(),
                saved.meta.txnid
            )));
        }
        opened.push((file, current, newest));
    }
    for ((file, current, _), saved) in opened.iter().zip(&checkpoint.envs) {
        if *current != saved.meta.pages {
            file.write_all_at(&saved.meta.pages, 0)?;
            file.sync_all()?;
        }
    }
    Ok(Recovered::Restored(
        checkpoint
            .envs
            .iter()
            .zip(&opened)
            .map(|(env, (_, _, newest))| (env.meta.txnid, *newest))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb::{DbFlags, Env};

    #[test]
    fn encodes_and_refuses_damage() {
        let checkpoint = Checkpoint {
            boot_id: "boot".into(),
            envs: vec![Saved {
                ino: 1,
                born: 2,
                meta: Meta {
                    txnid: 3,
                    page_size: 256,
                    pages: (0..512).map(|n| n as u8).collect(),
                },
            }],
        };
        let mut bytes = checkpoint.encode();
        assert_eq!(Checkpoint::decode(&bytes), Some(checkpoint));
        bytes[20] ^= 1;
        assert_eq!(Checkpoint::decode(&bytes), None);
        assert_eq!(Checkpoint::decode(&bytes[..10]), None);
    }

    /// The pages written after a checkpoint, garbage, as a crash of the
    /// machine can leave them on a filesystem that writes in any order:
    /// meta pages too. The checkpoint gets the store back, because its
    /// commit's pages were never reused, however much was freed since.
    #[test]
    fn gets_back_a_store_whose_later_pages_are_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let files = files(dir.path(), &[&other]);
        let open = || {
            let mut env = Env::open(dir.path(), 1 << 26, 4, 16).unwrap();
            env.attach(&other, 1 << 26, 4, 16).unwrap();
            let main = env.create_db("main", DbFlags::PLAIN).unwrap();
            let appended = env
                .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
                .unwrap();
            (env, main, appended)
        };
        let fill = |env: &Env, main, appended, round: u64, n: u64| {
            for chunk in 0..n / 100 {
                let mut txn = env.write_txn().unwrap();
                for i in chunk * 100..(chunk + 1) * 100 {
                    txn.put(main, &i.to_be_bytes(), &[round as u8; 200])
                        .unwrap();
                    let key = (round * 1_000_000 + i).to_ne_bytes();
                    txn.put(appended, &key, &[round as u8; 300]).unwrap();
                }
                txn.commit().unwrap();
            }
        };

        let (env, main, appended) = open();
        fill(&env, main, appended, 1, 3000);
        let metas = begin(&env).unwrap();
        finish(&env, dir.path(), &files, Some("before"), &metas).unwrap();
        let at_checkpoint: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
        // Overwrite everything, many times, and free the bodies: without
        // the pin, the checkpoint's pages would be reused.
        for round in 2..6 {
            fill(&env, main, appended, round, 3000);
            let mut txn = env.write_txn().unwrap();
            for i in 0..3000u64 {
                txn.del(appended, &((round - 1) * 1_000_000 + i).to_ne_bytes(), None)
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        drop(env);

        // Every page written since the checkpoint is garbage.
        for (file, before) in files.iter().zip(&at_checkpoint) {
            let mut after = std::fs::read(file).unwrap();
            for (n, page) in after.chunks_mut(4096).enumerate() {
                if before.get(n * 4096..(n + 1) * 4096) != Some(&*page) {
                    page.fill(0xA5);
                }
            }
            std::fs::write(file, &after).unwrap();
        }

        assert_eq!(
            recover(dir.path(), &files, Some("before")).unwrap(),
            Recovered::SameBoot
        );
        let Recovered::Restored(txnids) = recover(dir.path(), &files, Some("after")).unwrap()
        else {
            panic!("not restored");
        };
        // The meta pages since are garbage, so the latest commits aren't
        // known.
        let expected: Vec<_> = metas.iter().map(|m| (m.txnid, None)).collect();
        assert_eq!(txnids, expected);
        let (env, main, appended) = open();
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.len(main).unwrap(), 3000);
        assert_eq!(txn.len(appended).unwrap(), 3000);
        assert_eq!(
            txn.get(main, &2999u64.to_be_bytes()).unwrap(),
            Some(&[1; 200][..])
        );
        let mut cursor = txn.cursor(appended).unwrap();
        let mut entry = cursor.first().unwrap();
        while let Some((_, value)) = entry {
            assert_eq!(value, &[1; 300][..]);
            entry = cursor.next().unwrap();
        }
        drop(cursor);
        drop(txn);
        // And it's written to as usual.
        fill(&env, main, appended, 9, 3000);
    }

    #[test]
    fn leaves_a_replaced_store_alone() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path(), &[]);
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        env.create_db("main", DbFlags::PLAIN).unwrap();
        let metas = begin(&env).unwrap();
        finish(&env, dir.path(), &files, Some("before"), &metas).unwrap();
        drop(env);
        let copy = dir.path().join("copy");
        std::fs::copy(&files[0], &copy).unwrap();
        std::fs::rename(&copy, &files[0]).unwrap();
        assert!(matches!(
            recover(dir.path(), &files, Some("after")).unwrap(),
            Recovered::Ignored(_)
        ));
        std::fs::remove_file(dir.path().join(FILE)).unwrap();
        assert_eq!(
            recover(dir.path(), &files, None).unwrap(),
            Recovered::Nothing
        );
    }
}
