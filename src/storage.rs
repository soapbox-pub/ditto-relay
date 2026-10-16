//! Whether the filesystem the store is on suits LMDB.
//!
//! ZFS keeps a file in records of its dataset's `recordsize`, and never
//! changes part of one in place: writing into a record means writing a
//! whole new one, so the rest of it is read first. LMDB writes pages of the
//! machine's page size, 4K, scattered through its file. In records any
//! bigger, nearly every page written waits on reading a record from disk,
//! one at a time, as LMDB has one writer: on SATA SSDs, some 2,000 pages a
//! second, against 77,000 in 4K records. A file's records are the size its
//! dataset's were when it was written, so changing the dataset's isn't
//! enough: the file has to be written anew, which `ditto-relay compact`
//! does.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The magic number `statfs` gives for ZFS.
const ZFS_MAGIC: i64 = 0x2fc1_2fc1;

/// A file of the store kept in records bigger than LMDB's pages.
#[derive(Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub file: PathBuf,
    /// The size of the file's records, in bytes.
    pub record: u64,
    /// The ZFS dataset the file's in, if it can be told.
    pub dataset: Option<String>,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let page = page_size();
        write!(
            f,
            "{} is kept in {}K records on ZFS, and LMDB writes {}K pages, so ZFS reads a record from disk before writing each page, which makes writing many times slower. To fix it, run `zfs set recordsize={}K {}` where ZFS is managed (on the host, for a container), then, with the relay stopped, `ditto-relay compact`, which writes the database's files anew",
            self.file.display(),
            self.record / 1024,
            page / 1024,
            page / 1024,
            self.dataset.as_deref().unwrap_or("<the dataset>"),
        )
    }
}

/// The size of LMDB's pages: the machine's.
pub fn page_size() -> u64 {
    // SAFETY: sysconf only reads.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).unwrap_or(4096)
}

/// Those of `files` (which needn't exist) kept on ZFS in records bigger
/// than LMDB's pages.
pub fn check(files: &[PathBuf]) -> Vec<Mismatch> {
    let page = page_size();
    files
        .iter()
        .filter(|file| is_zfs(file))
        .filter_map(|file| {
            let stat = std::fs::metadata(file).ok()?;
            let record = records_of(stat.len(), stat.blksize())?;
            (record > page).then(|| Mismatch {
                file: file.clone(),
                record,
                dataset: dataset(file),
            })
        })
        .collect()
}

/// The size of a file's records, from its length and the block size
/// `stat` gives, if it's known: a file of one record has it sized to fit,
/// not as its dataset's are, until it grows past it.
fn records_of(len: u64, block: u64) -> Option<u64> {
    (block > 0 && len > block).then_some(block)
}

/// Whether a file written anew beside one whose length and block size are
/// `old` would be kept in smaller records: as `new`, of a file just written
/// there, is.
pub fn smaller_anew(old: (u64, u64), new: (u64, u64)) -> bool {
    match (records_of(old.0, old.1), records_of(new.0, new.1)) {
        (Some(old), Some(new)) => new < old,
        _ => false,
    }
}

fn is_zfs(path: &Path) -> bool {
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: plain data, filled in by the kernel, and a NUL-terminated path.
    let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return false;
    }
    stat.f_type as i64 == ZFS_MAGIC
}

/// The ZFS dataset mounted where `path` is, as this process's mounts say.
fn dataset(path: &Path) -> Option<String> {
    let path = std::fs::canonicalize(path).ok()?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    zfs_mount_of(&mounts, &path)
}

/// The source of the deepest mount in `mountinfo` holding `path`, if it's
/// ZFS's.
fn zfs_mount_of(mountinfo: &str, path: &Path) -> Option<String> {
    let (_, kind, source) = mountinfo
        .lines()
        .filter_map(|line| {
            let (mount, filesystem) = line.split_once(" - ")?;
            let point = PathBuf::from(unescape(mount.split(' ').nth(4)?));
            let mut filesystem = filesystem.split(' ');
            let (kind, source) = (filesystem.next()?, filesystem.next()?);
            path.starts_with(&point).then_some((point, kind, source))
        })
        .max_by_key(|(point, ..)| point.components().count())?;
    (kind == "zfs").then(|| unescape(source))
}

/// A mountinfo field, whose spaces and such are written as `\040`.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut n = 0;
    while n < bytes.len() {
        let octal = bytes
            .get(n + 1..n + 4)
            .filter(|digits| bytes[n] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)))
            .and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok());
        match octal {
            Some(byte) => {
                out.push(byte);
                n += 4;
            }
            None => {
                out.push(bytes[n]);
                n += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_dataset_a_file_is_in() {
        let mountinfo = "\
663 496 0:136 / / rw,relatime shared:223 master:1259 - zfs rpool/data/subvol-103-disk-0 rw,xattr
664 663 0:142 / /var/lib/ditto-relay rw,noatime shared:439 - zfs rpool/data/subvol-103-disk-1 rw,xattr
665 663 0:87 / /var/lib/ditto-relay/tmp rw,relatime shared:440 - tmpfs none rw
666 663 0:88 / /srv/my\\040relay rw - zfs tank/my\\040relay rw
";
        let at = |path: &str| zfs_mount_of(mountinfo, Path::new(path));
        assert_eq!(
            at("/var/lib/ditto-relay/db/data.mdb").as_deref(),
            Some("rpool/data/subvol-103-disk-1")
        );
        assert_eq!(
            at("/etc/x").as_deref(),
            Some("rpool/data/subvol-103-disk-0")
        );
        // Not the dataset over a mount of another kind in it.
        assert_eq!(at("/var/lib/ditto-relay/tmp/x"), None);
        // Nor one whose path only begins the same.
        assert_eq!(
            at("/var/lib/ditto-relay-2/x").as_deref(),
            Some("rpool/data/subvol-103-disk-0")
        );
        assert_eq!(at("/srv/my relay/db").as_deref(), Some("tank/my relay"));
    }

    #[test]
    fn tells_records_only_of_files_past_one() {
        assert_eq!(records_of(339 << 30, 16384), Some(16384));
        assert_eq!(records_of(10_240, 10_240), None);
        assert_eq!(records_of(100, 0), None);
        // Production's bodies, beside a main file written in 4K records.
        assert!(smaller_anew((339 << 30, 16384), (88 << 30, 4096)));
        assert!(!smaller_anew((339 << 30, 16384), (88 << 30, 16384)));
        assert!(!smaller_anew((339 << 30, 4096), (88 << 30, 4096)));
        // A copy too small to say.
        assert!(!smaller_anew((339 << 30, 16384), (8192, 8192)));
    }

    /// Not on ZFS here, or not in big records: nothing to say.
    #[test]
    fn says_nothing_of_other_filesystems() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.mdb");
        std::fs::write(&file, vec![1; 1 << 20]).unwrap();
        let gone = dir.path().join("gone");
        if !is_zfs(dir.path()) {
            assert_eq!(check(&[file, gone]), []);
        }
    }
}
