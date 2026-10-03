//! A small, safe wrapper over the LMDB C API.
//!
//! heed has no way to seek within a key's sorted duplicates
//! (`MDB_GET_BOTH_RANGE`) or to count them (`mdb_cursor_count`). The relay's
//! indexes are built on exactly those: each is a `DUPSORT | DUPFIXED` table
//! whose key is stored once and whose entries are packed fixed-size values,
//! which is several times smaller than one key per entry.
//!
//! All the `unsafe` in the crate lives here.

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;

use lmdb_master_sys as ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(i32);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAFETY: mdb_strerror returns a static, NUL-terminated string for any code.
        let message = unsafe { CStr::from_ptr(ffi::mdb_strerror(self.0)) };
        write!(f, "LMDB: {}", message.to_string_lossy())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn check(code: i32) -> Result<()> {
    if code == ffi::MDB_SUCCESS {
        Ok(())
    } else {
        Err(Error(code))
    }
}

/// `Ok(None)` for `MDB_NOTFOUND`, so lookups read naturally.
fn found(code: i32) -> Result<Option<()>> {
    match code {
        ffi::MDB_SUCCESS => Ok(Some(())),
        ffi::MDB_NOTFOUND => Ok(None),
        code => Err(Error(code)),
    }
}

fn val(bytes: &[u8]) -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut _,
    }
}

fn empty() -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

/// The bytes a value points at.
///
/// # Safety
/// `v` must have come from LMDB within a transaction that outlives `'t`.
unsafe fn bytes<'t>(v: &ffi::MDB_val) -> &'t [u8] {
    if v.mv_size == 0 {
        &[]
    } else {
        // SAFETY: LMDB hands back pointers into the map valid for the transaction.
        unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DbFlags {
    /// Keys may hold many values, kept sorted.
    pub dup_sort: bool,
    /// With `dup_sort`: every value is the same size, and stored packed.
    pub dup_fixed: bool,
    /// Keys are native-endian integers, compared as such.
    pub integer_key: bool,
}

impl DbFlags {
    pub const PLAIN: DbFlags = DbFlags {
        dup_sort: false,
        dup_fixed: false,
        integer_key: false,
    };
    pub const DUP_FIXED: DbFlags = DbFlags {
        dup_sort: true,
        dup_fixed: true,
        integer_key: false,
    };
    pub const INTEGER_KEY: DbFlags = DbFlags {
        dup_sort: false,
        dup_fixed: false,
        integer_key: true,
    };

    fn bits(self) -> u32 {
        let mut bits = ffi::MDB_CREATE;
        if self.dup_sort {
            bits |= ffi::MDB_DUPSORT;
        }
        if self.dup_fixed {
            bits |= ffi::MDB_DUPFIXED;
        }
        if self.integer_key {
            bits |= ffi::MDB_INTEGERKEY;
        }
        bits
    }
}

/// A table within an [`Env`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Db(ffi::MDB_dbi);

pub struct Env {
    ptr: *mut ffi::MDB_env,
}

// SAFETY: an MDB_env is safe to share between threads; transactions opened
// from it carry their own restrictions, enforced by the types below.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Env {
    /// Open (creating if need be) the environment in the directory `path`.
    pub fn open(path: &Path, map_size: usize, max_dbs: u32, max_readers: u32) -> Result<Env> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        let mut ptr = ptr::null_mut();
        // SAFETY: plain FFI calls in the documented order; the env is closed if any fails.
        unsafe {
            check(ffi::mdb_env_create(&mut ptr))?;
            let env = Env { ptr };
            check(ffi::mdb_env_set_mapsize(ptr, map_size))?;
            check(ffi::mdb_env_set_maxdbs(ptr, max_dbs))?;
            check(ffi::mdb_env_set_maxreaders(ptr, max_readers))?;
            // NOTLS: read transactions belong to no thread, so they can run on
            // any blocking-pool thread. NORDAHEAD: lookups are random, so
            // read-ahead mostly wastes page cache once the map outgrows RAM.
            check(ffi::mdb_env_open(
                ptr,
                path.as_ptr(),
                ffi::MDB_NOTLS | ffi::MDB_NORDAHEAD,
                0o600,
            ))?;
            Ok(env)
        }
    }

    /// Open a table, creating it if need be. Call these at startup, before
    /// any other transaction: LMDB forbids opening tables concurrently.
    pub fn create_db(&self, name: &str, flags: DbFlags) -> Result<Db> {
        let name = CString::new(name).map_err(|_| Error(libc::EINVAL))?;
        let txn = self.write_txn()?;
        let mut dbi = 0;
        // SAFETY: a live write transaction and a NUL-terminated name.
        check(unsafe { ffi::mdb_dbi_open(txn.0.ptr, name.as_ptr(), flags.bits(), &mut dbi) })?;
        txn.commit()?;
        Ok(Db(dbi))
    }

    /// Write a compacted copy of the environment into the directory `path`.
    #[cfg(test)]
    pub fn copy_compact(&self, path: &Path) -> Result<()> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        // SAFETY: the env is open and the path NUL-terminated.
        check(unsafe { ffi::mdb_env_copy2(self.ptr, path.as_ptr(), ffi::MDB_CP_COMPACT) })
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(RoTxn(self.begin(ffi::MDB_RDONLY)?))
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        Ok(RwTxn(self.begin(0)?))
    }

    fn begin(&self, flags: u32) -> Result<Txn<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: the env is open; the transaction is freed by Txn's drop or commit.
        check(unsafe { ffi::mdb_txn_begin(self.ptr, ptr::null_mut(), flags, &mut ptr) })?;
        Ok(Txn {
            ptr,
            _env: PhantomData,
        })
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // SAFETY: every transaction borrows the env, so none outlives it.
        unsafe { ffi::mdb_env_close(self.ptr) }
    }
}

/// What reading needs, shared by both kinds of transaction. Values read
/// borrow the transaction, so a write (which takes `&mut`) can't leave one
/// dangling.
pub struct Txn<'env> {
    ptr: *mut ffi::MDB_txn,
    _env: PhantomData<&'env Env>,
}

impl Txn<'_> {
    pub fn get(&self, db: Db, key: &[u8]) -> Result<Option<&[u8]>> {
        let (mut k, mut v) = (val(key), empty());
        // SAFETY: a live transaction; the value is valid while `self` is borrowed.
        Ok(
            found(unsafe { ffi::mdb_get(self.ptr, db.0, &mut k, &mut v) })?
                .map(|()| unsafe { bytes(&v) }),
        )
    }

    pub fn cursor(&self, db: Db) -> Result<Cursor<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live transaction; the cursor is closed on drop, before the txn ends.
        check(unsafe { ffi::mdb_cursor_open(self.ptr, db.0, &mut ptr) })?;
        Ok(Cursor {
            ptr,
            _txn: PhantomData,
        })
    }

    /// How many entries `db` holds, counting each duplicate.
    #[cfg(test)]
    pub fn len(&self, db: Db) -> Result<usize> {
        // SAFETY: MDB_stat is plain data, filled in by LMDB.
        let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
        check(unsafe { ffi::mdb_stat(self.ptr, db.0, &mut stat) })?;
        Ok(stat.ms_entries)
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: not yet committed or aborted.
            unsafe { ffi::mdb_txn_abort(self.ptr) }
        }
    }
}

pub struct RoTxn<'env>(Txn<'env>);

impl<'env> std::ops::Deref for RoTxn<'env> {
    type Target = Txn<'env>;
    fn deref(&self) -> &Txn<'env> {
        &self.0
    }
}

pub struct RwTxn<'env>(Txn<'env>);

impl<'env> std::ops::Deref for RwTxn<'env> {
    type Target = Txn<'env>;
    fn deref(&self) -> &Txn<'env> {
        &self.0
    }
}

impl RwTxn<'_> {
    /// Store `value` under `key`. In a duplicate-sorted table it's added
    /// alongside the key's other values. Returns `false`, writing nothing,
    /// when that exact pair is already there.
    pub fn put(&mut self, db: Db, key: &[u8], value: &[u8]) -> Result<bool> {
        self.put_flags(db, key, value, 0)
    }

    /// Like [`put`](Self::put) for duplicate-sorted tables, where adding a
    /// pair that's already there is not an error but a no-op.
    pub fn put_dup(&mut self, db: Db, key: &[u8], value: &[u8]) -> Result<bool> {
        self.put_flags(db, key, value, ffi::MDB_NODUPDATA)
    }

    fn put_flags(&mut self, db: Db, key: &[u8], value: &[u8], flags: u32) -> Result<bool> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: a live write transaction, and `&mut self` keeps no reads alive.
        match unsafe { ffi::mdb_put(self.0.ptr, db.0, &mut k, &mut v, flags) } {
            ffi::MDB_KEYEXIST => Ok(false),
            code => check(code).map(|()| true),
        }
    }

    /// Remove a key and all its values, or with `value`, just that one value
    /// of a duplicate-sorted key. Returns whether anything was there.
    pub fn del(&mut self, db: Db, key: &[u8], value: Option<&[u8]>) -> Result<bool> {
        let mut k = val(key);
        let mut v = value.map(val);
        let v_ptr = v.as_mut().map_or(ptr::null_mut(), |v| v as *mut _);
        // SAFETY: a live write transaction; a null data pointer means "every value".
        Ok(found(unsafe { ffi::mdb_del(self.0.ptr, db.0, &mut k, v_ptr) })?.is_some())
    }

    pub fn commit(mut self) -> Result<()> {
        let ptr = std::mem::replace(&mut self.0.ptr, ptr::null_mut());
        // SAFETY: commit frees the transaction whatever it returns, so it's
        // nulled first to keep Drop from aborting it again.
        check(unsafe { ffi::mdb_txn_commit(ptr) })
    }
}

/// A position in one table. Every move returns the entry it lands on, or
/// `None` if there's none there.
pub struct Cursor<'t> {
    ptr: *mut ffi::MDB_cursor,
    _txn: PhantomData<&'t Txn<'t>>,
}

pub type Entry<'t> = (&'t [u8], &'t [u8]);

impl<'t> Cursor<'t> {
    fn op(
        &mut self,
        key: Option<&[u8]>,
        value: Option<&[u8]>,
        op: ffi::MDB_cursor_op,
    ) -> Result<Option<Entry<'t>>> {
        let mut k = key.map_or_else(empty, val);
        let mut v = value.map_or_else(empty, val);
        // SAFETY: a live cursor; returned slices live as long as the transaction.
        let hit = found(unsafe { ffi::mdb_cursor_get(self.ptr, &mut k, &mut v, op) })?;
        Ok(hit.map(|()| unsafe { (bytes(&k), bytes(&v)) }))
    }

    /// The first entry of `key` exactly.
    pub fn set(&mut self, key: &[u8]) -> Result<Option<Entry<'t>>> {
        self.op(Some(key), None, ffi::MDB_SET_KEY)
    }

    /// Within `key`'s duplicates, the first value at least `value`.
    pub fn get_both_range(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Entry<'t>>> {
        self.op(Some(key), Some(value), ffi::MDB_GET_BOTH_RANGE)
    }

    /// The first entry whose key is at least `key`.
    pub fn set_range(&mut self, key: &[u8]) -> Result<Option<Entry<'t>>> {
        self.op(Some(key), None, ffi::MDB_SET_RANGE)
    }

    pub fn first(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_FIRST)
    }

    pub fn next(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_NEXT)
    }

    /// The last value of the current key.
    pub fn last_dup(&mut self) -> Result<Option<Entry<'t>>> {
        // MDB_LAST_DUP returns only the value; the key is unchanged.
        let hit = self.op(None, None, ffi::MDB_LAST_DUP)?;
        Ok(hit.map(|(_, v)| (&[][..], v)))
    }

    /// The next value of the current key, not crossing into another.
    pub fn next_dup(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_NEXT_DUP)
    }

    /// The previous value of the current key, not crossing into another.
    pub fn prev_dup(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_PREV_DUP)
    }

    /// The first entry of the next key.
    pub fn next_nodup(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_NEXT_NODUP)
    }

    /// In a `DUP_FIXED` table, the whole page of values the cursor is on,
    /// packed — from the page's start, which may be before the cursor —
    /// leaving the cursor on its last. Empty when the key has only the one
    /// value, which LMDB keeps outside any page: it's the one the cursor is
    /// on.
    pub fn get_multiple(&mut self) -> Result<&'t [u8]> {
        Ok(self
            .op(None, None, ffi::MDB_GET_MULTIPLE)?
            .map_or(&[][..], |(_, v)| v))
    }

    /// The next page of the current key's values, as
    /// [`get_multiple`](Self::get_multiple) returns them.
    pub fn next_multiple(&mut self) -> Result<Option<&'t [u8]>> {
        Ok(self.op(None, None, ffi::MDB_NEXT_MULTIPLE)?.map(|(_, v)| v))
    }

    /// How many values the current key has.
    pub fn count(&mut self) -> Result<usize> {
        let mut count = 0;
        // SAFETY: a live, positioned cursor on a duplicate-sorted table.
        check(unsafe { ffi::mdb_cursor_count(self.ptr, &mut count) })?;
        Ok(count)
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // SAFETY: the cursor's transaction is still alive (it's borrowed).
        unsafe { ffi::mdb_cursor_close(self.ptr) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        (dir, env)
    }

    #[test]
    fn stores_and_deletes() {
        let (_dir, env) = open();
        let db = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let mut txn = env.write_txn().unwrap();
        assert!(txn.put(db, b"a", b"1").unwrap());
        assert!(txn.put(db, b"a", b"2").unwrap());
        assert_eq!(txn.get(db, b"a").unwrap(), Some(&b"2"[..]));
        txn.commit().unwrap();

        // Uncommitted writes vanish.
        let mut txn = env.write_txn().unwrap();
        assert!(txn.del(db, b"a", None).unwrap());
        assert!(!txn.del(db, b"a", None).unwrap());
        drop(txn);
        assert_eq!(
            env.read_txn().unwrap().get(db, b"a").unwrap(),
            Some(&b"2"[..])
        );
    }

    #[test]
    fn seeks_and_counts_within_duplicates() {
        let (_dir, env) = open();
        let db = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
        let mut txn = env.write_txn().unwrap();
        for n in [10u16, 20, 30, 40] {
            txn.put_dup(db, b"k", &n.to_be_bytes()).unwrap();
        }
        txn.put_dup(db, b"m", &5u16.to_be_bytes()).unwrap();
        assert!(!txn.put_dup(db, b"k", &20u16.to_be_bytes()).unwrap());
        assert!(txn.del(db, b"k", Some(&40u16.to_be_bytes())).unwrap());
        txn.commit().unwrap();

        let txn = env.read_txn().unwrap();
        let mut cursor = txn.cursor(db).unwrap();
        assert!(cursor.set(b"k").unwrap().is_some());
        assert_eq!(cursor.count().unwrap(), 3);

        let (_, v) = cursor
            .get_both_range(b"k", &25u16.to_be_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(v, 30u16.to_be_bytes());
        let (_, v) = cursor.prev_dup().unwrap().unwrap();
        assert_eq!(v, 20u16.to_be_bytes());
        cursor.prev_dup().unwrap().unwrap();
        // Doesn't cross into the previous key.
        assert!(cursor.prev_dup().unwrap().is_none());

        assert!(
            cursor
                .get_both_range(b"k", &99u16.to_be_bytes())
                .unwrap()
                .is_none()
        );
        cursor.set(b"k").unwrap();
        assert_eq!(cursor.last_dup().unwrap().unwrap().1, 30u16.to_be_bytes());
        assert!(cursor.set(b"x").unwrap().is_none());
        assert_eq!(txn.len(db).unwrap(), 4);
    }

    #[test]
    fn reads_duplicates_a_page_at_a_time() {
        let (_dir, env) = open();
        let db = env.create_db("pages", DbFlags::DUP_FIXED).unwrap();
        let mut txn = env.write_txn().unwrap();
        for n in 0..3000u32 {
            txn.put_dup(db, b"k", &n.to_be_bytes()).unwrap();
        }
        txn.put_dup(db, b"m", &7u32.to_be_bytes()).unwrap();
        txn.put_dup(db, b"n", &8u32.to_be_bytes()).unwrap();
        txn.commit().unwrap();

        let txn = env.read_txn().unwrap();
        let mut cursor = txn.cursor(db).unwrap();
        cursor
            .get_both_range(b"k", &1500u32.to_be_bytes())
            .unwrap()
            .unwrap();
        // The first page starts before the cursor; together they're all.
        let mut values = Vec::new();
        let mut page = Some(cursor.get_multiple().unwrap());
        let mut pages = 0;
        while let Some(bytes) = page {
            pages += 1;
            values.extend(
                bytes
                    .chunks(4)
                    .map(|c| u32::from_be_bytes(c.try_into().unwrap())),
            );
            page = cursor.next_multiple().unwrap();
        }
        assert!(pages > 1);
        assert!(values[0] <= 1500);
        assert_eq!(values.last(), Some(&2999));
        assert!(values.windows(2).all(|w| w[1] == w[0] + 1));

        // A lone value is on no page.
        let (key, _) = cursor.next_nodup().unwrap().unwrap();
        assert_eq!(key, b"m");
        assert!(cursor.get_multiple().unwrap().is_empty());
        assert!(cursor.next_multiple().unwrap().is_none());
        assert_eq!(cursor.next_nodup().unwrap().unwrap().0, b"n");
        assert!(cursor.next_nodup().unwrap().is_none());
    }

    #[test]
    fn orders_integer_keys_numerically() {
        let (_dir, env) = open();
        let db = env.create_db("ints", DbFlags::INTEGER_KEY).unwrap();
        let mut txn = env.write_txn().unwrap();
        for n in [256u64, 1, 65536] {
            txn.put(db, &n.to_ne_bytes(), b"").unwrap();
        }
        txn.commit().unwrap();
        let txn = env.read_txn().unwrap();
        let mut cursor = txn.cursor(db).unwrap();
        let key = |entry: Option<Entry>| u64::from_ne_bytes(entry.unwrap().0.try_into().unwrap());
        assert_eq!(key(cursor.first().unwrap()), 1);
        assert_eq!(key(cursor.next().unwrap()), 256);
        assert_eq!(key(cursor.next().unwrap()), 65536);
        assert!(cursor.next().unwrap().is_none());
        assert_eq!(key(cursor.set_range(&2u64.to_ne_bytes()).unwrap()), 256);
        assert!(cursor.set_range(&65537u64.to_ne_bytes()).unwrap().is_none());
    }
}
