//! A small, safe wrapper over the LMDB C API.
//!
//! heed has no way to seek within a key's sorted duplicates
//! (`MDB_GET_BOTH_RANGE`) or to count them (`mdb_cursor_count`). The relay's
//! indexes are built on exactly those: each is a `DUPSORT | DUPFIXED` table
//! whose key is stored once and whose entries are packed fixed-size values,
//! which is several times smaller than one key per entry.
//!
//! An [`Env`] may be several LMDB environments, each its own file, whose
//! tables are used as one: a transaction spans them all, and each [`Db`]
//! knows which it's in. Read transactions begin in the order the
//! environments were opened, and write transactions commit in the reverse,
//! so a reader sees everything the first environment's tables point to in
//! the others, as long as writers put it there in the same transaction. A
//! crash between the commits can leave the later environments with writes
//! the first never committed: callers must cope with those.
//!
//! Commits are never flushed to disk as they're made. What survives a crash
//! of the machine is a [checkpoint](crate::checkpoint), which [`Env`] pins.
//!
//! All the `unsafe` in the crate lives here.

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;

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
        let mut bits = 0;
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

    /// The flags of a table LMDB says has `bits`, if it's one of the kinds
    /// this module makes.
    fn from_bits(bits: u32) -> Result<DbFlags> {
        let flags = DbFlags {
            dup_sort: bits & ffi::MDB_DUPSORT != 0,
            dup_fixed: bits & ffi::MDB_DUPFIXED != 0,
            integer_key: bits & ffi::MDB_INTEGERKEY != 0,
        };
        let known = ffi::MDB_DUPSORT | ffi::MDB_DUPFIXED | ffi::MDB_INTEGERKEY;
        if bits & !known != 0 || flags.dup_sort != flags.dup_fixed {
            return Err(Error(ffi::MDB_INCOMPATIBLE));
        }
        Ok(flags)
    }
}

/// A table within one of an [`Env`]'s environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Db {
    dbi: ffi::MDB_dbi,
    env: usize,
}

/// The most environments an [`Env`] holds.
const MAX_ENVS: usize = 2;

/// See [`Env::usage`].
pub struct Usage {
    pub map: u64,
    pub used: u64,
}

pub struct Env {
    ptrs: Vec<*mut ffi::MDB_env>,
    /// Where each environment's file is mapped, and how much of it, if
    /// that could be found: LMDB doesn't say.
    maps: Vec<Option<(usize, usize)>>,
    /// Opened only to read: no write transaction can begin, so the writer's
    /// lock, which another process may hold, is never waited on.
    read_only: bool,
    /// The read transactions [checkpoints](Self::begin_checkpoint) hold.
    pins: Mutex<Pins>,
}

// SAFETY: an MDB_env is safe to share between threads; transactions opened
// from it carry their own restrictions, enforced by the types below.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

/// A read transaction in each environment, keeping LMDB from reusing the
/// pages of the commits it reads. Not tied to a thread, as environments
/// are opened with `MDB_NOTLS`.
struct Pin([*mut ffi::MDB_txn; MAX_ENVS]);

impl Drop for Pin {
    fn drop(&mut self) {
        for &ptr in &self.0 {
            if !ptr.is_null() {
                // SAFETY: a live read transaction, aborted only here.
                unsafe { ffi::mdb_txn_abort(ptr) }
            }
        }
    }
}

// SAFETY: see Pin; it's only ever aborted, by one thread at a time.
unsafe impl Send for Pin {}

#[derive(Default)]
struct Pins {
    /// The last checkpoint made durable.
    held: Option<Pin>,
    /// One begun, until it's made durable.
    pending: Option<Pin>,
}

/// What a checkpoint keeps of one environment, as of the commit it pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// The pinned commit.
    pub txnid: u64,
    pub page_size: usize,
    /// The environment's first two pages, its meta pages, one of them the
    /// pinned commit's.
    pub pages: Vec<u8>,
}

impl Env {
    /// Open (creating if need be) the environment in the directory `path`.
    /// Commits aren't flushed to disk: the kernel writes them when it
    /// likes, and a crash of the machine can leave the latest corrupt.
    /// [Checkpoints](Self::begin_checkpoint) are what survive one.
    pub fn open(path: &Path, map_size: usize, max_dbs: u32, max_readers: u32) -> Result<Env> {
        let mut env = Env::new(false);
        env.add(path, map_size, ffi::MDB_NOSYNC, max_dbs, max_readers)?;
        Ok(env)
    }

    /// Open the existing environment in the directory `path` only to read.
    /// Its tables must exist already, and are opened without writing.
    pub fn open_read_only(
        path: &Path,
        map_size: usize,
        max_dbs: u32,
        max_readers: u32,
    ) -> Result<Env> {
        let mut env = Env::new(true);
        env.add(path, map_size, ffi::MDB_RDONLY, max_dbs, max_readers)?;
        Ok(env)
    }

    fn new(read_only: bool) -> Env {
        Env {
            ptrs: Vec::new(),
            maps: Vec::new(),
            read_only,
            pins: Mutex::default(),
        }
    }

    /// Open (creating if need be) another environment, in the directory
    /// `path`, whose tables share this one's transactions, returning which
    /// it is for [`create_db_in`](Self::create_db_in). It's for tables
    /// written in order, mostly appended to: the pages a commit writes are
    /// together, so they're written with a single call, not one each.
    pub fn attach(
        &mut self,
        path: &Path,
        map_size: usize,
        max_dbs: u32,
        max_readers: u32,
    ) -> Result<usize> {
        assert!(self.ptrs.len() < MAX_ENVS, "too many environments");
        let flags = match self.read_only {
            true => ffi::MDB_RDONLY,
            false => ffi::MDB_NOSYNC,
        };
        self.add(path, map_size, flags, max_dbs, max_readers)?;
        Ok(self.ptrs.len() - 1)
    }

    fn add(
        &mut self,
        path: &Path,
        map_size: usize,
        flags: u32,
        max_dbs: u32,
        max_readers: u32,
    ) -> Result<()> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        let mut ptr = ptr::null_mut();
        // SAFETY: plain FFI calls in the documented order; the env is closed
        // by Drop if any fails, once it's in `ptrs`.
        unsafe {
            check(ffi::mdb_env_create(&mut ptr))?;
            self.ptrs.push(ptr);
            check(ffi::mdb_env_set_mapsize(ptr, map_size))?;
            check(ffi::mdb_env_set_maxdbs(ptr, max_dbs))?;
            check(ffi::mdb_env_set_maxreaders(ptr, max_readers))?;
            // NOTLS: read transactions belong to no thread, so they can run on
            // any blocking-pool thread. NORDAHEAD: lookups are random, so
            // read-ahead mostly wastes page cache once the map outgrows RAM.
            let flags = flags | ffi::MDB_NOTLS | ffi::MDB_NORDAHEAD;
            check(ffi::mdb_env_open(ptr, path.as_ptr(), flags, 0o600))?;
        }
        self.maps.push(map_of(ptr));
        Ok(())
    }

    /// Begin a checkpoint of the latest commit: pin it, so that LMDB reuses
    /// none of its pages, and return each environment's meta pages, which
    /// point to them. Call it between write transactions, as one commit
    /// overwrites the meta page of the commit before last. Once
    /// [`sync`](Self::sync) has made the pinned commit durable and the meta
    /// pages are kept somewhere durable too, writing them back into a store
    /// whose machine crashed gets it back. Abandons a checkpoint begun and
    /// not [confirmed](Self::confirm_checkpoint).
    pub fn begin_checkpoint(&self) -> Result<Vec<Meta>> {
        let mut pin = Pin([ptr::null_mut(); MAX_ENVS]);
        for (env, slot) in self.ptrs.iter().zip(&mut pin.0) {
            // SAFETY: the env is open; the transaction is aborted by Pin's drop.
            check(unsafe { ffi::mdb_txn_begin(*env, ptr::null_mut(), ffi::MDB_RDONLY, slot) })?;
        }
        let mut metas = Vec::new();
        for (&env, &txn) in self.ptrs.iter().zip(&pin.0) {
            // SAFETY: plain data, filled in by LMDB from an open env, and a
            // live transaction.
            let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
            check(unsafe { ffi::mdb_env_stat(env, &mut stat) })?;
            let txnid = unsafe { ffi::mdb_txn_id(txn) } as u64;
            let mut fd = -1;
            check(unsafe { ffi::mdb_env_get_fd(env, &mut fd) })?;
            let page_size = stat.ms_psize as usize;
            let mut pages = vec![0; 2 * page_size];
            // SAFETY: reads into a buffer of the length given, from a file
            // LMDB holds open.
            let read = unsafe { libc::pread(fd, pages.as_mut_ptr().cast(), pages.len(), 0) };
            if read != pages.len() as isize {
                return Err(Error(libc::EIO));
            }
            metas.push(Meta {
                txnid,
                page_size,
                pages,
            });
        }
        self.pins.lock().expect("unpoisoned").pending = Some(pin);
        Ok(metas)
    }

    /// Flush every environment's file to disk, the last environment first.
    /// Safe to call while others read and write.
    pub fn sync(&self) -> Result<()> {
        for &env in self.ptrs.iter().rev() {
            // SAFETY: the env is open; 1 forces the flush, as NOSYNC skips it.
            check(unsafe { ffi::mdb_env_sync(env, 1) })?;
        }
        Ok(())
    }

    /// The checkpoint begun last is durable: keep it pinned in place of the
    /// one before, whose pages LMDB may now reuse.
    pub fn confirm_checkpoint(&self) {
        let mut pins = self.pins.lock().expect("unpoisoned");
        if let Some(pending) = pins.pending.take() {
            pins.held = Some(pending);
        }
    }

    /// Open a table, creating it if need be, or if the environment is
    /// [read-only](Self::open_read_only), only if it exists. Call these at
    /// startup, before any other transaction: LMDB forbids opening tables
    /// concurrently.
    pub fn create_db(&self, name: &str, flags: DbFlags) -> Result<Db> {
        self.create_db_in(0, name, flags)
    }

    /// Open a table in the environment `env`, as [`create_db`](Self::create_db).
    pub fn create_db_in(&self, env: usize, name: &str, flags: DbFlags) -> Result<Db> {
        let name = CString::new(name).map_err(|_| Error(libc::EINVAL))?;
        let (txn, bits) = match self.read_only {
            true => (self.begin(ffi::MDB_RDONLY)?, flags.bits()),
            false => (self.write_txn()?.0, flags.bits() | ffi::MDB_CREATE),
        };
        let mut dbi = 0;
        // SAFETY: a live transaction and a NUL-terminated name.
        check(unsafe { ffi::mdb_dbi_open(txn.ptrs[env], name.as_ptr(), bits, &mut dbi) })?;
        // Committed, even only to read, so the handle outlives it.
        RwTxn(txn).commit()?;
        Ok(Db { dbi, env })
    }

    /// Delete the table `name` in the first environment, if there is one,
    /// returning how many entries it held.
    pub fn remove_db(&self, name: &str) -> Result<Option<usize>> {
        let name = CString::new(name).map_err(|_| Error(libc::EINVAL))?;
        let txn = self.write_txn()?;
        let mut dbi = 0;
        // SAFETY: a live write transaction and a NUL-terminated name.
        if found(unsafe { ffi::mdb_dbi_open(txn.0.ptrs[0], name.as_ptr(), 0, &mut dbi) })?.is_none()
        {
            return Ok(None);
        }
        let entries = txn.len(Db { dbi, env: 0 })?;
        // SAFETY: a live write transaction; 1 deletes the table and closes
        // its handle, which nothing else holds.
        check(unsafe { ffi::mdb_drop(txn.0.ptrs[0], dbi, 1) })?;
        txn.commit()?;
        Ok(Some(entries))
    }

    /// Every table in the first environment, opened, with its flags, in
    /// the order of their names. Like [`create_db`](Self::create_db), call
    /// it before any other transaction.
    pub fn tables(&self) -> Result<Vec<(String, Db, DbFlags)>> {
        let txn = self.begin(ffi::MDB_RDONLY)?;
        let ptr = txn.ptrs[0];
        let mut main = 0;
        // SAFETY: a live transaction; a null name is the table of tables.
        check(unsafe { ffi::mdb_dbi_open(ptr, ptr::null(), 0, &mut main) })?;
        let mut names = Vec::new();
        let mut cursor = txn.cursor(Db { dbi: main, env: 0 })?;
        let mut entry = cursor.first()?;
        while let Some((name, _)) = entry {
            names.push(String::from_utf8(name.to_vec()).map_err(|_| Error(ffi::MDB_INCOMPATIBLE))?);
            entry = cursor.next()?;
        }
        drop(cursor);
        let mut tables = Vec::new();
        for name in names {
            let c_name = CString::new(name.as_str()).map_err(|_| Error(ffi::MDB_INCOMPATIBLE))?;
            let (mut dbi, mut bits) = (0, 0);
            // SAFETY: a live transaction and a NUL-terminated name. An
            // existing table's flags are its own, whatever's passed.
            check(unsafe { ffi::mdb_dbi_open(ptr, c_name.as_ptr(), 0, &mut dbi) })?;
            check(unsafe { ffi::mdb_dbi_flags(ptr, dbi, &mut bits) })?;
            tables.push((name, Db { dbi, env: 0 }, DbFlags::from_bits(bits)?));
        }
        // Committed, so the handles outlive it.
        RwTxn(txn).commit()?;
        Ok(tables)
    }

    /// Write a compacted copy of the environment `env` into the directory
    /// `path`.
    #[cfg(test)]
    pub fn copy_compact(&self, env: usize, path: &Path) -> Result<()> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        // SAFETY: the env is open and the path NUL-terminated.
        check(unsafe { ffi::mdb_env_copy2(self.ptrs[env], path.as_ptr(), ffi::MDB_CP_COMPACT) })
    }

    /// How big the environment `env`'s map is, and how much of it is used,
    /// in bytes.
    pub fn usage(&self, env: usize) -> Result<Usage> {
        let ptr = self.ptrs[env];
        // SAFETY: plain data, filled in by LMDB from an open env.
        let mut info = unsafe { std::mem::zeroed::<ffi::MDB_envinfo>() };
        let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
        check(unsafe { ffi::mdb_env_info(ptr, &mut info) })?;
        check(unsafe { ffi::mdb_env_stat(ptr, &mut stat) })?;
        Ok(Usage {
            map: info.me_mapsize as u64,
            used: (info.me_last_pgno as u64 + 1) * u64::from(stat.ms_psize),
        })
    }

    /// Have the kernel start reading the `len` bytes of environment
    /// `env`'s file from where `at`, read from its map, is, so that reading
    /// on from there in order doesn't wait on the disk a page at a time:
    /// environments are opened without the kernel's readahead, which
    /// random lookups have no use for. Only a hint, so failing is no error.
    pub fn will_need(&self, env: usize, at: &[u8], len: usize) {
        let mut fd = -1;
        // SAFETY: the env is open.
        if check(unsafe { ffi::mdb_env_get_fd(self.ptrs[env], &mut fd) }).is_err() {
            return;
        }
        let Some(offset) = self.offset_of(env, at) else {
            return;
        };
        // SAFETY: advice on a file LMDB holds open; nothing is read or
        // written through any pointer.
        unsafe {
            libc::posix_fadvise(
                fd,
                offset as libc::off_t,
                len as libc::off_t,
                libc::POSIX_FADV_WILLNEED,
            );
        }
    }

    /// Where in environment `env`'s file `at`, read from its map, is, if
    /// it's from there.
    pub fn offset_of(&self, env: usize, at: &[u8]) -> Option<usize> {
        let (base, len) = self.maps[env]?;
        let offset = (at.as_ptr() as usize).checked_sub(base)?;
        (offset < len).then_some(offset)
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(RoTxn(self.begin(ffi::MDB_RDONLY)?))
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        Ok(RwTxn(self.begin(0)?))
    }

    /// A transaction in each environment, in the order they were opened.
    fn begin(&self, flags: u32) -> Result<Txn<'_>> {
        let mut txn = Txn {
            ptrs: [ptr::null_mut(); MAX_ENVS],
            _env: PhantomData,
        };
        for (env, slot) in self.ptrs.iter().zip(&mut txn.ptrs) {
            // SAFETY: the env is open; the transaction is freed by Txn's
            // drop or commit, those already begun too if this fails.
            check(unsafe { ffi::mdb_txn_begin(*env, ptr::null_mut(), flags, slot) })?;
        }
        Ok(txn)
    }
}

/// Where the environment `env`'s file is mapped, and how long the mapping
/// is: LMDB's `me_mapaddr` is only where it asked to map it, with
/// `MDB_FIXEDMAP`. Found in `/proc/self/maps`, as the one mapping of the
/// file, by inode, from its start, of the map's size.
fn map_of(env: *mut ffi::MDB_env) -> Option<(usize, usize)> {
    // SAFETY: plain data, filled in by LMDB from an open env.
    let mut info = unsafe { std::mem::zeroed::<ffi::MDB_envinfo>() };
    let mut fd = -1;
    check(unsafe { ffi::mdb_env_info(env, &mut info) }).ok()?;
    check(unsafe { ffi::mdb_env_get_fd(env, &mut fd) }).ok()?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: an open descriptor, and a buffer of the right type.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return None;
    }
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut found = maps.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let (range, _, offset, _, inode) = (
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
        );
        let (start, end) = range.split_once('-')?;
        let (start, end) = (
            usize::from_str_radix(start, 16).ok()?,
            usize::from_str_radix(end, 16).ok()?,
        );
        let ours = inode.parse::<u64>().ok()? == stat.st_ino as u64
            && usize::from_str_radix(offset, 16).ok()? == 0
            && end - start == info.me_mapsize.next_multiple_of(4096);
        ours.then_some((start, end - start))
    });
    // The same file mapped twice, as by opening it twice: no telling which.
    match (found.next(), found.next()) {
        (Some(map), None) => Some(map),
        _ => None,
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Its transactions first.
        *self.pins.get_mut().expect("unpoisoned") = Pins::default();
        for &ptr in &self.ptrs {
            // SAFETY: every transaction borrows the env, so none outlives it.
            unsafe { ffi::mdb_env_close(ptr) }
        }
    }
}

/// What reading needs, shared by both kinds of transaction. Values read
/// borrow the transaction, so a write (which takes `&mut`) can't leave one
/// dangling.
pub struct Txn<'env> {
    /// One per environment, null past the last.
    ptrs: [*mut ffi::MDB_txn; MAX_ENVS],
    _env: PhantomData<&'env Env>,
}

impl Txn<'_> {
    /// The transaction in `db`'s environment.
    fn of(&self, db: Db) -> *mut ffi::MDB_txn {
        self.ptrs[db.env]
    }

    pub fn get(&self, db: Db, key: &[u8]) -> Result<Option<&[u8]>> {
        let (mut k, mut v) = (val(key), empty());
        // SAFETY: a live transaction; the value is valid while `self` is borrowed.
        Ok(
            found(unsafe { ffi::mdb_get(self.of(db), db.dbi, &mut k, &mut v) })?
                .map(|()| unsafe { bytes(&v) }),
        )
    }

    pub fn cursor(&self, db: Db) -> Result<Cursor<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live transaction; the cursor is closed on drop, before the txn ends.
        check(unsafe { ffi::mdb_cursor_open(self.of(db), db.dbi, &mut ptr) })?;
        Ok(Cursor {
            ptr,
            _txn: PhantomData,
        })
    }

    /// How `a` and `b` compare as `db`'s keys.
    pub fn cmp(&self, db: Db, a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        let (a, b) = (val(a), val(b));
        // SAFETY: a live transaction; LMDB only reads the two values.
        unsafe { ffi::mdb_cmp(self.of(db), db.dbi, &a, &b) }.cmp(&0)
    }

    /// How many entries `db` holds, counting each duplicate.
    pub fn len(&self, db: Db) -> Result<usize> {
        // SAFETY: MDB_stat is plain data, filled in by LMDB.
        let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
        check(unsafe { ffi::mdb_stat(self.of(db), db.dbi, &mut stat) })?;
        Ok(stat.ms_entries)
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        for &ptr in &self.ptrs {
            if !ptr.is_null() {
                // SAFETY: not yet committed or aborted.
                unsafe { ffi::mdb_txn_abort(ptr) }
            }
        }
    }
}

pub struct RoTxn<'env>(Txn<'env>);

// SAFETY: the environments are opened with MDB_NOTLS, so a read-only
// transaction belongs to no thread and may move to another; not being Sync,
// it's still only used by one at a time, as LMDB requires.
unsafe impl Send for RoTxn<'_> {}

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

    /// Store `value` under `key`, which must sort after every key in the
    /// table. LMDB then fills pages rather than splitting them in half.
    /// Returns `false`, writing nothing, if it doesn't.
    pub fn append(&mut self, db: Db, key: &[u8], value: &[u8]) -> Result<bool> {
        self.put_flags(db, key, value, ffi::MDB_APPEND)
    }

    fn put_flags(&mut self, db: Db, key: &[u8], value: &[u8], flags: u32) -> Result<bool> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: a live write transaction, and `&mut self` keeps no reads alive.
        match unsafe { ffi::mdb_put(self.0.of(db), db.dbi, &mut k, &mut v, flags) } {
            ffi::MDB_KEYEXIST => Ok(false),
            code => check(code).map(|()| true),
        }
    }

    /// A cursor that appends to `db`, for writing a table in order.
    pub fn appender(&mut self, db: Db) -> Result<Appender<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live write transaction, borrowed mutably while the
        // cursor lives; it's closed on drop.
        check(unsafe { ffi::mdb_cursor_open(self.0.of(db), db.dbi, &mut ptr) })?;
        Ok(Appender {
            ptr,
            _txn: PhantomData,
        })
    }

    /// Remove a key and all its values, or with `value`, just that one value
    /// of a duplicate-sorted key. Returns whether anything was there.
    pub fn del(&mut self, db: Db, key: &[u8], value: Option<&[u8]>) -> Result<bool> {
        let mut k = val(key);
        let mut v = value.map(val);
        let v_ptr = v.as_mut().map_or(ptr::null_mut(), |v| v as *mut _);
        // SAFETY: a live write transaction; a null data pointer means "every value".
        Ok(found(unsafe { ffi::mdb_del(self.0.of(db), db.dbi, &mut k, v_ptr) })?.is_some())
    }

    /// Remove every entry of a table, keeping the table.
    pub fn clear(&mut self, db: Db) -> Result<()> {
        // SAFETY: a live write transaction; 0 empties the table without
        // closing its handle.
        check(unsafe { ffi::mdb_drop(self.0.of(db), db.dbi, 0) })
    }

    /// Commit, the last environment opened first. If one fails, those not
    /// yet committed are aborted.
    pub fn commit(mut self) -> Result<()> {
        for slot in self.0.ptrs.iter_mut().rev() {
            if slot.is_null() {
                continue;
            }
            let ptr = std::mem::replace(slot, ptr::null_mut());
            // SAFETY: commit frees the transaction whatever it returns, so
            // it's nulled first to keep Drop from aborting it again.
            check(unsafe { ffi::mdb_txn_commit(ptr) })?;
        }
        Ok(())
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

    /// The last entry, the last value of the last key.
    pub fn last(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_LAST)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_NEXT)
    }

    pub fn prev(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, None, ffi::MDB_PREV)
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

    /// The page of the current key's values before the one
    /// [`get_multiple`](Self::get_multiple) or this last returned, as
    /// that returns them.
    pub fn prev_multiple(&mut self) -> Result<Option<&'t [u8]>> {
        Ok(self.op(None, None, ffi::MDB_PREV_MULTIPLE)?.map(|(_, v)| v))
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

/// A cursor writing a table in order, from [`RwTxn::appender`]. LMDB fills
/// each page before starting the next, rather than splitting them in half.
/// Anything out of order is refused with `MDB_KEYEXIST`.
pub struct Appender<'t> {
    ptr: *mut ffi::MDB_cursor,
    _txn: PhantomData<&'t mut ()>,
}

impl Appender<'_> {
    /// Store `value` under `key`, which must sort after every key in the
    /// table.
    pub fn append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: a live cursor of a live write transaction.
        check(unsafe { ffi::mdb_cursor_put(self.ptr, &mut k, &mut v, ffi::MDB_APPEND) })
    }

    /// In a `DUP_FIXED` table, store `values`, packed, each `size` bytes and
    /// in order, under `key`, after its other values. With `new`, `key` must
    /// sort after every key in the table; else it must be the last.
    pub fn append_dups(&mut self, key: &[u8], values: &[u8], size: usize, new: bool) -> Result<()> {
        if size == 0 || values.is_empty() || !values.len().is_multiple_of(size) {
            return Err(Error(libc::EINVAL));
        }
        let count = values.len() / size;
        let mut k = val(key);
        // MDB_MULTIPLE: the first the size and where, the second how many.
        let mut data = [
            ffi::MDB_val {
                mv_size: size,
                mv_data: values.as_ptr() as *mut _,
            },
            ffi::MDB_val {
                mv_size: count,
                mv_data: ptr::null_mut(),
            },
        ];
        let mut flags = ffi::MDB_MULTIPLE | ffi::MDB_APPENDDUP;
        if new {
            flags |= ffi::MDB_APPEND;
        }
        // SAFETY: a live cursor of a live write transaction; LMDB reads
        // `count` values of `size` bytes from `values`, and writes into
        // `data[1]` how many it stored.
        check(unsafe { ffi::mdb_cursor_put(self.ptr, &mut k, data.as_mut_ptr(), flags) })?;
        match data[1].mv_size == count {
            true => Ok(()),
            false => Err(Error(ffi::MDB_PROBLEM)),
        }
    }
}

impl Drop for Appender<'_> {
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

    /// A transaction spans every environment: committed together, and
    /// dropped together.
    #[test]
    fn spans_environments() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let mut env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        assert_eq!(env.attach(&other, 1 << 24, 4, 16).unwrap(), 1);
        let main = env.create_db("main", DbFlags::PLAIN).unwrap();
        let appended = env
            .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
            .unwrap();

        let mut txn = env.write_txn().unwrap();
        txn.put(main, b"a", b"1").unwrap();
        assert!(txn.append(appended, &1u64.to_ne_bytes(), b"one").unwrap());
        assert!(txn.append(appended, &2u64.to_ne_bytes(), b"two").unwrap());
        // Only past the last key.
        assert!(!txn.append(appended, &1u64.to_ne_bytes(), b"uno").unwrap());
        drop(txn);
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.len(main).unwrap() + txn.len(appended).unwrap(), 0);
        drop(txn);

        let mut txn = env.write_txn().unwrap();
        txn.put(main, b"a", b"1").unwrap();
        txn.append(appended, &1u64.to_ne_bytes(), b"one").unwrap();
        txn.commit().unwrap();
        drop(env);

        let mut env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        env.attach(&other, 1 << 24, 4, 16).unwrap();
        let main = env.create_db("main", DbFlags::PLAIN).unwrap();
        let appended = env
            .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
            .unwrap();
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.get(main, b"a").unwrap(), Some(&b"1"[..]));
        assert_eq!(
            txn.get(appended, &1u64.to_ne_bytes()).unwrap(),
            Some(&b"one"[..])
        );
    }

    /// Opened only to read, tables are opened without writing anything.
    #[test]
    fn opens_tables_only_to_read() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        {
            let mut env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
            env.attach(&other, 1 << 24, 4, 16).unwrap();
            let main = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
            let appended = env
                .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
                .unwrap();
            let mut txn = env.write_txn().unwrap();
            txn.put(main, b"a", b"1").unwrap();
            txn.append(appended, &1u64.to_ne_bytes(), b"one").unwrap();
            txn.commit().unwrap();
        }

        let mut env = Env::open_read_only(dir.path(), 1 << 24, 4, 16).unwrap();
        env.attach(&other, 1 << 24, 4, 16).unwrap();
        let main = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
        let appended = env
            .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
            .unwrap();
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.get(main, b"a").unwrap(), Some(&b"1"[..]));
        assert_eq!(
            txn.get(appended, &1u64.to_ne_bytes()).unwrap(),
            Some(&b"one"[..])
        );
        drop(txn);
        // Nothing is made, and nothing written.
        assert!(env.create_db("missing", DbFlags::PLAIN).is_err());
        assert!(env.write_txn().is_err());
    }

    #[test]
    fn removes_tables() {
        let (_dir, env) = open();
        let db = env.create_db("gone", DbFlags::PLAIN).unwrap();
        let mut txn = env.write_txn().unwrap();
        txn.put(db, b"a", b"1").unwrap();
        txn.put(db, b"b", b"2").unwrap();
        txn.commit().unwrap();
        assert_eq!(env.remove_db("gone").unwrap(), Some(2));
        assert_eq!(env.remove_db("gone").unwrap(), None);
    }

    #[test]
    fn keeps_writes_without_sync() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        let db = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let mut txn = env.write_txn().unwrap();
        txn.put(db, b"a", &[7; 10_000]).unwrap();
        txn.commit().unwrap();
        drop(env);

        let env = Env::open(dir.path(), 1 << 24, 4, 16).unwrap();
        let db = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.get(db, b"a").unwrap(), Some(&[7; 10_000][..]));
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

    /// Where a value read is in the file, as read ahead goes by.
    #[test]
    fn knows_where_its_file_is_mapped() {
        let (dir, env) = open();
        let db = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let mut txn = env.write_txn().unwrap();
        txn.put(db, b"k", &[7; 3000]).unwrap();
        txn.commit().unwrap();
        env.sync().unwrap();
        let txn = env.read_txn().unwrap();
        let value = txn.get(db, b"k").unwrap().unwrap();
        let offset = env.offset_of(0, value).expect("the map found");
        let file = std::fs::read(dir.path().join("data.mdb")).unwrap();
        assert_eq!(&file[offset..offset + value.len()], value);
        assert_eq!(env.offset_of(0, &[1, 2, 3]), None);
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
