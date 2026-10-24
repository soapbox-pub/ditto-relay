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
//! One of an [`Env`]'s environments can be [replaced](Env::replace) by
//! another while it's in use, as [`crate::repack`] does with a compacted
//! copy. Each transaction holds the environments it began in, which are
//! closed once the last that holds them ends. What's committed to one
//! meanwhile can be kept in a [`Journal`], to be replayed into the copy.
//!
//! All the `unsafe` in the crate lives here.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::{ArcSwap, ArcSwapOption};
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

impl Error {
    /// Whether it's LMDB's `MDB_NOTFOUND`, as for a table that isn't there.
    pub fn is_not_found(&self) -> bool {
        self.0 == ffi::MDB_NOTFOUND
    }

    /// LMDB's `MDB_CORRUPTED`, for something read that can't be.
    pub fn corrupted() -> Error {
        Error(ffi::MDB_CORRUPTED)
    }
}

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

/// How much of a [`will_need`](Env::will_need) is read at a time.
const READ_AHEAD_CHUNK: usize = 1 << 20;

/// The most reads ahead at once: more than the disk keeps up with are left
/// undone, as advice the kernel couldn't take would be.
const MAX_READS_AHEAD: usize = 16;

/// How many reads ahead are going.
static READS_AHEAD: AtomicUsize = AtomicUsize::new(0);

/// See [`Env::usage`].
pub struct Usage {
    pub map: u64,
    pub used: u64,
}

/// How much a [replay](Env::replay) writes in one transaction, about.
const REPLAY_COMMIT_BYTES: u64 = 64 << 20;

/// One LMDB environment, closed once nothing holds it.
struct Handle {
    ptr: *mut ffi::MDB_env,
    /// Where its file is mapped, and how much of it, if that could be
    /// found: LMDB doesn't say.
    map: Option<(usize, usize)>,
    /// What it was opened with, for one [alike](Env::create_like).
    map_size: usize,
    max_dbs: u32,
    max_readers: u32,
    /// The tables opened in it: their handles, names and flags.
    tables: Mutex<Vec<(ffi::MDB_dbi, String, DbFlags)>>,
}

// SAFETY: an MDB_env is safe to share between threads; transactions opened
// from it carry their own restrictions, enforced by the types below.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: every transaction holds the handles it's in, so none is
        // left in this one.
        unsafe { ffi::mdb_env_close(self.ptr) }
    }
}

/// An [`Env`]'s environments, in the order they were opened.
type Envs = Arc<Vec<Arc<Handle>>>;

pub struct Env {
    envs: ArcSwap<Vec<Arc<Handle>>>,
    /// Opened only to read: no write transaction can begin, so the writer's
    /// lock, which another process may hold, is never waited on.
    read_only: bool,
    /// The read transactions [checkpoints](Self::begin_checkpoint) hold.
    pins: Mutex<Pins>,
    /// Where what's committed to one of the environments is kept, if it is.
    journal: ArcSwapOption<Journal>,
}

/// A read transaction in each environment, keeping LMDB from reusing the
/// pages of the commits it reads. Not tied to a thread, as environments
/// are opened with `MDB_NOTLS`.
struct Pin {
    txns: [*mut ffi::MDB_txn; MAX_ENVS],
    _envs: Envs,
}

impl Drop for Pin {
    fn drop(&mut self) {
        for &ptr in &self.txns {
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

/// What's committed to one environment of an [`Env`] from when
/// [`Env::journal`] begins it, kept in a file as it's committed, to be
/// [replayed](Env::replay) into a copy of the environment as it was then.
/// A commit is its length (u64 LE), then its changes, each a tag, the
/// table's handle (u32 LE), and what the change takes, each byte string
/// its length (u32 LE) first:
///
/// | tag | change                                   |
/// |-----|------------------------------------------|
/// | 1   | put a key and value                      |
/// | 2   | delete a key, then 0, or 1 and its value |
/// | 3   | empty the table                          |
pub struct Journal {
    env: usize,
    /// Written, and locked from a commit until it's written, so that what's
    /// committed is in it once a writer that waited on the commit begins.
    file: Mutex<File>,
    /// Read from, while it's written.
    reader: File,
    /// How much of the file holds whole commits.
    written: AtomicU64,
    /// Whether a commit couldn't be written, which makes it of no use.
    failed: AtomicBool,
}

const OP_PUT: u8 = 1;
const OP_DEL: u8 = 2;
const OP_CLEAR: u8 = 3;

impl Journal {
    /// How much it holds, in bytes.
    pub fn len(&self) -> u64 {
        self.written.load(Ordering::Acquire)
    }

    /// Whether it holds nothing yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How much it holds once every commit made already is in it.
    fn settled(&self) -> u64 {
        let _file = self.file.lock().expect("unpoisoned");
        self.len()
    }

    /// Add a commit's changes, `ops`, to `file`, its own.
    fn append(&self, file: &File, ops: &[u8]) {
        if self.failed.load(Ordering::Relaxed) {
            return;
        }
        let at = self.written.load(Ordering::Relaxed);
        let wrote = file
            .write_all_at(&(ops.len() as u64).to_le_bytes(), at)
            .and_then(|()| file.write_all_at(ops, at + 8));
        match wrote {
            Ok(()) => self
                .written
                .store(at + 8 + ops.len() as u64, Ordering::Release),
            Err(err) => {
                tracing::error!("keeping a commit in the journal failed: {err}");
                self.failed.store(true, Ordering::Relaxed);
            }
        }
    }
}

fn put_field(ops: &mut Vec<u8>, bytes: &[u8]) {
    ops.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    ops.extend_from_slice(bytes);
}

fn record_put(ops: &mut Vec<u8>, dbi: ffi::MDB_dbi, key: &[u8], value: &[u8]) {
    ops.push(OP_PUT);
    ops.extend_from_slice(&dbi.to_le_bytes());
    put_field(ops, key);
    put_field(ops, value);
}

fn record_del(ops: &mut Vec<u8>, dbi: ffi::MDB_dbi, key: &[u8], value: Option<&[u8]>) {
    ops.push(OP_DEL);
    ops.extend_from_slice(&dbi.to_le_bytes());
    put_field(ops, key);
    match value {
        Some(value) => {
            ops.push(1);
            put_field(ops, value);
        }
        None => ops.push(0),
    }
}

fn record_clear(ops: &mut Vec<u8>, dbi: ffi::MDB_dbi) {
    ops.push(OP_CLEAR);
    ops.extend_from_slice(&dbi.to_le_bytes());
}

/// The changes of a commit in a [`Journal`], read one field at a time.
struct Ops<'a>(&'a [u8]);

impl<'a> Ops<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(Error::corrupted())?;
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn field(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// Make the changes of a commit in a [`Journal`] in `txn`, of an
/// environment of its own whose tables are numbered as the journal's are.
fn apply(txn: &mut RwTxn, ops: &[u8]) -> Result<()> {
    let mut ops = Ops(ops);
    while !ops.0.is_empty() {
        let tag = ops.byte()?;
        let db = Db {
            dbi: ops.u32()?,
            env: 0,
        };
        match tag {
            OP_PUT => {
                let (key, value) = (ops.field()?, ops.field()?);
                txn.put(db, key, value)?;
            }
            OP_DEL => {
                let key = ops.field()?;
                let value = match ops.byte()? {
                    0 => None,
                    _ => Some(ops.field()?),
                };
                txn.del(db, key, value)?;
            }
            OP_CLEAR => txn.clear(db)?,
            _ => return Err(Error::corrupted()),
        }
    }
    Ok(())
}

fn io_error(err: std::io::Error) -> Error {
    Error(err.raw_os_error().unwrap_or(libc::EIO))
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
            envs: ArcSwap::from_pointee(Vec::new()),
            read_only,
            pins: Mutex::default(),
            journal: ArcSwapOption::empty(),
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
        assert!(self.envs.load().len() < MAX_ENVS, "too many environments");
        let flags = match self.read_only {
            true => ffi::MDB_RDONLY,
            false => ffi::MDB_NOSYNC,
        };
        self.add(path, map_size, flags, max_dbs, max_readers)?;
        Ok(self.envs.load().len() - 1)
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
        // SAFETY: creates the env, closed by the handle's drop from then on.
        check(unsafe { ffi::mdb_env_create(&mut ptr) })?;
        let mut handle = Handle {
            ptr,
            map: None,
            map_size,
            max_dbs,
            max_readers,
            tables: Mutex::default(),
        };
        // SAFETY: plain FFI calls in the documented order, on the env just
        // created.
        unsafe {
            check(ffi::mdb_env_set_mapsize(ptr, map_size))?;
            check(ffi::mdb_env_set_maxdbs(ptr, max_dbs))?;
            check(ffi::mdb_env_set_maxreaders(ptr, max_readers))?;
            // NOTLS: read transactions belong to no thread, so they can run on
            // any blocking-pool thread. NORDAHEAD: lookups are random, so
            // read-ahead mostly wastes page cache once the map outgrows RAM.
            let flags = flags | ffi::MDB_NOTLS | ffi::MDB_NORDAHEAD;
            check(ffi::mdb_env_open(ptr, path.as_ptr(), flags, 0o600))?;
        }
        handle.map = map_of(ptr);
        let mut envs = Vec::clone(&self.envs.load());
        envs.push(Arc::new(handle));
        self.envs.store(Arc::new(envs));
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
        let envs = self.envs.load_full();
        let mut pin = Pin {
            txns: [ptr::null_mut(); MAX_ENVS],
            _envs: envs.clone(),
        };
        for (env, slot) in envs.iter().zip(&mut pin.txns) {
            // SAFETY: the env is open; the transaction is aborted by Pin's drop.
            check(unsafe { ffi::mdb_txn_begin(env.ptr, ptr::null_mut(), ffi::MDB_RDONLY, slot) })?;
        }
        let mut metas = Vec::new();
        for (env, &txn) in envs.iter().zip(&pin.txns) {
            // SAFETY: plain data, filled in by LMDB from an open env, and a
            // live transaction.
            let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
            check(unsafe { ffi::mdb_env_stat(env.ptr, &mut stat) })?;
            let txnid = unsafe { ffi::mdb_txn_id(txn) } as u64;
            let mut fd = -1;
            check(unsafe { ffi::mdb_env_get_fd(env.ptr, &mut fd) })?;
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
        for env in self.envs.load().iter().rev() {
            // SAFETY: the env is open; 1 forces the flush, as NOSYNC skips it.
            check(unsafe { ffi::mdb_env_sync(env.ptr, 1) })?;
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
        let c_name = CString::new(name).map_err(|_| Error(libc::EINVAL))?;
        let (txn, bits) = match self.read_only {
            true => (self.begin(ffi::MDB_RDONLY, None)?, flags.bits()),
            false => (self.write_txn()?.txn, flags.bits() | ffi::MDB_CREATE),
        };
        let mut dbi = 0;
        // SAFETY: a live transaction and a NUL-terminated name.
        check(unsafe { ffi::mdb_dbi_open(txn.ptrs[env], c_name.as_ptr(), bits, &mut dbi) })?;
        let handle = txn.envs[env].clone();
        // Committed, even only to read, so the handle outlives it.
        RwTxn::new(txn).commit()?;
        let mut tables = handle.tables.lock().expect("unpoisoned");
        if !tables.iter().any(|(opened, ..)| *opened == dbi) {
            tables.push((dbi, name.to_string(), flags));
        }
        Ok(Db { dbi, env })
    }

    /// Delete the table `name` in the first environment, if there is one,
    /// returning how many entries it held.
    pub fn remove_db(&self, name: &str) -> Result<Option<usize>> {
        let name = CString::new(name).map_err(|_| Error(libc::EINVAL))?;
        let txn = self.write_txn()?;
        let mut dbi = 0;
        // SAFETY: a live write transaction and a NUL-terminated name.
        if found(unsafe { ffi::mdb_dbi_open(txn.txn.ptrs[0], name.as_ptr(), 0, &mut dbi) })?
            .is_none()
        {
            return Ok(None);
        }
        let entries = txn.len(Db { dbi, env: 0 })?;
        // SAFETY: a live write transaction; 1 deletes the table and closes
        // its handle, which nothing else holds.
        check(unsafe { ffi::mdb_drop(txn.txn.ptrs[0], dbi, 1) })?;
        let handle = txn.envs[0].clone();
        txn.commit()?;
        let mut tables = handle.tables.lock().expect("unpoisoned");
        tables.retain(|(opened, ..)| *opened != dbi);
        Ok(Some(entries))
    }

    /// Every table in the first environment, opened, with its flags, in
    /// the order of their names. Like [`create_db`](Self::create_db), call
    /// it before any other transaction.
    pub fn tables(&self) -> Result<Vec<(String, Db, DbFlags)>> {
        let txn = self.begin(ffi::MDB_RDONLY, None)?;
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
        RwTxn::new(txn).commit()?;
        Ok(tables)
    }

    /// The tables opened in environment `env`, in the order they were.
    pub fn tables_of(&self, env: usize) -> Vec<(String, Db, DbFlags)> {
        let envs = self.envs.load();
        let mut tables = envs[env].tables.lock().expect("unpoisoned").clone();
        tables.sort_by_key(|(dbi, ..)| *dbi);
        tables
            .into_iter()
            .map(|(dbi, name, flags)| (name, Db { dbi, env }, flags))
            .collect()
    }

    /// The tables in environment `env`'s file that haven't been opened.
    /// Safe to call while others read and write, unlike
    /// [`tables`](Self::tables), as it opens none.
    pub fn unopened_tables(&self, env: usize) -> Result<Vec<String>> {
        let opened: Vec<String> = self
            .tables_of(env)
            .into_iter()
            .map(|(name, ..)| name)
            .collect();
        let txn = self.read_txn_in(env)?;
        let mut main = 0;
        // SAFETY: a live transaction; a null name is the table of tables,
        // which is always open, so LMDB only says which it is.
        check(unsafe { ffi::mdb_dbi_open(txn.ptrs[env], ptr::null(), 0, &mut main) })?;
        let mut cursor = txn.cursor(Db { dbi: main, env })?;
        let mut unopened = Vec::new();
        let mut entry = cursor.first()?;
        while let Some((name, _)) = entry {
            let name = String::from_utf8_lossy(name);
            if !opened.iter().any(|opened| *opened == name) {
                unopened.push(name.into_owned());
            }
            entry = cursor.next()?;
        }
        Ok(unopened)
    }

    /// Create an empty environment of its own in the directory `path`,
    /// opened as environment `env` is, its tables opened in the same order,
    /// so that each [`Db`] of `env`'s is the same table's in it, but for
    /// the environment it's in, which is 0.
    pub fn create_like(&self, env: usize, path: &Path) -> Result<Env> {
        let (map_size, max_dbs, max_readers) = {
            let envs = self.envs.load();
            let handle = &envs[env];
            (handle.map_size, handle.max_dbs, handle.max_readers)
        };
        let like = Env::open(path, map_size, max_dbs, max_readers)?;
        for (name, db, flags) in self.tables_of(env) {
            if like.create_db(&name, flags)?.dbi != db.dbi {
                return Err(Error(ffi::MDB_INCOMPATIBLE));
            }
        }
        Ok(like)
    }

    /// Begin keeping what's committed to environment `env` from now on in a
    /// [`Journal`], in a new file at `path`, and return it, with a read
    /// transaction of `env` alone as it is now, before any of it. Fails if
    /// a journal's kept already.
    pub fn journal(&self, env: usize, path: &Path) -> Result<(Arc<Journal>, RoTxn<'_>)> {
        // Holding the writer's lock, so that no commit is under way: each
        // write transaction begun after keeps what it commits.
        let writing = self.write_txn()?;
        if writing.journal.is_some() {
            return Err(Error(libc::EBUSY));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(io_error)?;
        let reader = file.try_clone().map_err(io_error)?;
        let journal = Arc::new(Journal {
            env,
            file: Mutex::new(file),
            reader,
            written: AtomicU64::new(0),
            failed: AtomicBool::new(false),
        });
        let before = self.read_txn_in(env)?;
        self.journal.store(Some(journal.clone()));
        drop(writing);
        Ok((journal, before))
    }

    /// Stop keeping a [`Journal`]. Write transactions begun before go on
    /// keeping theirs in it.
    pub fn stop_journal(&self) {
        self.journal.store(None);
    }

    /// Make in this environment, made [alike](Self::create_like) the
    /// environment `journal` is of, the changes it holds from `at`, up to
    /// what it holds now, or with `settled`, up to the end of every commit
    /// made already, as a commit may be being written to it still. Returns
    /// where they end.
    pub fn replay(&self, journal: &Journal, mut at: u64, settled: bool) -> Result<u64> {
        let end = match settled {
            true => journal.settled(),
            false => journal.len(),
        };
        if journal.failed.load(Ordering::Relaxed) {
            return Err(Error(libc::EIO));
        }
        let mut txn = self.write_txn()?;
        let (mut ops, mut pending) = (Vec::new(), 0);
        while at < end {
            let mut len = [0; 8];
            journal
                .reader
                .read_exact_at(&mut len, at)
                .map_err(io_error)?;
            let len = u64::from_le_bytes(len);
            if at + 8 + len > end {
                return Err(Error::corrupted());
            }
            ops.resize(len as usize, 0);
            journal
                .reader
                .read_exact_at(&mut ops, at + 8)
                .map_err(io_error)?;
            apply(&mut txn, &ops)?;
            at += 8 + len;
            pending += len;
            if pending >= REPLAY_COMMIT_BYTES {
                txn.commit()?;
                txn = self.write_txn()?;
                pending = 0;
            }
        }
        txn.commit()?;
        Ok(at)
    }

    /// Put `other`, an environment of its own made
    /// [alike](Self::create_like) environment `env`, in its place, and
    /// return the one replaced, as an environment of its own. Transactions
    /// begun before go on in the one replaced, which is closed once it's
    /// dropped and the last of them has ended. Call it holding a write
    /// transaction: one waiting on it to end is begun anew, in `other`.
    pub fn replace(&self, env: usize, other: Env) -> Env {
        let handle = other.envs.load()[0].clone();
        let mut envs = Vec::clone(&self.envs.load());
        let replaced = std::mem::replace(&mut envs[env], handle);
        self.envs.store(Arc::new(envs));
        let out = Env::new(self.read_only);
        out.envs.store(Arc::new(vec![replaced]));
        out
    }

    /// Write a compacted copy of the environment `env` into the directory
    /// `path`.
    #[cfg(test)]
    pub fn copy_compact(&self, env: usize, path: &Path) -> Result<()> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        let envs = self.envs.load();
        // SAFETY: the env is open and the path NUL-terminated.
        check(unsafe { ffi::mdb_env_copy2(envs[env].ptr, path.as_ptr(), ffi::MDB_CP_COMPACT) })
    }

    /// How big the environment `env`'s map is, and how much of it is used,
    /// in bytes.
    pub fn usage(&self, env: usize) -> Result<Usage> {
        let envs = self.envs.load();
        let ptr = envs[env].ptr;
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
    ///
    /// The bytes are read with `pread`, on a thread of its own, rather than
    /// advised with `POSIX_FADV_WILLNEED`. On ZFS, the kernel's readahead
    /// locks the pages it fills, then the file's range lock, while a write
    /// holds the range lock and waits on those pages: the writer and reader
    /// deadlock, and the pool's commits stop behind them. A read takes the
    /// range lock without holding pages, and leaves what it read in the ARC,
    /// where faulting the map in finds it.
    pub fn will_need(&self, env: usize, at: &[u8], len: usize) {
        let envs = self.envs.load();
        let handle = &envs[env];
        let mut fd = -1;
        // SAFETY: the env is open.
        if check(unsafe { ffi::mdb_env_get_fd(handle.ptr, &mut fd) }).is_err() {
            return;
        }
        let Some(offset) = offset_in(handle, at) else {
            return;
        };
        if READS_AHEAD.fetch_add(1, Ordering::AcqRel) >= MAX_READS_AHEAD {
            READS_AHEAD.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        // Its own, so that the env closing doesn't leave it reading another.
        // SAFETY: a file LMDB holds open.
        let fd = unsafe { libc::dup(fd) };
        if fd < 0 {
            READS_AHEAD.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        // SAFETY: just made, and only this owns it.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let read = move || {
            let mut buf = vec![0; READ_AHEAD_CHUNK];
            let mut at = offset as u64;
            let end = at + len as u64;
            while at < end {
                let want = (end - at).min(READ_AHEAD_CHUNK as u64) as usize;
                match file.read_at(&mut buf[..want], at) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => at += n as u64,
                }
            }
            READS_AHEAD.fetch_sub(1, Ordering::AcqRel);
        };
        if std::thread::Builder::new()
            .name("read-ahead".into())
            .spawn(read)
            .is_err()
        {
            READS_AHEAD.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Where in environment `env`'s file `at`, read from its map, is, if
    /// it's from there.
    pub fn offset_of(&self, env: usize, at: &[u8]) -> Option<usize> {
        offset_in(&self.envs.load()[env], at)
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(RoTxn(self.begin(ffi::MDB_RDONLY, None)?))
    }

    /// A read transaction in environment `env` alone: reading a table of
    /// another in it panics. It pins nothing of the others.
    pub fn read_txn_in(&self, env: usize) -> Result<RoTxn<'_>> {
        Ok(RoTxn(self.begin(ffi::MDB_RDONLY, Some(env))?))
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        let txn = self.begin(0, None)?;
        // Holding the writer's lock, as a journal's begun.
        let journal = self.journal.load_full().map(|journal| Recording {
            journal,
            ops: Vec::new(),
        });
        Ok(RwTxn { txn, journal })
    }

    /// A transaction in each environment, or with `only`, in that one, in
    /// the order they were opened.
    fn begin(&self, flags: u32, only: Option<usize>) -> Result<Txn<'_>> {
        loop {
            let mut txn = Txn {
                ptrs: [ptr::null_mut(); MAX_ENVS],
                envs: self.envs.load_full(),
                _env: PhantomData,
            };
            for (n, slot) in txn.ptrs.iter_mut().enumerate().take(txn.envs.len()) {
                if only.is_some_and(|only| only != n) {
                    continue;
                }
                // SAFETY: the env is open; the transaction is freed by Txn's
                // drop or commit, those already begun too if this fails.
                check(unsafe {
                    ffi::mdb_txn_begin(txn.envs[n].ptr, ptr::null_mut(), flags, slot)
                })?;
            }
            // A writer waits on the one before, which may have replaced an
            // environment meanwhile: then it's begun anew, in that.
            if flags & ffi::MDB_RDONLY != 0 || Arc::ptr_eq(&txn.envs, &self.envs.load()) {
                return Ok(txn);
            }
        }
    }
}

/// Where in `handle`'s file `at`, read from its map, is, if it's from
/// there.
fn offset_in(handle: &Handle, at: &[u8]) -> Option<usize> {
    let (base, len) = handle.map?;
    let offset = (at.as_ptr() as usize).checked_sub(base)?;
    (offset < len).then_some(offset)
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

/// What reading needs, shared by both kinds of transaction. Values read
/// borrow the transaction, so a write (which takes `&mut`) can't leave one
/// dangling.
pub struct Txn<'env> {
    /// One per environment, null past the last, or in those it isn't in.
    ptrs: [*mut ffi::MDB_txn; MAX_ENVS],
    /// The environments it's in, held open until it ends.
    envs: Envs,
    _env: PhantomData<&'env Env>,
}

impl Txn<'_> {
    /// The transaction in `db`'s environment.
    fn of(&self, db: Db) -> *mut ffi::MDB_txn {
        let ptr = self.ptrs[db.env];
        assert!(
            !ptr.is_null(),
            "a table of an environment the transaction isn't in"
        );
        ptr
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

pub struct RwTxn<'env> {
    txn: Txn<'env>,
    /// The changes to keep in the journal, if one's kept.
    journal: Option<Recording>,
}

/// A write transaction's changes to the environment a [`Journal`] is of,
/// for it to keep once they're committed.
struct Recording {
    journal: Arc<Journal>,
    ops: Vec<u8>,
}

impl<'env> std::ops::Deref for RwTxn<'env> {
    type Target = Txn<'env>;
    fn deref(&self) -> &Txn<'env> {
        &self.txn
    }
}

impl<'env> RwTxn<'env> {
    fn new(txn: Txn<'env>) -> RwTxn<'env> {
        RwTxn { txn, journal: None }
    }

    /// Where to note a change to `db`, if the journal's kept of its
    /// environment.
    fn recording(&mut self, db: Db) -> Option<&mut Vec<u8>> {
        self.journal
            .as_mut()
            .filter(|recording| recording.journal.env == db.env)
            .map(|recording| &mut recording.ops)
    }

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
        match unsafe { ffi::mdb_put(self.txn.of(db), db.dbi, &mut k, &mut v, flags) } {
            ffi::MDB_KEYEXIST => Ok(false),
            code => {
                check(code)?;
                if let Some(ops) = self.recording(db) {
                    record_put(ops, db.dbi, key, value);
                }
                Ok(true)
            }
        }
    }

    /// A cursor that walks `db` deleting as it goes, for sweeping a table.
    pub fn sweeper(&mut self, db: Db) -> Result<Sweeper<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live write transaction, borrowed mutably while the
        // cursor lives; it's closed on drop.
        check(unsafe { ffi::mdb_cursor_open(self.txn.of(db), db.dbi, &mut ptr) })?;
        Ok(Sweeper {
            ptr,
            dbi: db.dbi,
            ops: self.recording(db),
        })
    }

    /// A cursor that appends to `db`, for writing a table in order.
    pub fn appender(&mut self, db: Db) -> Result<Appender<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live write transaction, borrowed mutably while the
        // cursor lives; it's closed on drop.
        check(unsafe { ffi::mdb_cursor_open(self.txn.of(db), db.dbi, &mut ptr) })?;
        Ok(Appender {
            ptr,
            dbi: db.dbi,
            ops: self.recording(db),
        })
    }

    /// Remove a key and all its values, or with `value`, just that one value
    /// of a duplicate-sorted key. Returns whether anything was there.
    pub fn del(&mut self, db: Db, key: &[u8], value: Option<&[u8]>) -> Result<bool> {
        let mut k = val(key);
        let mut v = value.map(val);
        let v_ptr = v.as_mut().map_or(ptr::null_mut(), |v| v as *mut _);
        // SAFETY: a live write transaction; a null data pointer means "every value".
        let gone =
            found(unsafe { ffi::mdb_del(self.txn.of(db), db.dbi, &mut k, v_ptr) })?.is_some();
        if gone && let Some(ops) = self.recording(db) {
            record_del(ops, db.dbi, key, value);
        }
        Ok(gone)
    }

    /// Remove every entry of a table, keeping the table.
    pub fn clear(&mut self, db: Db) -> Result<()> {
        // SAFETY: a live write transaction; 0 empties the table without
        // closing its handle.
        check(unsafe { ffi::mdb_drop(self.txn.of(db), db.dbi, 0) })?;
        if let Some(ops) = self.recording(db) {
            record_clear(ops, db.dbi);
        }
        Ok(())
    }

    /// Commit, the last environment opened first. If one fails, those not
    /// yet committed are aborted.
    /// What's changed in the environment a journal's kept of is kept in
    /// it, once it's committed.
    pub fn commit(mut self) -> Result<()> {
        for (n, slot) in self.txn.ptrs.iter_mut().enumerate().rev() {
            if slot.is_null() {
                continue;
            }
            let recording = self
                .journal
                .as_ref()
                .filter(|recording| recording.journal.env == n && !recording.ops.is_empty());
            // Until it's kept, so that a writer begun once this commits
            // can wait for it to be: see Journal::settled.
            let file =
                recording.map(|recording| recording.journal.file.lock().expect("unpoisoned"));
            let ptr = std::mem::replace(slot, ptr::null_mut());
            // SAFETY: commit frees the transaction whatever it returns, so
            // it's nulled first to keep Drop from aborting it again.
            check(unsafe { ffi::mdb_txn_commit(ptr) })?;
            if let (Some(recording), Some(file)) = (recording, file) {
                recording.journal.append(&file, &recording.ops);
            }
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
    dbi: ffi::MDB_dbi,
    /// Where to note what's appended, if a journal's kept.
    ops: Option<&'t mut Vec<u8>>,
}

impl Appender<'_> {
    /// Store `value` under `key`, which must sort after every key in the
    /// table.
    pub fn append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let (mut k, mut v) = (val(key), val(value));
        // SAFETY: a live cursor of a live write transaction.
        check(unsafe { ffi::mdb_cursor_put(self.ptr, &mut k, &mut v, ffi::MDB_APPEND) })?;
        if let Some(ops) = &mut self.ops {
            record_put(ops, self.dbi, key, value);
        }
        Ok(())
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
        if data[1].mv_size != count {
            return Err(Error(ffi::MDB_PROBLEM));
        }
        if let Some(ops) = &mut self.ops {
            for value in values.chunks_exact(size) {
                record_put(ops, self.dbi, key, value);
            }
        }
        Ok(())
    }
}

/// A cursor that walks a table in order and deletes the entry it's on, from
/// [`RwTxn::sweeper`]. Seeking the next entry after a delete is done from
/// where the cursor is, which LMDB does without a search from the root
/// while it's on the same page. What it returns is
/// borrowed from it, so nothing it read outlives a delete, which can change
/// the page it was on.
pub struct Sweeper<'t> {
    ptr: *mut ffi::MDB_cursor,
    dbi: ffi::MDB_dbi,
    /// Where to note what's deleted, if a journal's kept.
    ops: Option<&'t mut Vec<u8>>,
}

impl Sweeper<'_> {
    fn op(
        &mut self,
        key: Option<&[u8]>,
        value: Option<&[u8]>,
        op: ffi::MDB_cursor_op,
    ) -> Result<Option<Entry<'_>>> {
        let mut k = key.map_or_else(empty, val);
        let mut v = value.map_or_else(empty, val);
        // SAFETY: a live cursor; the slices returned borrow it, so they
        // can't be held across a delete.
        let hit = found(unsafe { ffi::mdb_cursor_get(self.ptr, &mut k, &mut v, op) })?;
        Ok(hit.map(|()| unsafe { (bytes(&k), bytes(&v)) }))
    }

    pub fn first(&mut self) -> Result<Option<Entry<'_>>> {
        self.op(None, None, ffi::MDB_FIRST)
    }

    /// The next entry: the key's next value, or the next key's first.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Entry<'_>>> {
        self.op(None, None, ffi::MDB_NEXT)
    }

    /// The entry the cursor is on. Not after a [`del`](Self::del): that
    /// leaves it between entries.
    pub fn current(&mut self) -> Result<Option<Entry<'_>>> {
        self.op(None, None, ffi::MDB_GET_CURRENT)
    }

    /// The first entry of the next key.
    pub fn next_nodup(&mut self) -> Result<Option<Entry<'_>>> {
        self.op(None, None, ffi::MDB_NEXT_NODUP)
    }

    /// The first entry whose key is at least `key`.
    pub fn set_range(&mut self, key: &[u8]) -> Result<Option<Entry<'_>>> {
        self.op(Some(key), None, ffi::MDB_SET_RANGE)
    }

    /// Within `key`'s duplicates, the first value at least `value`.
    pub fn get_both_range(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Entry<'_>>> {
        self.op(Some(key), Some(value), ffi::MDB_GET_BOTH_RANGE)
    }

    /// Delete the entry the cursor is on: in a duplicate-sorted table, just
    /// that value. Seek what's after it by the deleted key, or key and
    /// value: what [`next`](Self::next) returns after a delete isn't
    /// reliable, not when the entry was the last on its page, where it can
    /// read past the page's end.
    pub fn del(&mut self) -> Result<()> {
        // Its value too, which only a duplicate-sorted table's deletion
        // heeds.
        let entry = match self.ops.is_some() {
            true => self
                .current()?
                .map(|(key, value)| (key.to_vec(), value.to_vec())),
            false => None,
        };
        // SAFETY: a live cursor of a live write transaction, on an entry.
        check(unsafe { ffi::mdb_cursor_del(self.ptr, 0) })?;
        if let (Some(ops), Some((key, value))) = (&mut self.ops, entry) {
            record_del(ops, self.dbi, &key, Some(&value));
        }
        Ok(())
    }
}

impl Drop for Sweeper<'_> {
    fn drop(&mut self) {
        // SAFETY: the cursor's transaction is still alive (it's borrowed).
        unsafe { ffi::mdb_cursor_close(self.ptr) }
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

    /// Deleting as it walks, and seeking what's after, it sees every entry
    /// once, across pages of duplicates and keys alike.
    #[test]
    fn sweeps_a_table_in_one_walk() {
        let (_dir, env) = open();
        let db = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
        let mut txn = env.write_txn().unwrap();
        for n in 0..3000u32 {
            txn.put_dup(db, b"big", &n.to_be_bytes()).unwrap();
        }
        for n in 0..3u32 {
            txn.put_dup(db, b"gone", &n.to_be_bytes()).unwrap();
        }
        txn.put_dup(db, b"last", &7u32.to_be_bytes()).unwrap();
        let mut sweeper = txn.sweeper(db).unwrap();
        let owned = |e: Option<Entry>| e.map(|(k, v)| (k.to_vec(), v.to_vec()));
        let mut entry = owned(sweeper.first().unwrap());
        let mut seen = 0;
        while let Some((key, value)) = entry {
            seen += 1;
            let n = u32::from_be_bytes(value[..].try_into().unwrap());
            entry = if key == b"gone" || (key == b"big" && n % 2 == 1) {
                sweeper.del().unwrap();
                // What's after it, sought.
                match owned(sweeper.get_both_range(&key, &value).unwrap()) {
                    Some(next) => Some(next),
                    None => match owned(sweeper.set_range(&key).unwrap()) {
                        Some((found, _)) if found == key => owned(sweeper.next_nodup().unwrap()),
                        other => other,
                    },
                }
            } else {
                owned(sweeper.next().unwrap())
            };
        }
        assert_eq!(seen, 3004);
        drop(sweeper);
        txn.commit().unwrap();
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.len(db).unwrap(), 1501);
        let mut cursor = txn.cursor(db).unwrap();
        assert!(cursor.set(b"gone").unwrap().is_none());
        cursor.set(b"big").unwrap();
        assert_eq!(cursor.count().unwrap(), 1500);
        assert!(
            cursor
                .get_both_range(b"big", &1u32.to_be_bytes())
                .unwrap()
                .unwrap()
                .1
                == 2u32.to_be_bytes()
        );
    }

    /// Every entry of `db`, in order.
    fn dump(txn: &Txn, db: Db) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut cursor = txn.cursor(db).unwrap();
        let mut entries = Vec::new();
        let mut entry = cursor.first().unwrap();
        while let Some((key, value)) = entry {
            entries.push((key.to_vec(), value.to_vec()));
            entry = cursor.next().unwrap();
        }
        entries
    }

    /// What's committed as a journal's kept, replayed into a copy made as
    /// it began, makes the copy the same; put in its place, the copy's
    /// read and written after, a writer that waited on it too.
    #[test]
    fn replays_a_journal_into_a_copy_put_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let (other, copy_dir) = (dir.path().join("other"), dir.path().join("copy"));
        std::fs::create_dir(&other).unwrap();
        std::fs::create_dir(&copy_dir).unwrap();
        let mut env = Env::open(dir.path(), 1 << 24, 8, 16).unwrap();
        env.attach(&other, 1 << 24, 4, 16).unwrap();
        let plain = env.create_db("plain", DbFlags::PLAIN).unwrap();
        let dups = env.create_db("dups", DbFlags::DUP_FIXED).unwrap();
        let gone = env.create_db("gone", DbFlags::PLAIN).unwrap();
        let appended = env
            .create_db_in(1, "appended", DbFlags::INTEGER_KEY)
            .unwrap();
        let mut txn = env.write_txn().unwrap();
        for n in 0..500u32 {
            txn.put(plain, format!("k{n:03}").as_bytes(), &n.to_be_bytes())
                .unwrap();
            txn.put_dup(dups, &[(n % 3) as u8], &n.to_be_bytes())
                .unwrap();
            txn.put(gone, &n.to_be_bytes(), b"x").unwrap();
        }
        txn.commit().unwrap();

        let copy = env.create_like(0, &copy_dir).unwrap();
        let (journal, before) = env.journal(0, &dir.path().join("journal")).unwrap();
        assert!(env.journal(0, &dir.path().join("second")).is_err());
        let copied: Vec<Db> = copy.tables_of(0).into_iter().map(|(_, db, _)| db).collect();
        let mut txn = copy.write_txn().unwrap();
        for ((_, db, _), &to) in env.tables_of(0).iter().zip(&copied) {
            for (key, value) in dump(&before, *db) {
                txn.put(to, &key, &value).unwrap();
            }
        }
        txn.commit().unwrap();
        drop(before);

        // Every kind of change, meanwhile.
        let mut txn = env.write_txn().unwrap();
        txn.put(plain, b"k001", b"changed").unwrap();
        txn.del(plain, b"k002", None).unwrap();
        txn.put_dup(dups, &[7], &9u32.to_be_bytes()).unwrap();
        txn.del(dups, &[1], Some(&4u32.to_be_bytes())).unwrap();
        txn.clear(gone).unwrap();
        let mut sweeper = txn.sweeper(dups).unwrap();
        let mut entry = sweeper
            .first()
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()));
        while let Some((key, value)) = entry {
            let n = u32::from_be_bytes(value[..].try_into().unwrap());
            entry = match n % 5 == 0 {
                true => {
                    sweeper.del().unwrap();
                    sweeper.get_both_range(&key, &value).unwrap()
                }
                false => sweeper.next().unwrap(),
            }
            .map(|(k, v)| (k.to_vec(), v.to_vec()));
        }
        drop(sweeper);
        txn.appender(plain).unwrap().append(b"zz", b"last").unwrap();
        // In the other environment, which isn't journaled.
        txn.put(appended, &1u64.to_ne_bytes(), b"one").unwrap();
        txn.commit().unwrap();
        // Never committed, so never kept.
        let mut txn = env.write_txn().unwrap();
        txn.put(plain, b"never", b"!").unwrap();
        drop(txn);
        assert!(!journal.is_empty());
        let at = copy.replay(&journal, 0, false).unwrap();
        assert_eq!(at, journal.len());
        let mut txn = env.write_txn().unwrap();
        txn.put(plain, b"late", b"!").unwrap();
        txn.commit().unwrap();
        assert_eq!(copy.replay(&journal, at, true).unwrap(), journal.len());
        env.stop_journal();

        let (live, copied_txn) = (env.read_txn().unwrap(), copy.read_txn().unwrap());
        for ((name, db, _), &to) in env.tables_of(0).iter().zip(&copied) {
            assert_eq!(dump(&live, *db), dump(&copied_txn, to), "{name}");
        }
        assert!(live.get(plain, b"never").unwrap().is_none());
        drop(copied_txn);

        // A writer waiting as it's put in place writes in the copy.
        let held = env.write_txn().unwrap();
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                let mut txn = env.write_txn().unwrap();
                txn.put(plain, b"waited", b"!").unwrap();
                txn.commit().unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(!waiting.is_finished());
            let old = env.replace(0, copy);
            drop(held);
            waiting.join().unwrap();
            // The old file, read from before, is as it was.
            assert!(live.get(plain, b"waited").unwrap().is_none());
            assert!(
                old.read_txn()
                    .unwrap()
                    .get(plain, b"waited")
                    .unwrap()
                    .is_none()
            );
        });
        drop(live);
        let txn = env.read_txn().unwrap();
        assert_eq!(txn.get(plain, b"waited").unwrap(), Some(&b"!"[..]));
        assert_eq!(txn.get(plain, b"zz").unwrap(), Some(&b"last"[..]));
        assert_eq!(
            txn.get(appended, &1u64.to_ne_bytes()).unwrap(),
            Some(&b"one"[..])
        );
        drop(txn);
        // And it's checkpointed, as the store's environments are.
        env.begin_checkpoint().unwrap();
        env.sync().unwrap();
        env.confirm_checkpoint();
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
