use crate::StateKey;
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    path::Path,
    ptr::{self, NonNull},
};
mod ffi {
    use super::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn rocksdb_options_create() -> *mut c_void;
        pub fn rocksdb_options_destroy(p: *mut c_void);
        pub fn rocksdb_options_set_create_if_missing(p: *mut c_void, value: u8);
        pub fn rocksdb_options_set_wal_recovery_mode(p: *mut c_void, value: c_int);
        pub fn rocksdb_open(
            options: *const c_void,
            path: *const c_char,
            error: *mut *mut c_char,
        ) -> *mut c_void;
        pub fn rocksdb_close(p: *mut c_void);
        pub fn rocksdb_readoptions_create() -> *mut c_void;
        pub fn rocksdb_readoptions_destroy(p: *mut c_void);
        pub fn rocksdb_get(
            db: *mut c_void,
            options: *const c_void,
            key: *const c_char,
            key_len: usize,
            value_len: *mut usize,
            error: *mut *mut c_char,
        ) -> *mut c_char;
        pub fn rocksdb_writeoptions_create() -> *mut c_void;
        pub fn rocksdb_writeoptions_destroy(p: *mut c_void);
        pub fn rocksdb_writeoptions_set_sync(p: *mut c_void, value: u8);
        pub fn rocksdb_writebatch_create() -> *mut c_void;
        pub fn rocksdb_writebatch_destroy(p: *mut c_void);
        pub fn rocksdb_writebatch_put(
            batch: *mut c_void,
            key: *const c_char,
            key_len: usize,
            value: *const c_char,
            value_len: usize,
        );
        pub fn rocksdb_writebatch_delete(batch: *mut c_void, key: *const c_char, key_len: usize);
        pub fn rocksdb_write(
            db: *mut c_void,
            options: *const c_void,
            batch: *mut c_void,
            error: *mut *mut c_char,
        );
        pub fn rocksdb_create_iterator(db: *mut c_void, options: *const c_void) -> *mut c_void;
        pub fn rocksdb_iter_destroy(p: *mut c_void);
        pub fn rocksdb_iter_seek_to_first(p: *mut c_void);
        pub fn rocksdb_iter_valid(p: *const c_void) -> u8;
        pub fn rocksdb_iter_next(p: *mut c_void);
        pub fn rocksdb_iter_key(p: *const c_void, len: *mut usize) -> *const c_char;
        pub fn rocksdb_iter_get_error(p: *const c_void, error: *mut *mut c_char);
        pub fn rocksdb_free(p: *mut c_void);
    }
}

struct Handle {
    ptr: NonNull<c_void>,
    destroy: unsafe extern "C" fn(*mut c_void),
}
impl Handle {
    fn new(ptr: *mut c_void, destroy: unsafe extern "C" fn(*mut c_void)) -> Result<Self> {
        Ok(Self {
            ptr: NonNull::new(ptr).context("native database returned a null handle")?,
            destroy,
        })
    }
    fn raw(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: each successful constructor transfers exactly one owned handle.
        unsafe { (self.destroy)(self.raw()) }
    }
}
fn native_status(error: *mut c_char) -> Result<()> {
    if error.is_null() {
        return Ok(());
    }
    // SAFETY: the C API allocates a terminated error string owned by this caller.
    let text = unsafe { CStr::from_ptr(error).to_string_lossy().into_owned() };
    unsafe { ffi::rocksdb_free(error.cast()) };
    bail!("native StateDb: {text}")
}

/// Opening replays the WAL but never implicitly creates a missing source database.
pub struct OfflineStore(Handle);
impl OfflineStore {
    pub fn open_existing(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("StateDb directory is missing")?;
        if !metadata.file_type().is_dir() {
            bail!("StateDb must be a real directory, not a symlink");
        }
        let store = Self::open(path, false)?;
        use tl_api::IntoBoxed;
        let expected = tl_api::serialize_boxed(
            &tl_api::tos::db::state::dbversion::DbVersion { version: 2 }.into_boxed(),
        )?;
        if store.get(&StateKey::Version)?.as_ref() != Some(&expected) {
            bail!("missing or unsupported StateDb version; expected native schema version 2");
        }
        Ok(store)
    }
    /// Creates only a new staging database; refuses an existing path.
    pub fn create_staging(path: &Path) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .context("create private staging StateDb")?;
        Self::open(path, true)
    }
    fn open(path: &Path, create: bool) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).context("NUL in StateDb path")?;
        // SAFETY: options and path stay alive throughout open; error is initialized null.
        unsafe {
            let options = Handle::new(ffi::rocksdb_options_create(), ffi::rocksdb_options_destroy)?;
            ffi::rocksdb_options_set_create_if_missing(options.raw(), u8::from(create));
            // Matches the engine's kTolerateCorruptedTailRecords WAL recovery policy.
            ffi::rocksdb_options_set_wal_recovery_mode(options.raw(), 0);
            let mut error = ptr::null_mut();
            let raw = ffi::rocksdb_open(options.raw(), path.as_ptr(), &mut error);
            native_status(error)?;
            Ok(Self(Handle::new(raw, ffi::rocksdb_close)?))
        }
    }
    /// Missing and present-empty are deliberately different results.
    pub fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>> {
        let key = key.bytes()?;
        // SAFETY: read handles and borrowed key are valid for the synchronous call.
        unsafe {
            let options =
                Handle::new(ffi::rocksdb_readoptions_create(), ffi::rocksdb_readoptions_destroy)?;
            let mut error = ptr::null_mut();
            let mut len = 0;
            let raw = ffi::rocksdb_get(
                self.0.raw(),
                options.raw(),
                key.as_ptr().cast(),
                key.len(),
                &mut len,
                &mut error,
            );
            native_status(error)?;
            if raw.is_null() {
                return Ok(None);
            }
            let value = std::slice::from_raw_parts(raw.cast::<u8>(), len).to_vec();
            ffi::rocksdb_free(raw.cast());
            Ok(Some(value))
        }
    }
    /// Bounded diagnostic inventory; keys alone grant no permission to export records.
    pub fn inventory_keys(&self) -> Result<Vec<Vec<u8>>> {
        // SAFETY: the iterator borrows the open database and options for this call only.
        unsafe {
            let options =
                Handle::new(ffi::rocksdb_readoptions_create(), ffi::rocksdb_readoptions_destroy)?;
            let iter = Handle::new(
                ffi::rocksdb_create_iterator(self.0.raw(), options.raw()),
                ffi::rocksdb_iter_destroy,
            )?;
            ffi::rocksdb_iter_seek_to_first(iter.raw());
            let mut keys = Vec::new();
            while ffi::rocksdb_iter_valid(iter.raw()) != 0 {
                if keys.len() >= 100_000 {
                    bail!("StateDb inventory exceeds record limit");
                }
                let mut len = 0;
                let raw = ffi::rocksdb_iter_key(iter.raw(), &mut len);
                if raw.is_null() || len > 4096 {
                    bail!("invalid or oversized StateDb key");
                }
                keys.push(std::slice::from_raw_parts(raw.cast::<u8>(), len).to_vec());
                ffi::rocksdb_iter_next(iter.raw());
            }
            let mut error = ptr::null_mut();
            ffi::rocksdb_iter_get_error(iter.raw(), &mut error);
            native_status(error)?;
            Ok(keys)
        }
    }

    /// One acknowledged synced batch; None deletes a key instead of writing an empty value.
    pub fn write(&mut self, changes: &[(StateKey, Option<Vec<u8>>)]) -> Result<()> {
        // Encode everything before building a batch so a bad key changes nothing.
        let encoded = changes
            .iter()
            .map(|(key, value)| Ok((key.bytes()?, value)))
            .collect::<Result<Vec<_>>>()?;
        // SAFETY: the batch copies every borrowed key/value; all handles outlive write.
        unsafe {
            let options =
                Handle::new(ffi::rocksdb_writeoptions_create(), ffi::rocksdb_writeoptions_destroy)?;
            let batch =
                Handle::new(ffi::rocksdb_writebatch_create(), ffi::rocksdb_writebatch_destroy)?;
            ffi::rocksdb_writeoptions_set_sync(options.raw(), 1);
            for (key, value) in encoded {
                match value {
                    Some(value) => ffi::rocksdb_writebatch_put(
                        batch.raw(),
                        key.as_ptr().cast(),
                        key.len(),
                        value.as_ptr().cast(),
                        value.len(),
                    ),
                    None => {
                        ffi::rocksdb_writebatch_delete(batch.raw(), key.as_ptr().cast(), key.len())
                    }
                }
            }
            let mut error = ptr::null_mut();
            ffi::rocksdb_write(self.0.raw(), options.raw(), batch.raw(), &mut error);
            native_status(error)
        }
    }
}
