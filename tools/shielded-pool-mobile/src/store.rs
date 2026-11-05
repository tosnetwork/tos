// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Private, directory-relative atomic snapshots. Callers supply an existing
//! OS app-private directory (0700), never shared storage or an untrusted path.
//! Reservation journal checkpoints are part of the encrypted state envelope.
//! Full note/payment schema and explicit candidate recovery remain separate.
use crate::{
    sealed::{Kind, RecordCipher},
    snapshot::{self, Restored, MAX_ENCODED_BYTES},
    Error,
};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const DIRECTORY_FLAGS: i32 =
    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const STATE: &CStr = c"state.bin";
const NEXT: &CStr = c"state.next";
const PENDING_PAYMENT_TAG: &[u8] = b"TOS-PENDING-PAYMENT\x02";
const STATE_HEADER: usize = 52;
pub const MAX_STATE_BYTES: usize = snapshot::MAX_SNAPSHOT_BYTES - STATE_HEADER;
#[path = "reservations.rs"]
mod reservations;
use reservations::Cursor;
#[path = "backup.rs"]
mod backup;
pub use backup::{BackupSummary, MAX_BACKUP_BYTES};

pub struct PendingPayment {
    pub intent: shielded_pool_circuit::field::Fr,
    pub request: zeroize::Zeroizing<Vec<u8>>,
}

struct StoredState {
    data: Restored,
    cursor: Cursor,
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Record(Error),
    UnsafeFile,
    Conflict,
    Poisoned,
    RecoveryRequired,
}
impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<Error> for StoreError {
    fn from(error: Error) -> Self {
        Self::Record(error)
    }
}
type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Created,
    Written,
    Synced,
    Renamed,
    DirectorySynced,
}

/// The directory descriptor holds the advisory lock until drop. All users of
/// this store must respect that lock. Same-UID code can bypass advisory locks;
/// an attacker executing as the app is outside this filesystem isolation model.
pub struct StateStore {
    directory: File,
    cipher: RecordCipher,
    generation: Option<[u8; 32]>,
    poisoned: bool,
    journal: Cursor,
}
impl StateStore {
    /// Low-level existing-directory API; never use a common open_wallet root here.
    /// Does not create directories, rewrite old formats, remove temporary files,
    /// or reset a wallet whose key/binding cannot authenticate existing state.
    pub fn open(path: &Path, cipher: RecordCipher) -> Result<Self> {
        if !path.is_absolute() {
            return Err(StoreError::UnsafeFile);
        }
        let directory = OpenOptions::new().read(true).custom_flags(DIRECTORY_FLAGS).open(path)?;
        Self::from_directory(directory, cipher)
    }
    /// Use one durable OS app-private root for all wallet aliases. The child
    /// name binds the original master, execution domain and trusted genesis,
    /// excluding RPC/UI identifiers and upgradeable pins. Caller authenticates
    /// the original master and root provenance; this API cannot establish them.
    pub fn open_wallet(root: &Path, cipher: RecordCipher) -> Result<Self> {
        let directory = Self::open_wallet_root(root)?;
        let name = Self::wallet_name(&cipher)?;
        Self::require_absent(&directory, &backup::restore_name(&cipher)?)?;
        // SAFETY: owned parent FD and fixed-length NUL-terminated hex name.
        if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        let child = Self::open_child(&directory, &name)?;
        // Sync even an existing entry: a previous creator may have failed here.
        directory.sync_all()?;
        Self::from_directory(child, cipher)
    }

    pub(crate) fn open_existing_wallet(root: &Path, cipher: RecordCipher) -> Result<Option<Self>> {
        let directory = Self::open_wallet_root(root)?;
        Self::require_absent(&directory, &backup::restore_name(&cipher)?)?;
        let name = Self::wallet_name(&cipher)?;
        match Self::open_child(&directory, &name) {
            Ok(child) => {
                directory.sync_all()?;
                Self::from_directory(child, cipher).map(Some)
            }
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn open_wallet_root(root: &Path) -> Result<File> {
        if !root.is_absolute() {
            return Err(StoreError::UnsafeFile);
        }
        let directory = OpenOptions::new().read(true).custom_flags(DIRECTORY_FLAGS).open(root)?;
        Self::private_directory(&directory)?;
        Self::exclusive_lock(&directory)?;
        // Never reinterpret a legacy flat store as a fresh canonical root.
        for name in [STATE, NEXT, reservations::JOURNAL] {
            Self::require_absent(&directory, name)?;
        }
        Ok(directory)
    }
    fn require_absent(directory: &File, name: &CStr) -> Result<()> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live parent FD/name and space for one stat result; never follow links.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(StoreError::RecoveryRequired);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error.into());
        }
        Ok(())
    }
    fn wallet_name(cipher: &RecordCipher) -> Result<CString> {
        CString::new(hex::encode(cipher.instance_id())).map_err(|_| Error::InvalidInput.into())
    }
    fn open_child(directory: &File, name: &CStr) -> Result<File> {
        // SAFETY: owned parent FD; flags neither create nor follow a symlink.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new uniquely owned descriptor.
        let child = unsafe { File::from_raw_fd(fd) };
        Self::private_directory(&child)?;
        Ok(child)
    }
    fn private_directory(directory: &File) -> Result<()> {
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(StoreError::UnsafeFile);
        }
        Ok(())
    }
    fn exclusive_lock(directory: &File) -> Result<()> {
        // SAFETY: this descriptor remains owned by the caller for the lock's life.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn from_directory(directory: File, cipher: RecordCipher) -> Result<Self> {
        Self::private_directory(&directory)?;
        Self::exclusive_lock(&directory)?;
        let mut store = Self {
            directory,
            cipher,
            generation: None,
            poisoned: false,
            journal: Cursor::default(),
        };
        match store.file(NEXT, libc::O_RDONLY, 0) {
            Ok(_) => return Err(StoreError::RecoveryRequired),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let state = store.read()?;
        store.generation = state.as_ref().map(|state| state.data.generation);
        store.journal =
            store.replay_journal(state.as_ref().map(|state| state.cursor).unwrap_or_default())?;
        Ok(store)
    }
    fn file(&self, name: &CStr, flags: i32, mode: libc::c_uint) -> Result<File> {
        // SAFETY: fixed NUL-terminated names, live owned directory descriptor;
        // successful openat transfers one newly owned descriptor to File.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: fd was just created and has no other Rust owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn private(file: &File) -> Result<()> {
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(StoreError::UnsafeFile);
        }
        Ok(())
    }
    fn read(&self) -> Result<Option<StoredState>> {
        self.read_private_bytes(STATE, MAX_ENCODED_BYTES)?
            .map(|bytes| Self::decode_state(&self.cipher, &bytes))
            .transpose()
    }
    fn read_private_bytes(&self, name: &CStr, limit: usize) -> Result<Option<Vec<u8>>> {
        let mut file = match self.file(name, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        Self::private(&file)?;
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Limit)?;
        if size > limit {
            return Err(Error::Limit.into());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Error::Limit)?;
        bytes.resize(size, 0);
        file.read_exact(&mut bytes)?;
        // Refuse growth without allowing read_to_end to grow the allocation.
        if file.read(&mut [0; 1])? != 0 {
            return Err(StoreError::Conflict);
        }
        Ok(Some(bytes))
    }
    fn decode_state(cipher: &RecordCipher, bytes: &[u8]) -> Result<StoredState> {
        let mut data = snapshot::open(cipher, Kind::State, bytes)?;
        let plain = &mut data.plaintext;
        if plain.len() < STATE_HEADER || &plain[..4] != b"SJS1" {
            return Err(Error::InvalidInput.into());
        }
        let records = u64::from_be_bytes(plain[4..12].try_into().map_err(|_| Error::InvalidInput)?);
        let next = u64::from_be_bytes(plain[12..20].try_into().map_err(|_| Error::InvalidInput)?);
        let digest = plain[20..52].try_into().map_err(|_| Error::InvalidInput)?;
        let cursor = Cursor { records, next, digest };
        cursor.validate()?;
        let size = plain.len().checked_sub(STATE_HEADER).ok_or(Error::InvalidInput)?;
        plain.copy_within(STATE_HEADER.., 0);
        use zeroize::Zeroize;
        plain[size..].zeroize();
        plain.truncate(size);
        Ok(StoredState { data, cursor })
    }
    fn checked_read(&self) -> Result<Option<Restored>> {
        let state = self.read()?;
        if state.as_ref().map(|state| state.data.generation) != self.generation {
            return Err(StoreError::Conflict);
        }
        let cursor =
            self.replay_journal(state.as_ref().map(|state| state.cursor).unwrap_or_default())?;
        if cursor != self.journal {
            return Err(StoreError::Conflict);
        }
        Ok(state.map(|state| state.data))
    }
    /// Returns opaque unverified state; no balance/freshness assertion is made.
    pub fn load(&mut self) -> Result<Option<Restored>> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let result = self.checked_read();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Return the original unresolved submission without changing its state.
    pub fn pending_payment(&mut self) -> Result<Option<PendingPayment>> {
        let Some(state) = self.load()? else {
            return Ok(None);
        };
        if state.plaintext.is_empty() {
            return Ok(None);
        }
        let (digest, request) = state
            .plaintext
            .strip_prefix(PENDING_PAYMENT_TAG)
            .and_then(|bytes| bytes.split_first_chunk::<32>())
            .filter(|(_, request)| !request.is_empty())
            .ok_or(StoreError::RecoveryRequired)?;
        let intent = shielded_pool_circuit::field::fr_from_be(digest)
            .map_err(|_| StoreError::RecoveryRequired)?;
        Ok(Some(PendingPayment { intent, request: zeroize::Zeroizing::new(request.to_vec()) }))
    }

    /// Persist the exact submission and its locally constructed intent before networking.
    pub fn persist_pending_payment(
        &mut self,
        intent: shielded_pool_circuit::field::Fr,
        exact_request: &[u8],
    ) -> Result<()> {
        let overhead = PENDING_PAYMENT_TAG.len() + 32;
        if exact_request.is_empty() || exact_request.len() > MAX_STATE_BYTES - overhead {
            return Err(Error::Limit.into());
        }
        if let Some(existing) = self.pending_payment()? {
            return if existing.intent == intent && existing.request.as_slice() == exact_request {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        let mut record =
            zeroize::Zeroizing::new(Vec::with_capacity(overhead + exact_request.len()));
        record.extend_from_slice(PENDING_PAYMENT_TAG);
        record.extend_from_slice(&shielded_pool_circuit::field::fr_to_be(&intent));
        record.extend_from_slice(exact_request);
        self.commit(&record)
    }

    /// Any failure after beginning the durable operation freezes this handle.
    /// A failed result may already have published the replacement: retain it,
    /// reopen/inspect explicitly, and never infer permission to send again.
    pub fn commit(&mut self, plaintext: &[u8]) -> Result<()> {
        self.commit_inner(plaintext, &mut |_| Ok(()))
    }
    fn commit_inner(
        &mut self,
        plaintext: &[u8],
        checkpoint: &mut dyn FnMut(Stage) -> io::Result<()>,
    ) -> Result<()> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if let Err(error) = self.checked_read() {
            self.poisoned = true;
            return Err(error);
        }
        self.publish(plaintext, checkpoint)
    }
    fn publish(
        &mut self,
        plaintext: &[u8],
        checkpoint: &mut dyn FnMut(Stage) -> io::Result<()>,
    ) -> Result<()> {
        if plaintext.len() > MAX_STATE_BYTES {
            return Err(Error::Limit.into());
        }
        let total = STATE_HEADER.checked_add(plaintext.len()).ok_or(Error::Limit)?;
        let mut wrapped = zeroize::Zeroizing::new(Vec::new());
        wrapped.try_reserve_exact(total).map_err(|_| Error::Limit)?;
        wrapped.extend_from_slice(b"SJS1");
        wrapped.extend_from_slice(&self.journal.records.to_be_bytes());
        wrapped.extend_from_slice(&self.journal.next.to_be_bytes());
        wrapped.extend_from_slice(&self.journal.digest);
        wrapped.extend_from_slice(plaintext);
        let (encoded, generation) = snapshot::seal_generated(&self.cipher, Kind::State, &wrapped)?;
        self.poisoned = true;
        let mut next = self.file(NEXT, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        Self::private(&next)?;
        checkpoint(Stage::Created)?;
        next.write_all(&encoded)?;
        checkpoint(Stage::Written)?;
        next.sync_all()?;
        checkpoint(Stage::Synced)?;
        // SAFETY: fixed names and the same live directory descriptor for both.
        let renamed = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                NEXT.as_ptr(),
                self.directory.as_raw_fd(),
                STATE.as_ptr(),
            )
        };
        if renamed != 0 {
            return Err(io::Error::last_os_error().into());
        }
        checkpoint(Stage::Renamed)?;
        self.directory.sync_all()?;
        checkpoint(Stage::DirectorySynced)?;
        self.generation = Some(generation);
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "instance_tests.rs"]
mod instance_tests;
