// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Private, directory-relative atomic snapshots. Callers supply an existing
//! OS app-private directory (0700), never shared storage or an untrusted path.
//! This layer does not implement business schema, journal or recovery policy.
use crate::{
    sealed::{Kind, RecordCipher},
    snapshot::{self, Restored, MAX_ENCODED_BYTES},
    Error,
};
use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const STATE: &CStr = c"state.bin";
const NEXT: &CStr = c"state.next";

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
}
impl StateStore {
    /// Does not create directories, rewrite old formats, remove temporary files,
    /// or reset a wallet whose key/binding cannot authenticate existing state.
    pub fn open(path: &Path, cipher: RecordCipher) -> Result<Self> {
        if !path.is_absolute() {
            return Err(StoreError::UnsafeFile);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(StoreError::UnsafeFile);
        }
        // SAFETY: this descriptor remains owned by the store for the lock's life.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut store = Self { directory, cipher, generation: None, poisoned: false };
        match store.file(NEXT, libc::O_RDONLY, 0) {
            Ok(_) => return Err(StoreError::RecoveryRequired),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        store.generation = store.read()?.map(|state| state.generation);
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
    fn read(&self) -> Result<Option<Restored>> {
        let mut file = match self.file(STATE, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        Self::private(&file)?;
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Limit)?;
        if size > MAX_ENCODED_BYTES {
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
        Ok(Some(snapshot::open(&self.cipher, Kind::State, &bytes)?))
    }
    fn checked_read(&self) -> Result<Option<Restored>> {
        let state = self.read()?;
        if state.as_ref().map(|state| state.generation) != self.generation {
            return Err(StoreError::Conflict);
        }
        Ok(state)
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
        let (encoded, generation) = snapshot::seal_generated(&self.cipher, Kind::State, plaintext)?;
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
