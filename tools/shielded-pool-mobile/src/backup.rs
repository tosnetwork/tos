// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Bind the complete encrypted state and reservation journal into one backup.
use super::{
    reservations::{JOURNAL, MAX_JOURNAL_BYTES},
    *,
};
use crate::sealed::{MAX_PLAINTEXT_BYTES, MAX_SEALED_BYTES};
use sha3::{Digest, Sha3_256};

const TAG: &[u8; 8] = b"TOSBKP\x01\0";
const MANIFEST_BYTES: usize = 80;
const SEALED_MANIFEST_BYTES: usize = MAX_SEALED_BYTES - MAX_PLAINTEXT_BYTES + MANIFEST_BYTES;
pub const MAX_BACKUP_BYTES: usize =
    4 + SEALED_MANIFEST_BYTES + MAX_ENCODED_BYTES + MAX_JOURNAL_BYTES;

/// Metadata from an authenticated backup. A fresh chain replay is still required.
#[derive(Debug, PartialEq, Eq)]
pub struct BackupSummary {
    pub reservation_high_water: u64,
    pub has_state: bool,
}

pub(super) fn restore_name(cipher: &RecordCipher) -> Result<CString> {
    CString::new(format!("{}.restore", hex::encode(cipher.instance_id())))
        .map_err(|_| Error::InvalidInput.into())
}

fn manifest(state: &[u8], journal: &[u8]) -> Result<[u8; MANIFEST_BYTES]> {
    if state.len() > MAX_ENCODED_BYTES || journal.len() > MAX_JOURNAL_BYTES {
        return Err(Error::Limit.into());
    }
    let mut result = [0; MANIFEST_BYTES];
    result[..8].copy_from_slice(TAG);
    result[8..12].copy_from_slice(&(state.len() as u32).to_be_bytes());
    result[12..16].copy_from_slice(&(journal.len() as u32).to_be_bytes());
    result[16..48].copy_from_slice(&Sha3_256::digest(state));
    result[48..].copy_from_slice(&Sha3_256::digest(journal));
    Ok(result)
}

fn validate_files(
    cipher: &RecordCipher,
    state: &[u8],
    journal: &[u8],
) -> Result<(Option<[u8; 32]>, Cursor)> {
    let state =
        if state.is_empty() { None } else { Some(StateStore::decode_state(cipher, state)?) };
    let anchor = state.as_ref().map(|state| state.cursor).unwrap_or_default();
    let cursor = if journal.is_empty() {
        if anchor != Cursor::default() {
            return Err(StoreError::RecoveryRequired);
        }
        anchor
    } else {
        StateStore::decode_journal(cipher, journal, journal.len(), anchor)?
    };
    Ok((state.map(|state| state.data.generation), cursor))
}

impl StateStore {
    /// Export the exact encrypted files while holding the wallet directory lock.
    /// A caller writing to disk must stage the output and publish only on success.
    pub fn export_backup(&mut self, mut output: impl Write) -> Result<()> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let state = self.read_private_bytes(STATE, MAX_ENCODED_BYTES)?;
        let journal = self.read_private_bytes(JOURNAL, MAX_JOURNAL_BYTES)?;
        if state.as_ref().is_some_and(Vec::is_empty) || journal.as_ref().is_some_and(Vec::is_empty)
        {
            self.poisoned = true;
            return Err(StoreError::RecoveryRequired);
        }
        let state = state.unwrap_or_default();
        let journal = journal.unwrap_or_default();
        let (generation, cursor) =
            validate_files(&self.cipher, &state, &journal).inspect_err(|_| {
                self.poisoned = true;
            })?;
        if generation != self.generation || cursor != self.journal {
            self.poisoned = true;
            return Err(StoreError::Conflict);
        }
        let header = self.cipher.seal(Kind::Backup, 0, &manifest(&state, &journal)?)?;
        output.write_all(&(header.len() as u32).to_be_bytes())?;
        output.write_all(&header)?;
        output.write_all(&state)?;
        output.write_all(&journal)?;
        Ok(())
    }

    /// Verify the binding, exact file list and complete journal without writing.
    pub fn inspect_backup(cipher: &RecordCipher, backup: &[u8]) -> Result<BackupSummary> {
        Self::parse_backup(cipher, backup).map(|(_, _, summary)| summary)
    }

    /// Restore into a fresh canonical wallet under the app-private root.
    /// Existing stores and interrupted restore candidates are preserved.
    pub fn restore_backup(
        root: &Path,
        cipher: RecordCipher,
        backup: &[u8],
    ) -> Result<BackupSummary> {
        let (state, journal, summary) = Self::parse_backup(&cipher, backup)?;
        let directory = Self::open_wallet_root(root)?;
        let name = Self::wallet_name(&cipher)?;
        let stage = restore_name(&cipher)?;
        Self::require_absent(&directory, &name)?;
        Self::require_absent(&directory, &stage)?;
        // SAFETY: both names are fixed-format and the root remains locked.
        if unsafe { libc::mkdirat(directory.as_raw_fd(), stage.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        let staged = Self::from_directory(Self::open_child(&directory, &stage)?, cipher)?;
        for (file, bytes) in [(STATE, state), (JOURNAL, journal)] {
            if !bytes.is_empty() {
                let mut output =
                    staged.file(file, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
                output.write_all(bytes)?;
                output.sync_all()?;
            }
        }
        staged.directory.sync_all()?;
        Self::require_absent(&directory, &name)?;
        // SAFETY: both fixed names resolve relative to the same live locked root.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                stage.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        Ok(summary)
    }

    fn parse_backup<'a>(
        cipher: &RecordCipher,
        backup: &'a [u8],
    ) -> Result<(&'a [u8], &'a [u8], BackupSummary)> {
        if backup.len() > MAX_BACKUP_BYTES {
            return Err(Error::Limit.into());
        }
        let (size, remaining) = backup.split_first_chunk::<4>().ok_or(Error::InvalidInput)?;
        let size = u32::from_be_bytes(*size) as usize;
        if size != SEALED_MANIFEST_BYTES {
            return Err(Error::InvalidInput.into());
        }
        let (sealed, files) = remaining.split_at_checked(size).ok_or(Error::InvalidInput)?;
        let header = cipher.open(Kind::Backup, 0, sealed)?;
        let header: &[u8; MANIFEST_BYTES] =
            header.as_slice().try_into().map_err(|_| Error::InvalidInput)?;
        let state_size =
            u32::from_be_bytes(header[8..12].try_into().map_err(|_| Error::InvalidInput)?) as usize;
        let (state, journal) = files.split_at_checked(state_size).ok_or(Error::InvalidInput)?;
        if *header != manifest(state, journal)? {
            return Err(StoreError::Conflict);
        }
        let (generation, cursor) = validate_files(cipher, state, journal)?;
        Ok((
            state,
            journal,
            BackupSummary { reservation_high_water: cursor.next, has_state: generation.is_some() },
        ))
    }
}
