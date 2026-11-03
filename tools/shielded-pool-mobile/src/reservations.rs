// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Sequential encrypted reservation events under the store's directory lock.
use super::*;
use crate::sealed::MAX_SEALED_BYTES;
use sha3::{Digest, Sha3_256};

const JOURNAL: &CStr = c"reservations.bin";
const MAX_RECORDS: u64 = 4096;
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESERVE: u8 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Cursor {
    pub records: u64,
    pub next: u64,
    pub digest: [u8; 32],
}
impl Cursor {
    pub(super) fn validate(&self) -> Result<()> {
        if self.records > MAX_RECORDS {
            return Err(Error::Limit.into());
        }
        if self.records == 0 && *self != Self::default() {
            return Err(Error::InvalidInput.into());
        }
        Ok(())
    }
    fn advance(self, plain: &[u8], frame: &[u8]) -> Result<Self> {
        if plain.len() != 14 || &plain[..5] != b"JR01\x01" {
            return Err(Error::InvalidInput.into());
        }
        let first = u64::from_be_bytes(plain[5..13].try_into().map_err(|_| Error::InvalidInput)?);
        let count = plain[13];
        if count == 0 || count > MAX_RESERVE || first < self.next {
            return Err(StoreError::Conflict);
        }
        let next = first.checked_add(u64::from(count)).ok_or(Error::Limit)?;
        let records = self.records.checked_add(1).ok_or(Error::Limit)?;
        let mut hash = Sha3_256::new();
        hash.update(b"TOS-MOBILE-RESERVATION-CHAIN-v1");
        hash.update(self.digest);
        hash.update(frame);
        Ok(Self { records, next, digest: hash.finalize().into() })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReserveStage {
    Written,
    JournalSynced,
    DirectorySynced,
}

impl StateStore {
    pub(super) fn replay_journal(&self, anchor: Cursor) -> Result<Cursor> {
        anchor.validate()?;
        let mut file = match self.file(JOURNAL, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return if anchor == Cursor::default() {
                    Ok(anchor)
                } else {
                    Err(StoreError::RecoveryRequired)
                };
            }
            Err(error) => return Err(error),
        };
        Self::private(&file)?;
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Limit)?;
        if size > MAX_JOURNAL_BYTES {
            return Err(Error::Limit.into());
        }
        if size < 4 {
            return Err(StoreError::RecoveryRequired);
        }
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"MJR1" {
            return Err(Error::InvalidInput.into());
        }
        let mut remaining = size.checked_sub(4).ok_or(Error::Limit)?;
        let mut cursor = Cursor::default();
        while remaining != 0 {
            if cursor.records >= MAX_RECORDS {
                return Err(Error::Limit.into());
            }
            if remaining < 4 {
                return Err(StoreError::RecoveryRequired);
            }
            let mut prefix = [0; 4];
            file.read_exact(&mut prefix)?;
            let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Limit)?;
            remaining = remaining.checked_sub(4).ok_or(Error::Limit)?;
            if length > MAX_SEALED_BYTES {
                return Err(Error::Limit.into());
            }
            if length > remaining {
                return Err(StoreError::RecoveryRequired);
            }
            let mut record = Vec::new();
            record.try_reserve_exact(length).map_err(|_| Error::Limit)?;
            record.resize(length, 0);
            file.read_exact(&mut record)?;
            let plain = self.cipher.open(Kind::Journal, cursor.records, &record)?;
            let mut frame = Vec::with_capacity(length + 4);
            frame.extend_from_slice(&prefix);
            frame.extend_from_slice(&record);
            cursor = cursor.advance(&plain, &frame)?;
            if cursor.records == anchor.records && cursor != anchor {
                return Err(StoreError::Conflict);
            }
            remaining = remaining.checked_sub(length).ok_or(Error::Limit)?;
        }
        if file.read(&mut [0; 1])? != 0 {
            return Err(StoreError::Conflict);
        }
        if cursor.records < anchor.records {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(cursor)
    }
    /// Monotonic durable reservations; this is not proof of current chain state.
    pub fn reservation_high_water(&mut self) -> Result<u64> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if let Err(error) = self.checked_read() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(self.journal.next)
    }
    /// Reserve before displaying a descriptor or preparing an output. Caller
    /// supplies a complete authenticated scan's next index; None is exhaustion.
    /// Failure can burn indices; never expose a range from a failed call.
    pub fn reserve_indices(&mut self, scanned_next: Option<u64>, count: u8) -> Result<Vec<u64>> {
        self.reserve_inner(scanned_next, count, &mut |_| Ok(()))
    }
    fn reserve_inner(
        &mut self,
        scanned_next: Option<u64>,
        count: u8,
        checkpoint: &mut dyn FnMut(ReserveStage) -> io::Result<()>,
    ) -> Result<Vec<u64>> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if count == 0 || count > MAX_RESERVE || self.journal.records >= MAX_RECORDS {
            return Err(Error::Limit.into());
        }
        let scanned = scanned_next.ok_or(Error::Limit)?;
        let state = match self.checked_read() {
            Ok(state) => state,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let first = scanned.max(self.journal.next);
        first.checked_add(u64::from(count)).ok_or(Error::Limit)?;
        let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(14));
        plain.extend_from_slice(b"JR01\x01");
        plain.extend_from_slice(&first.to_be_bytes());
        plain.push(count);
        let sealed = self.cipher.seal(Kind::Journal, self.journal.records, &plain)?;
        let mut frame = Vec::with_capacity(sealed.len() + 4);
        frame.extend_from_slice(
            &u32::try_from(sealed.len()).map_err(|_| Error::Limit)?.to_be_bytes(),
        );
        frame.extend_from_slice(&sealed);
        let next = self.journal.advance(&plain, &frame)?;
        self.poisoned = true;
        let (mut file, created) = match self.file(JOURNAL, libc::O_WRONLY | libc::O_APPEND, 0) {
            Ok(file) => (file, false),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => (
                self.file(
                    JOURNAL,
                    libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )?,
                true,
            ),
            Err(error) => return Err(error),
        };
        Self::private(&file)?;
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Limit)?;
        let extra = frame.len().checked_add(if created { 4 } else { 0 }).ok_or(Error::Limit)?;
        if size.checked_add(extra).ok_or(Error::Limit)? > MAX_JOURNAL_BYTES {
            return Err(Error::Limit.into());
        }
        if created {
            file.write_all(b"MJR1")?;
        }
        file.write_all(&frame)?;
        checkpoint(ReserveStage::Written)?;
        file.sync_all()?;
        checkpoint(ReserveStage::JournalSynced)?;
        self.directory.sync_all()?;
        checkpoint(ReserveStage::DirectorySynced)?;
        drop(file);
        self.journal = next;
        let data = state
            .map(|state| state.plaintext)
            .unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new()));
        self.publish(&data, &mut |_| Ok(()))?;
        (0..count)
            .map(|offset| first.checked_add(u64::from(offset)).ok_or(Error::Limit.into()))
            .collect()
    }
}

#[cfg(test)]
#[path = "reservation_tests.rs"]
mod tests;
