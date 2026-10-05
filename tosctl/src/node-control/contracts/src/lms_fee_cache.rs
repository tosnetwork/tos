// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Immutable retry bytes bound to an actual journal reservation. This layer
//! checks framing/integrity, not LMS cryptographic validity. A signing service
//! must verify backend output before storing it and reverify cache reads before
//! external export. Cache misses never authorize re-signing an old leaf.

use super::*;
use std::ffi::CString;

const CACHE_MAGIC: &[u8; 8] = b"TOSLMSC1";
const SIGNATURE_SIZE: usize = 2832;
const CACHE_SIZE: usize = 8 + 32 + 4 + 32 + SIGNATURE_SIZE + 32;

fn framing(leaf: u32, signature: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        leaf < LEAF_COUNT && signature.len() == SIGNATURE_SIZE,
        "invalid LMS cache size or leaf"
    );
    anyhow::ensure!(
        word(&signature[..4])? == 0
            && word(&signature[4..8])? == leaf
            && word(&signature[8..12])? == 3
            && word(&signature[2188..2192])? == 8,
        "cache must contain the reserved HSS L1 H20/W4 signature"
    );
    Ok(())
}

impl FeeJournal {
    /// Orchestrate one signing attempt through caller-supplied, reviewed LMS
    /// primitives. The signer is never invoked before a durable reservation.
    /// Verification failure burns the leaf; successful bytes are cached before
    /// return. This adapter supplies no cryptographic implementation or key store.
    pub fn sign_once<S, V>(
        &mut self,
        proven_time: u32,
        chain_next_leaf: u32,
        expected_leaf: u32,
        intent_hash: [u8; 32],
        signer: S,
        verify: V,
    ) -> anyhow::Result<Vec<u8>>
    where
        S: FnOnce(u32, &[u8; 32]) -> anyhow::Result<Vec<u8>>,
        V: FnOnce(u32, &[u8; 32], &[u8]) -> anyhow::Result<bool>,
    {
        let reservation = self.reserve(proven_time, chain_next_leaf, expected_leaf, intent_hash)?;
        let signature = signer(reservation.leaf(), reservation.intent_hash())?;
        anyhow::ensure!(
            verify(expected_leaf, &intent_hash, &signature)?,
            "LMS backend output failed verification"
        );
        self.cache_signature(reservation, &signature)?;
        self.cached_signature(expected_leaf, intent_hash)
    }

    fn cache_file(&self, leaf: u32, write: bool) -> anyhow::Result<File> {
        anyhow::ensure!(leaf < LEAF_COUNT, "invalid cache leaf");
        let name = CString::new(format!("fee-signature-{leaf:08x}"))?;
        let flags =
            if write { libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL } else { libc::O_RDONLY };
        // SAFETY: live pinned directory and a generated NUL-terminated basename;
        // a successful descriptor is moved exactly once into its File owner.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o777 == 0o600
                && meta.uid() == unsafe { libc::geteuid() },
            "cache file must be private and regular"
        );
        Ok(file)
    }

    /// Consume a receipt from this live session. Never overwrite existing cache
    /// bytes, even for the same digest: the backend must not sign that leaf again.
    pub fn cache_signature(
        &mut self,
        reservation: ReservedLeaf,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!self.poisoned, "journal requires recovery after uncertain write");
        anyhow::ensure!(
            Arc::ptr_eq(&reservation.session, &self.session),
            "reservation belongs to another session"
        );
        framing(reservation.leaf, signature)?;
        let mut record = Vec::with_capacity(CACHE_SIZE);
        record.extend(CACHE_MAGIC);
        record.extend(reservation.record_hash);
        record.extend(reservation.leaf.to_be_bytes());
        record.extend(reservation.intent_hash);
        record.extend(signature);
        let checksum = Sha256::digest(&record);
        record.extend(checksum);
        self.poisoned = true;
        let mut file = self.cache_file(reservation.leaf, true)?;
        file.write_all(&record)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.poisoned = false;
        Ok(())
    }

    /// Read identical bytes for an exact reserved intent, including after restart.
    /// A caller must separately check expiry, current chain admission and the
    /// cryptographic signature. Missing/damaged cache is an error, not a signer call.
    pub fn cached_signature(
        &mut self,
        leaf: u32,
        intent_hash: [u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        let mut file = self.cache_file(leaf, false)?;
        anyhow::ensure!(
            file.metadata()?.len() == CACHE_SIZE as u64,
            "truncated or oversized signature cache"
        );
        let mut cached = vec![0; CACHE_SIZE];
        file.read_exact(&mut cached)?;
        anyhow::ensure!(
            &cached[..8] == CACHE_MAGIC
                && word(&cached[40..44])? == leaf
                && cached[44..76] == intent_hash,
            "cache intent mismatch"
        );
        anyhow::ensure!(
            Sha256::digest(&cached[..CACHE_SIZE - 32])[..] == cached[CACHE_SIZE - 32..],
            "cache integrity failure"
        );

        // Confirm that the reservation exists, rather than treating a cache file
        // or an on-chain counter as proof that the signer reserved this intent.
        let size = self
            .file
            .metadata()?
            .len()
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| anyhow::anyhow!("truncated journal"))?;
        anyhow::ensure!(
            size % RECORD_SIZE == 0 && size / RECORD_SIZE <= u64::from(LEAF_COUNT),
            "invalid journal size"
        );
        self.file.seek(SeekFrom::Start(HEADER_SIZE))?;
        let mut hash: [u8; 32] = Sha256::digest(header(self.route)).into();
        let mut found = false;
        for _ in 0..size / RECORD_SIZE {
            let mut record = [0; RECORD_SIZE as usize];
            self.file.read_exact(&mut record)?;
            let mut h = Sha256::new();
            h.update(hash);
            h.update(&record[..40]);
            hash = h.finalize().into();
            anyhow::ensure!(record[40..] == hash, "journal integrity failure during cache lookup");
            if word(&record[..4])? == leaf {
                anyhow::ensure!(
                    record[8..40] == intent_hash && cached[8..40] == hash,
                    "cache does not match reservation"
                );
                found = true;
            }
        }
        anyhow::ensure!(found, "signature has no journal reservation");
        let signature = cached[76..CACHE_SIZE - 32].to_vec();
        framing(leaf, &signature)?;
        // A previous writer may have completed bytes but failed its sync. A
        // cache read is not an escape hatch around durability before export.
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn route() -> FeeRoute {
        FeeRoute { global_id: 42, network: [1; 32], vault: [2; 32], tree_id: [3; 32], epoch0: 100 }
    }

    // Framing-only fixture, deliberately not a cryptographically valid signature.
    fn bytes(q: u32) -> Vec<u8> {
        let mut signature = vec![0x55; SIGNATURE_SIZE];
        signature[..4].copy_from_slice(&0u32.to_be_bytes());
        signature[4..8].copy_from_slice(&q.to_be_bytes());
        signature[8..12].copy_from_slice(&3u32.to_be_bytes());
        signature[2188..2192].copy_from_slice(&8u32.to_be_bytes());
        signature
    }

    fn directory() -> anyhow::Result<tempfile::TempDir> {
        let d = tempfile::tempdir()?;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(d)
    }

    #[test]
    fn restart_retries_identical_bytes_without_reserving_again() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let reservation = journal.reserve(3700, 0, 4, [9; 32])?;
        journal.cache_signature(reservation, &bytes(4))?;
        assert_eq!(journal.cached_signature(4, [9; 32])?, bytes(4));
        assert!(journal.cached_signature(4, [8; 32]).is_err());
        assert!(journal.cached_signature(5, [9; 32]).is_err());
        drop(journal);
        let mut reopened = FeeJournal::open(d.path(), route(), 3700)?;
        assert!(reopened.preview(3700, 0).is_err());
        assert_eq!(reopened.cached_signature(4, [9; 32])?, bytes(4));
        assert_eq!(reopened.state.next_unreserved, 5);
        Ok(())
    }

    #[test]
    fn cache_cannot_be_written_using_a_receipt_from_another_session() -> anyhow::Result<()> {
        let d = directory()?;
        let mut original = FeeJournal::open(d.path(), route(), 100)?;
        let receipt = original.reserve(3700, 0, 4, [9; 32])?;
        drop(original);
        let mut reopened = FeeJournal::open(d.path(), route(), 3700)?;
        assert!(reopened.cache_signature(receipt, &bytes(4)).is_err());
        assert!(!d.path().join("fee-signature-00000004").exists());
        Ok(())
    }

    #[test]
    fn partial_existing_cache_is_never_overwritten_and_poisons_writer() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let receipt = journal.reserve(3700, 0, 4, [9; 32])?;
        let cache = d.path().join("fee-signature-00000004");
        std::fs::write(&cache, b"partial")?;
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600))?;
        assert!(journal.cache_signature(receipt, &bytes(4)).is_err());
        assert_eq!(std::fs::read(cache)?, b"partial");
        assert!(journal.preview(3700, 0).is_err());
        assert!(journal.cached_signature(4, [9; 32]).is_err());
        Ok(())
    }

    #[test]
    fn damaged_cache_and_rolled_back_reservation_are_refused() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let empty = std::fs::read(d.path().join("fee-reservations"))?;
        let receipt = journal.reserve(3700, 0, 4, [9; 32])?;
        journal.cache_signature(receipt, &bytes(4))?;
        let path = d.path().join("fee-signature-00000004");
        let valid = std::fs::read(&path)?;
        let mut changed = valid.clone();
        changed[100] ^= 1;
        std::fs::write(&path, changed)?;
        assert!(journal.cached_signature(4, [9; 32]).is_err());
        std::fs::write(&path, valid)?;
        drop(journal);
        std::fs::write(d.path().join("fee-reservations"), empty)?;
        let mut restored = FeeJournal::open(d.path(), route(), 3700)?;
        assert!(restored.cached_signature(4, [9; 32]).is_err());
        Ok(())
    }

    #[test]
    fn last_slot_can_retry_but_cannot_resume_signing_after_restart() -> anyhow::Result<()> {
        let d = directory()?;
        let last_slot = 100 + (LEAF_COUNT / 4 - 1) * 3600;
        let leaf = LEAF_COUNT - 4;
        let mut journal = FeeJournal::open(d.path(), route(), last_slot - 3600)?;
        let receipt = journal.reserve(last_slot, 0, leaf, [9; 32])?;
        journal.cache_signature(receipt, &bytes(leaf))?;
        drop(journal);
        let mut reopened = FeeJournal::open(d.path(), route(), last_slot)?;
        assert!(reopened.preview(last_slot, 0).is_err());
        assert_eq!(reopened.cached_signature(leaf, [9; 32])?, bytes(leaf));
        Ok(())
    }

    #[test]
    fn wrong_leaf_output_is_not_cached_and_reservation_stays_burned() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let receipt = journal.reserve(3700, 0, 4, [9; 32])?;
        assert!(journal.cache_signature(receipt, &bytes(5)).is_err());
        assert!(!d.path().join("fee-signature-00000004").exists());
        assert_eq!(journal.preview(3700, 0)?.leaf, 5);
        Ok(())
    }

    #[test]
    fn signing_callback_runs_after_reservation_and_retry_never_calls_it() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let calls = std::cell::Cell::new(0);
        let signed = journal.sign_once(
            3700,
            0,
            4,
            [9; 32],
            |q, hash| {
                let persisted = std::fs::read(d.path().join("fee-reservations"))?;
                assert_eq!(persisted.len(), (HEADER_SIZE + RECORD_SIZE) as usize);
                assert_eq!(word(&persisted[112..116])?, q);
                assert_eq!(&persisted[120..152], hash);
                calls.set(calls.get() + 1);
                Ok(bytes(q))
            },
            |q, _, signature| Ok(signature == bytes(q)),
        )?;
        assert_eq!(signed, bytes(4));
        assert!(
            journal
                .sign_once(
                    3700,
                    0,
                    4,
                    [9; 32],
                    |q, _| {
                        calls.set(calls.get() + 1);
                        Ok(bytes(q))
                    },
                    |_, _, _| Ok(true)
                )
                .is_err()
        );
        assert_eq!(journal.cached_signature(4, [9; 32])?, signed);
        assert_eq!(calls.get(), 1);
        Ok(())
    }

    #[test]
    fn failed_signer_or_verification_never_releases_or_reuses_leaf() -> anyhow::Result<()> {
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        assert!(
            journal
                .sign_once(
                    3700,
                    0,
                    4,
                    [9; 32],
                    |_, _| anyhow::bail!("backend failure"),
                    |_, _, _| panic!("verification must not run after signer failure")
                )
                .is_err()
        );
        assert_eq!(journal.preview(3700, 0)?.leaf, 5);
        assert!(
            journal
                .sign_once(3700, 0, 5, [9; 32], |q, _| Ok(bytes(q)), |_, _, _| Ok(false))
                .is_err()
        );
        assert_eq!(journal.preview(3700, 0)?.leaf, 6);
        assert!(journal.cached_signature(4, [9; 32]).is_err());
        assert!(journal.cached_signature(5, [9; 32]).is_err());
        Ok(())
    }
}
