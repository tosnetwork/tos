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
    /// Reserve durably, invoke the backend once, and verify using the native
    /// consensus implementation before caching and again before returning bytes.
    /// The caller supplies authenticated route/key/time; this low-level adapter
    /// does not validate chain proofs or provide an LMS private-key backend.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_once_verified<S>(
        &mut self,
        public_key: &[u8; 60],
        proven_time: u32,
        chain_next_leaf: u32,
        expected_leaf: u32,
        intent_hash: [u8; 32],
        signer: S,
    ) -> anyhow::Result<Vec<u8>>
    where
        S: FnOnce(u32, &[u8; 32]) -> anyhow::Result<Vec<u8>>,
    {
        self.sign_once(
            proven_time,
            chain_next_leaf,
            expected_leaf,
            intent_hash,
            signer,
            |leaf, digest, signature| {
                Ok(wallet_pq_signer::fee::verify_reserved_signature(
                    public_key, leaf, digest, signature,
                )
                .is_ok())
            },
        )?;
        self.cached_signature_verified(public_key, expected_leaf, intent_hash)
    }

    /// Reverify exact cached bytes before export. A cache miss never invokes a
    /// signer. Freshness, current route and message expiry remain caller gates.
    #[cfg(feature = "native-wallet-signer")]
    pub fn cached_signature_verified(
        &mut self,
        public_key: &[u8; 60],
        leaf: u32,
        intent_hash: [u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        let signature = self.cached_signature(leaf, intent_hash)?;
        wallet_pq_signer::fee::verify_reserved_signature(
            public_key,
            leaf,
            &intent_hash,
            &signature,
        )?;
        Ok(signature)
    }

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

    #[cfg(feature = "native-wallet-signer")]
    #[test]
    fn internal_fee_signature_matches_independent_vm() -> anyhow::Result<()> {
        use chain_block::{BuilderData, Cell};
        use tos_vm::{
            executor::{Engine, gas::gas_state::Gas},
            stack::{Stack, StackItem, integer::IntegerData, savelist::SaveList},
        };
        unsafe extern "C" {
            fn tos_wallet_lms_fee_sign_reserved(
                seed: *const u8,
                seed_size: usize,
                leaf: u32,
                digest: *const u8,
                digest_size: usize,
                path: *const u8,
                path_size: usize,
                key: *const u8,
                key_size: usize,
                output: *mut u8,
                output_size: usize,
            ) -> i32;
        }
        fn chain(bytes: &[u8]) -> anyhow::Result<Cell> {
            let mut tail = None;
            for chunk in bytes.chunks(127).rev() {
                let mut b = BuilderData::new();
                b.append_raw(chunk, chunk.len() * 8)?;
                if let Some(cell) = tail {
                    b.checked_append_reference(cell)?;
                }
                tail = Some(b.into_cell()?);
            }
            tail.ok_or_else(|| anyhow::anyhow!("empty fixture"))
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/lms-fee-signature.json"
        ))?;
        let key = hex::decode(fixture["public_key"].as_str().unwrap())?;
        let old = hex::decode(fixture["signature"].as_str().unwrap())?;
        let digest: [u8; 32] =
            hex::decode(fixture["digest"].as_str().unwrap())?.try_into().unwrap();
        let leaf = u32::try_from(fixture["leaf"].as_u64().unwrap())?;
        // Fixed public test key, never runtime key material.
        let mut seed = [0x44; 48];
        seed[32..].fill(0x55);
        let mut signature = vec![0; 2832];
        assert_eq!(
            unsafe {
                tos_wallet_lms_fee_sign_reserved(
                    seed.as_ptr(),
                    seed.len(),
                    leaf,
                    digest.as_ptr(),
                    digest.len(),
                    old[2192..].as_ptr(),
                    640,
                    key.as_ptr(),
                    key.len(),
                    signature.as_mut_ptr(),
                    signature.len(),
                )
            },
            1
        );
        wallet_pq_signer::fee::verify_reserved_signature(&key, leaf, &digest, &signature)?;
        for corrupted in [false, true] {
            let mut sig = signature.clone();
            if corrupted {
                sig[2831] ^= 1;
            }
            let mut stack = Stack::new();
            stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(&digest)));
            stack.push(StackItem::int(IntegerData::from_i64(i64::from(leaf))));
            stack.push(StackItem::Cell(chain(&sig)?));
            stack.push(StackItem::Cell(chain(&key)?));
            let mut code = BuilderData::new();
            code.append_raw(&[0xf9, 0x31, 0x03], 24)?;
            let mut vm = Engine::with_capabilities(0).setup_checked(
                code.into_cell()?,
                SaveList::new(),
                stack,
                Gas::test_with_limit(100_000),
                vec![],
            )?;
            vm.set_block_version(17);
            assert_eq!(vm.execute()?, 0);
            assert_eq!(vm.stack().depth(), 1);
            assert_eq!(
                vm.stack().get(0)?.as_integer_value(-1..=0)?,
                if corrupted { 0 } else { -1 },
                "native fee signing disagrees with independent VM"
            );
        }
        Ok(())
    }

    #[cfg(feature = "native-wallet-signer")]
    #[test]
    fn native_fee_verification_guards_backend_cache_and_retry() -> anyhow::Result<()> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/lms-fee-signature.json"
        ))?;
        let key: [u8; 60] =
            hex::decode(fixture["public_key"].as_str().unwrap())?.try_into().unwrap();
        let digest: [u8; 32] =
            hex::decode(fixture["digest"].as_str().unwrap())?.try_into().unwrap();
        let signature = hex::decode(fixture["signature"].as_str().unwrap())?;
        let leaf = u32::try_from(fixture["leaf"].as_u64().unwrap())?;
        assert_eq!(leaf, 12);
        let d = directory()?;
        let mut journal = FeeJournal::open(d.path(), route(), 100)?;
        let calls = std::cell::Cell::new(0);
        let output = journal.sign_once_verified(&key, 10900, 0, leaf, digest, |q, m| {
            assert_eq!(q, leaf);
            assert_eq!(m, &digest);
            calls.set(calls.get() + 1);
            Ok(signature.clone())
        })?;
        assert_eq!(output, signature);
        assert_eq!(calls.get(), 1);
        assert!(
            journal
                .sign_once_verified(&key, 10900, 0, leaf, digest, |_, _| panic!(
                    "native retry invoked backend"
                ))
                .is_err()
        );
        assert_eq!(journal.cached_signature_verified(&key, leaf, digest)?, signature);
        let mut wrong_key = key;
        wrong_key[28] ^= 1;
        assert!(
            journal.cached_signature_verified(&wrong_key, leaf, digest).is_err(),
            "native cache ignored enrolled key"
        );
        let mut invalid = signature.clone();
        invalid[4..8].copy_from_slice(&13u32.to_be_bytes());
        assert!(
            journal.sign_once_verified(&key, 10900, 0, 13, digest, |_, _| Ok(invalid)).is_err(),
            "native adapter cached invalid backend signature"
        );
        assert_eq!(journal.state.next_unreserved, 14, "invalid backend did not burn leaf");
        assert!(
            !d.path().join("fee-signature-0000000d").exists(),
            "invalid backend wrote signature cache"
        );
        // Corrupt signature bytes but preserve framing and the non-secret checksum.
        let cache = d.path().join("fee-signature-0000000c");
        let mut record = std::fs::read(&cache)?;
        record[76 + 44] ^= 1;
        let checksum = Sha256::digest(&record[..CACHE_SIZE - 32]);
        record[CACHE_SIZE - 32..].copy_from_slice(&checksum);
        std::fs::write(&cache, record)?;
        assert!(journal.cached_signature(leaf, digest).is_ok());
        assert!(
            journal.cached_signature_verified(&key, leaf, digest).is_err(),
            "native adapter exported forged cache"
        );
        assert_eq!(calls.get(), 1);
        Ok(())
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
