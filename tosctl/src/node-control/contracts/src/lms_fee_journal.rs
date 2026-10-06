// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Unix append-only fee reservations. Every open treats continuity as lost and
//! waits for the next proven slot, including an ordinary process restart.
//! The caller must revoke other devices and verify finalized chain proofs.
//! A file lock excludes local writers only; this is not a hardware monotonic store.

use crate::lms_fee_schedule::{
    Continuity, FeeRoute, IntactState, LEAF_COUNT, ReservationPlan, RestoreBarrier, ScheduleError,
    plan_reservation,
};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::Arc,
};

#[path = "lms_fee_cache.rs"]
mod cache;

const MAGIC: &[u8; 8] = b"TOSLMS01";
const HEADER_SIZE: u64 = 112;
const RECORD_SIZE: u64 = 72;

/// Returned only after the reservation and its hash-chain record are fsynced.
/// No signing or re-signing method is provided by this receipt.
#[derive(Debug)]
pub struct ReservedLeaf {
    leaf: u32,
    intent_hash: [u8; 32],
    record_hash: [u8; 32],
    session: Arc<()>,
}

impl ReservedLeaf {
    pub fn leaf(&self) -> u32 {
        self.leaf
    }
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.intent_hash
    }
}

/// Cached and reverified fee body. Broadcasting still requires current expiry,
/// admission/fee checks and an authenticated transaction receipt afterward.
pub struct SignedFeeMessage {
    vault: [u8; 32],
    intent: crate::wallet_v5r2_fee::FeeIntent,
    body: chain_block::Cell,
}
impl SignedFeeMessage {
    pub fn vault(&self) -> &[u8; 32] {
        &self.vault
    }
    pub fn intent(&self) -> &crate::wallet_v5r2_fee::FeeIntent {
        &self.intent
    }
    pub fn body(&self) -> &chain_block::Cell {
        &self.body
    }
}

pub struct FeeJournal {
    file: File,
    directory: File,
    session: Arc<()>,
    route: FeeRoute,
    state: IntactState,
    barrier: Option<RestoreBarrier>,
    resume_error: Option<ScheduleError>,
    hash: [u8; 32],
    poisoned: bool,
}

fn header(route: FeeRoute) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend(route.global_id.to_be_bytes());
    out.extend(route.network);
    out.extend(route.vault);
    out.extend(route.tree_id);
    out.extend(route.epoch0.to_be_bytes());
    out
}

fn word(bytes: &[u8]) -> anyhow::Result<u32> {
    Ok(u32::from_be_bytes(bytes.try_into()?))
}

impl FeeJournal {
    /// The directory must already exist, be owned by this user, and have mode
    /// 0700. No path replacement or implicit recovery of a damaged file occurs.
    pub fn open(directory: &Path, route: FeeRoute, proven_time: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(directory.is_absolute(), "journal directory must be absolute");
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let meta = dir.metadata()?;
        anyhow::ensure!(
            meta.is_dir()
                && meta.mode() & 0o777 == 0o700
                && meta.uid() == unsafe { libc::geteuid() },
            "journal directory must be private and owned"
        );
        // SAFETY: the directory descriptor is live; the filename is a fixed,
        // NUL-terminated basename. A successful descriptor has one File owner.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c"fee-reservations".as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o777 == 0o600
                && meta.uid() == unsafe { libc::geteuid() },
            "journal file must be private, regular and unlinked elsewhere"
        );
        file.try_lock_exclusive()?;
        let (barrier, resume_error) = match RestoreBarrier::new(route, proven_time) {
            Ok(barrier) => (Some(barrier), None),
            Err(error @ (ScheduleError::Exhausted | ScheduleError::TimeOverflow)) => {
                (None, Some(error))
            }
            Err(error) => anyhow::bail!("restore barrier: {error:?}"),
        };
        let expected = header(route);
        let mut hash: [u8; 32] = Sha256::digest(&expected).into();
        if file.metadata()?.len() == 0 {
            file.write_all(&expected)?;
            file.sync_all()?;
            dir.sync_all()?;
        }
        let length = file.metadata()?.len();
        let records = length
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| anyhow::anyhow!("truncated journal header"))?;
        anyhow::ensure!(
            records % RECORD_SIZE == 0 && records / RECORD_SIZE <= u64::from(LEAF_COUNT),
            "truncated or oversized journal"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut actual = vec![0; expected.len()];
        file.read_exact(&mut actual)?;
        anyhow::ensure!(actual == expected, "journal route or schema mismatch");
        let mut state = IntactState { route, next_unreserved: 0, last_proven_time: route.epoch0 };
        for _ in 0..records / RECORD_SIZE {
            let mut record = [0u8; RECORD_SIZE as usize];
            file.read_exact(&mut record)?;
            let mut h = Sha256::new();
            h.update(hash);
            h.update(&record[..40]);
            hash = h.finalize().into();
            anyhow::ensure!(record[40..] == hash, "journal integrity failure");
            let leaf = word(&record[..4])?;
            let time = word(&record[4..8])?;
            let plan = plan_reservation(route, time, leaf, Continuity::Intact(state))
                .map_err(|e| anyhow::anyhow!("invalid journal history: {e:?}"))?;
            anyhow::ensure!(plan.leaf == leaf, "journal reuses or predates a reserved leaf");
            state = plan.next_state;
        }
        anyhow::ensure!(proven_time >= state.last_proven_time, "stale opening proof");
        Ok(Self {
            file,
            directory: dir,
            session: Arc::new(()),
            route,
            state,
            barrier,
            resume_error,
            hash,
            poisoned: false,
        })
    }

    /// Open using a fresh authenticated vault observation. Reopening still
    /// enforces the next-slot restore barrier; a proof does not erase it.
    pub fn open_proven(
        directory: &Path,
        vault: &crate::wallet_v5r2_state::ProvenFeeVault,
        now: u32,
    ) -> anyhow::Result<Self> {
        vault.validate_freshness(now)?;
        Self::open(directory, vault.route(), vault.proven_time())
    }

    /// Build and sign one fee envelope using the exact authenticated route,
    /// counter, configuration and public key. Inner action authorization and
    /// network fee affordability must be verified separately. The callbacks
    /// must be trusted cryptographic implementations, never endpoint verdicts.
    pub fn sign_proven_fee<S, V>(
        &mut self,
        vault: &crate::wallet_v5r2_state::ProvenFeeVault,
        now: u32,
        valid_until: u32,
        value: u128,
        payload: crate::wallet_v5r2_fee::FeePayload,
        signer: S,
        mut verify: V,
    ) -> anyhow::Result<SignedFeeMessage>
    where
        S: FnOnce(u32, &[u8; 32]) -> anyhow::Result<Vec<u8>>,
        V: FnMut(&[u8; 60], u32, &[u8; 32], &[u8]) -> anyhow::Result<bool>,
    {
        use crate::wallet_v5r2_fee::{FeeBinding, FeeIntent};
        let plan = self.preview_proven(vault, now)?;
        anyhow::ensure!(valid_until > now, "fee deadline already expired by local clock");
        let intent = FeeIntent::new(
            FeeBinding {
                vault: vault.route().vault,
                config_hash: *vault.config_hash(),
                epoch0: vault.route().epoch0,
                leaf: plan.leaf,
                valid_until,
                value,
            },
            payload,
            vault.proven_time(),
        )?;
        let signature = self.sign_once(
            vault.proven_time(),
            vault.next_leaf(),
            plan.leaf,
            *intent.digest(),
            signer,
            |leaf, digest, bytes| verify(vault.fee_public_key(), leaf, digest, bytes),
        )?;
        anyhow::ensure!(
            verify(vault.fee_public_key(), plan.leaf, intent.digest(), &signature)?,
            "cached LMS output failed export verification"
        );
        let body = intent.encode_external(&signature)?;
        Ok(SignedFeeMessage { vault: vault.route().vault, intent, body })
    }

    /// Observe capacity using both authenticated chain state and this locked
    /// journal's local reservations and restore barrier. This neither reserves
    /// a leaf nor permits signing; reserve again before invoking the backend.
    pub fn preview_proven(
        &self,
        vault: &crate::wallet_v5r2_state::ProvenFeeVault,
        now: u32,
    ) -> anyhow::Result<ReservationPlan> {
        vault.validate_freshness(now)?;
        anyhow::ensure!(self.route == vault.route(), "proven vault and journal route mismatch");
        self.preview(vault.proven_time(), vault.next_leaf())
    }

    pub fn preview(
        &self,
        proven_time: u32,
        chain_next_leaf: u32,
    ) -> anyhow::Result<ReservationPlan> {
        anyhow::ensure!(!self.poisoned, "journal requires recovery after uncertain write");
        anyhow::ensure!(
            self.resume_error.is_none(),
            "new reservations unavailable: {:?}",
            self.resume_error
        );
        if let Some(barrier) = self.barrier {
            plan_reservation(
                self.route,
                proven_time,
                chain_next_leaf,
                Continuity::Restored(barrier),
            )
            .map_err(|e| anyhow::anyhow!("restore wait: {e:?}"))?;
        }
        plan_reservation(self.route, proven_time, chain_next_leaf, Continuity::Intact(self.state))
            .map_err(|e| anyhow::anyhow!("reservation: {e:?}"))
    }

    /// Bind the exact built fee intent to the previewed leaf. A stale preview
    /// fails. Only after this returns may the caller invoke its LMS signer.
    /// Failures after beginning the append poison this session, even if the
    /// record may have reached disk; no in-process retry can reuse that leaf.
    pub fn reserve(
        &mut self,
        proven_time: u32,
        chain_next_leaf: u32,
        expected_leaf: u32,
        intent_hash: [u8; 32],
    ) -> anyhow::Result<ReservedLeaf> {
        let plan = self.preview(proven_time, chain_next_leaf)?;
        anyhow::ensure!(plan.leaf == expected_leaf, "stale reservation preview");
        let mut record = Vec::with_capacity(RECORD_SIZE as usize);
        record.extend(plan.leaf.to_be_bytes());
        record.extend(proven_time.to_be_bytes());
        record.extend(intent_hash);
        let mut h = Sha256::new();
        h.update(self.hash);
        h.update(&record);
        let next_hash: [u8; 32] = h.finalize().into();
        record.extend(next_hash);
        self.poisoned = true;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&record)?;
        self.file.sync_all()?;
        self.state = plan.next_state;
        self.hash = next_hash;
        self.barrier = None;
        self.poisoned = false;
        Ok(ReservedLeaf {
            leaf: plan.leaf,
            intent_hash,
            record_hash: next_hash,
            session: Arc::clone(&self.session),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn route() -> FeeRoute {
        FeeRoute { global_id: 42, network: [1; 32], vault: [2; 32], tree_id: [3; 32], epoch0: 100 }
    }

    #[test]
    #[ignore = "invoked only by the process restart test with a private fixture path"]
    fn child_process_probe() -> anyhow::Result<()> {
        let directory = std::env::var("TOS_LMS_JOURNAL_TEST_DIR")?;
        let mode = std::env::var("TOS_LMS_JOURNAL_TEST_MODE")?;
        if mode == "locked" {
            assert!(FeeJournal::open(Path::new(&directory), route(), 3700).is_err());
        } else {
            anyhow::ensure!(mode == "restart", "unknown child probe mode");
            let mut journal = FeeJournal::open(Path::new(&directory), route(), 3700)?;
            assert_eq!(journal.state.next_unreserved, 5);
            assert!(journal.preview(3700, 0).is_err());
            assert_eq!(journal.reserve(7300, 0, 8, [8; 32])?.leaf(), 8);
        }
        Ok(())
    }

    #[test]
    fn exclusive_process_handoff_preserves_reservations() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut journal = FeeJournal::open(dir.path(), route(), 100)?;
        journal.reserve(3700, 0, 4, [4; 32])?;
        let child = |mode| -> anyhow::Result<()> {
            let result = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "lms_fee_journal::tests::child_process_probe",
                    "--nocapture",
                ])
                .env("TOS_LMS_JOURNAL_TEST_DIR", dir.path())
                .env("TOS_LMS_JOURNAL_TEST_MODE", mode)
                .output()?;
            anyhow::ensure!(
                result.status.success(),
                "child failed: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            anyhow::ensure!(
                String::from_utf8_lossy(&result.stdout).contains("1 passed"),
                "child test did not run"
            );
            Ok(())
        };
        child("locked")?;
        drop(journal);
        child("restart")?;
        let reopened = FeeJournal::open(dir.path(), route(), 7300)?;
        assert_eq!(reopened.state.next_unreserved, 9);
        assert!(reopened.preview(7300, 0).is_err());
        assert_eq!(reopened.preview(10900, 0)?.leaf, 12);
        Ok(())
    }

    #[test]
    fn durable_reservations_exclude_writers_and_restarts_wait() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut journal = FeeJournal::open(dir.path(), route(), 100)?;
        assert!(FeeJournal::open(dir.path(), route(), 100).is_err());
        assert!(journal.preview(3699, 0).is_err());
        assert_eq!(journal.preview(3700, 0)?.leaf, 4);
        let reserved = journal.reserve(3700, 0, 4, [7; 32])?;
        assert_eq!(reserved.leaf(), 4);
        assert_eq!(reserved.intent_hash(), &[7; 32]);
        let raw = std::fs::read(dir.path().join("fee-reservations"))?;
        assert_eq!(raw.len(), (HEADER_SIZE + RECORD_SIZE) as usize);
        assert_eq!(word(&raw[112..116])?, 4);
        assert_eq!(&raw[120..152], &[7; 32]);
        assert_eq!(journal.preview(3700, 0)?.leaf, 5);
        assert!(journal.reserve(3700, 0, 4, [8; 32]).is_err());
        drop(journal);
        let mut reopened = FeeJournal::open(dir.path(), route(), 3700)?;
        assert_eq!(reopened.state.next_unreserved, 5);
        assert!(reopened.preview(3700, 0).is_err());
        assert_eq!(reopened.reserve(7300, 0, 8, [9; 32])?.leaf(), 8);
        Ok(())
    }

    #[test]
    fn failed_write_poison_survives_repaired_handle() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut journal = FeeJournal::open(dir.path(), route(), 100)?;
        let readonly = File::open(dir.path().join("fee-reservations"))?;
        let locked = std::mem::replace(&mut journal.file, readonly);
        // Real OS write failure, while the original exclusive lock stays held.
        assert!(journal.reserve(3700, 0, 4, [1; 32]).is_err());
        journal.file = locked;
        assert!(journal.preview(3700, 0).is_err());
        assert!(journal.reserve(3700, 0, 4, [1; 32]).is_err());
        drop(journal);
        let recovered = FeeJournal::open(dir.path(), route(), 3700)?;
        assert!(recovered.preview(3700, 0).is_err());
        assert_eq!(recovered.preview(7300, 0)?.leaf, 8);
        Ok(())
    }

    #[test]
    fn links_and_nonprivate_directory_are_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let target = dir.path().join("other");
        std::fs::write(&target, b"untouched")?;
        let journal = dir.path().join("fee-reservations");
        std::os::unix::fs::symlink(&target, &journal)?;
        assert!(FeeJournal::open(dir.path(), route(), 100).is_err());
        assert_eq!(std::fs::read(&target)?, b"untouched");
        std::fs::remove_file(&journal)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        std::fs::hard_link(&target, &journal)?;
        assert!(FeeJournal::open(dir.path(), route(), 100).is_err());
        std::fs::remove_file(&journal)?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
        assert!(FeeJournal::open(dir.path(), route(), 100).is_err());
        Ok(())
    }

    #[test]
    fn rollback_snapshot_cannot_resume_current_slot() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut journal = FeeJournal::open(dir.path(), route(), 100)?;
        let file = dir.path().join("fee-reservations");
        let snapshot = std::fs::read(&file)?;
        journal.reserve(3700, 0, 4, [1; 32])?;
        drop(journal);
        std::fs::write(&file, snapshot)?;
        let restored = FeeJournal::open(dir.path(), route(), 3700)?;
        assert!(restored.preview(3700, 0).is_err());
        assert_eq!(restored.preview(7300, 0)?.leaf, 8);
        Ok(())
    }

    #[test]
    fn damaged_route_truncation_and_permissions_fail_closed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut journal = FeeJournal::open(dir.path(), route(), 100)?;
        journal.reserve(3700, 0, 4, [1; 32])?;
        drop(journal);
        assert!(
            FeeJournal::open(dir.path(), FeeRoute { tree_id: [9; 32], ..route() }, 3700).is_err()
        );
        let file = dir.path().join("fee-reservations");
        let original = std::fs::read(&file)?;
        let mut bad = original.clone();
        bad[120] ^= 1;
        std::fs::write(&file, bad)?;
        assert!(FeeJournal::open(dir.path(), route(), 3700).is_err());
        std::fs::write(&file, &original[..original.len() - 1])?;
        assert!(FeeJournal::open(dir.path(), route(), 3700).is_err());
        std::fs::write(&file, original)?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))?;
        assert!(FeeJournal::open(dir.path(), route(), 3700).is_err());
        Ok(())
    }
}
