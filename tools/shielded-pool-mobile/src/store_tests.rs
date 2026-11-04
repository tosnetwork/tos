// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use super::*;
use crate::sealed::Binding;
use std::{
    fs,
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) path: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tos-mobile-store-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("private");
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { root, path }
    }
    pub(super) fn open(&self) -> StateStore {
        StateStore::open(&self.path, cipher(42)).unwrap()
    }
    pub(super) fn state(&self) -> PathBuf {
        self.path.join("state.bin")
    }
    pub(super) fn next(&self) -> PathBuf {
        self.path.join("state.next")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn binding() -> Binding {
    Binding {
        global_id: 3,
        pool_account: [1; 32],
        genesis_root: [2; 32],
        genesis_file: [3; 32],
        code_hash: [4; 32],
        profile_hash: [5; 32],
        manifest_hash: [6; 32],
        verifying_key_hash: [7; 32],
    }
}
pub(super) fn cipher(seed: u8) -> RecordCipher {
    RecordCipher::derive(&[seed; 32], binding())
}
pub(super) fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn valid_stored_state(data: &[u8]) -> Vec<u8> {
    let fixture = Fixture::new();
    fixture.open().commit(data).unwrap();
    fs::read(fixture.state()).unwrap()
}

#[test]
fn backup_binds_the_exact_state_and_later_reservations() {
    let f = Fixture::new();
    let mut store = f.open();
    assert_eq!(store.reserve_indices(Some(4), 2).unwrap(), [4, 5]);
    store.commit(b"local state").unwrap();
    assert_eq!(store.reserve_indices(Some(0), 1).unwrap(), [6]);
    let mut backup = Vec::new();
    store.export_backup(&mut backup).unwrap();
    assert_eq!(
        StateStore::inspect_backup(&cipher(42), &backup).unwrap(),
        BackupSummary { reservation_high_water: 7, has_state: true },
    );
    assert!(StateStore::inspect_backup(&cipher(43), &backup).is_err());
    let mut other_genesis = binding();
    other_genesis.genesis_root[0] ^= 1;
    assert!(StateStore::inspect_backup(&RecordCipher::derive(&[42; 32], other_genesis), &backup)
        .is_err());
    assert!(StateStore::inspect_backup(&cipher(42), &backup[..backup.len() - 1]).is_err());
    let state_offset = 4 + u32::from_be_bytes(backup[..4].try_into().unwrap()) as usize;
    let replacement = valid_stored_state(b"local state");
    let state_size = fs::metadata(f.state()).unwrap().len() as usize;
    assert_eq!(replacement.len(), state_size);
    backup[state_offset..state_offset + state_size].copy_from_slice(&replacement);
    assert!(matches!(StateStore::inspect_backup(&cipher(42), &backup), Err(StoreError::Conflict)));
}

#[test]
fn backup_includes_the_checkpoint_for_an_empty_state_payload() {
    let f = Fixture::new();
    let mut store = f.open();
    assert_eq!(store.reserve_indices(Some(8), 1).unwrap(), [8]);
    let mut backup = Vec::new();
    store.export_backup(&mut backup).unwrap();
    assert_eq!(
        StateStore::inspect_backup(&cipher(42), &backup).unwrap(),
        BackupSummary { reservation_high_water: 9, has_state: true },
    );
}

#[test]
fn backup_restore_preserves_pending_bytes_and_the_next_index() {
    let source = Fixture::new();
    let target = Fixture::new();
    let mut store = source.open();
    let intent = 1_u64.into();
    let request = b"original unresolved request";
    store.reserve_indices(Some(19), 1).unwrap();
    store.persist_pending_payment(intent, request).unwrap();
    store.reserve_indices(Some(0), 1).unwrap();
    let mut backup = Vec::new();
    store.export_backup(&mut backup).unwrap();
    assert!(StateStore::restore_backup(&target.path, cipher(43), &backup).is_err());
    assert_eq!(fs::read_dir(&target.path).unwrap().count(), 0);
    let summary = StateStore::restore_backup(&target.path, cipher(42), &backup).unwrap();
    assert_eq!(summary.reservation_high_water, 21);
    let mut restored = StateStore::open_wallet(&target.path, cipher(42)).unwrap();
    let pending = restored.pending_payment().unwrap().unwrap();
    assert_eq!(pending.intent, intent);
    assert_eq!(pending.request.as_slice(), request);
    assert_eq!(restored.reserve_indices(Some(0), 1).unwrap(), [21]);
    assert!(matches!(
        StateStore::restore_backup(&target.path, cipher(42), &backup),
        Err(StoreError::RecoveryRequired),
    ));
    assert_eq!(restored.reservation_high_water().unwrap(), 22);
}

#[test]
fn an_interrupted_backup_restore_prevents_fresh_wallet_creation() {
    let f = Fixture::new();
    let candidate = backup::restore_name(&cipher(42)).unwrap();
    let candidate = f.path.join(candidate.to_str().unwrap());
    fs::DirBuilder::new().mode(0o700).create(&candidate).unwrap();
    private_write(&candidate.join("state.bin"), b"interrupted candidate");
    assert!(matches!(
        StateStore::open_wallet(&f.path, cipher(42)),
        Err(StoreError::RecoveryRequired),
    ));
    assert_eq!(fs::read(candidate.join("state.bin")).unwrap(), b"interrupted candidate");
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 1);
}
#[test]
fn real_files_round_trip_replace_and_reopen_privately() {
    let f = Fixture::new();
    let mut store = f.open();
    assert!(store.load().unwrap().is_none());
    store.commit(b"first opaque state").unwrap();
    assert_eq!(&*store.load().unwrap().unwrap().plaintext, b"first opaque state");
    assert_eq!(fs::metadata(f.state()).unwrap().mode() & 0o777, 0o600);
    let first = fs::read(f.state()).unwrap();
    store.commit(b"second opaque state").unwrap();
    assert_ne!(first, fs::read(f.state()).unwrap());
    assert!(!f.next().exists());
    drop(store);
    assert_eq!(&*f.open().load().unwrap().unwrap().plaintext, b"second opaque state");
}
#[test]
fn directory_lock_is_exclusive_and_released_on_drop() {
    let f = Fixture::new();
    let first = f.open();
    assert!(
        matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
    );
    drop(first);
    assert!(StateStore::open(&f.path, cipher(42)).is_ok());
}
#[test]
fn directory_permissions_and_final_symlink_are_refused() {
    let f = Fixture::new();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o700)).unwrap();
    let link = f.root.join("link");
    symlink(&f.path, &link).unwrap();
    assert!(StateStore::open(&link, cipher(42)).is_err());
}
#[test]
fn state_read_permissions_hard_links_and_symlinks_are_refused() {
    let f = Fixture::new();
    f.open().commit(b"protected").unwrap();
    let original = fs::read(f.state()).unwrap();
    fs::set_permissions(f.state(), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    fs::set_permissions(f.state(), fs::Permissions::from_mode(0o600)).unwrap();
    let alias = f.root.join("alias");
    fs::hard_link(f.state(), &alias).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    fs::remove_file(f.state()).unwrap();
    symlink(&alias, f.state()).unwrap();
    assert!(StateStore::open(&f.path, cipher(42)).is_err());
    assert_eq!(fs::read(alias).unwrap(), original);
}
#[test]
fn fifo_is_refused_without_blocking() {
    let f = Fixture::new();
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(f.state().as_os_str().as_bytes()).unwrap();
    // SAFETY: fixture-owned path with a live NUL-terminated string.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
}
#[test]
fn oversize_file_is_refused_and_original_is_retained() {
    let f = Fixture::new();
    private_write(&f.state(), b"");
    File::options()
        .write(true)
        .open(f.state())
        .unwrap()
        .set_len((MAX_ENCODED_BYTES as u64) + 1)
        .unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Record(Error::Limit))));
    assert_eq!(fs::metadata(f.state()).unwrap().len(), (MAX_ENCODED_BYTES as u64) + 1);
}
#[test]
fn wrong_seed_genesis_corruption_and_old_format_never_reset_existing_state() {
    let f = Fixture::new();
    f.open().commit(b"preserve pending bytes").unwrap();
    let original = fs::read(f.state()).unwrap();
    assert!(matches!(
        StateStore::open(&f.path, cipher(43)),
        Err(StoreError::Record(Error::Crypto))
    ));
    let mut b = binding();
    b.genesis_root[0] ^= 1;
    assert!(matches!(
        StateStore::open(&f.path, RecordCipher::derive(&[42; 32], b)),
        Err(StoreError::Record(Error::Crypto))
    ));
    assert_eq!(fs::read(f.state()).unwrap(), original);
    for bad in [b"old unsupported format".to_vec(), original[..original.len() - 1].to_vec()] {
        private_write(&f.state(), &bad);
        assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Record(_))));
        assert_eq!(fs::read(f.state()).unwrap(), bad);
        assert!(!f.next().exists());
    }
}
#[test]
fn uncertain_temporary_file_is_preserved_and_requires_explicit_recovery() {
    let f = Fixture::new();
    f.open().commit(b"old").unwrap();
    let original = fs::read(f.state()).unwrap();
    private_write(&f.next(), b"uncertain candidate");
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::RecoveryRequired)));
    assert_eq!(fs::read(f.state()).unwrap(), original);
    assert_eq!(fs::read(f.next()).unwrap(), b"uncertain candidate");
}
#[test]
fn outside_replacement_freezes_handle_without_overwriting_new_bytes() {
    let f = Fixture::new();
    let mut store = f.open();
    store.commit(b"old").unwrap();
    let external = valid_stored_state(b"external replacement");
    private_write(&f.state(), &external);
    assert!(matches!(store.load(), Err(StoreError::Conflict)));
    assert!(matches!(store.commit(b"must not publish"), Err(StoreError::Poisoned)));
    assert_eq!(fs::read(f.state()).unwrap(), external);
    assert!(!f.next().exists());
}
#[test]
fn directory_descriptor_prevents_path_retargeting() {
    let f = Fixture::new();
    let mut store = f.open();
    store.commit(b"old").unwrap();
    let moved = f.root.join("moved");
    fs::rename(&f.path, &moved).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&f.path).unwrap();
    private_write(&f.state(), b"do not touch replacement directory");
    store.commit(b"new in held directory").unwrap();
    assert_eq!(fs::read(f.state()).unwrap(), b"do not touch replacement directory");
    let state =
        StateStore::decode_state(&cipher(42), &fs::read(moved.join("state.bin")).unwrap()).unwrap();
    assert_eq!(&*state.data.plaintext, b"new in held directory");
}
#[test]
fn interrupted_commit_freezes_reads_and_writes_and_retains_both_outcomes() {
    for stage in
        [Stage::Created, Stage::Written, Stage::Synced, Stage::Renamed, Stage::DirectorySynced]
    {
        let f = Fixture::new();
        let mut store = f.open();
        store.commit(b"old").unwrap();
        let result = store.commit_inner(b"new", &mut |at| {
            if at == stage {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(StoreError::Io(e)) if e.raw_os_error() == Some(libc::ENOSPC)));
        assert!(matches!(store.load(), Err(StoreError::Poisoned)));
        assert!(matches!(store.commit(b"retry forbidden"), Err(StoreError::Poisoned)));
        let published =
            StateStore::decode_state(&cipher(42), &fs::read(f.state()).unwrap()).unwrap();
        let renamed = matches!(stage, Stage::Renamed | Stage::DirectorySynced);
        assert_eq!(&*published.data.plaintext, if renamed { b"new" } else { b"old" });
        assert_eq!(f.next().exists(), !renamed);
        drop(store);
        if renamed {
            assert_eq!(&*f.open().load().unwrap().unwrap().plaintext, b"new");
        } else {
            assert!(matches!(
                StateStore::open(&f.path, cipher(42)),
                Err(StoreError::RecoveryRequired)
            ));
        }
    }
}

#[test]
fn commit_preflight_rejects_changed_or_corrupt_state_before_creating_a_candidate() {
    for corrupt in [false, true] {
        let f = Fixture::new();
        let mut store = f.open();
        store.commit(b"old").unwrap();
        let external =
            if corrupt { b"broken state".to_vec() } else { valid_stored_state(b"external") };
        private_write(&f.state(), &external);
        let result = store.commit(b"must not replace external data");
        if corrupt {
            assert!(matches!(result, Err(StoreError::Record(_))));
        } else {
            assert!(matches!(result, Err(StoreError::Conflict)));
        }
        assert!(matches!(store.load(), Err(StoreError::Poisoned)));
        assert_eq!(fs::read(f.state()).unwrap(), external);
        assert!(!f.next().exists());
    }
}
#[test]
fn exclusive_candidate_creation_never_overwrites_an_uncertain_file() {
    let f = Fixture::new();
    let mut store = f.open();
    store.commit(b"old").unwrap();
    let old = fs::read(f.state()).unwrap();
    private_write(&f.next(), b"preserve uncertain candidate");
    assert!(
        matches!(store.commit(b"new"), Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists)
    );
    assert!(matches!(store.load(), Err(StoreError::Poisoned)));
    assert_eq!(fs::read(f.state()).unwrap(), old);
    assert_eq!(fs::read(f.next()).unwrap(), b"preserve uncertain candidate");
}

#[test]
fn pending_payment_survives_reopen_and_refuses_replacement() {
    let fixture = Fixture::new();
    let exact = b"original request bytes";
    let intent = shielded_pool_circuit::field::Fr::from(7u64);
    let mut store = fixture.open();
    assert!(store.pending_payment().unwrap().is_none());
    store.persist_pending_payment(intent, exact).unwrap();
    drop(store);

    let mut store = fixture.open();
    assert_eq!(store.pending_payment().unwrap().unwrap().request.as_slice(), exact);
    assert_eq!(store.pending_payment().unwrap().unwrap().intent, intent);
    store.persist_pending_payment(intent, exact).unwrap();
    assert!(matches!(
        store.persist_pending_payment(shielded_pool_circuit::field::Fr::from(8u64), exact),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store.persist_pending_payment(intent, b"new request"),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.pending_payment().unwrap().unwrap().request.as_slice(), exact);
}
