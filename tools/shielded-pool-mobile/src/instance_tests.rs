// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use super::tests::{cipher, private_write, Fixture};
use super::*;
use crate::sealed::Binding;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

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
fn child(f: &Fixture) -> std::path::PathBuf {
    f.path.join(hex::encode(cipher(42).instance_id()))
}

#[test]
fn aliases_and_restart_reuse_one_private_identity() {
    let f = Fixture::new();
    // Independently calculated with Python hashlib from the specified pool-master,
    // execution-domain and genesis derivations; never derived from the AEAD key.
    assert_eq!(
        hex::encode(cipher(42).instance_id()),
        "3931d5b4bc8aade3435f6eb0198c9091639730c9e24d2bbdf7e898c3e3f07109"
    );
    let mut a = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    assert_eq!(fs::metadata(child(&f)).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(a.reserve_indices(Some(10), 2).unwrap(), vec![10, 11]);
    assert!(matches!(StateStore::open_wallet(&f.path, cipher(42)), Err(StoreError::Io(_))));
    drop(a);
    let mut alias = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    assert_eq!(alias.reserve_indices(Some(0), 1).unwrap(), vec![12]);
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 1);
}
#[test]
fn masters_networks_pools_and_genesis_are_separate() {
    let f = Fixture::new();
    let original = *cipher(42).instance_id();
    let mut store = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    store.commit(b"original").unwrap();
    let mut variants = Vec::new();
    variants.push(RecordCipher::derive(&[43; 32], binding()));
    for field in 0..4 {
        let mut b = binding();
        match field {
            0 => b.global_id = 4,
            1 => b.pool_account[0] ^= 1,
            2 => b.genesis_root[0] ^= 1,
            _ => b.genesis_file[0] ^= 1,
        }
        variants.push(RecordCipher::derive(&[42; 32], b));
    }
    let mut names = std::collections::BTreeSet::from([original]);
    for key in variants {
        assert!(names.insert(*key.instance_id()));
        let mut other = StateStore::open_wallet(&f.path, key).unwrap();
        assert!(other.load().unwrap().is_none());
        other.commit(b"different").unwrap();
    }
    assert_eq!(names.len(), 6);
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 6);
    assert_eq!(&*store.load().unwrap().unwrap().plaintext, b"original");
}
#[test]
fn upgrade_pins_cannot_create_a_fresh_directory_and_forget_reservations() {
    let f = Fixture::new();
    let mut a = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    a.commit(b"opaque unknown bytes").unwrap();
    a.reserve_indices(Some(7), 1).unwrap();
    drop(a);
    let state = fs::read(child(&f).join("state.bin")).unwrap();
    let log = fs::read(child(&f).join("reservations.bin")).unwrap();
    for field in 0..4 {
        let mut b = binding();
        match field {
            0 => b.code_hash[0] ^= 1,
            1 => b.profile_hash[0] ^= 1,
            2 => b.manifest_hash[0] ^= 1,
            _ => b.verifying_key_hash[0] ^= 1,
        }
        let key = RecordCipher::derive(&[42; 32], b);
        assert_eq!(key.instance_id(), cipher(42).instance_id());
        assert!(matches!(
            StateStore::open_wallet(&f.path, key),
            Err(StoreError::Record(Error::Crypto))
        ));
        assert_eq!(fs::read(child(&f).join("state.bin")).unwrap(), state);
        assert_eq!(fs::read(child(&f).join("reservations.bin")).unwrap(), log);
        assert_eq!(fs::read_dir(&f.path).unwrap().count(), 1);
    }
    let mut restored = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    assert_eq!(restored.reservation_high_water().unwrap(), 8);
}
#[test]
fn unsafe_roots_and_child_entries_are_preserved_and_refused() {
    let f = Fixture::new();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(StateStore::open_wallet(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 0);
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = f.root.join("alias");
    symlink(&f.path, &alias).unwrap();
    assert!(StateStore::open_wallet(&alias, cipher(42)).is_err());
    let target = f.root.join("outside");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target, child(&f)).unwrap();
    assert!(StateStore::open_wallet(&f.path, cipher(42)).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    fs::remove_file(child(&f)).unwrap();
    private_write(&child(&f), b"not a directory");
    assert!(StateStore::open_wallet(&f.path, cipher(42)).is_err());
    assert_eq!(fs::read(child(&f)).unwrap(), b"not a directory");
    fs::remove_file(child(&f)).unwrap();
    fs::create_dir(child(&f)).unwrap();
    fs::set_permissions(child(&f), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(StateStore::open_wallet(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    assert_eq!(fs::metadata(child(&f)).unwrap().permissions().mode() & 0o777, 0o755);
}
#[test]
fn uncertain_candidate_is_not_removed_by_canonical_reopen() {
    let f = Fixture::new();
    let mut a = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    a.commit(b"original").unwrap();
    drop(a);
    private_write(&child(&f).join("state.next"), b"uncertain");
    let original = fs::read(child(&f).join("state.bin")).unwrap();
    assert!(matches!(
        StateStore::open_wallet(&f.path, cipher(42)),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(fs::read(child(&f).join("state.next")).unwrap(), b"uncertain");
    assert_eq!(fs::read(child(&f).join("state.bin")).unwrap(), original);
}
#[test]
fn retargeting_root_after_open_does_not_redirect_records() {
    let f = Fixture::new();
    let mut a = StateStore::open_wallet(&f.path, cipher(42)).unwrap();
    let name = hex::encode(cipher(42).instance_id());
    let moved = f.root.join("moved");
    fs::rename(&f.path, &moved).unwrap();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &f.path).unwrap();
    a.commit(b"owned descriptor").unwrap();
    a.reserve_indices(Some(2), 1).unwrap();
    assert!(moved.join(name).join("state.bin").is_file());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(&*a.load().unwrap().unwrap().plaintext, b"owned descriptor");
}

#[test]
fn legacy_flat_stores_and_their_lock_never_become_fresh_roots() {
    let f = Fixture::new();
    let mut legacy = StateStore::open(&f.path, cipher(42)).unwrap();
    assert!(matches!(StateStore::open_wallet(&f.path, cipher(42)), Err(StoreError::Io(_))));
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 0);
    legacy.commit(b"legacy unknown bytes").unwrap();
    drop(legacy);
    let old = fs::read(f.state()).unwrap();
    assert!(matches!(
        StateStore::open_wallet(&f.path, cipher(42)),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(fs::read(f.state()).unwrap(), old);
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 1);
    for name in ["state.bin", "state.next", "reservations.bin"] {
        let f = Fixture::new();
        let entry = f.path.join(name);
        symlink(f.root.join("missing"), &entry).unwrap();
        assert!(matches!(
            StateStore::open_wallet(&f.path, cipher(42)),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(entry.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read_dir(&f.path).unwrap().count(), 1);
    }
}
