// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use super::*;
use crate::store::tests::{cipher, private_write, Fixture};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};
fn path(f: &Fixture) -> std::path::PathBuf {
    f.path.join("reservations.bin")
}
fn frame(kind: Kind, seq: u64, first: u64, count: u8) -> Vec<u8> {
    let mut plain = b"JR01\x01".to_vec();
    plain.extend_from_slice(&first.to_be_bytes());
    plain.push(count);
    let sealed = cipher(42).seal(kind, seq, &plain).unwrap();
    let mut frame = (sealed.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&sealed);
    frame
}
fn journal(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"MJR1".to_vec();
    for frame in frames {
        bytes.extend_from_slice(frame);
    }
    bytes
}
#[test]
fn reservations_survive_restart_and_preserve_cached_payload() {
    let f = Fixture::new();
    let mut store = f.open();
    store.commit(b"cached notes").unwrap();
    assert_eq!(store.reserve_indices(Some(10), 3).unwrap(), vec![10, 11, 12]);
    assert_eq!(store.reservation_high_water().unwrap(), 13);
    assert_eq!(&*store.load().unwrap().unwrap().plaintext, b"cached notes");
    drop(store);
    let mut store = f.open();
    assert!(matches!(store.reserve_indices(Some(0), 1), Ok(values) if values == vec![13]));
    assert_eq!(store.reserve_indices(Some(100), 1).unwrap(), vec![100]);
    assert_eq!(store.reservation_high_water().unwrap(), 101);
    let state = StateStore::decode_state(&cipher(42), &fs::read(f.state()).unwrap()).unwrap();
    assert_eq!(state.cursor.records, 3);
    assert_eq!(state.cursor.next, 101);
    assert_eq!(&*state.data.plaintext, b"cached notes");
    assert_eq!(fs::metadata(path(&f)).unwrap().permissions().mode() & 0o777, 0o600);
}
#[test]
fn acknowledged_checkpoint_refuses_missing_or_truncated_journal() {
    let f = Fixture::new();
    let mut store = f.open();
    store.reserve_indices(Some(0), 1).unwrap();
    let prefix = fs::read(path(&f)).unwrap();
    store.reserve_indices(Some(0), 1).unwrap();
    let complete = fs::read(path(&f)).unwrap();
    let state = fs::read(f.state()).unwrap();
    drop(store);
    for truncated in [b"MJR1".to_vec(), prefix, complete[..complete.len() - 1].to_vec()] {
        private_write(&path(&f), &truncated);
        assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::RecoveryRequired)));
        assert_eq!(fs::read(f.state()).unwrap(), state);
        assert_eq!(fs::read(path(&f)).unwrap(), truncated);
    }
    fs::remove_file(path(&f)).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::RecoveryRequired)));
}
#[test]
fn unacknowledged_complete_tail_is_burned_before_next_reservation() {
    for stage in [ReserveStage::Written, ReserveStage::JournalSynced, ReserveStage::DirectorySynced]
    {
        let f = Fixture::new();
        let mut store = f.open();
        store.commit(b"old cache").unwrap();
        let original = fs::read(f.state()).unwrap();
        let result = store.reserve_inner(Some(7), 1, &mut |at| {
            if at == stage {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(result,Err(StoreError::Io(error)) if error.raw_os_error()==Some(libc::ENOSPC))
        );
        assert!(matches!(store.reservation_high_water(), Err(StoreError::Poisoned)));
        assert_eq!(fs::read(f.state()).unwrap(), original);
        drop(store);
        let mut store = f.open();
        assert_eq!(store.reservation_high_water().unwrap(), 8);
        assert_eq!(&*store.load().unwrap().unwrap().plaintext, b"old cache");
        assert_eq!(store.reserve_indices(Some(0), 1).unwrap(), vec![8]);
        drop(store);
        assert_eq!(f.open().reservation_high_water().unwrap(), 9);
    }
}
#[test]
fn authenticated_prefix_substitution_is_refused() {
    let f = Fixture::new();
    f.open().reserve_indices(Some(0), 1).unwrap();
    let replacement = journal(&[frame(Kind::Journal, 0, 0, 1)]);
    assert_ne!(replacement, fs::read(path(&f)).unwrap());
    private_write(&path(&f), &replacement);
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Conflict)));
    assert_eq!(fs::read(path(&f)).unwrap(), replacement);
}
#[test]
fn overlapping_authenticated_ranges_are_refused() {
    let f = Fixture::new();
    private_write(
        &path(&f),
        &journal(&[frame(Kind::Journal, 0, 0, 1), frame(Kind::Journal, 1, 0, 1)]),
    );
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Conflict)));
}
#[test]
fn journal_records_cannot_use_the_state_encryption_purpose() {
    let f = Fixture::new();
    private_write(&path(&f), &journal(&[frame(Kind::State, 0, 0, 1)]));
    assert!(matches!(
        StateStore::open(&f.path, cipher(42)),
        Err(StoreError::Record(Error::InvalidInput))
    ));
}
#[test]
fn malformed_partial_and_oversize_frames_are_retained() {
    let f = Fixture::new();
    let mut too_big = b"MJR1".to_vec();
    too_big.extend_from_slice(&((MAX_SEALED_BYTES + 1) as u32).to_be_bytes());
    private_write(&path(&f), &too_big);
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Record(Error::Limit))));
    for bytes in [
        b"MJ".to_vec(),
        b"MJR1\0".to_vec(),
        journal(&[frame(Kind::Journal, 0, 0, 1)])[..10].to_vec(),
    ] {
        private_write(&path(&f), &bytes);
        assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::RecoveryRequired)));
        assert_eq!(fs::read(path(&f)).unwrap(), bytes);
    }
    private_write(&path(&f), b"MJR1");
    let mut store = f.open();
    assert_eq!(store.reserve_indices(Some(2), 1).unwrap(), vec![2]);
}
#[test]
fn exhausted_and_invalid_requests_never_publish_or_reuse_an_index() {
    let f = Fixture::new();
    let mut store = f.open();
    for (scan, count) in
        [(Some(0), 0), (Some(0), 5), (None, 1), (Some(u64::MAX), 1), (Some(u64::MAX - 1), 2)]
    {
        assert!(matches!(
            store.reserve_indices(scan, count),
            Err(StoreError::Record(Error::Limit))
        ));
        assert!(!path(&f).exists());
        assert!(!f.state().exists());
    }
    assert_eq!(store.reserve_indices(Some(u64::MAX - 1), 1).unwrap(), vec![u64::MAX - 1]);
    assert!(matches!(store.reserve_indices(Some(0), 1), Err(StoreError::Record(Error::Limit))));
    drop(store);
    assert_eq!(f.open().reservation_high_water().unwrap(), u64::MAX);
}
#[test]
fn record_limit_is_enforced_without_resetting() {
    let f = Fixture::new();
    let mut bytes = b"MJR1".to_vec();
    for index in 0..MAX_RECORDS {
        bytes.extend_from_slice(&frame(Kind::Journal, index, index, 1));
    }
    private_write(&path(&f), &bytes);
    let mut store = f.open();
    assert_eq!(store.reservation_high_water().unwrap(), MAX_RECORDS);
    assert!(matches!(store.reserve_indices(Some(0), 1), Err(StoreError::Record(Error::Limit))));
    assert_eq!(fs::read(path(&f)).unwrap(), bytes);
    drop(store);
}
#[test]
fn file_size_limit_is_checked_before_parsing_frames() {
    let f = Fixture::new();
    private_write(&path(&f), b"MJR1");
    let file = File::options().write(true).open(path(&f)).unwrap();
    file.set_len((MAX_JOURNAL_BYTES as u64) + 1).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::Record(Error::Limit))));
    assert_eq!(file.metadata().unwrap().len(), (MAX_JOURNAL_BYTES as u64) + 1);
}
#[test]
fn unsafe_journal_permissions_links_and_corrupt_ciphertext_are_refused() {
    let f = Fixture::new();
    f.open().reserve_indices(Some(0), 1).unwrap();
    let original = fs::read(path(&f)).unwrap();
    fs::set_permissions(path(&f), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    fs::set_permissions(path(&f), fs::Permissions::from_mode(0o600)).unwrap();
    let alias = f.root.join("alias");
    fs::hard_link(path(&f), &alias).unwrap();
    assert!(matches!(StateStore::open(&f.path, cipher(42)), Err(StoreError::UnsafeFile)));
    fs::remove_file(path(&f)).unwrap();
    symlink(&alias, path(&f)).unwrap();
    assert!(StateStore::open(&f.path, cipher(42)).is_err());
    assert_eq!(fs::read(&alias).unwrap(), original);
    fs::remove_file(path(&f)).unwrap();
    fs::remove_file(alias).unwrap();
    let mut corrupt = original;
    corrupt[40] ^= 1;
    private_write(&path(&f), &corrupt);
    assert!(matches!(
        StateStore::open(&f.path, cipher(42)),
        Err(StoreError::Record(Error::Crypto))
    ));
    assert_eq!(fs::read(path(&f)).unwrap(), corrupt);
}

#[test]
fn process_kill_after_journal_sync_never_reuses_the_unacknowledged_index() {
    const CHILD: &str = "TOS_RESERVATION_CRASH_TEST_DIR";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = std::path::PathBuf::from(directory);
        assert_eq!(directory.file_name().unwrap(), "private");
        assert!(directory
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("tos-mobile-store-"));
        let mut store = StateStore::open(&directory, cipher(42)).unwrap();
        let _result = store.reserve_inner(Some(7), 1, &mut |stage| {
            if stage == ReserveStage::DirectorySynced {
                // SAFETY: kill only this deliberately spawned test process.
                let sent = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                assert_eq!(sent, 0);
                // Never return into publish while a fatal process signal is
                // pending. A missing delivery must fail, not move the boundary.
                std::thread::sleep(std::time::Duration::from_secs(2));
                std::process::exit(98);
            }
            Ok(())
        });
        std::process::exit(99);
    }
    let f = Fixture::new();
    f.open().commit(b"cache before process exit").unwrap();
    let before = fs::read(f.state()).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "store::reservations::tests::process_kill_after_journal_sync_never_reuses_the_unacknowledged_index"])
        .env(CHILD,&f.path).output().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.status.signal(), Some(libc::SIGKILL));
    assert!(!f.next().exists(), "Crash boundary must precede candidate creation");
    assert_eq!(fs::read(f.state()).unwrap(), before);
    let mut store = f.open();
    assert_eq!(store.reservation_high_water().unwrap(), 8);
    assert_eq!(store.reserve_indices(Some(0), 1).unwrap(), vec![8]);
}
#[test]
fn authenticated_legacy_opaque_state_is_preserved_without_automatic_reinterpretation() {
    let f = Fixture::new();
    let old = snapshot::seal(&cipher(42), Kind::State, &[0; STATE_HEADER]).unwrap();
    private_write(&f.state(), &old);
    assert!(matches!(
        StateStore::open(&f.path, cipher(42)),
        Err(StoreError::Record(Error::InvalidInput))
    ));
    assert_eq!(fs::read(f.state()).unwrap(), old);
    assert!(!path(&f).exists());
}

#[test]
fn payment_indices_are_durable_and_held_inputs_do_not_reserve() {
    use shielded_pool_circuit::field::Fr;
    use shielded_pool_wallet::{
        delivery::Kind,
        descriptor::Descriptor,
        import::Imported,
        keys::PoolInstance,
        plan::{PoolTerms, Request},
        scan::Recovered,
    };
    let domain = Fr::from(7u64);
    let recipient = Descriptor::issue(&PoolInstance::new(&[1; 32], domain), 0).unwrap();
    let fee = Descriptor::issue(&PoolInstance::new(&[2; 32], domain), 0).unwrap();
    let request = Request::relayed_transfer(domain, &recipient, 10, &fee, 1).unwrap();
    let terms = PoolTerms { denominations: vec![], withdrawal_fee: 1 };
    let word = Fr::from(1u64);
    let recovered = Recovered {
        notes: vec![Imported {
            kind: Kind::Ordinary,
            note_key_index: 7,
            amount: 20,
            note_secret: word,
            owner_commitment: word,
            note_body: word,
            output_data_hash: word,
            spendable: true,
            spent: false,
        }],
        leaves: vec![Some(3)],
        ..Default::default()
    };
    let fixture = Fixture::new();
    let mut store = fixture.open();
    assert!(store.reserve_payment_plan(&terms, &recovered, &[3].into(), &request).is_err());
    assert_eq!(store.reservation_high_water().unwrap(), 0);
    let mut indices = store
        .reserve_payment_plan(&terms, &recovered, &Default::default(), &request)
        .unwrap()
        .own_indices();
    indices.sort_unstable();
    assert_eq!(indices, vec![8, 9]);
    drop(store);
    let mut store = fixture.open();
    assert_eq!(store.reservation_high_water().unwrap(), 10);
    store.persist_pending_payment(word, b"exact signed payment").unwrap();
    assert!(matches!(
        store.reserve_payment_plan(&terms, &recovered, &Default::default(), &request),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.reservation_high_water().unwrap(), 10);
}
