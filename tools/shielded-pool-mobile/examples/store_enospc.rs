// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Acceptance harness: requires a fresh, empty, private Linux tmpfs mount.
#![allow(clippy::unwrap_used)]
#[cfg(target_os = "linux")]
fn main() {
    use shielded_pool_mobile::{
        sealed::{Binding, Kind, RecordCipher},
        store::{StateStore, StoreError},
    };
    use std::{
        ffi::CString,
        fs,
        io::Write,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        path::PathBuf,
    };
    let path = PathBuf::from(std::env::args_os().nth(1).unwrap());
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live C path and writable space for exactly one statfs result.
    assert_eq!(unsafe { libc::statfs(name.as_ptr(), info.as_mut_ptr()) }, 0);
    // SAFETY: statfs succeeded and initialized the result.
    let info = unsafe { info.assume_init() };
    assert_eq!(info.f_type, libc::TMPFS_MAGIC, "Only a disposable tmpfs is allowed");
    assert_eq!(
        info.f_blocks.checked_mul(u64::try_from(info.f_bsize).unwrap()).unwrap(),
        65536,
        "Requires a dedicated 64KiB tmpfs, never a shared or large filesystem"
    );
    let mode = std::env::args().nth(2).unwrap_or_else(|| "state".to_owned());
    assert!(mode == "state" || mode == "reserve", "Unknown fixture mode");
    assert!(fs::read_dir(&path).unwrap().next().is_none(), "Requires an empty test mount");
    let cipher = || {
        RecordCipher::derive(
            &[42; 32],
            Binding {
                global_id: 3,
                pool_account: [1; 32],
                genesis_root: [2; 32],
                genesis_file: [3; 32],
                code_hash: [4; 32],
                profile_hash: [5; 32],
                manifest_hash: [6; 32],
                verifying_key_hash: [7; 32],
            },
        )
    };
    let mut store = StateStore::open(&path, cipher()).unwrap();
    store.commit(b"old synthetic state").unwrap();
    assert_eq!(&*store.load().unwrap().unwrap().plaintext, b"old synthetic state");
    if mode == "reserve" {
        assert_eq!(store.reserve_indices(Some(0), 1).unwrap(), vec![0]);
        let old = fs::read(path.join("state.bin")).unwrap();
        let old_journal = fs::read(path.join("reservations.bin")).unwrap();
        let mut filler = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("fill.bin"))
            .unwrap();
        let mut full = false;
        for _ in 0..17 {
            match filler.write_all(&[0x55; 4096]) {
                Ok(()) => {}
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
                    full = true;
                    break;
                }
            }
        }
        assert!(full);
        drop(filler);
        assert!(
            matches!(store.reserve_indices(Some(0),1),Err(StoreError::Io(error)) if error.raw_os_error()==Some(libc::ENOSPC))
        );
        assert!(matches!(store.load(), Err(StoreError::Poisoned)));
        assert_eq!(fs::read(path.join("state.bin")).unwrap(), old);
        let journal = fs::read(path.join("reservations.bin")).unwrap();
        assert!(journal.starts_with(&old_journal));
        let tail = &journal[old_journal.len()..];
        let length = u32::from_be_bytes(tail[..4].try_into().unwrap()) as usize;
        assert_eq!(tail.len(), 4 + length);
        let record = cipher().open(Kind::Journal, 1, &tail[4..]).unwrap();
        assert_eq!(&record[..5], b"JR01\x01");
        assert_eq!(u64::from_be_bytes(record[5..13].try_into().unwrap()), 1);
        assert_eq!(record[13], 1);
        assert!(path.join("state.next").exists());
        drop(store);
        assert!(matches!(StateStore::open(&path, cipher()), Err(StoreError::RecoveryRequired)));
        println!("Actual reservation ENOSPC: no range returned, durable journal tail retained, old checkpoint retained, handle frozen, explicit recovery required");
        return;
    }
    let old = fs::read(path.join("state.bin")).unwrap();
    assert!(
        matches!(store.commit(&vec![0x55; 128*1024]), Err(StoreError::Io(e)) if e.raw_os_error() == Some(libc::ENOSPC))
    );
    assert!(matches!(store.load(), Err(StoreError::Poisoned)));
    assert!(matches!(store.commit(b"retry forbidden"), Err(StoreError::Poisoned)));
    assert_eq!(fs::read(path.join("state.bin")).unwrap(), old);
    let candidate = fs::metadata(path.join("state.next")).unwrap();
    assert!(candidate.len() > 0 && candidate.len() < 128 * 1024);
    drop(store);
    assert!(matches!(StateStore::open(&path, cipher()), Err(StoreError::RecoveryRequired)));
    println!("Actual tmpfs ENOSPC: old state retained, partial candidate retained, handle frozen, reopen requires recovery");
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This acceptance harness requires a disposable Linux tmpfs mount");
    std::process::exit(1);
}
