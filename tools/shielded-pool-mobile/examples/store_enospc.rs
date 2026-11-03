// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Acceptance harness: requires a fresh, empty, private Linux tmpfs mount.
#![allow(clippy::unwrap_used)]
#[cfg(target_os = "linux")]
fn main() {
    use shielded_pool_mobile::{
        sealed::{Binding, Kind, RecordCipher},
        snapshot,
        store::{StateStore, StoreError},
    };
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, path::PathBuf};
    let path = PathBuf::from(std::env::args_os().nth(1).unwrap());
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live C path and writable space for exactly one statfs result.
    assert_eq!(unsafe { libc::statfs(name.as_ptr(), info.as_mut_ptr()) }, 0);
    // SAFETY: statfs succeeded and initialized the result.
    let info = unsafe { info.assume_init() };
    assert_eq!(info.f_type, libc::TMPFS_MAGIC, "Only a disposable tmpfs is allowed");
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
    let old = fs::read(path.join("state.bin")).unwrap();
    assert!(
        matches!(store.commit(&vec![0x55; 128*1024]), Err(StoreError::Io(e)) if e.raw_os_error() == Some(libc::ENOSPC))
    );
    assert!(matches!(store.load(), Err(StoreError::Poisoned)));
    assert!(matches!(store.commit(b"retry forbidden"), Err(StoreError::Poisoned)));
    assert_eq!(fs::read(path.join("state.bin")).unwrap(), old);
    let candidate = fs::metadata(path.join("state.next")).unwrap();
    assert!(candidate.len() > 0 && candidate.len() < 128 * 1024);
    assert_eq!(
        &*snapshot::open(&cipher(), Kind::State, &old).unwrap().plaintext,
        b"old synthetic state"
    );
    drop(store);
    assert!(matches!(StateStore::open(&path, cipher()), Err(StoreError::RecoveryRequired)));
    println!("Actual tmpfs ENOSPC: old state retained, partial candidate retained, handle frozen, reopen requires recovery");
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This acceptance harness requires a disposable Linux tmpfs mount");
    std::process::exit(1);
}
