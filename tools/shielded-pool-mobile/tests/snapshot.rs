// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use sha3::{Digest, Sha3_256};
use shielded_pool_mobile::{
    sealed::{Binding, Kind, RecordCipher, MAX_PLAINTEXT_BYTES},
    snapshot::{self, MAX_ENCODED_BYTES, MAX_SNAPSHOT_BYTES},
    Error,
};
fn cipher(seed: u8) -> RecordCipher {
    RecordCipher::derive(
        &[seed; 32],
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
}
fn prefix(encoded: &[u8]) -> usize {
    12 + u32::from_be_bytes(encoded[8..12].try_into().unwrap()) as usize
}
fn authenticated(c: &RecordCipher, manifest: &[u8], pages: &[u8]) -> Vec<u8> {
    let sealed = c.seal(Kind::State, 0, manifest).unwrap();
    let mut out = b"TSSN\x01\0\0\0".to_vec();
    out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed);
    out.extend_from_slice(pages);
    out
}
fn manifest(total: u32, count: u32) -> Vec<u8> {
    let mut out = b"SM01".to_vec();
    out.extend_from_slice(&[9; 32]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out
}
#[test]
fn round_trip_empty_and_page_edges_with_fresh_generations() {
    let c = cipher(42);
    for length in [0, 1, MAX_PLAINTEXT_BYTES, MAX_PLAINTEXT_BYTES + 1] {
        let bytes = vec![0x55; length];
        for kind in [Kind::State, Kind::Backup] {
            let a = snapshot::seal(&c, kind, &bytes).unwrap();
            let b = snapshot::seal(&c, kind, &bytes).unwrap();
            let restored = snapshot::open(&c, kind, &a).unwrap();
            assert_eq!(*restored.plaintext, bytes);
            assert_ne!(restored.generation, snapshot::open(&c, kind, &b).unwrap().generation);
            assert_ne!(a, b);
        }
    }
}
#[test]
fn exact_limit_is_usable_and_over_limit_is_rejected() {
    let c = cipher(42);
    let body = vec![0x23; MAX_SNAPSHOT_BYTES];
    let encoded = snapshot::seal(&c, Kind::State, &body).unwrap();
    assert!(encoded.len() <= MAX_ENCODED_BYTES);
    assert_eq!(*snapshot::open(&c, Kind::State, &encoded).unwrap().plaintext, body);
    assert!(matches!(
        snapshot::seal(&c, Kind::State, &vec![0; MAX_SNAPSHOT_BYTES + 1]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        snapshot::open(&c, Kind::State, &vec![0; MAX_ENCODED_BYTES + 1]),
        Err(Error::Limit)
    ));
}
#[test]
fn wrong_key_purpose_header_and_manifest_are_refused() {
    let c = cipher(42);
    let encoded = snapshot::seal(&c, Kind::State, b"notes and UNKNOWN wire").unwrap();
    assert!(matches!(snapshot::open(&cipher(43), Kind::State, &encoded), Err(Error::Crypto)));
    assert!(snapshot::open(&c, Kind::Backup, &encoded).is_err());
    assert!(snapshot::open(&c, Kind::Journal, &encoded).is_err());
    assert!(snapshot::seal(&c, Kind::Journal, b"no journal schema").is_err());
    for position in [0, 4, 8, 12, prefix(&encoded) - 1] {
        let mut bad = encoded.clone();
        bad[position] ^= 1;
        assert!(snapshot::open(&c, Kind::State, &bad).is_err());
    }
}
#[test]
fn mixed_reordered_missing_and_extra_pages_are_refused() {
    let c = cipher(42);
    let body = vec![1; MAX_PLAINTEXT_BYTES * 2];
    let a = snapshot::seal(&c, Kind::State, &body).unwrap();
    let b = snapshot::seal(&c, Kind::State, &body).unwrap();
    let start = prefix(&a);
    let page_size = MAX_PLAINTEXT_BYTES + 54;
    let mut mixed = a.clone();
    mixed[start..start + page_size].copy_from_slice(&b[prefix(&b)..prefix(&b) + page_size]);
    assert!(matches!(snapshot::open(&c, Kind::State, &mixed), Err(Error::Crypto)));
    let mut reordered = a.clone();
    reordered[start..].rotate_left(page_size);
    assert!(matches!(snapshot::open(&c, Kind::State, &reordered), Err(Error::Crypto)));
    for length in [0, 7, 12, start - 1, start, a.len() - 1] {
        assert!(snapshot::open(&c, Kind::State, &a[..length]).is_err());
    }
    let mut extra = a.clone();
    extra.push(0);
    assert!(matches!(snapshot::open(&c, Kind::State, &extra), Err(Error::InvalidInput)));
}
#[test]
fn authenticated_manifest_bounds_and_shape_are_checked() {
    let c = cipher(42);
    for (total, count, error) in [
        (MAX_SNAPSHOT_BYTES as u32 + 1, 0, Error::Limit),
        (0, 33, Error::Limit),
        (1, 0, Error::InvalidInput),
        (0, 1, Error::InvalidInput),
    ] {
        let encoded = authenticated(&c, &manifest(total, count), &[]);
        assert!(matches!(snapshot::open(&c, Kind::State, &encoded), Err(e) if e == error));
    }
    let mut m = manifest(0, 0);
    m.push(0);
    assert!(matches!(
        snapshot::open(&c, Kind::State, &authenticated(&c, &m, &[])),
        Err(Error::InvalidInput)
    ));
    let mut m = manifest(0, 0);
    m[3] = b'2';
    assert!(matches!(
        snapshot::open(&c, Kind::State, &authenticated(&c, &m, &[])),
        Err(Error::InvalidInput)
    ));
}
#[test]
fn authenticated_page_hash_does_not_replace_record_kind_and_position() {
    let c = cipher(42);
    for (kind, sequence) in [(Kind::Backup, 1), (Kind::State, 0), (Kind::State, 2)] {
        let page = c.seal(kind, sequence, b"secret").unwrap();
        let mut m = manifest(6, 1);
        m.extend_from_slice(&(page.len() as u32).to_be_bytes());
        m.extend_from_slice(&Sha3_256::digest(&page));
        assert!(matches!(
            snapshot::open(&c, Kind::State, &authenticated(&c, &m, &page)),
            Err(Error::InvalidInput)
        ));
    }
}

#[test]
fn manifest_envelope_length_is_bounded_before_decoding() {
    let c = cipher(42);
    let mut encoded = snapshot::seal(&c, Kind::State, &[]).unwrap();
    encoded[8..12].copy_from_slice(&(44u32 + 32 * 36 + 54 + 1).to_be_bytes());
    assert!(matches!(snapshot::open(&c, Kind::State, &encoded), Err(Error::Limit)));
}
