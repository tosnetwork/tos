// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use shielded_pool_mobile::{
    sealed::{Binding, Kind, RecordCipher, MAX_PLAINTEXT_BYTES, MAX_SEALED_BYTES},
    Error,
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
fn cipher() -> RecordCipher {
    RecordCipher::derive(&[0x42; 32], binding())
}

#[test]
fn all_page_kinds_round_trip_with_expected_position() {
    let cipher = cipher();
    for kind in [Kind::State, Kind::Journal, Kind::Backup] {
        for sequence in [0, 1, u64::MAX] {
            let record =
                cipher.seal(kind, sequence, b"private notes and exact UNKNOWN bytes").unwrap();
            assert_eq!(
                &*cipher.open(kind, sequence, &record).unwrap(),
                b"private notes and exact UNKNOWN bytes"
            );
            assert!(!record.windows(13).any(|w| w == b"private notes"));
        }
    }
}
#[test]
fn repeated_state_replacements_use_fresh_nonces() {
    let cipher = cipher();
    let a = cipher.seal(Kind::State, 0, b"same plaintext").unwrap();
    let b = cipher.seal(Kind::State, 0, b"same plaintext").unwrap();
    assert_ne!(&a[14..38], &b[14..38]);
    assert_eq!(
        *cipher.open(Kind::State, 0, &a).unwrap(),
        *cipher.open(Kind::State, 0, &b).unwrap()
    );
}
#[test]
fn wrong_seed_and_each_independent_binding_are_refused() {
    let cipher = cipher();
    let record = cipher.seal(Kind::Backup, 1, b"must remain private").unwrap();
    assert_eq!(
        RecordCipher::derive(&[0x43; 32], binding()).open(Kind::Backup, 1, &record),
        Err(Error::Crypto)
    );
    for field in 0..8 {
        let mut b = binding();
        match field {
            0 => b.global_id = 4,
            1 => b.pool_account[0] ^= 1,
            2 => b.genesis_root[0] ^= 1,
            3 => b.genesis_file[0] ^= 1,
            4 => b.code_hash[0] ^= 1,
            5 => b.profile_hash[0] ^= 1,
            6 => b.manifest_hash[0] ^= 1,
            _ => b.verifying_key_hash[0] ^= 1,
        }
        assert_eq!(
            RecordCipher::derive(&[0x42; 32], b).open(Kind::Backup, 1, &record),
            Err(Error::Crypto),
            "binding field {field}"
        );
    }
}
#[test]
fn expected_kind_and_sequence_cannot_come_from_the_record() {
    let cipher = cipher();
    let record = cipher.seal(Kind::Journal, 7, b"request").unwrap();
    assert_eq!(cipher.open(Kind::State, 7, &record), Err(Error::InvalidInput));
    assert_eq!(cipher.open(Kind::Journal, 8, &record), Err(Error::InvalidInput));
}
#[test]
fn forging_header_to_match_a_new_position_still_fails_authentication() {
    let cipher = cipher();
    let mut record = cipher.seal(Kind::Journal, 7, b"request").unwrap();
    record[6..14].copy_from_slice(&8u64.to_be_bytes());
    assert_eq!(cipher.open(Kind::Journal, 8, &record), Err(Error::Crypto));
    let mut record = cipher.seal(Kind::Journal, 7, b"request").unwrap();
    record[5] = Kind::Backup as u8;
    assert_eq!(cipher.open(Kind::Backup, 7, &record), Err(Error::Crypto));
}
#[test]
fn ciphertext_nonce_and_tag_tampering_are_refused_without_rewriting_input() {
    let cipher = cipher();
    let original = cipher.seal(Kind::State, 0, b"private state").unwrap();
    for index in [14, 38, original.len() - 1] {
        let mut record = original.clone();
        record[index] ^= 1;
        let before = record.clone();
        assert_eq!(cipher.open(Kind::State, 0, &record), Err(Error::Crypto));
        assert_eq!(record, before);
    }
}
#[test]
fn partial_and_unknown_format_records_are_refused() {
    let cipher = cipher();
    let record = cipher.seal(Kind::State, 0, b"state").unwrap();
    for length in 0..record.len() {
        assert_eq!(
            cipher.open(Kind::State, 0, &record[..length]),
            Err(if length < 54 { Error::InvalidInput } else { Error::Crypto })
        );
    }
    for index in [0, 4] {
        let mut wrong = record.clone();
        wrong[index] ^= 3;
        assert_eq!(cipher.open(Kind::State, 0, &wrong), Err(Error::InvalidInput));
    }
}
#[test]
fn plaintext_and_envelope_limits_are_checked_before_crypto() {
    let cipher = cipher();
    let plain = vec![0x55; MAX_PLAINTEXT_BYTES];
    let record = cipher.seal(Kind::State, 0, &plain).unwrap();
    assert_eq!(record.len(), MAX_SEALED_BYTES);
    assert_eq!(*cipher.open(Kind::State, 0, &record).unwrap(), plain);
    assert_eq!(cipher.seal(Kind::State, 0, &vec![0; MAX_PLAINTEXT_BYTES + 1]), Err(Error::Limit));
    assert_eq!(cipher.open(Kind::State, 0, &vec![0; MAX_SEALED_BYTES + 1]), Err(Error::Limit));
}
