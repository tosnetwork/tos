/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The Rust half of the controller-authorisation lock. The other implementation writes
//! the same file, so a field order that drifts on either side is caught here rather than
//! by an authorisation nobody can verify.

use super::*;

fn vectors() -> std::collections::HashMap<String, (usize, String)> {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-native/controller-auth-vectors.tsv");
    let text = std::fs::read_to_string(path).expect("the shared controller vectors");
    let mut cases = std::collections::HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed vector line");
        let length: usize = fields[1].parse().expect("a byte count");
        assert_eq!(
            length * 2,
            fields[2].len(),
            "{}: the stated length is not the hex length",
            fields[0]
        );
        cases.insert(fields[0].to_string(), (length, fields[2].to_string()));
    }
    cases
}

fn fill(byte: u8) -> UInt256 {
    UInt256::from_slice(&[byte; 32])
}

#[test]
fn builds_exactly_the_bytes_the_other_implementation_builds() {
    let mut cases = vectors();
    let mut check = |name: &str, bytes: Vec<u8>| {
        let (length, expected) =
            cases.remove(name).unwrap_or_else(|| panic!("the shared file is missing {name}"));
        assert_eq!(bytes.len(), length, "{name}: length differs");
        assert_eq!(hex::encode(&bytes), expected, "{name}: bytes differ");
    };

    check(
        "controller-auth",
        controller_auth_preimage(-239, &fill(0xa1), 7, 3, 1_789_434_000, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-network",
        controller_auth_preimage(-1, &fill(0xa1), 7, 3, 1_789_434_000, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-controller",
        controller_auth_preimage(-239, &fill(0xa2), 7, 3, 1_789_434_000, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-epoch",
        controller_auth_preimage(-239, &fill(0xa1), 8, 3, 1_789_434_000, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-nonce",
        controller_auth_preimage(-239, &fill(0xa1), 7, 4, 1_789_434_000, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-expiry",
        controller_auth_preimage(-239, &fill(0xa1), 7, 3, 1_789_434_001, 1, &fill(0xb2)),
    );
    check(
        "controller-auth-other-kind",
        controller_auth_preimage(-239, &fill(0xa1), 7, 3, 1_789_434_000, 2, &fill(0xb2)),
    );
    check(
        "controller-auth-other-payload",
        controller_auth_preimage(-239, &fill(0xa1), 7, 3, 1_789_434_000, 1, &fill(0xb3)),
    );
    check("context", CONTROLLER_AUTH_CONTEXT.to_vec());

    // The pinned key and signature are material for the consumers that verify; this side
    // only has to agree that they are there and are the right size.
    let (public_key, _) = cases.remove("root-public-key").expect("a pinned root key");
    assert_eq!(public_key, 1312, "the pinned root key is not an ML-DSA-44 public key");
    let (signature, _) = cases.remove("root-signature").expect("a pinned signature");
    assert_eq!(signature, 2420, "the pinned signature is not an ML-DSA-44 signature");

    assert!(cases.is_empty(), "cases no implementation here builds: {cases:?}");
}

#[test]
fn the_controller_domain_is_its_own() {
    let controller =
        controller_auth_preimage(-239, &fill(0xa1), 7, 3, 1_789_434_000, 1, &fill(0xb2));
    assert_eq!(controller.len(), 93, "the frozen controller authorisation is 93 bytes");

    // One byte apart from the complaint tags, which is exactly the kind of thing eyes miss.
    for frozen in [
        crate::pq_elector::ELECTOR_PQ_STAKE_OP,
        crate::pq_elector::ELECTOR_PQ_STAKE_SIGN_TAG,
        crate::pq_elector::CONFIG_PQ_VOTE_OP,
        crate::pq_elector::CONFIG_PQ_VOTE_SIGN_TAG,
        crate::pq_elector::ELECTOR_PQ_COMPLAINT_OP,
        crate::pq_elector::ELECTOR_PQ_COMPLAINT_SIGN_TAG,
    ] {
        assert_ne!(frozen, CONTROLLER_AUTH_OP);
        assert_ne!(frozen, CONTROLLER_AUTH_SIGN_TAG);
    }
    assert_ne!(CONTROLLER_AUTH_OP, CONTROLLER_AUTH_SIGN_TAG);

    // A single field changed must change the bytes, or the field is not committed.
    let nonce = controller_auth_preimage(-239, &fill(0xa1), 7, 4, 1_789_434_000, 1, &fill(0xb2));
    assert_ne!(controller, nonce);
    let stake = crate::pq_elector::stake_preimage(
        -239,
        1_789_434_000,
        0x10000,
        &fill(0xa1),
        &fill(0xd7),
        1,
        &fill(0xb2),
        &fill(0xc3),
    );
    assert_ne!(controller[..4], stake[..4], "two authorities share a domain tag");
}
