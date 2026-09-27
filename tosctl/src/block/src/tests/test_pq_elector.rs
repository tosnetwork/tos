/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! The Rust half of the authorisation-preimage lock. The C++ half produces the same file,
//! and the contracts are written against it.

use super::*;

fn fill(byte: u8) -> UInt256 {
    UInt256::from([byte; 32])
}

fn vectors() -> std::collections::HashMap<String, (usize, String)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../test/pq-native/authorisation-preimage-vectors.tsv"
    );
    let text = std::fs::read_to_string(path).expect("the shared preimage vectors");
    let mut cases = std::collections::HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed vector line");
        let length: usize = fields[1].parse().expect("a byte count");
        assert!(
            cases.insert(fields[0].to_string(), (length, fields[2].to_string())).is_none(),
            "duplicate case {}",
            fields[0]
        );
    }
    cases
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
        "stake",
        stake_preimage(
            -239,
            1_789_434_000,
            0x10000,
            &fill(0xa1),
            &fill(0xd7),
            1,
            &fill(0xb2),
            &fill(0xc3),
        ),
    );
    check("config-vote", config_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 7, &fill(0xe5)));
    check(
        "complaint-vote",
        complaint_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 7, 1_789_434_000, &fill(0xf6)),
    );
    check(
        "stake-other-key",
        stake_preimage(
            -239,
            1_789_434_000,
            0x10000,
            &fill(0xa1),
            &fill(0xd7),
            1,
            &fill(0xb3),
            &fill(0xc3),
        ),
    );
    check(
        "stake-other-validator",
        stake_preimage(
            -239,
            1_789_434_000,
            0x10000,
            &fill(0xa2),
            &fill(0xd7),
            1,
            &fill(0xb2),
            &fill(0xc3),
        ),
    );
    check(
        "stake-other-algorithm",
        stake_preimage(
            -239,
            1_789_434_000,
            0x10000,
            &fill(0xa1),
            &fill(0xd7),
            2,
            &fill(0xb2),
            &fill(0xc3),
        ),
    );
    check(
        "stake-other-owner",
        stake_preimage(
            -239,
            1_789_434_000,
            0x10000,
            &fill(0xa1),
            &fill(0xd8),
            1,
            &fill(0xb2),
            &fill(0xc3),
        ),
    );
    check(
        "stake-other-network",
        stake_preimage(
            -1,
            1_789_434_000,
            0x10000,
            &fill(0xa1),
            &fill(0xd7),
            1,
            &fill(0xb2),
            &fill(0xc3),
        ),
    );
    check(
        "config-vote-other-set",
        config_vote_preimage(-239, &fill(0xd5), &fill(0xa1), 7, &fill(0xe5)),
    );
    check(
        "config-vote-other-index",
        config_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 8, &fill(0xe5)),
    );
    check(
        "complaint-vote-other-election",
        complaint_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 7, 1_789_434_001, &fill(0xf6)),
    );

    // A case in the file that nothing here produces would be a layout no implementation
    // is held to, which is the same as not having frozen it.
    let unchecked: Vec<&String> = cases.keys().collect();
    assert!(unchecked.is_empty(), "cases no implementation here builds: {unchecked:?}");
}

#[test]
fn the_three_domains_cannot_be_mistaken_for_one_another() {
    let vote = config_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 7, &fill(0xe5));
    let complaint = complaint_vote_preimage(-239, &fill(0xd4), &fill(0xa1), 7, 1, &fill(0xe5));
    assert_ne!(vote[..4], complaint[..4], "two authorisations share a domain tag");
    assert_ne!(
        ELECTOR_PQ_STAKE_SIGN_TAG, ELECTOR_PQ_STAKE_OP,
        "the signed domain and the message operation must differ, or a message body reads as a preimage"
    );
}
