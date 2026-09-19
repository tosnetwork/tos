// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// Constants that exist once per language, and inside Rust once per crate. Each
// definition is checked against the same file the C++ side checks, so a value
// changed on one side alone fails here instead of leaving two implementations
// that quietly disagree about the wire.
//
// This is the single Rust site for the shared file. It lives in the VM crate
// because the VM is where Rust defines the ML-DSA-44 signature length at all:
// the block crate has no such constant, so a site there could never hold it.
// The VM depends on the block crate, so one test reaches every definition.

use super::{CHUNK_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use chain_block::pq_bytes::{PQ_BYTES_CHUNK, PQ_BYTES_HARD_MAX};
use chain_block::validators::{
    ValidatorSet, MLDSA44_ALGORITHM_ID, MLDSA44_PUBLIC_KEY_BYTES, VALIDATOR_DESC_PQ_TAG,
};
use std::collections::HashMap;

fn frozen_constants() -> HashMap<String, u64> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-native/frozen-constants.tsv");
    let text = std::fs::read_to_string(path).expect("shared frozen constants");
    let mut frozen = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (name, value) = line.split_once('\t').expect("bad constant line");
        let value = value.trim().parse::<u64>().expect("decimal value");
        assert!(frozen.insert(name.to_string(), value).is_none(), "duplicate constant {name}");
    }
    frozen
}

/// Reading a constant also consumes it, so the emptiness check at the end of the
/// test proves every row was actually compared against a definition.
fn frozen_value(frozen: &mut HashMap<String, u64>, name: &str) -> u64 {
    frozen.remove(name).unwrap_or_else(|| panic!("missing constant {name}"))
}

#[test]
fn frozen_constants_match_cpp() {
    let mut frozen = frozen_constants();

    // Two crates encode the snake chunk, and both have to agree with the file.
    let chunk = frozen_value(&mut frozen, "pq_bytes_chunk");
    assert_eq!(PQ_BYTES_CHUNK as u64, chunk);
    assert_eq!(CHUNK_BYTES as u64, chunk);

    assert_eq!(PQ_BYTES_HARD_MAX as u64, frozen_value(&mut frozen, "pq_bytes_hard_max"));

    let public_key = frozen_value(&mut frozen, "mldsa44_public_key_bytes");
    assert_eq!(MLDSA44_PUBLIC_KEY_BYTES as u64, public_key);
    assert_eq!(PUBLIC_KEY_BYTES as u64, public_key);

    // The VM holds Rust's only definition of the signature length.
    assert_eq!(SIGNATURE_BYTES as u64, frozen_value(&mut frozen, "mldsa44_signature_bytes"));

    assert_eq!(MLDSA44_ALGORITHM_ID as u64, frozen_value(&mut frozen, "mldsa44_algorithm_id"));
    assert_eq!(VALIDATOR_DESC_PQ_TAG as u64, frozen_value(&mut frozen, "validator_descr_pq_tag"));
    assert_eq!(
        ValidatorSet::HASH_SHORT_MAGIC_V2 as u64,
        frozen_value(&mut frozen, "validator_set_hash_magic_v2")
    );

    use chain_block::pq_elector::{
        CONFIG_PQ_VOTE_OP, CONFIG_PQ_VOTE_SIGN_TAG, ELECTOR_PQ_COMPLAINT_OP,
        ELECTOR_PQ_COMPLAINT_SIGN_TAG, ELECTOR_PQ_STAKE_OP, ELECTOR_PQ_STAKE_SIGN_TAG,
    };
    for (name, value) in [
        ("elector_pq_stake_op", ELECTOR_PQ_STAKE_OP),
        ("elector_pq_stake_sign_tag", ELECTOR_PQ_STAKE_SIGN_TAG),
        ("config_pq_vote_op", CONFIG_PQ_VOTE_OP),
        ("config_pq_vote_sign_tag", CONFIG_PQ_VOTE_SIGN_TAG),
        ("elector_pq_complaint_op", ELECTOR_PQ_COMPLAINT_OP),
        ("elector_pq_complaint_sign_tag", ELECTOR_PQ_COMPLAINT_SIGN_TAG),
    ] {
        assert_eq!(value as u64, frozen_value(&mut frozen, name), "{name}");
    }

    // A row added to the shared file without a Rust definition to hold it fails
    // here, rather than looking locked while nothing on this side reads it.
    let unchecked: Vec<&String> = frozen.keys().collect();
    assert!(unchecked.is_empty(), "constants no Rust definition is bound to: {unchecked:?}");
}
