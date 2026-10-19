/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! The Rust half of the vote-carrier lock.
//!
//! The C++ half produces `test/pq-native/vote-carrier-vectors.tsv` and reads it back; the
//! contracts parse what it describes. A vote built to a layout the contract does not read
//! is refused after the sender has paid for the message, so the three sides are held to
//! one recorded set of bytes rather than to each other's source.

use chain_block::{Cell, read_single_root_boc, write_boc};
use contracts::{config_contract, elector};
use std::collections::HashMap;

const SIGNATURE_BYTES: usize = 2420;
const QUERY_ID: u64 = 0x1234_5678_90AB_CDEF;

/// The same pattern the generator writes: nothing verifies it, the point is the shape.
fn pattern_signature() -> Vec<u8> {
    (0..SIGNATURE_BYTES).map(|i| (i % 251) as u8).collect()
}

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn recorded() -> HashMap<String, (String, String)> {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../test/pq-native/vote-carrier-vectors.tsv");
    let text = std::fs::read_to_string(path).expect("the shared carrier vectors");
    let mut cases = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed vector line");
        assert!(
            cases
                .insert(fields[0].to_string(), (fields[1].to_string(), fields[2].to_string()))
                .is_none(),
            "duplicate case {}",
            fields[0]
        );
    }
    assert!(!cases.is_empty(), "the carrier vectors are empty");
    cases
}

fn built() -> Vec<(&'static str, Cell)> {
    let signature = pattern_signature();
    vec![
        (
            "config-vote",
            config_contract::messages::signed_vote(QUERY_ID, 7, &fill(0xE5), &signature).unwrap(),
        ),
        (
            "complaint-vote",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_000,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "config-vote-other-query",
            config_contract::messages::signed_vote(QUERY_ID - 1, 7, &fill(0xE5), &signature)
                .unwrap(),
        ),
        (
            "config-vote-other-index",
            config_contract::messages::signed_vote(QUERY_ID, 8, &fill(0xE5), &signature).unwrap(),
        ),
        (
            "config-vote-other-proposal",
            config_contract::messages::signed_vote(QUERY_ID, 7, &fill(0xE6), &signature).unwrap(),
        ),
        (
            "complaint-vote-other-index",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                8,
                1_789_434_000,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "complaint-vote-other-election",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_001,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "complaint-vote-other-complaint",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_000,
                &fill(0xF7),
                &signature,
            )
            .unwrap(),
        ),
    ]
}

/// Where the bytes this side writes are kept, for the node's reader to be held to.
/// Regenerated with `TOS_WRITE_CARRIER_TOOLING=1`, and otherwise compared.
const TOOLING_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../test/pq-native/vote-carrier-vectors-tooling.tsv"
);

#[test]
fn builds_exactly_the_carriers_the_other_implementation_builds() {
    let mut cases = recorded();
    let mut written_by_tooling: Vec<(String, String)> = Vec::new();
    for (name, cell) in built() {
        let (hash, boc) = cases.remove(name).unwrap_or_else(|| panic!("no recorded case {name}"));
        assert_eq!(
            cell.repr_hash().as_hex_string().to_uppercase(),
            hash.to_uppercase(),
            "{name}: the root hash differs from the recorded one"
        );
        // The recorded bytes, read by this side. What is locked is the tree, not the
        // envelope it travels in: the two libraries frame a bag of cells differently --
        // one appends a checksum, the other does not -- and the contract is handed the
        // tree. A side that cannot read the other's bytes at all is the failure that
        // matters, and it fails here.
        let from_recorded = read_single_root_boc(hex::decode(&boc).expect("the recorded bytes"))
            .unwrap_or_else(|e| panic!("{name}: cannot read the recorded carrier: {e}"));
        assert_eq!(
            from_recorded.repr_hash(),
            cell.repr_hash(),
            "{name}: the recorded bytes are a different message"
        );
        // And what this side writes is recorded in turn, so the node's reader is held to
        // it. Reading back only with this side's own reader would leave the direction
        // that matters -- tooling writes, node reads -- untested, and two changes that
        // suited each other would pass.
        let written = write_boc(&cell).expect("serialise the carrier");
        let round_tripped = read_single_root_boc(&written).expect("read back what we wrote");
        assert_eq!(
            round_tripped.repr_hash(),
            cell.repr_hash(),
            "{name}: this side cannot read back its own carrier"
        );
        written_by_tooling.push((name.to_string(), hex::encode(&written)));
    }
    assert!(
        cases.is_empty(),
        "the file records carriers this side does not build: {:?}",
        cases.keys().collect::<Vec<_>>()
    );

    let mut produced = String::from(
        "# The same carriers, serialised by the operator tooling rather than by the node.\n\
         #\n\
         # The two libraries frame a bag of cells differently, so these bytes are not the\n\
         # ones beside them in vote-carrier-vectors.tsv. They are here so the node's reader is\n\
         # held to what the tooling actually sends: a test that only read back its own\n\
         # output would pass two changes that suited each other and nothing else.\n\
         #\n\
         # Written by the Rust carrier test with TOS_WRITE_CARRIER_TOOLING=1.\n\
         #\n\
         # name\tboc_hex\n",
    );
    written_by_tooling.sort();
    for (name, boc) in &written_by_tooling {
        produced.push_str(name);
        produced.push('\t');
        produced.push_str(boc);
        produced.push('\n');
    }
    if std::env::var("TOS_WRITE_CARRIER_TOOLING").is_ok() {
        std::fs::write(TOOLING_FILE, &produced).expect("record what this side writes");
        return;
    }
    let recorded_tooling =
        std::fs::read_to_string(TOOLING_FILE).expect("the recorded tooling serialisations");
    assert_eq!(
        recorded_tooling, produced,
        "what this side writes has changed; regenerate with TOS_WRITE_CARRIER_TOOLING=1 and \
         say in the commit why the bytes the node must read are different"
    );
}

/// Each recorded "other" case differs from its base in exactly one field. Two of them
/// being the same message would mean a field this side does not put on the wire.
#[test]
fn no_two_carriers_are_the_same_message() {
    let mut seen = HashMap::new();
    for (name, cell) in built() {
        let hash = cell.repr_hash().as_hex_string();
        if let Some(other) = seen.insert(hash, name) {
            panic!("{name} and {other} are the same message");
        }
    }
}
