/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, str::FromStr};

const EXPECTED_CASES: [&str; 23] = [
    "valid-1",
    "valid-21",
    "duplicate-validator-id",
    "unknown-algorithm",
    "wrong-signature-length-short",
    "wrong-signature-length-long",
    "noncanonical-pqbytes",
    "sig-count-mismatch",
    "dictionary-gap",
    "dictionary-extra-entry",
    "candidate-data-oversize",
    "candidate-data-noncanonical-chunk",
    "candidate-data-non-byte-aligned",
    "candidate-data-multiple-refs",
    "candidate-data-overlong-chain",
    "candidate-data-trailing-ref",
    "candidate-data-trailing-tl",
    "401-signers",
    "claimed-weight-mismatch",
    "unknown-validator-id",
    "validator-algorithm-mismatch",
    "old-11-under-pq-vset",
    "old-12-under-pq-vset",
];

fn parse_list<T: FromStr>(text: &str) -> Vec<T>
where
    T::Err: std::fmt::Debug,
{
    if text == "-" {
        Vec::new()
    } else {
        text.split(',').map(|item| item.parse().unwrap()).collect()
    }
}

#[test]
fn shared_pq_block_signature_codec_parity_does_not_verify_finality() {
    // This gate proves byte-identical C++/Rust #13 codec behavior. Rust tooling
    // does not establish validator authority or verify finality in this path.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../test/pq-native/pq-block-signature-vectors.txt"
    );
    let text = std::fs::read_to_string(path).expect("shared post-quantum block-signature vectors");
    let expected: BTreeSet<&str> = EXPECTED_CASES.into_iter().collect();
    let mut seen = BTreeSet::new();

    for line in text.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let row: Vec<&str> = line.split('\t').collect();
        assert_eq!(row.len(), 14, "RUST_VECTOR_BAD_ROW fields={}", row.len());
        let case = row[0];
        assert!(expected.contains(case), "RUST_VECTOR_UNCLAIMED_ROW case={case}");
        assert!(seen.insert(case), "RUST_VECTOR_DUPLICATE_ROW case={case}");

        let boc = hex::decode(row[4]).expect("RUST_VECTOR_BAD_BOC_HEX");
        let ids: Vec<UInt256> = parse_list(row[9]);
        let algorithms: Vec<u16> = parse_list(row[10]);
        assert_eq!(ids.len(), algorithms.len(), "RUST_VECTOR_METADATA_MISMATCH case={case}");
        let validators: Vec<PqBlockValidatorWeight> = ids
            .iter()
            .zip(&algorithms)
            .map(|(validator_id, algorithm_id)| PqBlockValidatorWeight {
                validator_id: validator_id.clone(),
                algorithm_id: *algorithm_id,
                weight: 1,
            })
            .collect();

        let parsed = BlockSignaturesSimplexPq::construct_from_pq_boc(&boc, &validators);
        if row[1] == "reject" {
            let error = match parsed {
                Ok(_) => panic!("RUST_VECTOR_UNEXPECTED_ACCEPT case={case} expected={}", row[2]),
                Err(error) => error,
            };
            let actual = pq_block_signature_reason_code(&error)
                .map(PqBlockSignatureReasonCode::as_str)
                .unwrap_or("unclassified");
            assert_eq!(actual, row[2], "RUST_VECTOR_REASON_CODE_MISMATCH case={case}");
            continue;
        }

        assert_eq!(row[1], "accept", "RUST_VECTOR_BAD_OUTCOME case={case}");
        let parsed = parsed.unwrap_or_else(|error| {
            panic!("RUST_VECTOR_UNEXPECTED_REJECT case={case} actual={error}")
        });
        assert_eq!(row[2], "-", "RUST_VECTOR_METADATA_MISMATCH case={case}");
        assert_eq!(row[5], "#13", "RUST_VECTOR_METADATA_MISMATCH case={case}");
        assert_eq!(parsed.validator_info.validator_list_hash_short, row[6].parse().unwrap());
        assert_eq!(parsed.validator_info.catchain_seqno, row[7].parse().unwrap());
        assert_eq!(parsed.sig_count, row[8].parse().unwrap());
        assert_eq!(
            parsed.signatures.iter().map(|pair| &pair.validator_id).collect::<Vec<_>>(),
            ids.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            parsed.signatures.iter().map(|pair| pair.algorithm_id).collect::<Vec<_>>(),
            algorithms
        );
        assert_eq!(parsed.session_id, UInt256::from_str(row[11]).unwrap());
        assert_eq!(parsed.slot, row[12].parse().unwrap());
        let candidate = read_candidate_data(&parsed.candidate_data).unwrap();
        assert_eq!(hex::encode_upper(Sha256::digest(candidate)), row[13]);

        let reserialized = parsed.write_to_bytes().unwrap_or_else(|error| {
            panic!("RUST_VECTOR_RESERIALIZATION_FAILED case={case} actual={error}")
        });
        assert_eq!(reserialized, boc, "RUST_VECTOR_RESERIALIZATION_DRIFT case={case}");
    }

    if let Some(missing) = expected.difference(&seen).next() {
        panic!("RUST_VECTOR_MISSING_ROW case={missing}");
    }
    println!("RUST_PQ_BLOCK_SIGNATURE_VECTORS_OK rows={}", seen.len());
}
