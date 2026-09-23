/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 10.1: the development fixture, and the pairing equation.
//!
//! The fixture is one valid proof plus one each with `A`, `B`, `C` and a public
//! input mutated. Only the valid vector may verify.
//!
//! The pairing equation is measured here rather than recalled. Six candidate
//! sign/order forms are evaluated against all five vectors, and the test pins
//! the measured outcome: which forms accept the valid vector and reject every
//! mutation, and which do not. Section 10.1 forbids inferring the signs any
//! other way.

mod scenario;

use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::groth16;
use shielded_pool_circuit::public_inputs::{ORDER, PUBLIC_INPUT_COUNT};

#[test]
fn one_valid_proof_and_four_mutations() {
    let (_pool, public, witness) = scenario::valid_withdrawal();
    let keys = match groth16::development_keys(ShieldedTransactionCircuit::blank(public)) {
        Ok(keys) => keys,
        Err(error) => panic!("setup: {error}"),
    };
    assert_eq!(
        keys.verifying.gamma_abc_g1.len(),
        PUBLIC_INPUT_COUNT + 1,
        "18 public inputs require exactly 19 IC points"
    );

    let proof =
        match groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness.clone()), 1) {
            Ok(proof) => proof,
            Err(error) => panic!("prove: {error}"),
        };

    let valid = match groth16::verify(&keys.verifying, &public, &proof) {
        Ok(result) => result,
        Err(error) => panic!("verify: {error}"),
    };
    assert!(valid, "the valid vector does not verify");

    let mutated_public = match groth16::mutate_public(&public, 11) {
        Ok(mutated) => mutated,
        Err(error) => panic!("mutating {}: {error}", ORDER[11]),
    };

    let cases: [(&str, &_, &_); 4] = [
        ("A mutated", &groth16::mutate_a(&proof), &public),
        ("B mutated", &groth16::mutate_b(&proof), &public),
        ("C mutated", &groth16::mutate_c(&proof), &public),
        ("public input 11 mutated", &proof, &mutated_public),
    ];
    for (label, mutated_proof, inputs) in cases {
        let accepted = match groth16::verify(&keys.verifying, inputs, mutated_proof) {
            Ok(result) => result,
            Err(error) => panic!("verify ({label}): {error}"),
        };
        assert!(!accepted, "{label} still verified");
        println!("{label}: rejected");
    }
    println!("valid vector: accepted; all four mutations rejected");
}

#[test]
fn the_pairing_equation_is_measured_not_assumed() {
    let (_pool, public, witness) = scenario::valid_withdrawal();
    let keys = match groth16::development_keys(ShieldedTransactionCircuit::blank(public)) {
        Ok(keys) => keys,
        Err(error) => panic!("setup: {error}"),
    };
    let proof = match groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 1) {
        Ok(proof) => proof,
        Err(error) => panic!("prove: {error}"),
    };
    let mutated_public = match groth16::mutate_public(&public, 0) {
        Ok(mutated) => mutated,
        Err(error) => panic!("mutating {}: {error}", ORDER[0]),
    };

    let report =
        match groth16::pairing_equation_report(&keys.verifying, &public, &proof, &mutated_public) {
            Ok(report) => report,
            Err(error) => panic!("pairing report: {error}"),
        };

    println!("candidate four-pair forms, measured against one valid proof and four mutations:");
    for verdict in report.iter() {
        println!(
            "  valid={:5}  A={:5} B={:5} C={:5} input={:5}  {}",
            verdict.holds_for_valid,
            verdict.holds_for_mutations[0],
            verdict.holds_for_mutations[1],
            verdict.holds_for_mutations[2],
            verdict.holds_for_mutations[3],
            verdict.name
        );
    }

    let usable: Vec<&str> = report
        .iter()
        .filter(|verdict| verdict.is_the_equation())
        .map(|verdict| verdict.name)
        .collect();
    // Two of the six forms hold, and they are the same statement: the second
    // is the first with both sides inverted in the target group. The other
    // four sign patterns fail on the valid vector, which is what makes this a
    // measurement rather than a recollection.
    assert_eq!(
        usable,
        vec![
            "e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1",
            "e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1",
        ],
        "the set of forms that accept the valid vector and reject every mutation is not the \
         measured one"
    );
    assert_eq!(report.len() - usable.len(), 4, "four sign patterns must have been ruled out");
    println!(
        "MEASURED EQUATION: e(A,B) = e(alpha,beta) * e(vk_x,gamma) * e(C,delta), \
         with vk_x = IC[0] + sum(public_input[i] * IC[i+1]). Both product-equals-one \
         spellings of it hold; the four other sign patterns do not."
    );
}

#[test]
/// Ruling A1: the wire bytes are the blst/IETF encoding, not whatever the
/// proving library happens to emit.
///
/// Worth recording plainly, because the migration changed no bytes: arkworks
/// 0.5 already produced exactly these bytes for BLS12-381. That made the old
/// encoding accidentally right, unverified and undocumented. What this test
/// establishes is that it is now pinned -- every point is produced through
/// blst, round trips through it unchanged, and carries its flags where the
/// IETF layout puts them, so a future library change that moved to the
/// flags-last layout would fail here instead of silently changing a hash that
/// lives in chain state.
#[test]
fn every_point_is_canonical_in_the_chains_own_encoding() {
    let (_pool, public, witness) = scenario::valid_withdrawal();
    let keys = match groth16::development_keys(ShieldedTransactionCircuit::blank(public)) {
        Ok(keys) => keys,
        Err(error) => panic!("setup: {error}"),
    };
    let proof = match groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 1) {
        Ok(proof) => proof,
        Err(error) => panic!("prove: {error}"),
    };
    let canonical = match groth16::CanonicalProof::from_proof(&proof) {
        Ok(canonical) => canonical,
        Err(error) => panic!("proof encoding: {error}"),
    };
    let vk = match groth16::canonical_verifying_key(&keys.verifying) {
        Ok(vk) => vk,
        Err(error) => panic!("verifying key encoding: {error}"),
    };

    // Every G1 in the proof, and every 48-byte group in the VK stream that is
    // one: alpha, then IC[0..18]. The G2s are checked by width below.
    let mut g1s: Vec<[u8; 48]> = vec![canonical.a, canonical.c];
    let mut g2s: Vec<[u8; 96]> = vec![canonical.b];
    g1s.push(vk.bytes[..48].try_into().expect("alpha"));
    for index in 0..3 {
        let start = 48 + index * 96;
        g2s.push(vk.bytes[start..start + 96].try_into().expect("a G2"));
    }
    for index in 0..vk.ic_count {
        let start = 48 + 3 * 96 + index * 48;
        g1s.push(vk.bytes[start..start + 48].try_into().expect("an IC point"));
    }
    assert_eq!(g1s.len(), 2 + 1 + vk.ic_count, "not every G1 was collected");
    assert_eq!(g2s.len(), 4, "not every G2 was collected");

    for (index, bytes) in g1s.iter().enumerate() {
        assert_ne!(bytes[0] & 0x80, 0, "G1 {index}: the compression flag is not in the first byte");
        if let Err(error) = groth16::round_trip_g1(bytes) {
            panic!("G1 {index}: {error}");
        }
        // Clearing the compression flag makes it an uncompressed prefix, which
        // is 48 bytes short: blst must refuse rather than guess.
        let mut flagless = *bytes;
        flagless[0] &= 0x7f;
        assert!(
            groth16::round_trip_g1(&flagless).is_err(),
            "G1 {index}: blst accepted bytes whose compression flag was cleared, so the \
             flag position is not actually being enforced"
        );
        // Claiming infinity while carrying a coordinate must also be refused.
        let mut lying = *bytes;
        lying[0] |= 0x40;
        assert!(
            groth16::round_trip_g1(&lying).is_err(),
            "G1 {index}: blst accepted an infinity flag on a point with coordinates"
        );
    }
    for (index, bytes) in g2s.iter().enumerate() {
        assert_ne!(bytes[0] & 0x80, 0, "G2 {index}: the compression flag is not in the first byte");
        if let Err(error) = groth16::round_trip_g2(bytes) {
            panic!("G2 {index}: {error}");
        }
        let mut flagless = *bytes;
        flagless[0] &= 0x7f;
        assert!(groth16::round_trip_g2(&flagless).is_err(), "G2 {index}: flag position unenforced");
    }
}

#[test]
fn the_canonical_encodings_have_the_frozen_lengths() {
    let (_pool, public, witness) = scenario::valid_withdrawal();
    let keys = match groth16::development_keys(ShieldedTransactionCircuit::blank(public)) {
        Ok(keys) => keys,
        Err(error) => panic!("setup: {error}"),
    };
    let proof = match groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 1) {
        Ok(proof) => proof,
        Err(error) => panic!("prove: {error}"),
    };
    let canonical = match groth16::CanonicalProof::from_proof(&proof) {
        Ok(canonical) => canonical,
        Err(error) => panic!("proof encoding: {error}"),
    };
    assert_eq!(canonical.a.len(), 48);
    assert_eq!(canonical.b.len(), 96);
    assert_eq!(canonical.c.len(), 48);
    assert_eq!(canonical.flat().len(), 192, "section 10.1 fixes 192 bytes");

    let vk = match groth16::canonical_verifying_key(&keys.verifying) {
        Ok(vk) => vk,
        Err(error) => panic!("verifying key encoding: {error}"),
    };
    assert_eq!(vk.ic_count, 19);
    assert_eq!(
        vk.bytes.len(),
        48 + 96 * 3 + 19 * 48,
        "the verifying key encoding is not the section 10.1 layout"
    );
    println!(
        "verifying key: {} bytes, {} IC points, sha256 {}",
        vk.bytes.len(),
        vk.ic_count,
        vk.sha256
    );
}
