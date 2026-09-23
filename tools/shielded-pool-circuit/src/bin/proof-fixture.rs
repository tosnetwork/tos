/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Writes the section 10.1 development fixture: the verifying key, one valid
//! proof and the four mutated vectors, with the public inputs in the frozen
//! section 10 order.
//!
//! The keys come from a fixed seed, so the toxic waste is known. This fixture
//! is for `test/shielded-pool/` and for nothing else.

use std::path::PathBuf;

use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::groth16;
use shielded_pool_circuit::public_inputs::{PublicInputs, ORDER};

fn vector(
    name: &str,
    proof: &ark_groth16::Proof<ark_bls12_381::Bls12_381>,
    public: &PublicInputs,
    verifying: &ark_groth16::VerifyingKey<ark_bls12_381::Bls12_381>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let canonical = groth16::CanonicalProof::from_proof(proof)?;
    let accepted = groth16::verify(verifying, public, proof)?;
    Ok(serde_json::json!({
        "name": name,
        "must_verify": name == "valid",
        "verified_by_the_prover_library": accepted,
        "proof": {
            "a_hex": hex::encode(canonical.a),
            "b_hex": hex::encode(canonical.b),
            "c_hex": hex::encode(canonical.c),
            "cell_order_a_c_then_b_hex": hex::encode(canonical.flat()),
        },
        "public_inputs_decimal": groth16::public_decimals(public),
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = match std::env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("usage: proof-fixture <output.json>");
            std::process::exit(2);
        }
    };

    let (public, witness) = shielded_pool_circuit::scenario::development_transaction()?;
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))?;
    let proof = groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 1)?;
    let mutated_public = groth16::mutate_public(&public, 11)?;
    let vk = groth16::canonical_verifying_key(&keys.verifying)?;

    let report =
        groth16::pairing_equation_report(&keys.verifying, &public, &proof, &mutated_public)?;
    let equation: Vec<&str> = report
        .iter()
        .filter(|verdict| verdict.is_the_equation())
        .map(|verdict| verdict.name)
        .collect();

    let document = serde_json::json!({
        "warning": "Development keys from a fixed seed. The toxic waste is known; these keys \
                    must never verify a real transaction.",
        "profile": "TOS Shielded Pool V1 implementation profile, sections 10 and 10.1",
        "public_input_order": ORDER,
        "point_encoding": "blst/IETF BLS12-381 compressed encoding: big-endian x with the \
                           compression, infinity and sort flags in the first byte, 48 bytes for \
                           G1 and 96 for G2. Every point here was produced by blst and round \
                           trips through blst_*_uncompress and blst_*_affine_compress unchanged. \
                           arkworks is the prover's curve implementation and not the wire format.",
        "verifying_key": {
            "ic_count": vk.ic_count,
            "bytes": vk.bytes.len(),
            "sha256": vk.sha256,
            "hex": hex::encode(&vk.bytes),
        },
        "pairing_equation_forms_that_hold": equation,
        "vectors": [
            vector("valid", &proof, &public, &keys.verifying)?,
            vector("a_mutated", &groth16::mutate_a(&proof), &public, &keys.verifying)?,
            vector("b_mutated", &groth16::mutate_b(&proof), &public, &keys.verifying)?,
            vector("c_mutated", &groth16::mutate_c(&proof), &public, &keys.verifying)?,
            vector("public_input_11_mutated", &proof, &mutated_public, &keys.verifying)?,
        ],
    });

    std::fs::write(&destination, format!("{}\n", serde_json::to_string_pretty(&document)?))?;
    println!(
        "wrote the verifying key ({} bytes, sha256 {}) and five vectors to {}",
        vk.bytes.len(),
        vk.sha256,
        destination.display()
    );
    Ok(())
}
