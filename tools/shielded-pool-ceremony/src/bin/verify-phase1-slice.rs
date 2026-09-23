/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Checks a fetched phase-1 slice, and says what the check does and does not
//! cover.
//!
//!     verify-phase1-slice <slice.bin> <slice.json>
//!
//! Exits non-zero on the first thing that is wrong, naming it.

use std::process::ExitCode;

use shielded_pool_ceremony::{lagrange, shape, slice, verify, Result};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::scenario;

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(slice_path), Some(record_path)) = (args.next(), args.next()) else {
        return Err(shielded_pool_ceremony::Error::Slice(
            "usage: verify-phase1-slice <slice.bin> <slice.json>".into(),
        ));
    };

    // The circuit decides the exponent, so a slice is checked against the
    // circuit as it is now and not against the circuit as it was when the
    // slice was fetched.
    let (_pool, public, witness) = scenario::valid_withdrawal()
        .map_err(|error| shielded_pool_ceremony::Error::Layout(format!("scenario: {error}")))?;
    let measured = shape(ShieldedTransactionCircuit::new(public, witness))?;
    let exponent = measured.domain_exponent();
    println!(
        "circuit: {} constraints, {} variables -> QAP degree {} -> domain 2^{exponent}",
        measured.constraints,
        measured.instance_variables + measured.witness_variables,
        measured.qap_degree(),
    );

    let bytes = std::fs::read(&slice_path)?;
    let record: slice::Provenance = serde_json::from_slice(&std::fs::read(&record_path)?)?;
    println!("\nceremony: {} (2^{})", record.transcript, record.source_power);
    println!("          {}", record.source_url);
    println!("          {}", record.published_checksums);
    if let Some(digest) = &record.transcript_hash {
        println!("          head digest {digest}");
    }
    println!("slice:    {} bytes", bytes.len());

    let parsed = slice::parse(&bytes, &record, exponent)?;
    println!(
        "parsed:  {} G1 powers, {} G2 powers, {} alpha, {} beta, all in the prime-order subgroup",
        parsed.tau_g1.len(),
        parsed.tau_g2.len(),
        parsed.alpha_tau_g1.len(),
        parsed.beta_tau_g1.len(),
    );

    // The batching randomness must not be anything the transcript could have
    // predicted, so it comes from the operating system rather than from a
    // seed in this file.
    let mut seed = [0u8; 32];
    getrandom(&mut seed)?;
    verify::verify(&parsed, seed)?;
    println!("\nthe slice is a well-formed powers-of-tau string over domain 2^{exponent}.");

    // And the basis change, because a verified slice is still not something a
    // setup can use. It is fast, it has no secrets, and its result is what a
    // phase-2 transcript would name itself against -- so it belongs in the
    // same run rather than in a separate step someone can forget.
    let srs = lagrange::transform(&parsed)?;
    getrandom(&mut seed)?;
    lagrange::verify(&parsed, &srs, seed)?;
    println!(
        "the Lagrange basis over that domain checks out: {} basis points a group, {} in the h \
         query.",
        srs.degree(),
        srs.h.len()
    );
    println!("reference string {}", lagrange::digest(&srs));
    println!(
        "\nWhat none of that says: anything about who knows tau. That comes from the {} \
         ceremony's\ncontribution chain, which cannot be checked from a slice -- re-verifying \
         it means\nreplaying every response in the transcript.\n\n  What is inherited: {}.\n\n\
         The identifiers printed at the top are what to hold against that ceremony's published\n\
         attestations. The reference string digest names only what came out of this run.",
        record.transcript, record.custody
    );
    Ok(())
}

/// Entropy from the operating system, without adding a dependency for it.
fn getrandom(out: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(out)?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("REFUSED: {error}");
            ExitCode::FAILURE
        }
    }
}
