/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Opens a phase-2 ceremony.
//!
//! Builds the key a ceremony starts from -- `gamma = delta = 1`, no secrets in
//! it at all -- from the phase-1 slice this repository commits and the
//! circuit it ships, and writes a ceremony directory nobody has contributed to
//! yet.
//!
//! Nothing here is secret and nothing here is trusted: the starting key is a
//! deterministic function of the slice and the circuit, so every later
//! participant rebuilds it rather than accepting this one, and the digest
//! printed below is what they will compare against.
//!
//! ```text
//! phase2-begin <ceremony-directory>
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use shielded_pool_ceremony::contribution::Transcript;
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem};
use shielded_pool_ceremony::record::{digest_of_transcript, Directory, Record, PROTOCOL};
use shielded_pool_ceremony::{committed, shape, Result};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: phase2-begin <ceremony-directory>");
        return Err(shielded_pool_ceremony::Error::Structure("no ceremony directory given".into()));
    };

    let directory = Directory::at(&path);
    // Before the expensive part, so an hour of pairing checks is not spent
    // discovering that the destination is occupied.
    directory.create()?;

    let circuit = committed::the_circuit()?;
    let measured = shape(circuit)?;
    println!(
        "circuit: {} constraints, {} instance variables -> QAP degree {} -> domain 2^{}",
        measured.constraints,
        measured.instance_variables,
        measured.qap_degree(),
        measured.domain_exponent()
    );
    if measured.domain_exponent() != committed::EXPONENT {
        return Err(shielded_pool_ceremony::Error::Structure(format!(
            "this circuit needs a 2^{} slice and the committed one is 2^{}; the ceremony would \
             be over the wrong reference string",
            measured.domain_exponent(),
            committed::EXPONENT
        )));
    }

    // The slice's structural checks batch against weights its author could not
    // have known, so they are drawn here rather than fixed.
    let mut seed = [0u8; 32];
    OperatingSystem.fill(&mut seed)?;

    println!(
        "verifying the committed phase-1 slice, changing its basis and building the starting \
         key (a few minutes)"
    );
    let (key, provenance) = committed::starting_key(&committed::artifacts_directory(), seed)?;
    println!("inheriting: {}", provenance.custody);

    let key_sha256 = directory.write_key(&key)?;
    directory.write_contributions(&[])?;
    let transcript = Transcript::begin(&key)?;
    let record = Record {
        protocol: PROTOCOL.into(),
        phase1_transcript: provenance.transcript.clone(),
        phase1_slice_sha256: provenance.slice_sha256.clone(),
        constraints: measured.constraints,
        instance_variables: measured.instance_variables,
        starting_key_sha256: key_sha256.clone(),
        entries: Vec::new(),
        key_sha256,
        transcript: digest_of_transcript(&transcript),
    };
    directory.write_record(&record)?;

    println!();
    println!("ceremony opened in {}", directory.path().display());
    println!(
        "  phase 1        {} ({})",
        record.phase1_transcript,
        &record.phase1_slice_sha256[..16]
    );
    println!("  starting key   {}", record.starting_key_sha256);
    println!("  transcript     {}", record.transcript);
    println!();
    println!("Publish those two digests. Every participant rebuilds the starting key from");
    println!("the committed slice and must get the first of them, or they are contributing");
    println!("to something other than this circuit.");
    println!();
    println!("Next: phase2-contribute {}", directory.path().display());
    Ok(())
}
