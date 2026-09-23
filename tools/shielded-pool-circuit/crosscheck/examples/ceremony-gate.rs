/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Puts a finished ceremony's key through the acceptance gate.
//!
//! ```text
//! TOS_ROOT=<a checkout with a built func/fift> \
//!   cargo run --release --example ceremony-gate -- <ceremony-directory>
//! ```
//!
//! `ceremony_acceptance.rs` proves the gate *judges* -- it accepts a key from
//! a setup it has never seen and refuses a proof made under a different key.
//! But every key in it is built from a seed in that file, so there was no way
//! to point the gate at an actual ceremony's output: the tests never read a
//! ceremony directory, and `phase2-verify` could only suggest a command that
//! would have re-run them against the development key.
//!
//! This is that missing step. It deploys a pool carrying exactly the 1,248
//! bytes the ceremony produced, proves a real private transfer under the
//! ceremony's proving key, sends it, and requires the contract to accept.
//! Everything short of that is a claim about a serializer.
//!
//! It reads `key.bin` and needs no secret, because there is none: the whole
//! ceremony directory is publishable.

use std::path::PathBuf;
use std::process::ExitCode;

use shielded_pool_ceremony::record::Directory;
use shielded_pool_circuit::groth16::{self, DevelopmentKeys};
use shielded_pool_circuit_crosscheck::acceptance::{self, CANONICAL_VK_BYTES};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("REFUSED: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        return Err("usage: ceremony-gate <ceremony-directory>".into());
    };

    let directory = Directory::at(&path);
    let record = directory.read_record().map_err(|error| error.to_string())?;
    let key = directory.read_key().map_err(|error| error.to_string())?;

    println!("ceremony   {}", directory.path().display());
    println!("steps      {}", record.entries.len());
    if !record.is_finished() {
        // Not fatal here -- the gate answers "does the chain accept this key",
        // and it does for an unfinished one. Saying so is the point: a key
        // that passes the gate is not a key that may be deployed.
        println!("WARNING: this ceremony has no beacon step, so it is not finished");
    }

    let encoded = groth16::canonical_verifying_key(&key.vk)
        .map_err(|error| format!("encoding the verifying key: {error}"))?;
    if encoded.bytes.len() != CANONICAL_VK_BYTES {
        return Err(format!(
            "the canonical encoding is {} bytes, not {CANONICAL_VK_BYTES}",
            encoded.bytes.len()
        ));
    }

    let verifying = key.vk.clone();
    let keys = DevelopmentKeys { proving: key, verifying };
    let outcome =
        acceptance::run(&keys, &encoded.bytes).map_err(|error| format!("the gate: {error}"))?;

    println!("\nverifying key {}", outcome.vk_sha256);
    println!("  length     {} bytes", outcome.vk_bytes);
    println!("  IC points  {}", outcome.ic_count);
    println!("  pool       {}", outcome.address);
    println!("  transact   exit {} at {} gas", outcome.exit, outcome.gas);

    if outcome.exit != 0 {
        return Err(format!(
            "a pool carrying this key refused a transfer proved under it (exit {})",
            outcome.exit
        ));
    }
    println!("\nACCEPTED: the chain takes a real private transfer under this key.");
    println!("That is what the gate establishes and all it establishes -- whether the");
    println!("scalars behind it were destroyed is not visible here or anywhere.");
    Ok(())
}
