/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Audits a phase-2 ceremony and extracts the bytes the chain will carry.
//!
//! ```text
//! phase2-verify <ceremony-directory> [--vk-out <file>]
//! ```
//!
//! This is the command an outsider runs. It trusts the directory for nothing
//! except the contributions themselves:
//!
//! * the **starting key is rebuilt** from the phase-1 slice this repository
//!   commits and the circuit it ships, and has to match the digest the record
//!   claims. An audit that read the starting key out of the directory would be
//!   an audit of whatever it was handed;
//! * the **chain is verified** -- every contribution's proof of knowledge, its
//!   link to the one before, and one batched check that the queries were
//!   divided by the product `delta` was multiplied by;
//! * the **beacon step is recomputed** from the bytes in the directory and
//!   compared, because a participant-chosen scalar wearing the beacon's name
//!   passes every pairing;
//! * and the **1,248 bytes** are extracted, so what gets deployed comes out of
//!   the audit rather than out of a separate step nobody watched.
//!
//! What it cannot check, and says so at the end: that any participant drew
//! their scalar unpredictably and destroyed it, and that the beacon was named
//! before the ceremony opened. Those are the two things the whole construction
//! rests on and neither is observable from the artifacts.

use std::path::PathBuf;
use std::process::ExitCode;

use shielded_pool_ceremony::audit::{audit, preflight, StartingKey};
use shielded_pool_ceremony::record::{short, Directory};
use shielded_pool_ceremony::{Error, Result};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("REFUSED: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut path: Option<PathBuf> = None;
    let mut vk_out: Option<PathBuf> = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--vk-out" => {
                vk_out = Some(PathBuf::from(
                    rest.next().ok_or_else(|| Error::Structure("--vk-out needs a path".into()))?,
                ));
            }
            other if other.starts_with("--") => {
                return Err(Error::Structure(format!("unknown option {other}")));
            }
            other => path = Some(PathBuf::from(other)),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: phase2-verify <ceremony-directory> [--vk-out <file>]");
        return Err(Error::Structure("no ceremony directory given".into()));
    };

    let directory = Directory::at(&path);
    // What needs only the directory is refused before the slow part.
    preflight(&directory)?;
    let record = directory.read_record()?;
    println!("ceremony   {}", directory.path().display());
    println!("steps      {}", record.entries.len());

    println!("\nrebuilding the starting key from the committed slice (a couple of minutes)");
    let start = StartingKey::rebuild()?;
    let audited = audit(&directory, &start)?;
    let record = audited.record();
    println!("starting key matches: {}", start.digest());
    println!(
        "phase 1    {} ({})",
        record.phase1_transcript,
        short(&record.phase1_slice_sha256, "phase1_slice_sha256")?
    );
    println!(
        "circuit    {} constraints, {} instance variables",
        record.constraints, record.instance_variables
    );
    println!("the chain audits: {} contribution(s)", audited.steps());
    if let Some(beacon) = audited.beacon_sha256() {
        println!("the finalising step is the one beacon {} determines", short(beacon, "beacon")?);
    }
    println!("transcript {}", audited.transcript());

    // --- the bytes --------------------------------------------------------
    println!("\nverifying key");
    println!("  length     {} bytes", audited.verifying_key().len());
    println!("  IC points  {}", audited.ic_count());
    println!("  sha256     {}", audited.vk_sha256());
    if let Some(out) = vk_out {
        std::fs::write(&out, audited.verifying_key())?;
        println!("  written to {}", out.display());
    }

    println!();
    if audited.is_finished() {
        println!("This ceremony is finished: {} step(s), ending in its beacon.", audited.steps());
    } else {
        println!("NOT FINISHED. No beacon has closed this ceremony, so its delta is a product");
        println!("of participant scalars only -- sound if one of them was honest, but with");
        println!("nothing anchoring it to a value they could not all have known in advance.");
    }
    println!();
    println!("Still unchecked, by anything, ever:");
    println!("  * that any participant drew their scalar unpredictably and destroyed it;");
    println!("  * that the beacon was named before this ceremony opened.");
    println!("Both rest on what people published about themselves, not on these artifacts.");
    println!();
    println!("Before deploying, put this key through the acceptance gate -- which deploys a");
    println!("pool carrying exactly these bytes and requires it to accept a real transfer:");
    println!("  TOS_ROOT=<a checkout with a built func/fift> cargo run --release \\");
    println!("    --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \\");
    println!("    --example ceremony-gate -- {}", directory.path().display());
    println!();
    println!("Then, for the state hash and the address: the genesis generator re-runs this");
    println!("audit itself and takes the key from it, refusing an unfinished ceremony:");
    println!("  cargo run --release --manifest-path tools/shielded-pool-genesis/Cargo.toml \\");
    println!("    --bin genesis -- . out/manifest.json <profile commit> <profile blob> \\");
    println!("    --ceremony {}", directory.path().display());
    Ok(())
}
