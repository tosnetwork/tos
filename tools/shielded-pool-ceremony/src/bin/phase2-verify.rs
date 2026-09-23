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

use shielded_pool_ceremony::contribution::{verify_beacon_step, verify_chain, Transcript};
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem};
use shielded_pool_ceremony::record::{
    checked_digest, digest_of, key_digest, short, Directory, Step,
};
use shielded_pool_ceremony::{committed, shape, Error, Result};
use shielded_pool_circuit::groth16;

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
    let record = directory.read_record()?;
    let key = directory.read_key()?;
    let contributions = directory.read_contributions()?;
    if contributions.len() != record.entries.len() {
        return Err(Error::Structure(format!(
            "the record lists {} steps and the file holds {} contributions",
            record.entries.len(),
            contributions.len()
        )));
    }
    if contributions.is_empty() {
        return Err(Error::Structure(
            "this ceremony has no contributions; its delta is one and known to everyone".into(),
        ));
    }
    if let Some(position) = record.beacon_out_of_place() {
        return Err(Error::Structure(format!(
            "step {position} is the beacon and it is not the last one. Whoever contributed after \
             it already knew the value the beacon was there to supply, so the final delta \
             depends on nothing unpredictable. This ceremony has to be run again, not finished"
        )));
    }

    // Every digest in the record is held to being a digest before any of the
    // messages below index into it.
    for (field, value) in [
        ("phase1_slice_sha256", &record.phase1_slice_sha256),
        ("starting_key_sha256", &record.starting_key_sha256),
        ("key_sha256", &record.key_sha256),
        ("transcript", &record.transcript),
    ] {
        checked_digest(value, field)?;
    }
    for entry in &record.entries {
        checked_digest(&entry.sha256, "an entry's sha256")?;
        checked_digest(&entry.transcript_after, "an entry's transcript_after")?;
        if let Step::Beacon { beacon_sha256 } = &entry.step {
            checked_digest(beacon_sha256, "a beacon's sha256")?;
        }
    }

    println!("ceremony   {}", directory.path().display());
    println!("steps      {}", record.entries.len());

    // --- the starting key, rebuilt not read -------------------------------
    let mut seed = [0u8; 32];
    OperatingSystem.fill(&mut seed)?;
    println!("\nrebuilding the starting key from the committed slice (a couple of minutes)");
    let (initial, provenance) = committed::starting_key(&committed::artifacts_directory(), seed)?;
    if provenance.slice_sha256 != record.phase1_slice_sha256 {
        return Err(Error::Structure(format!(
            "this checkout holds the {} slice {} and the ceremony was begun over {}",
            provenance.transcript,
            &provenance.slice_sha256[..16],
            &record.phase1_slice_sha256[..16]
        )));
    }
    let rebuilt = key_digest(&initial)?;
    if rebuilt != record.starting_key_sha256 {
        return Err(Error::Structure(format!(
            "the starting key this checkout builds is {} and the record says {}",
            short(&rebuilt, "the rebuilt key")?,
            short(&record.starting_key_sha256, "starting_key_sha256")?
        )));
    }
    println!("starting key matches: {rebuilt}");

    // The record's descriptive fields, held against what was reconstructed
    // rather than printed as facts.
    //
    // The digests above already bind the real slice and the real circuit, so
    // a record that lies here cannot substitute a different circuit -- but it
    // can put a false ceremony name and a false constraint count in front of
    // whoever reads the audit, and an audit that prints unchecked strings in
    // its own voice is the wrong place to learn that.
    let measured = shape(committed::the_circuit()?)?;
    if record.phase1_transcript != provenance.transcript {
        return Err(Error::Structure(format!(
            "the record says this ceremony inherits {:?} and the slice it was begun over is \
             from {:?}",
            record.phase1_transcript, provenance.transcript
        )));
    }
    if record.constraints != measured.constraints
        || record.instance_variables != measured.instance_variables
    {
        return Err(Error::Structure(format!(
            "the record says {} constraints and {} instance variables; this circuit has {} and {}",
            record.constraints,
            record.instance_variables,
            measured.constraints,
            measured.instance_variables
        )));
    }
    println!(
        "phase 1    {} ({})",
        record.phase1_transcript,
        short(&record.phase1_slice_sha256, "phase1_slice_sha256")?
    );
    println!(
        "circuit    {} constraints, {} instance variables",
        record.constraints, record.instance_variables
    );

    // --- the chain --------------------------------------------------------
    verify_chain(&initial, &key, &contributions, &mut OperatingSystem)?;
    println!("the chain audits: {} contribution(s)", contributions.len());

    // --- the record agrees with the contributions -------------------------
    let mut transcript = Transcript::begin(&initial)?;
    for (position, (entry, contribution)) in record.entries.iter().zip(&contributions).enumerate() {
        if entry.index != position + 1 {
            return Err(Error::Structure(format!(
                "record entry {} is numbered {}",
                position + 1,
                entry.index
            )));
        }
        if entry.sha256 != digest_of(&contribution.to_bytes()) {
            return Err(Error::Structure(format!(
                "step {}'s digest does not match the contribution beside it",
                entry.index
            )));
        }

        // The beacon step, recomputed from the published bytes and the
        // previous step's published delta. No intermediate key is involved --
        // a ceremony keeps none, so an audit that needed one would be an audit
        // nobody could repeat.
        if let Step::Beacon { beacon_sha256 } = &entry.step {
            let beacon = directory.read_beacon()?;
            let actual = digest_of(&beacon);
            if &actual != beacon_sha256 {
                return Err(Error::Structure(format!(
                    "the stored beacon hashes to {} and the record says {beacon_sha256}",
                    &actual[..16]
                )));
            }
            let (previous_g1, previous_g2) = match position.checked_sub(1) {
                Some(earlier) => (contributions[earlier].delta_g1, contributions[earlier].delta_g2),
                None => (initial.delta_g1, initial.vk.delta_g2),
            };
            verify_beacon_step(previous_g1, previous_g2, &transcript, &beacon, contribution)?;
            println!("the finalising step is the one beacon {} determines", &actual[..16]);
        }

        transcript = transcript.extend(contribution);
        if shielded_pool_ceremony::record::digest_of_transcript(&transcript)
            != entry.transcript_after
        {
            return Err(Error::Structure(format!(
                "step {}'s transcript is not the one the record states, so a participant's \
                 published position does not match this record",
                entry.index
            )));
        }
    }

    // The summary the record publishes has to be the transcript the chain
    // actually produced.
    //
    // Every entry's `transcript_after` was checked in the loop above, and the
    // writing commands check this field too -- but the final audit did not,
    // so a record could carry a summary digest belonging to nothing and still
    // be reported finished. The summary is what a reader quotes.
    let ending = shielded_pool_ceremony::record::digest_of_transcript(&transcript);
    if ending != record.transcript {
        return Err(Error::Structure(format!(
            "the chain ends at transcript {} and the record summarises it as {}",
            short(&ending, "the computed transcript")?,
            short(&record.transcript, "the record's transcript")?
        )));
    }

    // --- the bytes --------------------------------------------------------
    let encoded = groth16::canonical_verifying_key(&key.vk)
        .map_err(|error| Error::Structure(format!("encoding the verifying key: {error}")))?;
    println!("\nverifying key");
    println!("  length     {} bytes", encoded.bytes.len());
    println!("  IC points  {}", encoded.ic_count);
    println!("  sha256     {}", digest_of(&encoded.bytes));
    if let Some(out) = vk_out {
        std::fs::write(&out, &encoded.bytes)?;
        println!("  written to {}", out.display());
    }

    println!();
    if record.is_finished() {
        println!(
            "This ceremony is finished: {} step(s), ending in its beacon.",
            record.entries.len()
        );
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
    println!("Then, for the state hash and the address these bytes imply:");
    println!("  cargo run --manifest-path tools/shielded-pool-genesis/Cargo.toml \\");
    println!("    --bin genesis -- . out/manifest.json --verifying-key <the file above>");
    Ok(())
}
