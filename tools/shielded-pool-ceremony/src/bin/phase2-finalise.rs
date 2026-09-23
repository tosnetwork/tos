/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Closes a phase-2 ceremony with a public random beacon.
//!
//! ```text
//! phase2-finalise <ceremony-directory> <beacon-file>
//! ```
//!
//! # What this adds, and what it does not
//!
//! **No secrecy.** The scalar is a hash of the bytes in `<beacon-file>` and
//! anybody can recompute it; a ceremony consisting only of this step is worth
//! nothing.
//!
//! **And it does not rescue a ceremony whose participants all colluded.** The
//! final `delta` is every contribution's scalar multiplied together with this
//! one, and this one is public -- a coalition holding the rest holds the
//! product. Security rests on one participant having destroyed their scalar.
//!
//! What it does add is that the finished parameters depend on a value nobody
//! could have predicted while contributing, so no participant could steer
//! `delta` towards something prepared in advance.
//!
//! That is a claim about *when* the beacon was fixed, and no program can check
//! it. **The beacon has to be named before the ceremony opens**: which source,
//! at which height or round, witnessed by whom. A beacon chosen after the
//! contributions are in is decoration, and this command cannot tell the
//! difference.
//!
//! The bytes are copied into the directory so the ceremony audits on its own.
//! An auditor still compares the digest printed below against what the beacon
//! actually published; the copy shows the record is self-consistent, not that
//! it used the beacon it promised.

use std::path::PathBuf;
use std::process::ExitCode;

use shielded_pool_ceremony::contribution::{
    finalise, verify_beacon_step, verify_chain, Transcript, MINIMUM_BEACON_BYTES,
};
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem};
use shielded_pool_ceremony::record::{
    digest_of, digest_of_transcript, key_digest, Directory, Entry, Step,
};
use shielded_pool_ceremony::{committed, Error, Result};

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
    let mut arguments = std::env::args_os().skip(1);
    let (Some(path), Some(beacon_path)) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: phase2-finalise <ceremony-directory> <beacon-file>");
        return Err(Error::Structure("a ceremony directory and a beacon file are needed".into()));
    };
    let directory = Directory::at(PathBuf::from(path));
    let beacon = std::fs::read(PathBuf::from(&beacon_path))?;
    if beacon.len() < MINIMUM_BEACON_BYTES {
        return Err(Error::Structure(format!(
            "the beacon output is {} bytes; {MINIMUM_BEACON_BYTES} is the minimum, because a \
             shorter one can be ground out in advance",
            beacon.len()
        )));
    }

    let mut record = directory.read_record()?;
    if let Some(position) = record.beacon_out_of_place() {
        return Err(Error::Structure(format!(
            "step {position} is the beacon and it is not the last one; this ceremony is already \
             broken and adding to it cannot repair it"
        )));
    }
    if record.is_finished() {
        return Err(Error::Structure(
            "this ceremony has already been finalised; finalising twice would replace the \
             beacon everyone contributed under"
                .into(),
        ));
    }
    if record.entries.is_empty() {
        return Err(Error::Structure(
            "no participant has contributed, so finalising would produce a key whose delta is a \
             hash of public bytes -- forgeable by anyone who can read the beacon"
                .into(),
        ));
    }
    let mut key = directory.read_key()?;
    let mut contributions = directory.read_contributions()?;

    // --- audit before closing --------------------------------------------
    let mut seed = [0u8; 32];
    OperatingSystem.fill(&mut seed)?;
    println!("rebuilding the starting key from the committed slice (a couple of minutes)");
    let (initial, provenance) = committed::starting_key(&committed::artifacts_directory(), seed)?;
    if provenance.slice_sha256 != record.phase1_slice_sha256
        || key_digest(&initial)? != record.starting_key_sha256
    {
        return Err(Error::Structure(
            "this checkout does not rebuild the key this ceremony was begun over".into(),
        ));
    }
    println!("auditing {} contribution(s)", contributions.len());
    verify_chain(&initial, &key, &contributions, &mut OperatingSystem)?;
    println!("the chain audits");

    let mut transcript = Transcript::begin(&initial)?;
    for contribution in &contributions {
        transcript = transcript.extend(contribution);
    }
    if digest_of_transcript(&transcript) != record.transcript {
        return Err(Error::Structure(
            "the transcript the contributions produce is not the one the record states".into(),
        ));
    }

    // --- close it ---------------------------------------------------------
    let previous_g1 = key.delta_g1;
    let previous_g2 = key.vk.delta_g2;
    let ending = finalise(&mut key, &transcript, &beacon)?;

    // Recomputed and compared, here as well as in the audit: this command is
    // the one place the beacon's bytes and the ceremony meet, and a step that
    // is not the one those bytes determine should never reach the directory.
    verify_beacon_step(previous_g1, previous_g2, &transcript, &beacon, &ending)?;
    transcript = transcript.extend(&ending);

    let index = contributions.len() + 1;
    let contribution_sha256 = digest_of(&ending.to_bytes());
    let beacon_sha256 = digest_of(&beacon);
    contributions.push(ending);

    let key_sha256 = directory.write_key(&key)?;
    directory.write_contributions(&contributions)?;
    directory.write_beacon(&beacon)?;
    record.entries.push(Entry {
        index,
        step: Step::Beacon { beacon_sha256: beacon_sha256.clone() },
        sha256: contribution_sha256,
        transcript_after: digest_of_transcript(&transcript),
    });
    record.key_sha256 = key_sha256;
    record.transcript = digest_of_transcript(&transcript);
    directory.write_record(&record)?;

    println!();
    println!("ceremony finalised after {} step(s).", record.entries.len());
    println!("  beacon         {beacon_sha256}");
    println!("  transcript     {}", record.transcript);
    println!();
    println!("Compare that beacon digest against what the source actually published. A");
    println!("ceremony is only worth its beacon if the beacon was named before it opened.");
    println!();
    println!("Next: phase2-verify {}", directory.path().display());
    Ok(())
}
