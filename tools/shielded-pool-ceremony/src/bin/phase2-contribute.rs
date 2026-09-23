/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Adds one participant's contribution to a phase-2 ceremony.
//!
//! ```text
//! phase2-contribute <ceremony-directory> [--entropy-file <path>]
//! ```
//!
//! # It checks before it contributes
//!
//! The first thing this does, before drawing anything, is rebuild the starting
//! key from the committed slice and audit every contribution already in the
//! directory. A contribution added to a chain that does not audit is wasted:
//! the ceremony will be re-run and the participant's scalar -- which they have
//! by then destroyed -- cannot be re-used.
//!
//! That rebuild is why this takes a couple of minutes. Reading a starting key
//! out of the directory instead would take a second and would check that the
//! contribution was applied to *something*.
//!
//! # The secret
//!
//! Drawn from the operating system inside the library, used, and wiped. It is
//! never a variable in this file, never printed, never written to the
//! directory, and there is no flag that would change any of that -- so there
//! is no file to shred afterwards and no passphrase to remember.
//!
//! What that does **not** cover: the scalar was in this process's memory while
//! it ran, and a kernel may have paged that memory to disk. Defending against
//! somebody who can read a machine's memory or its swap is out of scope here
//! and is a property of the machine, not of this command. Running a
//! contribution on a host with encrypted swap, or none, is the participant's
//! part of that.
//!
//! `--entropy-file` mixes the contents of a file into the draw for a
//! participant who does not want to rely on the machine's generator alone. It
//! is stirred in, never substituted: the result is unpredictable if *either*
//! source was. The file is read, mixed and wiped from memory; delete it
//! afterwards if it was meant to be transient.

use std::path::PathBuf;
use std::process::ExitCode;

use shielded_pool_ceremony::contribution::{contribute, verify_chain, Transcript};
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem, Stirred};
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
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut path: Option<PathBuf> = None;
    let mut entropy_file: Option<PathBuf> = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--entropy-file" => {
                entropy_file = Some(PathBuf::from(
                    rest.next()
                        .ok_or_else(|| Error::Structure("--entropy-file needs a path".into()))?,
                ));
            }
            other if other.starts_with("--") => {
                return Err(Error::Structure(format!("unknown option {other}")));
            }
            other => path = Some(PathBuf::from(other)),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: phase2-contribute <ceremony-directory> [--entropy-file <path>]");
        return Err(Error::Structure("no ceremony directory given".into()));
    };

    let directory = Directory::at(&path);
    let mut record = directory.read_record()?;
    if let Some(position) = record.beacon_out_of_place() {
        return Err(Error::Structure(format!(
            "step {position} is the beacon and it is not the last one; this ceremony is already \
             broken and adding to it cannot repair it"
        )));
    }
    if record.is_finished() {
        return Err(Error::Structure(
            "this ceremony has already been finalised with its beacon; contributing after the \
             beacon would undo the one thing the beacon establishes"
                .into(),
        ));
    }
    let key = directory.read_key()?;
    let mut contributions = directory.read_contributions()?;
    if contributions.len() != record.entries.len() {
        return Err(Error::Structure(format!(
            "the record lists {} contributions and the file holds {}",
            record.entries.len(),
            contributions.len()
        )));
    }

    // --- check what is there, before adding to it -------------------------
    let mut seed = [0u8; 32];
    OperatingSystem.fill(&mut seed)?;
    println!("rebuilding the starting key from the committed slice (a couple of minutes)");
    let (initial, provenance) = committed::starting_key(&committed::artifacts_directory(), seed)?;

    if provenance.slice_sha256 != record.phase1_slice_sha256 {
        return Err(Error::Structure(format!(
            "this ceremony was begun over the {} slice {} and the one here is {}",
            record.phase1_transcript,
            &record.phase1_slice_sha256[..16],
            &provenance.slice_sha256[..16]
        )));
    }
    let rebuilt = key_digest(&initial)?;
    if rebuilt != record.starting_key_sha256 {
        return Err(Error::Structure(format!(
            "the starting key this checkout builds is {} and the ceremony says {}; this is not a \
             ceremony over this circuit and this slice",
            &rebuilt[..16],
            &record.starting_key_sha256[..16]
        )));
    }
    println!("starting key rebuilt and matches: {}", &rebuilt[..32]);

    if contributions.is_empty() {
        // Nothing has been contributed, so `verify_chain` has nothing to say
        // -- and without this, nothing at all ties `key.bin` to the key just
        // rebuilt. `read_key` only established that the file matches the
        // record's `key_sha256`, and both of those are written by whoever
        // prepared the directory: a record could carry the true starting
        // digest alongside a `key_sha256` for some other key entirely, and the
        // first participant would contribute to that instead.
        if record.key_sha256 != rebuilt {
            return Err(Error::Structure(format!(
                "this ceremony has no contributions, so its key must be the starting key -- and \
                 it is {} while the starting key is {}. Nothing explains the difference, so the \
                 directory was not produced by phase2-begin over this slice and circuit",
                &record.key_sha256[..16],
                &rebuilt[..16]
            )));
        }
        println!("no contributions yet; this will be the first, on the starting key itself");
    } else {
        println!("auditing {} contribution(s) already in the chain", contributions.len());
        verify_chain(&initial, &key, &contributions, &mut OperatingSystem)?;
        println!("the chain audits");
    }

    // --- contribute -------------------------------------------------------
    let mut transcript = Transcript::begin(&initial)?;
    for contribution in &contributions {
        transcript = transcript.extend(contribution);
    }
    if digest_of_transcript(&transcript) != record.transcript {
        return Err(Error::Structure(
            "the transcript the contributions produce is not the one the record states".into(),
        ));
    }

    let mut key = key;
    let contribution = match entropy_file {
        None => contribute(&mut key, &transcript, &mut OperatingSystem)?,
        Some(file) => {
            let mut material = std::fs::read(&file)?;
            println!("stirring in {} bytes from {}", material.len(), file.display());
            let mut source = Stirred::new(OperatingSystem, std::mem::take(&mut material))?;
            contribute(&mut key, &transcript, &mut source)?
            // `source` wipes the material when it drops.
        }
    };
    transcript = transcript.extend(&contribution);

    let index = contributions.len() + 1;
    let contribution_sha256 = digest_of(&contribution.to_bytes());
    contributions.push(contribution);

    // The key first: a directory whose record lists a contribution the key
    // does not carry is worse than one whose key is ahead of its record,
    // because the second is visibly incomplete and the first looks finished.
    let key_sha256 = directory.write_key(&key)?;
    directory.write_contributions(&contributions)?;
    record.entries.push(Entry {
        index,
        step: Step::Participant,
        sha256: contribution_sha256.clone(),
        transcript_after: digest_of_transcript(&transcript),
    });
    record.key_sha256 = key_sha256;
    record.transcript = digest_of_transcript(&transcript);
    directory.write_record(&record)?;

    println!();
    println!("contribution {index} added.");
    println!("  contribution   {contribution_sha256}");
    println!("  transcript     {}", record.transcript);
    println!();
    println!("Publish those two lines, signed, saying you drew a scalar and destroyed it.");
    println!("They name your position in a way nobody can move it afterwards.");
    println!();
    println!("Nothing was written to this machine to shred: the scalar existed only in this");
    println!("process's memory and was wiped. Swap, if this host has any, is yours to think");
    println!("about.");
    Ok(())
}
