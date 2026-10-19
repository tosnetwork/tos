/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Builds the genesis state and writes the frozen manifest.
//!
//! ```text
//! genesis <repo root> <output manifest> <source commit> <source blob>
//!         --ceremony <ceremony directory>
//!         [--verifying-key <file>] [--ceremony-transcript <digest>]
//! genesis <repo root> <output manifest> [<source commit> <source blob>] --development
//! ```
//!
//! A pool's genesis carries its verifying key for good, so which key it gets
//! is never a default, and never a file taken on its word. `--ceremony` names
//! a phase-2 ceremony directory: the generator rebuilds the starting key from
//! the committed slice, runs the same audit `phase2-verify` runs, refuses a
//! ceremony no beacon has closed, and takes the key out of that audit.
//! `--verifying-key` and `--ceremony-transcript` are optional cross-checks --
//! the bytes `phase2-verify --vk-out` wrote and the transcript digest that was
//! announced -- and each must match what the audit found. The profile's
//! source commit and blob are required as git object ids. Before anything is
//! written the rendered manifest is put through `manifest::require_production`.
//!
//! The development key -- fixed seed, toxic waste in the source -- is only
//! used with `--development`, and the manifest then says so, which
//! `manifest::require_production` refuses.
//!
//! Building around a candidate ceremony is also how its deployment address is
//! found before anyone commits to it, since the key is part of the state and
//! therefore part of the address.

use std::path::PathBuf;

use shielded_pool_genesis::{
    audit, manifest, plan, CeremonyDirectory, KeyClass, Request, StartingKey,
};

const USAGE: &str = "usage: genesis <repo root> <output> <commit> <blob> --ceremony <directory> \
                     [--verifying-key <file>] [--ceremony-transcript <digest>]\n   or: genesis \
                     <repo root> <output> [commit blob] --development";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Vec<String> = Vec::new();
    let mut request = Request::default();
    let mut ceremony: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--ceremony" => ceremony = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            "--verifying-key" => {
                let path = PathBuf::from(args.next().ok_or(USAGE)?);
                request.verifying_key = Some(std::fs::read(&path)?);
            }
            "--ceremony-transcript" => {
                request.ceremony_transcript = Some(args.next().ok_or(USAGE)?)
            }
            "--development" => request.development = true,
            other if other.starts_with("--") => {
                return Err(format!("{USAGE}\nunknown option {other}").into())
            }
            other => positional.push(other.to_string()),
        }
    }
    let mut positional = positional.into_iter();
    let root = PathBuf::from(positional.next().ok_or(USAGE)?);
    let output = PathBuf::from(positional.next().ok_or(USAGE)?);
    request.source_commit = positional.next();
    request.source_blob = positional.next();
    if positional.next().is_some() {
        return Err(USAGE.into());
    }

    if let Some(path) = ceremony {
        if request.development {
            return Err("a development genesis takes no verifying key or ceremony".into());
        }
        let directory = CeremonyDirectory::at(&path);
        shielded_pool_genesis::preflight(&directory)?;
        eprintln!("auditing the ceremony in {}", path.display());
        eprintln!("rebuilding the starting key from the committed slice (a couple of minutes)");
        let start = StartingKey::rebuild()?;
        let audited = audit(&directory, &start)?;
        eprintln!(
            "ceremony audits: {} step(s), transcript {}, verifying key sha256 {}",
            audited.steps(),
            audited.transcript(),
            audited.vk_sha256()
        );
        request.ceremony = Some(audited);
    }

    let planned = plan(&root, request)?;
    let genesis = planned.build()?;
    let rendered = manifest::render(&genesis, planned.provenance(), planned.key(), None)?;
    if let KeyClass::Ceremony(_) = planned.key() {
        manifest::require_production(&root, &rendered, &planned, None)?;
    }
    std::fs::write(&output, &rendered)?;
    eprintln!("state hash {}", hex(&manifest::cell_hash(&genesis.state)));
    match planned.key() {
        KeyClass::Development => eprintln!("key class development"),
        KeyClass::Ceremony(ceremony) => {
            eprintln!("key class ceremony, transcript {}", ceremony.transcript())
        }
    }
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
