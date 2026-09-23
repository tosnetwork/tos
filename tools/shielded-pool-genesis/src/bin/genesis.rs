/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Builds the genesis state and writes the frozen manifest.
//!
//! Usage: `genesis <repo root> <output manifest> [<source commit> <source blob>]`
//!          `[--verifying-key <file>]`
//!
//! The parameters are `development_parameters`, which lives in the library
//! because the on-chain fixture deploys the same state to a real node, and a
//! second copy of the constants would be a second deployment.
//!
//! `--verifying-key` takes the 1,248 bytes a phase-2 ceremony produced --
//! `phase2-verify --vk-out` writes them -- and builds the genesis state around
//! those instead of the development key. It is also how a candidate key's
//! deployment address is found *before* anyone commits to it, since the key is
//! part of the state and therefore part of the address.

use std::path::PathBuf;

use shielded_pool_genesis::manifest::{self, Provenance};
use shielded_pool_genesis::{build, development_parameters, parameters_with_verifying_key};

const USAGE: &str = "usage: genesis <repo root> <output> [commit blob] [--verifying-key <file>]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Vec<String> = Vec::new();
    let mut verifying_key: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--verifying-key" => {
                verifying_key = Some(PathBuf::from(args.next().ok_or(USAGE)?));
            }
            other if other.starts_with("--") => {
                return Err(format!("{USAGE}\nunknown option {other}").into())
            }
            other => positional.push(other.to_string()),
        }
    }
    let mut positional = positional.into_iter();
    let root = PathBuf::from(positional.next().ok_or(USAGE)?);
    let output = PathBuf::from(positional.next().ok_or(USAGE)?);
    let source_commit = positional.next().unwrap_or_else(|| "unknown".to_string());
    let source_blob = positional.next().unwrap_or_else(|| "unknown".to_string());

    let parameters = match &verifying_key {
        None => development_parameters(&root)?,
        Some(path) => {
            let bytes = std::fs::read(path)?;
            eprintln!(
                "verifying key from {} ({} bytes, sha256 {})",
                path.display(),
                bytes.len(),
                hex(&sha256(&bytes))
            );
            parameters_with_verifying_key(&root, bytes)?
        }
    };
    let genesis = build(parameters)?;

    let rendered = manifest::render(&genesis, &Provenance { source_commit, source_blob }, None)?;
    std::fs::write(&output, &rendered)?;
    eprintln!("state hash {}", hex(&manifest::cell_hash(&genesis.state)));
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
