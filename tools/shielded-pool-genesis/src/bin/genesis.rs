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
//!         --verifying-key <file> --ceremony-transcript <digest>
//! genesis <repo root> <output manifest> [<source commit> <source blob>] --development
//! ```
//!
//! A pool's genesis carries its verifying key for good, so which key it gets
//! is never a default. `--verifying-key` takes the 1,248 bytes `phase2-verify
//! --vk-out` wrote, and `--ceremony-transcript` the transcript digest that
//! audit printed; the profile's source commit and blob are required too. The
//! development key -- fixed seed, toxic waste in the source -- is only used
//! with `--development`, and the manifest then says so, which
//! `manifest::require_production` refuses.
//!
//! Building around a candidate key is also how its deployment address is
//! found before anyone commits to it, since the key is part of the state and
//! therefore part of the address.

use std::path::PathBuf;

use shielded_pool_genesis::{build, manifest, plan, Request};

const USAGE: &str = "usage: genesis <repo root> <output> <commit> <blob> --verifying-key <file> \
                     --ceremony-transcript <digest>\n   or: genesis <repo root> <output> [commit blob] \
                     --development";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Vec<String> = Vec::new();
    let mut request = Request::default();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--verifying-key" => {
                let path = PathBuf::from(args.next().ok_or(USAGE)?);
                let bytes = std::fs::read(&path)?;
                eprintln!(
                    "verifying key from {} ({} bytes, sha256 {})",
                    path.display(),
                    bytes.len(),
                    hex(&shielded_pool_genesis::sha256(&bytes))
                );
                request.verifying_key = Some(bytes);
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

    let (parameters, key, provenance) = plan(&root, request)?;
    let genesis = build(parameters)?;
    let rendered = manifest::render(&genesis, &provenance, &key, None)?;
    std::fs::write(&output, &rendered)?;
    eprintln!("state hash {}", hex(&manifest::cell_hash(&genesis.state)));
    eprintln!("key {key:?}");
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
