/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Makes the frozen known-answer table includable from a test module.
//!
//! The table lives in the node tree, where it is a crate root and opens with
//! inner doc comments. Those cannot appear at an `include!` site, so the file
//! is copied with its inner doc comments turned into ordinary comments and
//! nothing else changed. No constant is rewritten: a copy that differed from
//! the committed table would defeat the whole point of testing against it.

use std::path::PathBuf;

const KAT_RELATIVE: &str = "../../tosctl/src/block/src/poseidon2_kat.rs";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let source = manifest_dir.join(KAT_RELATIVE);
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed=build.rs");

    let text = std::fs::read_to_string(&source)?;
    let mut rewritten = String::with_capacity(text.len());
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("//!") {
            rewritten.push_str("//");
            rewritten.push_str(rest);
        } else {
            rewritten.push_str(line);
        }
        rewritten.push('\n');
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(out_dir.join("poseidon2_kat_includable.rs"), rewritten)?;
    Ok(())
}
