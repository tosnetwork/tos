/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Writes the section 4 / section 5 fixture the FunC cross-check consumes.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let destination = match args.next() {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("usage: gadget-fixture <output.json>");
            std::process::exit(2);
        }
    };
    let fixture = shielded_pool_circuit::fixture::build()?;
    let text = serde_json::to_string_pretty(&fixture)?;
    std::fs::write(&destination, format!("{text}\n"))?;
    println!(
        "wrote {} note cases, {} node cases and {} append runs to {}",
        fixture.notes.len(),
        fixture.commit_nodes.len(),
        fixture.appends.len(),
        destination.display()
    );
    Ok(())
}
