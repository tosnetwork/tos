/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Prints what to fetch from a phase-1 ceremony, as JSON.
//!
//!     phase1-ranges <transcript> <exponent>
//!
//! The fetcher reads this rather than recomputing the offsets. Two copies of
//! that arithmetic would be two chances to get it wrong, and this is the copy
//! with the published file size behind it.

use std::process::ExitCode;

use shielded_pool_ceremony::layout;

fn run() -> shielded_pool_ceremony::Result<String> {
    let mut args = std::env::args().skip(1);
    let (Some(name), Some(exponent)) = (args.next(), args.next()) else {
        return Err(shielded_pool_ceremony::Error::Layout(format!(
            "usage: phase1-ranges <transcript> <exponent>; transcripts: {}",
            layout::ALL.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
        )));
    };
    let transcript = layout::by_name(&name)?;
    let exponent: u32 = exponent
        .parse()
        .map_err(|error| shielded_pool_ceremony::Error::Layout(format!("exponent: {error}")))?;

    let ranges = layout::slice_ranges(transcript, exponent)?;
    let entries: Vec<serde_json::Value> = ranges
        .iter()
        .map(|range| {
            serde_json::json!({
                "name": range.name,
                "offset": range.offset,
                "length": range.length,
                "points": range.points,
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "transcript": transcript.name,
        "url": transcript.url,
        "file_bytes": transcript.file_bytes,
        "power": transcript.power,
        "head_digest": transcript.head_digest,
        "published_checksums": transcript.published_checksums,
        "custody": transcript.custody,
        "ranges": entries,
    }))?)
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
