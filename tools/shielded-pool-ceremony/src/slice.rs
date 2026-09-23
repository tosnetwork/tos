/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The fetched slice on disk, and the record of where it came from.
//!
//! The slice file is the five ranges end to end with nothing added: no
//! header, no framing, no re-encoding. That is deliberate. Anyone holding the
//! transcript can reproduce the file with five `dd` invocations and compare
//! hashes, which they could not do if this tool had invented a container.
//!
//! The provenance record beside it is what makes the bytes checkable without
//! the transcript: **which ceremony** it came from, the URL, the file's own
//! size, the ranges by offset and length, the SHA-256 of each range, and
//! whatever the host publishes to identify the file. The ceremony's name comes
//! first because it decides what every other field means, and because a
//! deployment's custody argument is a statement about that one word.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::layout;
use crate::points;
use crate::verify::Phase1Slice;

/// One fetched range, as recorded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchedRange {
    pub name: String,
    pub offset: u64,
    pub length: u64,
    pub points: u64,
    pub sha256: String,
}

/// Everything needed to decide whether a slice file is the right bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// Which ceremony this came from -- `zcash` or `filecoin`. The first
    /// field, because it decides what every other field means, and because a
    /// deployment's custody argument is a statement about this word.
    pub transcript: String,
    /// Where the transcript was read from.
    pub source_url: String,
    /// The size the transcript had when read. If this is not the size the
    /// named transcript's layout describes, the offsets below mean nothing.
    pub source_bytes: u64,
    /// The exponent the ceremony was run to.
    pub source_power: u32,
    /// The exponent this slice was taken at: the circuit's domain.
    pub slice_power: u32,
    /// For a transcript whose file opens with one: the 64-byte BLAKE2b digest
    /// chaining it to the previous entry. Filecoin's challenge file has one;
    /// Zcash's transcript does not, and is identified by the archive's
    /// published checksums instead.
    ///
    /// Not verified here either way -- verifying a digest chain means
    /// replaying the whole transcript -- but recorded so a deployment can be
    /// held against the ceremony's published attestations.
    pub transcript_hash: Option<String>,
    /// What the ceremony's host says the file is, copied from the transcript
    /// descriptor so the record is self-contained.
    pub published_checksums: String,
    /// What a deployment carrying this slice is inheriting, in one line.
    pub custody: String,
    pub ranges: Vec<FetchedRange>,
    /// The SHA-256 of the concatenated slice file.
    pub slice_sha256: String,
}

impl Provenance {
    /// The transcript this record names, refused if it is not one we describe.
    pub fn transcript(&self) -> Result<&'static layout::Transcript> {
        layout::by_name(&self.transcript).map_err(|error| Error::Slice(error.to_string()))
    }

    /// Checks the record describes the layout this circuit needs, before any
    /// of its bytes are believed.
    pub fn check_against_layout(&self, slice_power: u32) -> Result<()> {
        let transcript = self.transcript()?;
        if self.source_url != transcript.url {
            return Err(Error::Slice(format!(
                "the record says it came from {} and {} is published at {}",
                self.source_url, transcript.name, transcript.url
            )));
        }
        if self.source_bytes != transcript.file_bytes {
            return Err(Error::Slice(format!(
                "the transcript was {} bytes when this slice was taken and {}'s layout describes \
                 a file of {}; every offset in this record is for a different file",
                self.source_bytes, transcript.name, transcript.file_bytes
            )));
        }
        if self.source_power != transcript.power {
            return Err(Error::Slice(format!(
                "the record says the ceremony was run to 2^{} and {} was run to 2^{}",
                self.source_power, transcript.name, transcript.power
            )));
        }
        // A transcript with no digest at the head of its file cannot have
        // recorded one, and a transcript with one must have.
        if transcript.head_digest != self.transcript_hash.is_some() {
            return Err(Error::Slice(format!(
                "{} {} a digest at the head of its file and this record {} one",
                transcript.name,
                if transcript.head_digest { "carries" } else { "carries no" },
                if self.transcript_hash.is_some() { "has" } else { "has not" }
            )));
        }
        if self.slice_power != slice_power {
            return Err(Error::Slice(format!(
                "this slice was taken at 2^{} and the circuit needs 2^{slice_power}",
                self.slice_power
            )));
        }
        let expected = layout::slice_ranges(transcript, self.slice_power)?;
        if expected.len() != self.ranges.len() {
            return Err(Error::Slice(format!(
                "the record has {} ranges and the layout has {}",
                self.ranges.len(),
                expected.len()
            )));
        }
        for (want, got) in expected.iter().zip(&self.ranges) {
            if want.name != got.name
                || want.offset != got.offset
                || want.length != got.length
                || want.points != got.points
            {
                return Err(Error::Slice(format!(
                    "range {}: the record says offset {} length {} ({} points) and the layout \
                     says offset {} length {} ({} points)",
                    got.name,
                    got.offset,
                    got.length,
                    got.points,
                    want.offset,
                    want.length,
                    want.points
                )));
            }
        }
        Ok(())
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Parses a slice file against its provenance record.
///
/// Every check that can be made without the transcript is made here, in the
/// order that fails soonest: the record against the layout, the file's length
/// against the record, each range's hash against the record, and only then the
/// bytes into points.
pub fn parse(bytes: &[u8], provenance: &Provenance, slice_power: u32) -> Result<Phase1Slice> {
    provenance.check_against_layout(slice_power)?;

    let expected_length: u64 = provenance.ranges.iter().map(|range| range.length).sum();
    if bytes.len() as u64 != expected_length {
        return Err(Error::Slice(format!(
            "the slice file is {} bytes and its record describes {expected_length}",
            bytes.len()
        )));
    }
    if hex_sha256(bytes) != provenance.slice_sha256 {
        return Err(Error::Slice("the slice file does not hash to what its record says".into()));
    }

    let mut cursor = 0usize;
    let mut sections: Vec<&[u8]> = Vec::with_capacity(provenance.ranges.len());
    for range in &provenance.ranges {
        let end = cursor + range.length as usize;
        let section = &bytes[cursor..end];
        if hex_sha256(section) != range.sha256 {
            return Err(Error::Slice(format!(
                "the {} section does not hash to what its record says",
                range.name
            )));
        }
        sections.push(section);
        cursor = end;
    }

    let degree = 1usize << slice_power;
    let tau_g1 = points::g1_section(sections[0], 2 * degree - 1)?;
    let tau_g2 = points::g2_section(sections[1], degree)?;
    let alpha_tau_g1 = points::g1_section(sections[2], degree)?;
    let beta_tau_g1 = points::g1_section(sections[3], degree)?;
    let beta_g2 = points::g2_from_uncompressed(sections[4])?;

    Ok(Phase1Slice { tau_g1, tau_g2, alpha_tau_g1, beta_tau_g1, beta_g2 })
}

/// Builds the provenance record for bytes already in hand. Used by the
/// fetcher's self-check and by the tests, which construct slices without a
/// transcript.
pub fn describe(
    bytes: &[u8],
    transcript: &layout::Transcript,
    transcript_hash: Option<String>,
    slice_power: u32,
) -> Result<Provenance> {
    let ranges = layout::slice_ranges(transcript, slice_power)?;
    let mut cursor = 0usize;
    let mut fetched = Vec::with_capacity(ranges.len());
    for range in &ranges {
        let end = cursor + range.length as usize;
        if end > bytes.len() {
            return Err(Error::Slice(format!(
                "the bytes run out inside the {} section",
                range.name
            )));
        }
        fetched.push(FetchedRange {
            name: range.name.to_string(),
            offset: range.offset,
            length: range.length,
            points: range.points,
            sha256: hex_sha256(&bytes[cursor..end]),
        });
        cursor = end;
    }
    Ok(Provenance {
        transcript: transcript.name.to_string(),
        source_url: transcript.url.to_string(),
        source_bytes: transcript.file_bytes,
        source_power: transcript.power,
        slice_power,
        transcript_hash,
        published_checksums: transcript.published_checksums.to_string(),
        custody: transcript.custody.to_string(),
        ranges: fetched,
        slice_sha256: hex_sha256(bytes),
    })
}

/// The five sections of a parsed slice back as the bytes they came from, in
/// order. Used to build a slice file from a constructed `Phase1Slice`.
pub fn to_bytes(slice: &Phase1Slice) -> Vec<u8> {
    let mut out = Vec::new();
    for point in &slice.tau_g1 {
        out.extend_from_slice(&points::g1_to_uncompressed(point));
    }
    for point in &slice.tau_g2 {
        out.extend_from_slice(&points::g2_to_uncompressed(point));
    }
    for point in &slice.alpha_tau_g1 {
        out.extend_from_slice(&points::g1_to_uncompressed(point));
    }
    for point in &slice.beta_tau_g1 {
        out.extend_from_slice(&points::g1_to_uncompressed(point));
    }
    out.extend_from_slice(&points::g2_to_uncompressed(&slice.beta_g2));
    out
}
