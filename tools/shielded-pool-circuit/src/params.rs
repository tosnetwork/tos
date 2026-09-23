/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The frozen Poseidon2 t=8 parameters, read from the committed manifest.
//!
//! Profile section 1.2 pins the parameters to one upstream commit and forbids
//! copying constants from anywhere else. This crate therefore keeps no table of
//! its own: it parses `crypto/poseidon2/manifest.bin`, the same byte stream the
//! C++ and Rust node implementations rebuild and digest. The digest below is
//! the one recorded in `crypto/poseidon2/PROVENANCE.md`; a manifest that does
//! not hash to it is refused before a single constant is used.
//!
//! The manifest alone is not sufficient evidence. It fixes the constants, not
//! the round structure, and the internal matrix it carries is never read by the
//! permutation, which uses only the diagonal. The known-answer vectors are what
//! stands behind the structure, and they are checked separately.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::field::{fr_from_be, FieldBytes, Fr, MODULUS_BE};

/// The manifest byte stream as committed to the tree.
const MANIFEST_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../crypto/poseidon2/manifest.bin"));

/// SHA-256 of the manifest, recorded in `crypto/poseidon2/PROVENANCE.md`.
pub const MANIFEST_SHA256_HEX: &str =
    "57ed3c8ac13652a1bdeced6b82a53f20db32d4b02338354178ec160a68e6804c";

/// The tag the manifest opens with, trailing NUL included.
const MANIFEST_TAG: &[u8] = b"TOS-POSEIDON2-BLS381-T8-v1\0";

/// Profile section 1.2 freezes the instance shape; anything else is refused.
pub const STATE_WIDTH: usize = 8;
pub const SBOX_ALPHA: u8 = 5;
pub const ROUNDS_F: usize = 8;
pub const ROUNDS_P: usize = 57;
pub const ROUNDS_TOTAL: usize = ROUNDS_F + ROUNDS_P;
pub const ROUNDS_F_BEGINNING: usize = ROUNDS_F / 2;

/// The parsed parameter set.
pub struct Poseidon2Params {
    /// `MAT_DIAG8_M_1`: the only part of the internal matrix the permutation
    /// reads.
    pub diag: [Fr; STATE_WIDTH],
    /// `MAT_INTERNAL8` as carried by the manifest. Kept so that the digest
    /// covers it, deliberately never used by the permutation.
    pub internal: [[Fr; STATE_WIDTH]; STATE_WIDTH],
    /// `RC8`, one row per round.
    pub round_constants: [[Fr; STATE_WIDTH]; ROUNDS_TOTAL],
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| Error::Manifest("length overflow".to_string()))?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| Error::Manifest(format!("truncated at offset {}", self.cursor)))?;
        self.cursor = end;
        Ok(slice)
    }

    fn take_element(&mut self) -> Result<Fr> {
        let raw = self.take(32)?;
        let mut value: FieldBytes = [0u8; 32];
        value.copy_from_slice(raw);
        fr_from_be(&value)
    }
}

fn parse(bytes: &[u8]) -> Result<Poseidon2Params> {
    let digest = hex::encode(Sha256::digest(bytes));
    if digest != MANIFEST_SHA256_HEX {
        return Err(Error::Manifest(format!(
            "digest {digest} does not match the frozen {MANIFEST_SHA256_HEX}"
        )));
    }

    let mut reader = Reader { bytes, cursor: 0 };

    if reader.take(MANIFEST_TAG.len())? != MANIFEST_TAG {
        return Err(Error::Manifest("wrong tag".to_string()));
    }
    if reader.take(32)? != MODULUS_BE {
        return Err(Error::Manifest(
            "manifest modulus is not the BLS12-381 scalar modulus".to_string(),
        ));
    }
    let header = reader.take(4)?;
    let declared = (header[0], header[1], header[2], header[3]);
    let expected = (STATE_WIDTH as u8, SBOX_ALPHA, ROUNDS_F as u8, ROUNDS_P as u8);
    if declared != expected {
        return Err(Error::Manifest(format!(
            "instance {declared:?} is not the frozen (t, alpha, RF, RP) = {expected:?}"
        )));
    }

    let mut diag = [Fr::from(0u64); STATE_WIDTH];
    for slot in diag.iter_mut() {
        *slot = reader.take_element()?;
    }
    let mut internal = [[Fr::from(0u64); STATE_WIDTH]; STATE_WIDTH];
    for row in internal.iter_mut() {
        for slot in row.iter_mut() {
            *slot = reader.take_element()?;
        }
    }
    let mut round_constants = [[Fr::from(0u64); STATE_WIDTH]; ROUNDS_TOTAL];
    for row in round_constants.iter_mut() {
        for slot in row.iter_mut() {
            *slot = reader.take_element()?;
        }
    }

    if reader.cursor != bytes.len() {
        return Err(Error::Manifest(format!(
            "{} trailing bytes after the constant tables",
            bytes.len().saturating_sub(reader.cursor)
        )));
    }

    Ok(Poseidon2Params { diag, internal, round_constants })
}

/// The frozen parameters, parsed once.
///
/// # Panics
///
/// Only if the committed manifest itself is unreadable, which is a build-tree
/// defect rather than a run-time condition. [`try_params`] returns the error.
pub fn params() -> &'static Poseidon2Params {
    static PARAMS: OnceLock<Poseidon2Params> = OnceLock::new();
    match PARAMS.get() {
        Some(existing) => existing,
        None => {
            let parsed = match parse(MANIFEST_BYTES) {
                Ok(parsed) => parsed,
                Err(error) => unreachable_manifest(&error),
            };
            let _ = PARAMS.set(parsed);
            match PARAMS.get() {
                Some(existing) => existing,
                None => unreachable_manifest(&Error::Manifest(
                    "parameters vanished after initialisation".to_string(),
                )),
            }
        }
    }
}

/// The fallible entry point, used by the tests that check the manifest itself.
pub fn try_params() -> Result<Poseidon2Params> {
    parse(MANIFEST_BYTES)
}

/// The committed manifest bytes, for callers that want to re-digest them.
pub fn manifest_bytes() -> &'static [u8] {
    MANIFEST_BYTES
}

fn unreachable_manifest(error: &Error) -> ! {
    // A corrupt committed manifest cannot be worked around: every value this
    // crate produces would be wrong. Abort rather than continue.
    eprintln!("frozen Poseidon2 manifest is unusable: {error}");
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_and_has_the_frozen_digest() {
        let parsed = match try_params() {
            Ok(parsed) => parsed,
            Err(error) => panic!("frozen manifest rejected: {error}"),
        };
        assert_eq!(parsed.round_constants.len(), 65);
        assert_eq!(hex::encode(Sha256::digest(MANIFEST_BYTES)), MANIFEST_SHA256_HEX);
    }

    #[test]
    fn a_flipped_manifest_byte_is_refused() {
        let mut mutated = MANIFEST_BYTES.to_vec();
        let last = mutated.len().saturating_sub(1);
        mutated[last] ^= 0x01;
        assert!(parse(&mutated).is_err());
    }

    #[test]
    fn a_manifest_declaring_fewer_partial_rounds_is_refused() {
        let mut mutated = MANIFEST_BYTES.to_vec();
        // Offset of RP inside the header: tag, modulus, then t, alpha, RF, RP.
        let rp_offset = MANIFEST_TAG.len() + 32 + 3;
        mutated[rp_offset] = 56;
        assert!(parse(&mutated).is_err());
    }
}
