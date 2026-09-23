/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The phase-1 slice this repository ships, and the reference string it
//! becomes.
//!
//! Three steps sit between eighteen megabytes on disk and something a phase-2
//! ceremony can start from, and skipping any of them produces an artifact that
//! looks right:
//!
//! 1. **parse** -- the sections are the lengths the layout says, and every
//!    point is on the curve and in the prime-order subgroup;
//! 2. **verify** -- the pairing checks that say it is a powers-of-tau string
//!    and not merely a list of valid points. This is the expensive one and it
//!    is not optional: a slice that parses and does not verify would produce a
//!    key that proves and verifies against itself and means nothing;
//! 3. **transform** -- the monomial basis `tau^i` into the Lagrange basis
//!    `L_j(tau)` that a setup consumes, and the `h` query with it.
//!
//! [`reference_string`] is all three, in order, so no caller can do two of
//! them. It is what both the ceremony binaries and the end-to-end test use,
//! rather than each assembling the steps themselves.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::lagrange::{self, LagrangeSrs};
use crate::{slice, verify};

/// The exponent this circuit's QAP domain needs. Measured by [`crate::shape`]
/// and held to it by `degree.rs`; stated here because the slice's byte ranges
/// are located by it.
pub const EXPONENT: u32 = 15;

/// Where a fetched slice and its provenance record live, relative to the
/// repository root.
pub const ARTIFACTS: &str = "artifacts/phase1";

/// The slice on disk, with the record that says where it came from.
///
/// Looks for a record **with bytes beside it**. The records are committed and
/// a slice may not be, so the failure worth distinguishing is "nobody fetched
/// anything" from "you fetched the other ceremony's".
pub fn load_slice(directory: &Path) -> Result<(Vec<u8>, slice::Provenance)> {
    let how_to_fetch = "\n\nFetch one:\n  uv run python \
                        scripts/shielded-pool-phase1-slice.py --out artifacts/phase1\n  \
                        (add --transcript filecoin for the other ceremony)";

    let mut records: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|error| Error::Slice(format!("{}: {error}{how_to_fetch}", directory.display())))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect();
    records.sort();

    let Some(json) = records.iter().find(|json| json.with_extension("bin").exists()) else {
        let named: Vec<String> = records
            .iter()
            .filter_map(|path| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
            .collect();
        return Err(Error::Slice(format!(
            "{} holds records for [{}] but the bytes for none of them{how_to_fetch}",
            directory.display(),
            named.join(", ")
        )));
    };

    let record: slice::Provenance = serde_json::from_slice(&std::fs::read(json)?)?;
    let bytes = std::fs::read(json.with_extension("bin"))?;
    Ok((bytes, record))
}

/// Parse, verify and transform, in that order.
///
/// `batching_seed` is the randomness the structural checks batch with. It has
/// to be something the transcript's author could not have known, so a caller
/// draws it from [`crate::entropy`] rather than passing a constant -- a
/// batched pairing check against weights the adversary chose is not a check.
pub fn reference_string(
    bytes: &[u8],
    record: &slice::Provenance,
    batching_seed: [u8; 32],
) -> Result<LagrangeSrs> {
    let parsed = slice::parse(bytes, record, EXPONENT)?;
    verify::verify(&parsed, batching_seed)?;
    lagrange::transform(&parsed)
}

/// The repository root, from this crate's manifest.
///
/// Used by the binaries so they can be run from anywhere, and by tests. A
/// ceremony run from a checkout wants the slice this checkout committed, not
/// whatever happens to be in the working directory.
pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `<repository>/artifacts/phase1`.
pub fn artifacts_directory() -> PathBuf {
    repository_root().join(ARTIFACTS)
}

/// The circuit a ceremony is for, constructed exactly one way.
///
/// A setup reads the circuit's shape and never its witness, so `blank` is the
/// right constructor and the scenario behind it only supplies public-input
/// *shape*. But "two constructions that ought to agree" is precisely the kind
/// of thing that silently does not, and two keys over the same circuit built
/// differently would be two keys -- with two deployment addresses and no
/// obvious reason. So every caller comes here, and there is nothing to keep in
/// step.
pub fn the_circuit() -> Result<shielded_pool_circuit::circuit::ShieldedTransactionCircuit> {
    use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
    let (_pool, public, _witness) = shielded_pool_circuit::scenario::valid_transfer()
        .map_err(|error| Error::Structure(format!("building the circuit's shape: {error}")))?;
    Ok(ShieldedTransactionCircuit::blank(public))
}

/// The key a ceremony over this circuit starts from, rebuilt from the
/// committed slice.
///
/// Every binary does this rather than reading a starting key from the ceremony
/// directory, and the cost -- a couple of minutes -- is the point. A
/// participant who takes the coordinator's word for the starting key has
/// checked that their own contribution was applied to *something*; one who
/// rebuilds it has checked it was applied to the key this repository's slice
/// and circuit determine.
pub fn starting_key(
    directory: &Path,
    batching_seed: [u8; 32],
) -> Result<(ark_groth16::ProvingKey<ark_bls12_381::Bls12_381>, slice::Provenance)> {
    let (bytes, record) = load_slice(directory)?;
    let srs = reference_string(&bytes, &record, batching_seed)?;
    let key = crate::phase2::initial(&srs, the_circuit()?)?;
    Ok((key, record))
}
