/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Genesis zero-state generation helper.
//!
//! Runs the `create-state` tool against a Fift zero-state template (e.g.
//! `crypto/smartcont/gen-zerostate.fif`) and parses the resulting
//! masterchain state, so genesis-level invariants (like total supply) can be
//! asserted in an automated test instead of only by manual review.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use chain_block::{read_single_root_boc, CurrencyCollection, Deserializable, ShardStateUnsplit};

use crate::error::{SandboxError, SandboxResult};

/// Locate the TOS repository root by checking common paths.
fn find_tos_root() -> Option<PathBuf> {
    if let Ok(root) = env::var("TOS_ROOT") {
        let p = PathBuf::from(root);
        if p.join("build/crypto/create-state").exists() {
            return Some(p);
        }
    }
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(&home).join("tos");
        if p.join("build/crypto/create-state").exists() {
            return Some(p);
        }
    }
    for candidate in &[".", "..", "../..", "../../..", "../../../.."] {
        let p = PathBuf::from(candidate);
        if p.join("build/crypto/create-state").exists() {
            return Some(p);
        }
    }
    None
}

/// Run `create-state` against a zero-state Fift template and return the
/// resulting masterchain state's total balance (the sum of every account
/// registered at genesis, plus any protocol-reserved balances).
///
/// # Environment
/// * `TOS_ROOT` -- if set, used to locate `build/crypto/create-state` and
///   `crypto/fift/lib` / `crypto/smartcont`. Falls back to `~/tos` or
///   relative paths.
/// * `CREATE_STATE_PATH` -- override the path to the `create-state` binary.
pub fn generate_zerostate_total_balance(
    fif_path: impl AsRef<Path>,
) -> SandboxResult<CurrencyCollection> {
    let tos_root = find_tos_root();

    let create_state_bin = env::var("CREATE_STATE_PATH")
        .map(PathBuf::from)
        .ok()
        .or_else(|| tos_root.as_ref().map(|r| r.join("build/crypto/create-state")))
        .ok_or_else(|| {
            SandboxError::ConfigError(
                "Cannot find create-state tool. Set TOS_ROOT or CREATE_STATE_PATH.".into(),
            )
        })?;

    let fift_lib = tos_root.as_ref().map(|r| r.join("crypto/fift/lib")).ok_or_else(|| {
        SandboxError::ConfigError("Cannot find crypto/fift/lib. Set TOS_ROOT.".into())
    })?;
    let smartcont = tos_root.as_ref().map(|r| r.join("crypto/smartcont")).ok_or_else(|| {
        SandboxError::ConfigError("Cannot find crypto/smartcont. Set TOS_ROOT.".into())
    })?;

    // Compiled contract code (`auto/*.fif`) is generated into the build tree,
    // not the source tree; CreateState.fif and gen-zerostate.fif include it by
    // the bare `auto/...` name, so the build tree's smartcont dir must be on
    // the include path too. Prefer the dir next to the create-state binary
    // (honors CREATE_STATE_PATH overrides), fall back to TOS_ROOT/build.
    let generated_smartcont = create_state_bin
        .parent()
        .map(|d| d.join("smartcont"))
        .filter(|d| d.join("auto").is_dir())
        .or_else(|| {
            tos_root
                .as_ref()
                .map(|r| r.join("build/crypto/smartcont"))
                .filter(|d| d.join("auto").is_dir())
        })
        .ok_or_else(|| {
            SandboxError::ConfigError(
                "Cannot find generated contract code (build/crypto/smartcont/auto). \
                 Build the C++ tree first, or set CREATE_STATE_PATH to a binary inside it."
                    .into(),
            )
        })?;

    let tmp =
        tempfile::tempdir().map_err(|e| SandboxError::Serialization(format!("tmpdir: {e}")))?;

    // gen-zerostate templates read a genesis validator key manifest
    // (`validator-keys.pub`, four concatenated 32-byte public keys) from the
    // working directory. Supply a deterministic manifest of four distinct
    // keys: the key bytes only shape the validator set, not the total
    // balance being measured here, and determinism keeps the run reproducible.
    let manifest: Vec<u8> = (1u8..=4).flat_map(|i| [i; 32]).collect();
    std::fs::write(tmp.path().join("validator-keys.pub"), manifest)
        .map_err(|e| SandboxError::Serialization(format!("write validator manifest: {e}")))?;

    let fif_path = fif_path
        .as_ref()
        .canonicalize()
        .map_err(|e| SandboxError::ConfigError(format!("zerostate template not found: {e}")))?;

    let output = Command::new(&create_state_bin)
        .current_dir(tmp.path())
        .arg("-I")
        .arg(&fift_lib)
        .arg("-I")
        .arg(&smartcont)
        .arg("-I")
        .arg(&generated_smartcont)
        .arg("-s")
        .arg(&fif_path)
        .output()
        .map_err(|e| {
            SandboxError::ConfigError(format!(
                "Failed to run create-state at {}: {e}",
                create_state_bin.display()
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Serialization(format!("create-state failed:\n{stderr}")));
    }

    let boc_path = tmp.path().join("zerostate.boc");
    if !boc_path.exists() {
        return Err(SandboxError::Serialization(
            "create-state did not produce zerostate.boc".into(),
        ));
    }
    let boc_bytes = std::fs::read(&boc_path)
        .map_err(|e| SandboxError::Serialization(format!("read BOC: {e}")))?;
    let cell = read_single_root_boc(boc_bytes)
        .map_err(|e| SandboxError::Serialization(format!("parse BOC: {e}")))?;
    let state = ShardStateUnsplit::construct_from_cell(cell)
        .map_err(|e| SandboxError::Serialization(format!("parse ShardStateUnsplit: {e}")))?;

    Ok(state.total_balance().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the canonical mainnet genesis template: under the
    /// validator-led bootstrap economics, genesis mints exactly 101,000 TOS —
    /// a bounded 100,000-TOS validator-bootstrap main wallet plus 500 TOS
    /// each for the elector and config contracts (see doc/Currency.md,
    /// doc/Zerostate.md). No premine, treasury, or team allocation exists;
    /// the long-run 5 B TOS figure is a creation target reached through
    /// block rewards and AIPoW minting, not a genesis balance.
    #[test]
    fn mainnet_genesis_total_supply_matches_validator_bootstrap_allocation() {
        let tos_root = find_tos_root().expect("TOS_ROOT (or a parent build dir) must be locatable");
        let fif_path = tos_root.join("crypto/smartcont/gen-zerostate.fif");
        let balance = generate_zerostate_total_balance(&fif_path).expect("zerostate generation");

        const NANOTOS_PER_TOS: u128 = 1_000_000_000;
        const EXPECTED_TOTAL_SUPPLY_TOS: u128 = 101_000;

        let total_nanotos = balance.coins.as_u128();
        assert_eq!(
            total_nanotos,
            EXPECTED_TOTAL_SUPPLY_TOS * NANOTOS_PER_TOS,
            "genesis total supply must be exactly 101,000 TOS, got {} nanotos ({} TOS)",
            total_nanotos,
            total_nanotos / NANOTOS_PER_TOS
        );
    }
}
