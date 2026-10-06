// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Cross-language fixture adapter. Pins are supplied by the trusted local test
// compiler; this executable does not authenticate a production release bundle.
use chain_block::{Cell, read_single_root_boc, write_boc};
use contracts::{
    wallet_v5r2_genesis::{
        CodeBundle, CodeHashes, GenesisParameters, SuccessorDeployment, WalletGenesis,
    },
    wallet_v5r2_manifest::{InitialRecoveryManifest, RecoveryDerivation},
    wallet_v5r2_pop::RescuePolicy,
};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
struct Input {
    wallet_code: String,
    module_code: String,
    vault_code: String,
    wallet_pin: String,
    module_pin: String,
    vault_pin: String,
    global_id: i32,
    network: String,
    wallet_id: u32,
    primary_key: String,
    rescue_key: String,
    policy: u8,
    fee_tree_id: String,
    fee_public_key: String,
    epoch0: u32,
    existing_wallet: Option<String>,
    recovery_derivation: Option<RecoveryDerivation>,
    recovery_manifest: Option<String>,
    expected_wallet: Option<String>,
}
fn bytes<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("field width"))
}
fn cell(s: &str) -> anyhow::Result<Cell> {
    read_single_root_boc(hex::decode(s)?)
}
fn main() -> anyhow::Result<()> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let i: Input = serde_json::from_str(&text)?;
    let policy = match i.policy {
        1 => RescuePolicy::Ready,
        2 => RescuePolicy::Required,
        _ => anyhow::bail!("unknown policy"),
    };
    let code = || {
        CodeBundle::new(
            cell(&i.wallet_code)?,
            cell(&i.module_code)?,
            cell(&i.vault_code)?,
            CodeHashes {
                wallet: bytes(&i.wallet_pin)?,
                module: bytes(&i.module_pin)?,
                vault: bytes(&i.vault_pin)?,
            },
        )
    };
    let parameters = GenesisParameters {
        global_id: i.global_id,
        network: bytes(&i.network)?,
        wallet_id: i.wallet_id,
        primary_key: bytes(&i.primary_key)?,
        rescue_key: bytes(&i.rescue_key)?,
        policy,
        fee_tree_id: bytes(&i.fee_tree_id)?,
        fee_public_key: bytes(&i.fee_public_key)?,
        epoch0: i.epoch0,
    };
    let mut result = serde_json::Map::new();
    let g = if let Some(derivation) = i.recovery_derivation {
        anyhow::ensure!(
            i.existing_wallet.is_none(),
            "initial manifest cannot reconstruct successor"
        );
        let (prepared, _) = InitialRecoveryManifest::prepare(code()?, parameters, derivation)?;
        let encoded = match i.recovery_manifest {
            Some(encoded) => encoded.into_bytes(),
            None => prepared.to_json()?,
        };
        let expected = i
            .expected_wallet
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("independent expected wallet required"))?;
        let (manifest, genesis) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, code()?, bytes(expected)?)?;
        result.insert("recovery_manifest".into(), String::from_utf8(manifest.to_json()?)?.into());
        genesis
    } else {
        anyhow::ensure!(
            i.recovery_manifest.is_none() && i.expected_wallet.is_none(),
            "manifest reconstruction requires declared derivation"
        );
        WalletGenesis::new(code()?, parameters)?
    };
    if let Some(owner) = i.existing_wallet {
        let successor = SuccessorDeployment::new(g, bytes(&owner)?)?;
        for (name, cell) in [
            ("module_data", successor.module_data()),
            ("module_init", successor.module_init()),
            ("metadata", successor.metadata()),
            ("vault_data", successor.vault_data()),
            ("vault_init", successor.vault_init()),
        ] {
            result.insert(name.into(), hex::encode(write_boc(cell)?).into());
        }
        result.insert("config_hash".into(), hex::encode(successor.config_hash()).into());
    } else {
        for (name, cell) in [
            ("module_data", g.module_data()),
            ("module_init", g.module_init()),
            ("metadata", g.metadata()),
            ("wallet_data", g.wallet_data()),
            ("wallet_init", g.wallet_init()),
            ("vault_data", g.vault_data()),
            ("vault_init", g.vault_init()),
        ] {
            result.insert(name.into(), hex::encode(write_boc(cell)?).into());
        }
        result.insert("config_hash".into(), hex::encode(g.config_hash()).into());
    }
    println!("{}", serde_json::Value::Object(result));
    Ok(())
}
