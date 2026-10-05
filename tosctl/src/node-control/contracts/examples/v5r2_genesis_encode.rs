// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Cross-language fixture adapter. Pins are supplied by the trusted local test
// compiler; this executable does not authenticate a production release bundle.
use chain_block::{Cell, read_single_root_boc, write_boc};
use contracts::{
    wallet_v5r2_genesis::{CodeBundle, CodeHashes, GenesisParameters, WalletGenesis},
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
    let code = CodeBundle::new(
        cell(&i.wallet_code)?,
        cell(&i.module_code)?,
        cell(&i.vault_code)?,
        CodeHashes {
            wallet: bytes(&i.wallet_pin)?,
            module: bytes(&i.module_pin)?,
            vault: bytes(&i.vault_pin)?,
        },
    )?;
    let g = WalletGenesis::new(
        code,
        GenesisParameters {
            global_id: i.global_id,
            network: bytes(&i.network)?,
            wallet_id: i.wallet_id,
            primary_key: bytes(&i.primary_key)?,
            rescue_key: bytes(&i.rescue_key)?,
            policy,
            fee_tree_id: bytes(&i.fee_tree_id)?,
            fee_public_key: bytes(&i.fee_public_key)?,
            epoch0: i.epoch0,
        },
    )?;
    let mut result = serde_json::Map::new();
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
    println!("{}", serde_json::Value::Object(result));
    Ok(())
}
