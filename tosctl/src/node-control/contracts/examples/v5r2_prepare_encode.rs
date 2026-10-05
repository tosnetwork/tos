// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Cross-language fixture adapter. No keys or signing backend.
use chain_block::{read_single_root_boc, write_boc};
use contracts::wallet_v5r2_prepare::{PreparationBinding, PreparationPlan, PreparationRequest};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
struct Input {
    global_id: i32,
    network: String,
    wallet: String,
    source_module: String,
    deadline: u32,
    proven_time: u32,
    module_amount: String,
    vault_amount: String,
    module_init: String,
    metadata: String,
    vault_init: String,
    signature: String,
}
fn hash(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
fn main() -> anyhow::Result<()> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let i: Input = serde_json::from_str(&text)?;
    let req = PreparationRequest::new(
        PreparationBinding {
            global_id: i.global_id,
            network: hash(&i.network)?,
            wallet: hash(&i.wallet)?,
            source_module: hash(&i.source_module)?,
            valid_until: i.deadline,
        },
        PreparationPlan {
            module_amount: i.module_amount.parse()?,
            vault_amount: i.vault_amount.parse()?,
            module_init: read_single_root_boc(hex::decode(i.module_init)?)?,
            metadata: read_single_root_boc(hex::decode(i.metadata)?)?,
            vault_init: read_single_root_boc(hex::decode(i.vault_init)?)?,
        },
        i.proven_time,
    )?;
    println!(
        "{}",
        serde_json::json!({"request": hex::encode(write_boc(req.cell())?),
        "digest": hex::encode(req.digest()), "context": hex::encode(req.signing_context()),
        "deployment_value": req.deployment_value().to_string(),
        "submission": hex::encode(write_boc(&req.encode_submission(&hex::decode(i.signature)?)?)?)})
    );
    Ok(())
}
