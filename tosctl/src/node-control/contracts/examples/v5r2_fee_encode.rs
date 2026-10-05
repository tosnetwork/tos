// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Cross-language wire fixture adapter; no signing backend or trusted proof source.
use chain_block::{read_single_root_boc, write_boc};
use contracts::wallet_v5r2_fee::{FeeBinding, FeeClass, FeeIntent, FeePayload};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
struct Input {
    class: u8,
    vault: String,
    config_hash: String,
    epoch0: u32,
    leaf: u32,
    deadline: u32,
    value: String,
    proven_time: u32,
    payload: String,
    signature: Option<String>,
}
fn hash(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
fn main() -> anyhow::Result<()> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let i: Input = serde_json::from_str(&text)?;
    let class = match i.class {
        1 => FeeClass::RescueAuth,
        2 => FeeClass::Pop,
        3 => FeeClass::Prepare,
        _ => anyhow::bail!("unknown fee class"),
    };
    let payload =
        FeePayload::from_submission(class, read_single_root_boc(hex::decode(i.payload)?)?)?;
    let intent = FeeIntent::new(
        FeeBinding {
            vault: hash(&i.vault)?,
            config_hash: hash(&i.config_hash)?,
            epoch0: i.epoch0,
            leaf: i.leaf,
            valid_until: i.deadline,
            value: i.value.parse()?,
        },
        payload,
        i.proven_time,
    )?;
    let external = match i.signature {
        Some(sig) => Some(hex::encode(write_boc(&intent.encode_external(&hex::decode(sig)?)?)?)),
        None => None,
    };
    println!(
        "{}",
        serde_json::json!({"intent": hex::encode(write_boc(intent.cell())?), "digest": hex::encode(intent.digest()), "leaf": intent.leaf(), "external": external})
    );
    Ok(())
}
