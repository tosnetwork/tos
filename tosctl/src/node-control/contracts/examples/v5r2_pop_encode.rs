// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Test adapter for independent POP wire checks; no keys or signing backend.
use chain_block::write_boc;
use contracts::{
    wallet_v5r2::AuthRole,
    wallet_v5r2_pop::{PopBinding, PopRequest, RescuePolicy},
};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
struct Input {
    global_id: i32,
    network: String,
    account: String,
    module: String,
    challenge: String,
    deadline: u32,
    proven_time: u32,
    role: u8,
    policy: u8,
    primary_key_hash: String,
    rescue_key: String,
    signature: Option<String>,
}
fn hash(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
fn main() -> anyhow::Result<()> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let role = match input.role {
        1 => AuthRole::Primary,
        2 => AuthRole::Rescue,
        _ => anyhow::bail!("unknown role"),
    };
    let policy = match input.policy {
        1 => RescuePolicy::Ready,
        2 => RescuePolicy::Required,
        _ => anyhow::bail!("unknown policy"),
    };
    let req = PopRequest::new(
        PopBinding {
            global_id: input.global_id,
            network: hash(&input.network)?,
            account: hash(&input.account)?,
            module: hash(&input.module)?,
            challenge: hash(&input.challenge)?,
            valid_until: input.deadline,
        },
        role,
        policy,
        hash(&input.primary_key_hash)?,
        hash(&input.rescue_key)?,
        input.proven_time,
    )?;
    let submission = match input.signature {
        Some(bytes) => Some(hex::encode(write_boc(&req.encode_submission(&hex::decode(bytes)?)?)?)),
        None => None,
    };
    println!(
        "{}",
        serde_json::json!({"request": hex::encode(write_boc(req.cell())?),
        "digest": hex::encode(req.digest()), "context": hex::encode(req.signing_context()), "submission": submission})
    );
    Ok(())
}
