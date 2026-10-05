// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Test adapter for cross-language wire and actual-transaction checks; no signing.
use chain_block::{Cell, read_single_root_boc, write_boc};
use contracts::wallet_v5r2::{AuthAction, AuthBinding, AuthRequest, AuthRole};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct Input {
    global_id: i32,
    network: String,
    account: String,
    module: String,
    epoch: u64,
    nonce: u64,
    deadline: u32,
    proven_time: u32,
    role: u8,
    kind: u8,
    refs: Vec<String>,
    replacement: bool,
}
fn hash(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
fn main() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input: Input = serde_json::from_str(&input)?;
    let refs: Vec<Cell> = input
        .refs
        .iter()
        .map(|s| Ok(read_single_root_boc(hex::decode(s)?)?))
        .collect::<anyhow::Result<_>>()?;
    let action = match (input.kind, input.replacement, refs.as_slice()) {
        (0, false, [actions]) => AuthAction::Execute { actions: actions.clone() },
        (1, false, []) => AuthAction::Configure { fee_replacement: None },
        (1, true, [metadata, vault]) => {
            AuthAction::Configure { fee_replacement: Some((metadata.clone(), vault.clone())) }
        }
        (3, false, []) => AuthAction::LockPrimary,
        (4, false, [module, metadata, vault]) => AuthAction::Migrate {
            module_init: module.clone(),
            metadata: metadata.clone(),
            vault_init: vault.clone(),
        },
        _ => anyhow::bail!("unsupported action shape"),
    };
    let role = match input.role {
        1 => AuthRole::Primary,
        2 => AuthRole::Rescue,
        _ => anyhow::bail!("unknown role"),
    };
    let request = AuthRequest::new(
        AuthBinding {
            global_id: input.global_id,
            network: hash(&input.network)?,
            account: hash(&input.account)?,
            module: hash(&input.module)?,
            epoch: input.epoch,
            nonce: input.nonce,
            valid_until: input.deadline,
        },
        role,
        action,
        input.proven_time,
    )?;
    println!(
        "{}",
        serde_json::json!({"request": hex::encode(write_boc(request.cell())?),
        "digest": hex::encode(request.digest()), "context": hex::encode(request.signing_context())})
    );
    Ok(())
}
