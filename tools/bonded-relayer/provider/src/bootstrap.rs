// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Local setup uses the same native wallet and durable one-send boundary.
use crate::{chain::Chain, config::Config, protocol, store::Store, transport};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{read_single_root_boc, write_boc, Cell, Deserializable, StateInit};
use node_contracts::relayer_bond::RelayerBond;
use node_contracts::Wallet;
use serde_json::json;
use std::str::FromStr;

pub async fn run(mode: &str) -> Result<()> {
    ensure!(
        matches!(mode, "deploy-bond" | "activate-bond" | "retire-bond" | "withdraw-bond"),
        "bootstrap operation"
    );
    let directory = std::env::current_dir()?;
    let _lock = crate::private_io::lock(&directory)?;
    let raw = crate::private_io::read(&directory.join("provider.json"), 65536)?;
    let value = protocol::parse(&raw)?;
    let config = Config::load(&directory, &json!({"release":value["release"]}))?;
    let chain = Chain::new(&config)?;
    let (funding_state, sequence) = chain.funding(&config).await?;
    let wallet = crate::funding::wallet(&config, &directory).await?;
    let (amount, body, init) = if mode == "deploy-bond" {
        let bytes = crate::private_io::read(&directory.join("bond-init.boc"), 65536)?;
        (
            2_000_000_000,
            Cell::default(),
            Some(StateInit::construct_from_cell(read_single_root_boc(&bytes)?)?),
        )
    } else if mode == "retire-bond" || mode == "withdraw-bond" {
        let (state, bond) = chain.bond_identity(&config).await?;
        let owner = chain_block::MsgAddressInt::from_str(&config.funding_wallet)?;
        let clock =
            lifecycle_clock(state.evidence().block_gen_utime, state.evidence().account.gen_utime);
        let op = lifecycle_operation(
            mode,
            config.release.global_id,
            bond.init.owner == owner,
            bond.phase,
            bond.exit_after,
            clock,
        )?;
        (100_000_000, RelayerBond::header(op, 0)?.into_cell()?, None)
    } else {
        let bytes = crate::private_io::read(&directory.join("bond-activate.boc"), 65536)?;
        (1_100_000_000, read_single_root_boc(&bytes)?, None)
    };
    if mode == "retire-bond" || mode == "withdraw-bond" {
        lifecycle_budget(config.funding_cap, &funding_state.evidence().account.balance, amount)?;
    }
    let request = protocol::hash(format!("{}:{mode}", config.release.scope()?).as_bytes());
    let binding = protocol::hash(&protocol::canonical(
        &json!({"mode":mode,"scope":config.release.scope()?,"sequence":sequence}),
    )?);
    let mut store = Store::open(&directory.join("leases.db"), &config.release.scope()?)?;
    let lease = store.reserve(&request, &binding, sequence)?;
    // A persisted message can be inspected, but bootstrap never retries a send
    // after an unknown outcome or signs its replacement.
    ensure!(
        lease.fresh && lease.message.is_none(),
        "bootstrap already signed; reconcile without repeating"
    );
    let message = wallet
        .build_message(
            chain_block::MsgAddressInt::from_str(&config.release.bond)?,
            amount,
            body,
            true,
            Some(sequence),
            None,
            init,
        )
        .await?;
    let bytes = write_boc(&message)?;
    store.persist_message(&request, &bytes)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let mut random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
    let permit = hex::encode(random);
    store.permit(&request, &permit, &protocol::hash(&bytes), now)?;
    store.consume(&permit, &bytes, now)?;
    // Synchronous RPC clients run outside the async executor thread.
    let url = config.rpc_url.clone();
    let encoded = STANDARD.encode(&bytes);
    tokio::task::spawn_blocking(move || transport::rpc(&url, "sendBoc", json!({"boc":encoded})))
        .await??;
    println!(
        "{}",
        json!({"status":"submitted-not-finalized","operation":mode,"sequence":sequence,"message_hash":message.repr_hash().to_hex_string(),"message_sha256":protocol::hash(&bytes)})
    );
    Ok(())
}

fn lifecycle_clock(master: u32, shard: u32) -> u32 {
    master.min(shard)
}

fn lifecycle_budget(cap: u64, balance: &str, amount: u64) -> Result<()> {
    ensure!(amount <= cap, "lifecycle funding cap");
    let balance = balance.parse::<u128>()?;
    let ceiling = u128::from(amount)
        .checked_add(100_000_000)
        .ok_or_else(|| anyhow::anyhow!("lifecycle funding ceiling overflow"))?;
    ensure!(
        balance.checked_sub(ceiling).is_some_and(|left| left >= 1_000_000_000),
        "lifecycle funding wallet must retain one TOS after amount and fee ceiling"
    );
    Ok(())
}

/// The tool cannot shorten the immutable on-chain exit delay or act on public custody.
fn lifecycle_operation(
    mode: &str,
    global_id: i32,
    is_owner: bool,
    phase: u8,
    exit_after: u32,
    clock: u32,
) -> Result<u32> {
    ensure!(global_id == 3, "lifecycle tool requires isolated global id 3");
    ensure!(is_owner, "funding wallet is not the Bond owner");
    match mode {
        "retire-bond" => {
            ensure!(phase == 1, "retirement requires ACTIVE");
            Ok(0x42520003)
        }
        "withdraw-bond" => {
            ensure!(phase == 2, "withdrawal requires EXITING");
            ensure!(exit_after > 0 && clock >= exit_after, "immutable exit delay not elapsed");
            Ok(0x42520004)
        }
        _ => anyhow::bail!("unsupported lifecycle operation"),
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn lifecycle_owner_network_phase_and_exact_deadline() {
        assert_eq!(lifecycle_operation("retire-bond", 3, true, 1, 0, 100).ok(), Some(0x42520003));
        assert_eq!(
            lifecycle_operation("withdraw-bond", 3, true, 2, 100, 100).ok(),
            Some(0x42520004)
        );
        assert!(lifecycle_operation("withdraw-bond", 3, true, 2, 100, 101).is_ok());
        for mode in ["retire-bond", "withdraw-bond"] {
            let phase = if mode == "retire-bond" { 1 } else { 2 };
            assert!(lifecycle_operation(mode, 2, true, phase, 100, 100).is_err());
            assert!(lifecycle_operation(mode, 3, false, phase, 100, 100).is_err());
            for wrong in [0, 3, 4, if phase == 1 { 2 } else { 1 }] {
                assert!(lifecycle_operation(mode, 3, true, wrong, 100, 100).is_err());
            }
        }
        assert!(lifecycle_operation("withdraw-bond", 3, true, 2, 100, 99).is_err());
        assert!(lifecycle_operation("withdraw-bond", 3, true, 2, 0, 100).is_err());
        assert!(lifecycle_operation("activate-bond", 3, true, 1, 0, 100).is_err());
    }
    #[test]
    fn lifecycle_budget_exact_reserve_and_cap() {
        assert!(lifecycle_budget(100_000_000, "1200000000", 100_000_000).is_ok());
        assert!(lifecycle_budget(99_999_999, "1200000000", 100_000_000).is_err());
        for bad in [
            "1199999999",
            "0",
            "199999999",
            "-1",
            "not-a-balance",
            "340282366920938463463374607431768211456",
        ] {
            assert!(lifecycle_budget(100_000_000, bad, 100_000_000).is_err());
        }
    }
    #[test]
    fn lifecycle_deadline_requires_both_proven_clocks() {
        for (master, shard) in [(100, 99), (99, 100), (u32::MAX, 99), (99, u32::MAX)] {
            assert!(lifecycle_operation(
                "withdraw-bond",
                3,
                true,
                2,
                100,
                lifecycle_clock(master, shard)
            )
            .is_err());
        }
        assert!(lifecycle_operation("withdraw-bond", 3, true, 2, 100, lifecycle_clock(100, 100))
            .is_ok());
    }
}
