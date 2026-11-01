// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Full native compute/action execution on proven state is an estimate only.
use crate::{
    candidate::{ordinary_boc, Candidate},
    chain::Chain,
    config::Config,
    transport,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{
    ConfigParams, Serializable, SliceData, TrComputePhase, Transaction, TransactionDescr, UInt256,
};
use node_contracts::proven_getters::{GetMethodCall, ProvenAccountState, ReadPolicy};
use serde_json::{json, Value};
use std::str::FromStr;
use tos_executor::{
    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor,
};

pub struct Simulation {
    pub pool: ProvenAccountState,
    pub funding: u64,
}
pub fn successful(tx: &Transaction) -> Result<()> {
    let TransactionDescr::Ordinary(description) = tx.read_description()? else {
        anyhow::bail!("ordinary transaction required")
    };
    ensure!(!description.aborted && !description.destroyed, "transaction aborted/destroyed");
    let TrComputePhase::Vm(vm) = description.compute_ph else { anyhow::bail!("compute skipped") };
    ensure!(vm.success && vm.exit_code == 0, "native compute refused");
    let action = description.action.ok_or_else(|| anyhow::anyhow!("action phase missing"))?;
    ensure!(
        action.success && action.result_code == 0 && action.valid && !action.no_funds,
        "native action refused"
    );
    Ok(())
}
pub async fn run(config: &Config, chain: &Chain, candidate: &Candidate) -> Result<Simulation> {
    let (bond, _) = chain.bond(config).await?;
    let address = chain_block::MsgAddressInt::from_str(&config.release.pool)?;
    let policy = ReadPolicy::Historical(bond.evidence().checkpoint.clone());
    let (pool, context) = chain
        .verifier()
        .read_account_for_execution(&address, GetMethodCall::new("commitment_root"), &policy)
        .await?;
    bond.require_same_checkpoint(&pool)?;
    ensure!(pool.evidence().account.code_hash == config.release.pool_code_hash, "pool code pin");
    let data = pool.account().get_data().ok_or_else(|| anyhow::anyhow!("pool data absent"))?;
    ensure!(
        data.reference(2)?.repr_hash().to_hex_string() == config.release.pool_config_hash,
        "pool configuration pin"
    );
    ensure!(
        context["global_version"].as_u64().is_some_and(|n| n >= 16)
            && context["libraries"].as_array().is_some_and(|x| x.is_empty()),
        "unsupported execution version/libraries"
    );
    let now = context["unixtime"]
        .as_u64()
        .and_then(|x| u32::try_from(x).ok())
        .ok_or_else(|| anyhow::anyhow!("execution time"))?;
    ensure!(candidate.request.valid_until > now, "candidate expired");
    let block_lt =
        context["block_lt"].as_u64().ok_or_else(|| anyhow::anyhow!("execution logical time"))?;
    let seed =
        context["rand_seed"].as_str().ok_or_else(|| anyhow::anyhow!("execution random seed"))?;
    let seed = UInt256::from_str(seed)?;
    let url = config.rpc_url.clone();
    let seqno = pool.evidence().checkpoint.seqno;
    let raw = tokio::task::spawn_blocking(move || {
        transport::rpc(&url, "getConfigAll", json!({"seqno":seqno}))
    })
    .await??;
    let encoded = raw["config"]["bytes"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("configuration BOC absent"))?;
    ensure!(encoded.len() <= 87384, "configuration byte bound");
    let bytes = STANDARD.decode(encoded)?;
    ensure!(
        bytes.len() <= 65536 && STANDARD.encode(&bytes) == encoded,
        "configuration encoding bound"
    );
    let root = ordinary_boc(&bytes)?;
    ensure!(
        Value::String(root.repr_hash().to_hex_string()) == context["config_root_hash"],
        "unproven full configuration"
    );
    let parameters = ConfigParams::with_root(root)?;
    ensure!(parameters.global_version() >= 16, "native global version");
    let executor = OrdinaryTransactionExecutor::new(BlockchainConfig::with_config(parameters)?);
    // Conservative, explicit local development funding. The exact candidate is
    // executed with this amount, and both request and operator caps must cover it.
    let funding = 250_000_000u64;
    ensure!(
        funding <= candidate.request.funding_cap && funding <= config.funding_cap,
        "simulation funding exceeds cap"
    );
    let message = tos_sandbox::MessageBuilder::internal(
        &chain_block::MsgAddressInt::from_str(&config.funding_wallet)?,
        &address,
        funding,
    )
    .bounce(true)
    .body_slice(SliceData::load_cell(candidate.body.clone())?)
    .build();
    let mut account = pool.account().clone();
    let params = ExecuteParams {
        block_unixtime: now,
        block_lt,
        last_tr_lt: pool
            .evidence()
            .account
            .last_trans_lt
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("logical time overflow"))?,
        seed_block: seed,
        ..ExecuteParams::default()
    };
    let transaction =
        executor.execute_with_params(Some(message.serialize()?), &mut account, params)?;
    successful(&transaction)?;
    Ok(Simulation { pool, funding })
}
