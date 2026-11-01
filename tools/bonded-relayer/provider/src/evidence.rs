// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Authenticate destination history from its proven head, then import once.
use crate::{
    candidate::{ordinary_boc, Candidate},
    chain::Chain,
    config::Config,
    identity::Identity,
    prepared, protocol, simulation,
    store::Store,
    transport,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{Cell, Deserializable, Message, MsgAddressInt, SliceData, Transaction};
use node_contracts::proven_getters::{ProvenAccountState, ReadPolicy};
use serde_json::{json, Value};
use std::{path::Path, str::FromStr};

async fn history(
    config: &Config,
    address: &str,
    state: &ProvenAccountState,
) -> Result<Vec<(Cell, Transaction)>> {
    let url = config.rpc_url.clone();
    let address = address.to_owned();
    let lt = state.evidence().account.last_trans_lt;
    let head = hex::encode(state.last_transaction_hash());
    let hash = STANDARD.encode(state.last_transaction_hash());
    let address_request = address.clone();
    let raw = tokio::task::spawn_blocking(move || {
        transport::rpc(
            &url,
            "getTransactions",
            json!({"address":address_request,"limit":16,"lt":lt.to_string(),"hash":hash}),
        )
    })
    .await??;
    let rows = raw.as_array().ok_or_else(|| anyhow::anyhow!("transaction history array"))?;
    ensure!(!rows.is_empty() && rows.len() <= 16, "transaction history bound");
    let mut expected_hash = head;
    let mut expected_lt = lt;
    let mut out = Vec::new();
    for row in rows {
        let encoded =
            row["data"].as_str().ok_or_else(|| anyhow::anyhow!("transaction bytes missing"))?;
        ensure!(encoded.len() <= 699052, "transaction byte bound");
        let bytes = STANDARD.decode(encoded)?;
        ensure!(STANDARD.encode(&bytes) == encoded, "transaction canonical encoding");
        let cell = ordinary_boc(&bytes)?;
        ensure!(
            cell.repr_hash().to_hex_string() == expected_hash,
            "unproven transaction predecessor"
        );
        let transaction = Transaction::construct_from_cell(cell.clone())?;
        ensure!(
            transaction.logical_time() == expected_lt
                && hex::encode(transaction.account_id().get_bytestring(0)) == address[2..],
            "transaction account/logical time"
        );
        expected_hash = transaction.prev_trans_hash().to_hex_string();
        expected_lt = transaction.prev_trans_lt();
        out.push((cell, transaction));
        if expected_lt == 0 {
            break;
        }
    }
    Ok(out)
}
fn inbound(transaction: &Transaction) -> Result<(Cell, Message)> {
    let cell =
        transaction.in_msg_cell().ok_or_else(|| anyhow::anyhow!("transaction inbound absent"))?;
    Ok((cell.clone(), Message::construct_from_cell(cell)?))
}
fn append_count(transaction: &Transaction) -> Result<u64> {
    simulation::successful(transaction)?;
    let (_, message) = inbound(transaction)?;
    counter_delta(&message)
}
fn counter_delta(message: &Message) -> Result<u64> {
    let header =
        message.int_header().ok_or_else(|| anyhow::anyhow!("pool mutation must be internal"))?;
    ensure!(!header.bounced, "intervening bounce needs separate recovery evidence");
    let Some(body) = message.body() else { return Ok(0) };
    if body.remaining_bits() == 0 {
        return Ok(0);
    }
    let mut body = body.clone();
    let operation = body.get_next_u32()?;
    match operation {
        0x53485001 => Ok(1),
        0x53485002 => Ok(3),
        0x53485003 => Ok(0),
        _ => anyhow::bail!("unsupported intervening pool mutation"),
    }
}
pub async fn run(
    config: &Config,
    identity: &Identity,
    directory: &Path,
    payload: &Value,
) -> Result<Value> {
    protocol::fields(payload, &["release", "request", "prepared"])?;
    let mut raw = b"TOS-BR1-REQUEST\0".to_vec();
    raw.extend(protocol::canonical(&payload["request"])?);
    let id = protocol::hash(&raw);
    let mut store = Store::open(&directory.join("leases.db"), &config.release.scope()?)?;
    if store.lookup(&id)?.is_none() {
        return Ok(Value::Null);
    }
    let record = protocol::parse(&store.record(&id)?)?;
    prepared::validate(
        config,
        identity,
        directory,
        &json!({"release":payload["release"],"request":payload["request"],"prepared":payload["prepared"],"slot":record["slot"],"issued_at":record["issued_at"],"funding":record["funding"]}),
    )?;
    let terms = prepared::check_quote(config, identity, &record["quote"], false)?;
    let candidate = Candidate::parse(&payload["request"], config, identity, &terms)?;
    let chain = Chain::new(config)?;
    let pool = chain
        .verifier()
        .read_account(&MsgAddressInt::from_str(&config.release.pool)?, &ReadPolicy::Live)
        .await?;
    ensure!(
        pool.evidence().account.code_hash == config.release.pool_code_hash,
        "pool evidence code pin"
    );
    let data = pool.account().get_data().ok_or_else(|| anyhow::anyhow!("pool data absent"))?;
    ensure!(
        data.reference(2)?.repr_hash().to_hex_string() == config.release.pool_config_hash,
        "pool evidence configuration pin"
    );
    let mut state = SliceData::load_cell(data)?;
    ensure!(
        state.get_next_u32()? == 0x53505631 && state.get_next_int(16)? == 1,
        "pool state version"
    );
    let _root = state.get_next_bytes(32)?;
    let mut next = state.get_next_u64()?;
    let transactions = history(config, &config.release.pool, &pool).await?;
    let mut target = None;
    for (cell, transaction) in &transactions {
        let (_, message) = inbound(transaction)?;
        let matches = message.body().is_some_and(|b| {
            b.clone().into_cell().is_ok_and(|body| body.repr_hash() == candidate.body.repr_hash())
        });
        if matches {
            simulation::successful(transaction)?;
            let header =
                message.int_header().ok_or_else(|| anyhow::anyhow!("Shield inbound header"))?;
            ensure!(
                !header.bounced
                    && header.src
                        == chain_block::MsgAddressIntOrNone::Some(MsgAddressInt::from_str(
                            &config.funding_wallet
                        )?)
                    && header.dst == MsgAddressInt::from_str(&config.release.pool)?,
                "Shield source/destination"
            );
            let start = next.checked_sub(3).ok_or_else(|| anyhow::anyhow!("fee leaf underflow"))?;
            let leaf = start
                .checked_add(u64::from(candidate.request.fee_slot))
                .ok_or_else(|| anyhow::anyhow!("fee leaf overflow"))?;
            target = Some((cell.repr_hash().to_hex_string(), leaf, transaction));
            break;
        }
        next = next
            .checked_sub(append_count(transaction)?)
            .ok_or_else(|| anyhow::anyhow!("commitment history underflow"))?;
    }
    let Some((transaction_hash, leaf, transaction)) = target else { return Ok(Value::Null) };
    let wallet = chain
        .verifier()
        .read_account(
            &MsgAddressInt::from_str(&config.funding_wallet)?,
            &ReadPolicy::Historical(pool.evidence().checkpoint.clone()),
        )
        .await?;
    pool.require_same_checkpoint(&wallet)?;
    let destination_in = inbound(transaction)?.0.repr_hash();
    let mut source_proven = false;
    for (_, source) in history(config, &config.funding_wallet, &wallet).await? {
        let (external, _) = inbound(&source)?;
        if Value::String(external.repr_hash().to_hex_string())
            != payload["prepared"]["message_hash"]
        {
            continue;
        }
        simulation::successful(&source)?;
        source.iterate_out_msgs(|message| {
            if message.serialize_as_is()?.0.into_cell()?.repr_hash() == destination_in {
                source_proven = true;
            }
            Ok(true)
        })?;
        break;
    }
    if !source_proven {
        return Ok(Value::Null);
    }
    let plaintext = shielded_pool_wallet::delivery::open(
        identity.recipient(),
        &candidate.fee_payload,
        candidate.request.fee_slot,
    )
    .map_err(|_| anyhow::anyhow!("fee payload rejected"))?;
    let chain_slot = shielded_pool_wallet::import::ChainSlot {
        output_data_hash: shielded_pool_circuit::wire::output_data_hash(&candidate.fee_payload),
        note_body: candidate.fee_body,
        recovered: None,
    };
    let imported =
        shielded_pool_wallet::import::import(identity.recipient(), &plaintext, &chain_slot)?
            .map_err(|_| anyhow::anyhow!("fee import rejected"))?;
    ensure!(
        imported.spendable
            && imported.amount == u128::from(config.fee)
            && imported.note_key_index == candidate.request.fee_note_index,
        "fee import economic binding"
    );
    let proof = pool.evidence();
    let credit = json!({"schema":"tos.relayer.fee-credit.v1","note_body":candidate.request.fee_note_body,"note_key_index":candidate.request.fee_note_index,"slot":candidate.request.fee_slot,"checkpoint_root":proof.checkpoint.root_hash,"leaf_index":leaf,"transaction":transaction_hash,"amount":config.fee.to_string()});
    store.import_fee(
        &transaction_hash,
        leaf,
        &candidate.request.fee_note_body,
        &protocol::canonical(&credit)?,
        &candidate.fee_payload,
    )?;
    let digest = protocol::hash(&protocol::canonical(
        &json!({"pool_state":proof.account.state_hash,"wallet_state":wallet.evidence().account.state_hash,"transaction":transaction_hash,"source_external":payload["prepared"]["message_hash"],"fee_credit":credit}),
    )?);
    Ok(
        json!({"kind":"pool_execution","scope":config.release.scope()?,"request":id,"message_hash":payload["prepared"]["message_hash"],"pool":config.release.pool,"intent":candidate.request.intent,"body_sha256":candidate.request.body_sha256,"checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime},"proof_digest":digest,"transaction":transaction_hash,"fee_credit":credit}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{BuilderData, IBitstring};
    fn incoming(operation: u32, bounced: bool) -> Result<Message> {
        let address = MsgAddressInt::from_str(&format!("0:{}", "01".repeat(32)))?;
        let mut body = BuilderData::new();
        body.append_u32(operation)?;
        let mut message = tos_sandbox::MessageBuilder::internal(&address, &address, 1)
            .body_slice(SliceData::load_cell(body.into_cell()?)?)
            .build();
        let header = message.int_header_mut().ok_or_else(|| anyhow::anyhow!("internal header"))?;
        header.bounced = bounced;
        Ok(message)
    }
    #[test]
    fn bounced_deposit_prefix_cannot_move_fee_leaf_cursor() -> Result<()> {
        let result = counter_delta(&incoming(0x53485001, true)?);
        assert!(
            matches!(result,Err(error) if error.to_string()=="intervening bounce needs separate recovery evidence")
        );
        Ok(())
    }
    #[test]
    fn recovery_prefix_alone_is_not_proof_of_a_minted_leaf() -> Result<()> {
        let result = counter_delta(&incoming(0xfffffffe, false)?);
        assert!(
            matches!(result,Err(error) if error.to_string()=="unsupported intervening pool mutation")
        );
        Ok(())
    }
}
