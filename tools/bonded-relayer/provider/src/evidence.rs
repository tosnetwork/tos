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
use chain_block::{
    Cell, Deserializable, Message, MsgAddressInt, SliceData, Transaction, TransactionDescr,
};
use node_contracts::{
    proven_getters::{ProvenAccountState, ReadPolicy},
    MasterchainCheckpoint,
};
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
fn atomic_abort(transaction: &Transaction) -> Result<bool> {
    let TransactionDescr::Ordinary(description) = transaction.read_description()? else {
        anyhow::bail!("ordinary pool transaction required")
    };
    ensure!(!description.destroyed, "destroyed pool needs separate evidence");
    Ok(description.aborted)
}
fn owned_inbound(message: &Message, funding: &MsgAddressInt, pool: &MsgAddressInt) -> bool {
    message.int_header().is_some_and(|header| {
        !header.bounced
            && header.src == chain_block::MsgAddressIntOrNone::Some(funding.clone())
            && header.dst == *pool
    })
}
fn target_leaf(transaction: &Transaction, next: u64, slot: u8) -> Result<Option<u64>> {
    if atomic_abort(transaction)? {
        return Ok(None);
    }
    simulation::successful(transaction)?;
    let start = next.checked_sub(3).ok_or_else(|| anyhow::anyhow!("fee leaf underflow"))?;
    Ok(Some(
        start.checked_add(u64::from(slot)).ok_or_else(|| anyhow::anyhow!("fee leaf overflow"))?,
    ))
}
fn append_count(transaction: &Transaction) -> Result<Option<u64>> {
    if atomic_abort(transaction)? {
        return Ok(Some(0));
    }
    simulation::successful(transaction)?;
    let (_, message) = inbound(transaction)?;
    counter_delta(&message)
}
fn counter_delta(message: &Message) -> Result<Option<u64>> {
    let header =
        message.int_header().ok_or_else(|| anyhow::anyhow!("pool mutation must be internal"))?;
    if header.bounced {
        let body = message.body().cloned().unwrap_or_default();
        return Ok(node_contracts::shielded_pool::bounce_original_body_hash(&body)?
            .is_none()
            .then_some(0));
    }
    let Some(body) = message.body() else { return Ok(Some(0)) };
    if body.remaining_bits() < 32 {
        return Ok(Some(0));
    }
    let mut body = body.clone();
    let operation = body.get_next_u32()?;
    match operation {
        0x53485001 => Ok(Some(1)),
        0x53485002 => Ok(Some(3)),
        0x53485003 => Ok(Some(0)),
        _ => anyhow::bail!("unsupported intervening pool mutation"),
    }
}
/// A checkpoint supplies the actual commitment counter, including any recovery
/// notes the chain minted. Never price an earlier bounce with today's gas.
fn commitment_next(config: &Config, pool: &ProvenAccountState) -> Result<u64> {
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
    state.get_next_u64()
}

async fn checkpoint_hint(config: &Config, selector: Value) -> Result<MasterchainCheckpoint> {
    let url = config.rpc_url.clone();
    let block = tokio::task::spawn_blocking(move || {
        let mut params = selector;
        params["workchain"] = json!(-1);
        params["shard"] = json!("-9223372036854775808");
        transport::rpc(&url, "lookupBlock", params)
    })
    .await??;
    let seqno = block["seqno"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| anyhow::anyhow!("checkpoint sequence absent"))?;
    let hash = |field: &str| -> Result<String> {
        let value =
            block[field].as_str().ok_or_else(|| anyhow::anyhow!("checkpoint hash absent"))?;
        let bytes = if value.len() == 64 { hex::decode(value)? } else { STANDARD.decode(value)? };
        ensure!(bytes.len() == 32, "checkpoint hash length");
        Ok(hex::encode(bytes))
    };
    Ok(MasterchainCheckpoint {
        seqno,
        root_hash: hash("root_hash")?,
        file_hash: hash("file_hash")?,
    })
}

/// Move between two positions in the hash-linked history. A successful rich
/// bounce is deliberately not assigned a delta from its envelope or value.
fn counter_at(
    deltas: &[Option<u64>],
    mut next: u64,
    from: usize,
    to: usize,
) -> Result<Option<u64>> {
    if from < to {
        for delta in &deltas[from..to] {
            let Some(delta) = delta else { return Ok(None) };
            next = next
                .checked_sub(*delta)
                .ok_or_else(|| anyhow::anyhow!("commitment history underflow"))?;
        }
    } else {
        for delta in deltas[to..from].iter().rev() {
            let Some(delta) = delta else { return Ok(None) };
            next = next
                .checked_add(*delta)
                .ok_or_else(|| anyhow::anyhow!("commitment history overflow"))?;
        }
    }
    Ok(Some(next))
}

/// Reconcile the two proven counters with the known append operations.
fn recovery_appends(deltas: &[Option<u64>], live: u64, destination: u64) -> Result<u64> {
    let known = deltas.iter().flatten().sum::<u64>();
    let recoveries = deltas.iter().filter(|delta| delta.is_none()).count() as u64;
    let appended = live
        .checked_sub(destination)
        .and_then(|delta| delta.checked_sub(known))
        .ok_or_else(|| anyhow::anyhow!("recovery commitment history underflow"))?;
    ensure!(appended <= recoveries, "recovery commitment history mismatch");
    Ok(appended)
}

async fn counter_at_destination(
    config: &Config,
    chain: &Chain,
    address: &MsgAddressInt,
    live: &ProvenAccountState,
    history: &[(Cell, Transaction)],
    target: usize,
) -> Result<u64> {
    let next = commitment_next(config, live)?;
    let deltas =
        history[..target].iter().map(|(_, tx)| append_count(tx)).collect::<Result<Vec<_>>>()?;
    if let Some(counter) = counter_at(&deltas, next, 0, target)? {
        return Ok(counter);
    }

    // The RPC's LT lookup is only a hint. A snapshot counts only when the
    // verifier proves it and its account head occurs in this exact history.
    let lt = history[target].1.logical_time();
    let hint = checkpoint_hint(config, json!({"lt":lt.to_string()})).await?;
    let live_seqno = live.evidence().checkpoint.seqno;
    for seqno in [hint.seqno, hint.seqno.saturating_add(1), hint.seqno.saturating_sub(1)] {
        if seqno == 0 || seqno >= live_seqno {
            continue;
        }
        let checkpoint = if seqno == hint.seqno {
            hint.clone()
        } else {
            checkpoint_hint(config, json!({"seqno":seqno})).await?
        };
        ensure!(checkpoint.seqno == seqno, "checkpoint sequence mismatch");
        let snapshot =
            chain.verifier().read_account(address, &ReadPolicy::Historical(checkpoint)).await?;
        let Some(position) = history.iter().position(|(cell, tx)| {
            tx.logical_time() == snapshot.evidence().account.last_trans_lt
                && cell.repr_hash().as_array() == snapshot.last_transaction_hash()
        }) else {
            continue;
        };
        let snapshot_next = commitment_next(config, &snapshot)?;
        let counter = if position <= target {
            counter_at(&deltas, snapshot_next, position, target)?
        } else {
            let forward = history[target..position]
                .iter()
                .map(|(_, tx)| append_count(tx))
                .collect::<Result<Vec<_>>>()?;
            counter_at(&forward, snapshot_next, forward.len(), 0)?
        };
        if let Some(counter) = counter {
            recovery_appends(&deltas, next, counter)?;
            return Ok(counter);
        }
    }
    anyhow::bail!("no authenticated checkpoint isolates the destination from intervening mutations")
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
    if let Some(cached) = store.refusal(&id)? {
        let cached = protocol::parse(&cached)?;
        if !matches!(
            cached["schema"].as_str(),
            Some("tos.br1.native-nonacceptance.v1" | "tos.br1.native-refusal.v1")
        ) || cached["evidence"]["proof_digest"]
            != protocol::hash(&protocol::canonical(&cached["witness"])?)
        {
            return Ok(Value::Null);
        }
        return Ok(cached["evidence"].clone());
    }
    if let Some((receipt, witness)) =
        crate::nonacceptance::prove(config, &chain, &record, &candidate, &payload["prepared"])
            .await?
    {
        let message = store
            .lookup(&id)?
            .and_then(|lease| lease.message)
            .ok_or_else(|| anyhow::anyhow!("nonacceptance unsigned lease"))?;
        let retained = json!({"schema":"tos.br1.native-nonacceptance.v1","evidence":receipt,"witness":witness});
        store.retire_refused(&id, &message, &protocol::canonical(&retained)?)?;
        return Ok(receipt);
    }
    let pool_address = MsgAddressInt::from_str(&config.release.pool)?;
    let funding = MsgAddressInt::from_str(&config.funding_wallet)?;
    let pool = chain.verifier().read_account(&pool_address, &ReadPolicy::Live).await?;
    commitment_next(config, &pool)?;
    let transactions = history(config, &config.release.pool, &pool).await?;
    let mut target = None;
    for (index, (cell, transaction)) in transactions.iter().enumerate() {
        let (_, message) = inbound(transaction)?;
        let matches = message.body().is_some_and(|b| {
            b.clone().into_cell().is_ok_and(|body| body.repr_hash() == candidate.body.repr_hash())
        });
        if matches && owned_inbound(&message, &funding, &pool_address) {
            target = Some((index, cell.repr_hash().to_hex_string(), transaction));
            break;
        }
    }
    let Some((index, transaction_hash, transaction)) = target else { return Ok(Value::Null) };
    let leaf = if atomic_abort(transaction)? {
        None
    } else {
        let next =
            counter_at_destination(config, &chain, &pool_address, &pool, &transactions, index)
                .await?;
        target_leaf(transaction, next, candidate.request.fee_slot)?
    };
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
    let Some(leaf) = leaf else {
        // The descriptor alone is not a refusal witness: exact prepared wallet
        // execution and its actual outbound-to-inbound link were proven above.
        let proof = pool.evidence();
        let witness = json!({"kind":"pool_atomic_abort_linked_to_prepared","release":config.release.scope()?,
            "request":id,"source_external":payload["prepared"]["message_hash"],
            "pool_state":proof.account.state_hash,"wallet_state":wallet.evidence().account.state_hash,
            "pool_transaction":transaction_hash,"destination_inbound":destination_in.to_hex_string(),
            "checkpoint_root":proof.checkpoint.root_hash,"checkpoint_file":proof.checkpoint.file_hash,"checkpoint_seqno":proof.checkpoint.seqno});
        let digest = protocol::hash(&protocol::canonical(&witness)?);
        let receipt = json!({"kind":"terminal_refusal","scope":config.release.scope()?,"request":id,"message_hash":payload["prepared"]["message_hash"],"pool":config.release.pool,"intent":candidate.request.intent,"body_sha256":candidate.request.body_sha256,"checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime},"proof_digest":digest,"transaction":transaction_hash,"fee_credit":null});
        let retained =
            json!({"schema":"tos.br1.native-refusal.v1","evidence":receipt,"witness":witness});
        let message = store
            .lookup(&id)?
            .and_then(|lease| lease.message)
            .ok_or_else(|| anyhow::anyhow!("refusal unsigned lease"))?;
        store.retire_refused(&id, &message, &protocol::canonical(&retained)?)?;
        return Ok(receipt);
    };
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
    fn described(aborted: bool, destroyed: bool) -> Result<Transaction> {
        let mut transaction = Transaction::default();
        transaction.write_description(&TransactionDescr::Ordinary(
            chain_block::TransactionDescrOrdinary { aborted, destroyed, ..Default::default() },
        ))?;
        Ok(transaction)
    }
    #[test]
    fn native_cpp_gas_and_action_abort_fixtures_never_mint_a_fee() -> Result<()> {
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../../test/bonded-relayer/fixtures/native-refusal/manifest.json"
        ))?;
        assert_eq!(
            manifest["source_sha256"],
            protocol::hash(include_bytes!(
                "../../../../test/bonded-relayer/fixtures/native-refusal/phases.fc"
            ))
        );
        let cases: [(&str, &[u8], bool); 4] = [
            (
                "gas-positive",
                include_bytes!(
                    "../../../../test/bonded-relayer/fixtures/native-refusal/gas-positive.boc"
                ),
                false,
            ),
            (
                "gas-exhausted",
                include_bytes!(
                    "../../../../test/bonded-relayer/fixtures/native-refusal/gas-exhausted.boc"
                ),
                true,
            ),
            (
                "action-positive",
                include_bytes!(
                    "../../../../test/bonded-relayer/fixtures/native-refusal/action-positive.boc"
                ),
                false,
            ),
            (
                "action-no-funds",
                include_bytes!(
                    "../../../../test/bonded-relayer/fixtures/native-refusal/action-no-funds.boc"
                ),
                true,
            ),
        ];
        let metadata =
            manifest["cases"].as_array().ok_or_else(|| anyhow::anyhow!("fixture cases"))?;
        for (name, bytes, aborted) in cases {
            let expected = metadata
                .iter()
                .find(|case| case["name"] == name)
                .ok_or_else(|| anyhow::anyhow!("fixture missing"))?;
            assert_eq!(expected["sha256"], protocol::hash(bytes));
            let transaction =
                Transaction::construct_from_cell(chain_block::read_single_root_boc(bytes)?)?;
            assert_eq!(atomic_abort(&transaction)?, aborted);
            if aborted {
                assert!(simulation::successful(&transaction).is_err());
                assert_eq!(target_leaf(&transaction, 0, 2)?, None);
                assert_eq!(append_count(&transaction)?, Some(0));
            } else {
                simulation::successful(&transaction)?;
            }
        }
        Ok(())
    }
    #[test]
    fn atomic_abort_never_mints_fee_and_destroyed_or_nonaborted_failures_stay_unknown() -> Result<()>
    {
        let aborted = described(true, false)?;
        assert_eq!(append_count(&aborted)?, Some(0));
        assert_eq!(target_leaf(&aborted, 0, 2)?, None);
        assert!(target_leaf(&described(false, false)?, 3, 2).is_err());
        let error = target_leaf(&described(true, true)?, 3, 2)
            .err()
            .ok_or_else(|| anyhow::anyhow!("destroyed pool accepted"))?;
        assert!(error.to_string().contains("destroyed pool needs separate evidence"));
        Ok(())
    }
    #[test]
    fn matching_body_from_another_sender_is_not_this_workers_attempt() -> Result<()> {
        let funding = MsgAddressInt::from_str(&format!("0:{}", "01".repeat(32)))?;
        let other = MsgAddressInt::from_str(&format!("0:{}", "02".repeat(32)))?;
        let pool = MsgAddressInt::from_str(&format!("0:{}", "03".repeat(32)))?;
        let message = tos_sandbox::MessageBuilder::internal(&funding, &pool, 1).build();
        assert!(owned_inbound(&message, &funding, &pool));
        assert!(!owned_inbound(&message, &other, &pool));
        assert!(!owned_inbound(&message, &funding, &other));
        let mut bounced = message;
        bounced.int_header_mut().ok_or_else(|| anyhow::anyhow!("internal header"))?.bounced = true;
        assert!(!owned_inbound(&bounced, &funding, &pool));
        Ok(())
    }
    #[test]
    fn plain_bounce_does_not_move_fee_leaf_cursor() -> Result<()> {
        assert_eq!(counter_delta(&incoming(0x53485001, true)?)?, Some(0));
        Ok(())
    }
    #[test]
    fn fee_leaf_uses_the_same_historical_counter_with_or_without_recovery_credit() -> Result<()> {
        // Newest first: a later deposit, the recovery, the withdrawal, and
        // the deposit immediately preceding it. The recovery may mint zero
        // or one leaf, so the live counter alone cannot place the fee note.
        let deltas = [Some(1), None, Some(3), Some(1)];
        for (live, appended) in [(5, 0), (6, 1)] {
            assert_eq!(counter_at(&deltas, live, 0, 2)?, None);
            assert_eq!(recovery_appends(&deltas[..2], live, 4)?, appended);
        }
        assert!(recovery_appends(&deltas[..2], 7, 4).is_err());
        assert_eq!(counter_at(&deltas, 4, 2, 2)?, Some(4));
        // Even if the withdrawal and bounce first appear in the same
        // checkpoint, the preceding proven state can place the fee.
        assert_eq!(counter_at(&deltas, 1, 3, 2)?, Some(4));
        Ok(())
    }
    #[test]
    fn native_withdrawal_bounce_history_places_the_original_fee_leaf() -> Result<()> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../shielded-pool-circuit/fixtures/pool-history-development.json"
        ))?;
        let decode = |value: &Value| -> Result<Cell> {
            let encoded = value.as_str().ok_or_else(|| anyhow::anyhow!("fixture BOC absent"))?;
            chain_block::read_single_root_boc(&hex::decode(encoded)?)
        };
        let state =
            node_contracts::shielded_pool::PoolState::parse(&decode(&fixture["account_data"])?)?;
        let rows = fixture["transactions"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("fixture history absent"))?;
        let transactions = rows
            .iter()
            .rev()
            .map(|row| Transaction::construct_from_cell(decode(&row["boc"])?))
            .collect::<Result<Vec<_>>>()?;
        let deltas = transactions.iter().take(3).map(append_count).collect::<Result<Vec<_>>>()?;
        assert_eq!(deltas, [Some(3), None, Some(3)]);
        assert_eq!(counter_at(&deltas, state.commitment_next_index, 0, 2)?, None);
        let before = 4;
        assert_eq!(counter_at(&deltas, before, 3, 2)?, Some(7));
        assert_eq!(recovery_appends(&deltas[..2], state.commitment_next_index, 7)?, 1);
        assert_eq!(target_leaf(&transactions[2], 7, 2)?, Some(6));
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
