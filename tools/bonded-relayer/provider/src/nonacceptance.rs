// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Expiry alone is insufficient: the proven wallet head must be unchanged since signing.
use crate::{candidate::Candidate, chain::Chain, config::Config, prepared, protocol};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use node_contracts::proven_getters::ProvenGetterResults;
use serde_json::{json, Value};

fn unchanged_after_expiry(
    record: &Value,
    sequence: u32,
    head: &str,
    lt: u64,
    time: u32,
    expiry: u32,
) -> bool {
    record["sequence"].as_u64() == Some(u64::from(sequence))
        && record["funding_head_hash"].as_str() == Some(head)
        && record["funding_head_lt"].as_u64() == Some(lt)
        && time >= expiry
}

fn unchanged_at_wallet_block(
    record: &Value,
    sequence: u32,
    head: &str,
    proof: &ProvenGetterResults,
    expiry: u32,
) -> bool {
    // A newer masterchain checkpoint may still commit an older shard state.
    // Only the actual wallet shard's time closes its acceptance window.
    unchanged_after_expiry(
        record,
        sequence,
        head,
        proof.account.last_trans_lt,
        proof.account.gen_utime,
        expiry,
    )
}

pub async fn prove(
    config: &Config,
    chain: &Chain,
    record: &Value,
    candidate: &Candidate,
    signed: &Value,
) -> Result<Option<(Value, Value)>> {
    // Legacy records cannot establish an unchanged pre-signing head. Never
    // manufacture a baseline from today's state or infer absence from timeout.
    if record["funding_head_hash"].as_str().is_none()
        || record["funding_head_lt"].as_u64().is_none()
    {
        return Ok(None);
    }
    let encoded =
        signed["message_b64"].as_str().ok_or_else(|| anyhow::anyhow!("signed wallet bytes"))?;
    let expiry = prepared::wallet_expiry(&STANDARD.decode(encoded)?)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    if now < u64::from(expiry) {
        return Ok(None);
    }
    let (wallet, sequence) = chain.funding(config).await?;
    let proof = wallet.evidence();
    let head = hex::encode(wallet.last_transaction_hash());
    if !unchanged_at_wallet_block(record, sequence, &head, proof, expiry) {
        return Ok(None);
    }
    let witness = json!({
        "kind":"wallet_expired_unchanged_head", "release":config.release.scope()?, "request":candidate.identity,
        "source_external":signed["message_hash"], "wallet_state":proof.account.state_hash,
        "pre_signing_head":record["funding_head_hash"], "pre_signing_lt":record["funding_head_lt"],
        "wallet_head":head,"wallet_sequence":sequence,"wallet_expiry":expiry,
        "checkpoint_root":proof.checkpoint.root_hash,"checkpoint_file":proof.checkpoint.file_hash,"checkpoint_seqno":proof.checkpoint.seqno,
        "masterchain_time":proof.block_gen_utime,"wallet_shard_time":proof.account.gen_utime
    });
    let digest = protocol::hash(&protocol::canonical(&witness)?);
    Ok(Some((
        json!({"kind":"terminal_refusal","scope":config.release.scope()?,"request":candidate.identity,"message_hash":signed["message_hash"],"pool":config.release.pool,"intent":candidate.request.intent,"body_sha256":candidate.request.body_sha256,"checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime},"proof_digest":digest,"transaction":head,"fee_credit":null}),
        witness,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newer_masterchain_time_cannot_expire_an_older_wallet_shard_state() {
        use node_contracts::{
            chain_provider::MasterchainCheckpoint, proven_getters::ProvenAccount,
        };
        let record = json!({"sequence":7,"funding_head_hash":"head","funding_head_lt":100});
        let mut proof = ProvenGetterResults {
            live: true,
            checkpoint: MasterchainCheckpoint {
                seqno: 1,
                root_hash: "01".repeat(32),
                file_hash: "02".repeat(32),
            },
            block_gen_utime: 130,
            account: ProvenAccount {
                address: format!("0:{}", "03".repeat(32)),
                state_hash: "04".repeat(32),
                balance: "100".into(),
                code_hash: "05".repeat(32),
                data_hash: "06".repeat(32),
                last_trans_lt: 100,
                gen_utime: 119,
            },
            results: vec![],
            request_sha256: "07".repeat(32),
        };
        assert!(!unchanged_at_wallet_block(&record, 7, "head", &proof, 120));
        proof.account.gen_utime = 120;
        assert!(unchanged_at_wallet_block(&record, 7, "head", &proof, 120));
    }
    #[test]
    fn nonacceptance_requires_unchanged_signing_head_sequence_and_finalized_expiry() {
        let record = json!({"sequence":7,"funding_head_hash":"head","funding_head_lt":100});
        assert!(unchanged_after_expiry(&record, 7, "head", 100, 120, 120));
        assert!(!unchanged_after_expiry(&record, 8, "head", 100, 120, 120));
        assert!(!unchanged_after_expiry(&record, 7, "changed", 100, 120, 120));
        assert!(!unchanged_after_expiry(&record, 7, "head", 101, 120, 120));
        assert!(!unchanged_after_expiry(&record, 7, "head", 100, 119, 120));
        assert!(!unchanged_after_expiry(&json!({"sequence":7}), 7, "head", 100, 120, 120));
    }
}
