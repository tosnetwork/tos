// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{
    candidate::Candidate, chain::Chain, config::Config, identity::Identity, protocol, quotes,
    simulation, store::Store,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{write_boc, Deserializable, Message};
use node_contracts::{relayer_bond::RelayerBond, Wallet};
use serde_json::{json, Value};
use std::{path::Path, str::FromStr};

pub fn check_quote(
    config: &Config,
    identity: &Identity,
    envelope: &Value,
    current: bool,
) -> Result<Value> {
    protocol::fields(envelope, &["schema", "terms", "public_key_b64", "signature_b64"])?;
    ensure!(envelope["schema"] == "tos.br1.quote.v1", "quote schema");
    let terms = protocol::canonical(&envelope["terms"])?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let checked =
        quotes::validate(&terms, config, identity, if current { Some(now) } else { None })?;
    identity.verify(
        &terms,
        envelope["public_key_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote key"))?,
        envelope["signature_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote signature"))?,
    )?;
    Ok(checked)
}
fn binding(slot: u64, issued: u32, funding: u64, sequence: u32) -> Result<String> {
    Ok(protocol::hash(&protocol::canonical(
        &json!({"slot":slot,"issued_at":issued,"funding":funding,"sequence":sequence}),
    )?))
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().ok_or_else(|| anyhow::anyhow!("prepared integer"))
}
fn hash32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
pub async fn prepare(
    config: &Config,
    identity: &Identity,
    directory: &Path,
    payload: &Value,
) -> Result<Value> {
    protocol::fields(payload, &["release", "request", "quote", "slot", "issued_at", "funding"])?;
    let terms = check_quote(config, identity, &payload["quote"], true)?;
    let candidate = Candidate::parse(&payload["request"], config, identity, &terms)?;
    let slot = integer(payload, "slot")?;
    let issued = u32::try_from(integer(payload, "issued_at")?)?;
    let funding = integer(payload, "funding")?;
    let mut store = Store::open(&directory.join("leases.db"), &config.release.scope()?)?;
    store.assert_claimable(&candidate.identity, &candidate.request.quote_hash, slot)?;
    if let Some(prior) = store.lookup(&candidate.identity)? {
        store.claim_quote(&candidate.identity, &candidate.request.quote_hash)?;
        ensure!(
            prior.binding == binding(slot, issued, funding, prior.sequence)?,
            "prepared lease parameters changed"
        );
        let message = prior
            .message
            .ok_or_else(|| anyhow::anyhow!("interrupted signing requires manual reconciliation"))?;
        let record = protocol::parse(&store.record(&candidate.identity)?)?;
        return Ok(
            json!({"message_b64":STANDARD.encode(&message),"message_hash":crate::candidate::ordinary_boc(&message)?.repr_hash().to_hex_string(),"acceptance_b64":record["acceptance_b64"]}),
        );
    }
    let chain = Chain::new(config)?;
    let simulated = simulation::run(config, &chain, &candidate).await?;
    ensure!(funding == simulated.funding, "funding estimate changed");
    let (wallet_state, sequence) = chain.funding(config).await?;
    ensure!(
        wallet_state.evidence().account.balance.parse::<u128>()?
            >= u128::from(funding)
                .checked_add(100_000_000)
                .ok_or_else(|| anyhow::anyhow!("funding balance overflow"))?,
        "funding wallet insufficient"
    );
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    ensure!(
        u64::from(issued) <= now
            && now.checked_sub(u64::from(issued)).is_some_and(|age| age <= 60)
            && now
                .checked_add(125)
                .is_some_and(|end| end <= u64::from(candidate.request.valid_until)),
        "insufficient/current acceptance lifetime"
    );
    let lease =
        store.reserve(&candidate.identity, &binding(slot, issued, funding, sequence)?, sequence)?;
    ensure!(lease.fresh, "interrupted signing refused");
    store.bind_slot(&candidate.identity, slot)?;
    store.claim_quote(&candidate.identity, &candidate.request.quote_hash)?;
    let (_, bond) = chain.bond(config).await?;
    let receipt = RelayerBond::acceptance(
        slot,
        issued,
        candidate.request.valid_until,
        &hash32(&candidate.request.intent)?,
        &hash32(&candidate.request.body_sha256)?,
        &hash32(&candidate.request.quote_hash)?,
        &hash32(&candidate.request.fee_note_body)?,
    )?;
    let acceptance = protocol::canonical(
        &json!({"schema":"tos.br1.acceptance.v1","receipt_b64":STANDARD.encode(write_boc(&receipt)?),"signature_b64":STANDARD.encode(identity.acceptance(&bond.init,&receipt)?)}),
    )?;
    let wallet = crate::funding::wallet(config, directory).await?;
    let message = wallet
        .build_message(
            chain_block::MsgAddressInt::from_str(&config.release.pool)?,
            funding,
            candidate.body,
            true,
            Some(sequence),
            None,
            None,
        )
        .await?;
    let bytes = write_boc(&message)?;
    let record = protocol::canonical(
        &json!({"quote":payload["quote"],"slot":slot,"issued_at":issued,"funding":funding,"sequence":sequence,"acceptance_b64":STANDARD.encode(&acceptance)}),
    )?;
    store.persist_prepared(&candidate.identity, &bytes, &record)?;
    Ok(
        json!({"message_b64":STANDARD.encode(&bytes),"message_hash":message.repr_hash().to_hex_string(),"acceptance_b64":STANDARD.encode(&acceptance)}),
    )
}

pub fn validate(
    config: &Config,
    identity: &Identity,
    directory: &Path,
    payload: &Value,
) -> Result<Value> {
    protocol::fields(payload, &["release", "request", "prepared", "slot", "issued_at", "funding"])?;
    let request: crate::candidate::Request = serde_json::from_value(payload["request"].clone())?;
    let mut raw = b"TOS-BR1-REQUEST\0".to_vec();
    raw.extend(protocol::canonical(&payload["request"])?);
    let id = protocol::hash(&raw);
    let store = Store::open(&directory.join("leases.db"), &config.release.scope()?)?;
    let lease = store.lookup(&id)?.ok_or_else(|| anyhow::anyhow!("unknown native lease"))?;
    let record = protocol::parse(&store.record(&id)?)?;
    let terms = check_quote(config, identity, &record["quote"], false)?;
    let candidate = Candidate::parse(&payload["request"], config, identity, &terms)?;
    for name in ["slot", "issued_at", "funding"] {
        ensure!(payload[name] == record[name], "native prepared binding mismatch");
    }
    let prepared = &payload["prepared"];
    protocol::fields(prepared, &["message_b64", "message_hash", "acceptance_b64"])?;
    let bytes = lease.message.ok_or_else(|| anyhow::anyhow!("native message missing"))?;
    ensure!(
        prepared["message_b64"] == STANDARD.encode(&bytes)
            && prepared["acceptance_b64"] == record["acceptance_b64"],
        "prepared bytes changed"
    );
    let cell = crate::candidate::ordinary_boc(&bytes)?;
    ensure!(
        prepared["message_hash"] == cell.repr_hash().to_hex_string(),
        "prepared TVM hash changed"
    );
    let message = Message::construct_from_cell(cell)?;
    ensure!(
        message.is_inbound_external()
            && message.dst() == Some(chain_block::MsgAddressInt::from_str(&config.funding_wallet)?)
            && message.state_init().is_none(),
        "funding external envelope"
    );
    let mut body = message.body().ok_or_else(|| anyhow::anyhow!("funding body absent"))?.clone();
    let signature: [u8; 64] =
        body.get_next_bytes(64)?.try_into().map_err(|_| anyhow::anyhow!("wallet signature"))?;
    let signed = body.clone().into_cell()?;
    let seed = crate::private_io::seed(&directory.join("funding.seed"))?;
    ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().verify_strict(
        signed.repr_hash().as_slice(),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )?;
    ensure!(
        body.get_next_i32()? == config.release.global_id && body.get_next_u32()? == 3,
        "funding network binding"
    );
    let expire = body.get_next_u32()?;
    ensure!(expire <= request.valid_until, "wallet may outlive candidate");
    ensure!(
        body.get_next_u32()? == lease.sequence
            && body.get_next_int(8)? == 3
            && body.remaining_bits() == 0
            && body.remaining_references() == 1,
        "funding sequence/send mode"
    );
    let internal = Message::construct_from_cell(body.checked_drain_reference()?)?;
    let header =
        internal.int_header().ok_or_else(|| anyhow::anyhow!("internal transfer missing"))?;
    ensure!(
        header.dst == chain_block::MsgAddressInt::from_str(&config.release.pool)?
            && header.bounce
            && header.value.coins.to_string() == integer(payload, "funding")?.to_string(),
        "funding destination/value"
    );
    ensure!(
        internal
            .body()
            .ok_or_else(|| anyhow::anyhow!("Shield body absent"))?
            .clone()
            .into_cell()?
            .repr_hash()
            == candidate.body.repr_hash(),
        "funding Shield body mismatch"
    );
    let acceptance = STANDARD.decode(
        prepared["acceptance_b64"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("acceptance encoding"))?,
    )?;
    ensure!(
        lease.binding
            == binding(
                integer(payload, "slot")?,
                u32::try_from(integer(payload, "issued_at")?)?,
                integer(payload, "funding")?,
                lease.sequence
            )?,
        "native immutable lease binding"
    );
    let acceptance_value = protocol::parse(&acceptance)?;
    protocol::fields(&acceptance_value, &["schema", "receipt_b64", "signature_b64"])?;
    ensure!(
        acceptance_value["schema"] == "tos.br1.acceptance.v1"
            && protocol::canonical(&acceptance_value)? == acceptance,
        "acceptance schema/encoding"
    );
    let receipt_text = acceptance_value["receipt_b64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("receipt encoding"))?;
    ensure!(receipt_text.len() <= 16384, "receipt byte bound");
    let receipt = crate::candidate::ordinary_boc(&STANDARD.decode(receipt_text)?)?;
    let expected = RelayerBond::acceptance(
        integer(payload, "slot")?,
        u32::try_from(integer(payload, "issued_at")?)?,
        request.valid_until,
        &hash32(&request.intent)?,
        &hash32(&request.body_sha256)?,
        &hash32(&request.quote_hash)?,
        &hash32(&request.fee_note_body)?,
    )?;
    ensure!(receipt.repr_hash() == expected.repr_hash(), "acceptance does not bind candidate");
    let init_bytes = crate::private_io::read(&directory.join("bond-init.boc"), 65536)?;
    let init =
        chain_block::StateInit::construct_from_cell(crate::candidate::ordinary_boc(&init_bytes)?)?;
    let address = chain_block::MsgAddressInt::from_str(&config.release.bond)?;
    let bond = RelayerBond::decode(
        &address,
        &init.data.ok_or_else(|| anyhow::anyhow!("initial bond data absent"))?,
    )?;
    ensure!(
        RelayerBond::address(&bond.init)? == address
            && protocol::hash(&bond.init.worker_key) == config.release.worker_key_hash,
        "acceptance immutable worker"
    );
    let signature = crate::identity::decode(
        acceptance_value["signature_b64"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("acceptance signature"))?,
        2420,
    )?;
    let signature: [u8; 2420] =
        signature.try_into().map_err(|_| anyhow::anyhow!("signature width"))?;
    let public: [u8; 1312] =
        bond.init.worker_key.clone().try_into().map_err(|_| anyhow::anyhow!("worker width"))?;
    use fips204::traits::{SerDes as _, Verifier as _};
    let public = fips204::ml_dsa_44::PublicKey::try_from_bytes(public)
        .map_err(|_| anyhow::anyhow!("worker key encoding"))?;
    let digest = RelayerBond::signing_hash(
        &bond.init,
        node_contracts::relayer_bond::ACCEPTANCE_TAG,
        receipt.repr_hash().as_array(),
    )?;
    ensure!(
        public.verify(&digest, &signature, node_contracts::relayer_bond::CONTEXT),
        "acceptance signature refused"
    );
    Ok(
        json!({"scope":config.release.scope()?,"request":id,"slot":payload["slot"],"issued_at":payload["issued_at"],"funding":payload["funding"],"message_hash":prepared["message_hash"],"message_sha256":protocol::hash(&bytes),"acceptance_sha256":protocol::hash(&acceptance)}),
    )
}

/// Check only at send admission, never when authenticating historical evidence.
pub fn check_send_expiry(bytes: &[u8], now: u64) -> Result<()> {
    let message = Message::construct_from_cell(crate::candidate::ordinary_boc(bytes)?)?;
    let mut body = message.body().ok_or_else(|| anyhow::anyhow!("funding body absent"))?.clone();
    body.get_next_bytes(64)?;
    body.get_next_i32()?;
    body.get_next_u32()?;
    let expiry = u64::from(body.get_next_u32()?);
    ensure!(
        now.checked_add(5).is_some_and(|end| end < expiry),
        "funding wallet expires before send budget"
    );
    Ok(())
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use chain_block::{BuilderData, ExternalInboundMessageHeader, IBitstring, Serializable};
    #[test]
    fn send_budget_refuses_expired_and_near_expiry_wallets() -> Result<()> {
        let mut body = BuilderData::new();
        body.append_raw(&[0; 64], 512)?.append_i32(3)?.append_u32(3)?.append_u32(1120)?;
        let mut message = Message::with_ext_in_header(ExternalInboundMessageHeader::default());
        message.set_body(chain_block::SliceData::load_cell(body.into_cell()?)?);
        let bytes = write_boc(&message.serialize()?)?;
        check_send_expiry(&bytes, 1114)?;
        for now in [1115, 1120, 1200, u64::MAX] {
            let error = check_send_expiry(&bytes, now)
                .err()
                .ok_or_else(|| anyhow::anyhow!("expiry guard missing"))?;
            assert!(error.to_string().contains("funding wallet expires before send budget"));
        }
        Ok(())
    }
}
