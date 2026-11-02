// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{chain::Chain, config::Config, identity::Identity, protocol, quotes};
use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::str::FromStr;

pub async fn dispatch(operation: &str, payload: &Value) -> Result<Value> {
    let directory = std::env::current_dir()?;
    let _lock = crate::private_io::lock(&directory)?;
    let config = Config::load(&directory, payload)?;
    let identity =
        Identity::load(&directory, &config.execution_domain, &config.release.worker_key_hash)?;
    let pool: [u8; 32] = hex::decode(&config.release.pool[2..])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pool id"))?;
    let domain = shielded_pool_circuit::wire::execution_domain(config.release.global_id, &pool);
    ensure!(
        hex::encode(shielded_pool_wallet::keys::fr_be32(domain)) == config.execution_domain,
        "pool execution domain pin mismatch"
    );
    let scope = config.release.scope()?;
    match operation {
        "capabilities" => {
            protocol::fields(payload, &["release"])?;
            let chain = Chain::new(&config)?;
            chain.bond(&config).await?;
            let (wallet, _) = chain.funding(&config).await?;
            ensure!(
                wallet.evidence().account.balance.parse::<u128>()?
                    >= u128::from(config.funding_cap)
                        .checked_add(100_000_000)
                        .ok_or_else(|| anyhow::anyhow!("funding admission overflow"))?,
                "funding wallet below admission reserve"
            );
            crate::store::Store::open(&directory.join("leases.db"), &scope)?;
            Ok(
                json!({"scope":scope,"protocol":"tos.br1.native.v1","features":["live_bond_v1","shield_exact_simulation_v1","worker_mldsa44_v1","funded_wallet_v1","wallet_sequence_lease_v1","destination_finality_v1","fee_note_import_v1","quote_descriptor_v1","proven_pool_head_v1"]}),
            )
        }
        "pool_head" => {
            protocol::fields(payload, &["release"])?;
            let chain = Chain::new(&config)?;
            let (bond, _) = chain.bond(&config).await?;
            let pool = chain
                .verifier()
                .read_account(
                    &chain_block::MsgAddressInt::from_str(&config.release.pool)?,
                    &node_contracts::proven_getters::ReadPolicy::Historical(
                        bond.evidence().checkpoint.clone(),
                    ),
                )
                .await?;
            bond.require_same_checkpoint(&pool)?;
            ensure!(
                pool.evidence().account.code_hash == config.release.pool_code_hash,
                "pool snapshot code pin"
            );
            let data =
                pool.account().get_data().ok_or_else(|| anyhow::anyhow!("pool snapshot data"))?;
            ensure!(
                data.reference(2)?.repr_hash().to_hex_string() == config.release.pool_config_hash,
                "pool snapshot configuration pin"
            );
            let proof = pool.evidence();
            Ok(
                json!({"schema":"tos.br1.proven-pool-head.v1","scope":scope,"pool":config.release.pool,
                "checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime},
                "account_state_hash":proof.account.state_hash,"account_shard_time":proof.account.gen_utime,
                "last_transaction_hash":hex::encode(pool.last_transaction_hash()),"last_transaction_lt":proof.account.last_trans_lt}),
            )
        }
        "descriptor" => {
            protocol::fields(payload, &["release", "note_index"])?;
            let index =
                payload["note_index"].as_u64().ok_or_else(|| anyhow::anyhow!("note index"))?;
            Chain::new(&config)?.bond(&config).await?;
            Ok(
                json!({"scope":scope,"note_index":index,"descriptor_b64":STANDARD.encode(identity.descriptor(index)?)}),
            )
        }
        "sign_quote" => {
            protocol::fields(payload, &["release", "terms_b64"])?;
            let encoded =
                payload["terms_b64"].as_str().ok_or_else(|| anyhow::anyhow!("terms base64"))?;
            ensure!(!encoded.is_empty() && encoded.len() <= 21848, "terms base64 bound");
            let bytes = STANDARD.decode(encoded)?;
            ensure!(STANDARD.encode(&bytes) == encoded, "terms canonical encoding");
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            quotes::validate(&bytes, &config, &identity, Some(now))?;
            Chain::new(&config)?.bond(&config).await?;
            identity.sign(&bytes)
        }
        "verify_quote" => {
            protocol::fields(payload, &["release", "envelope"])?;
            let envelope = &payload["envelope"];
            protocol::fields(envelope, &["schema", "terms", "public_key_b64", "signature_b64"])?;
            ensure!(envelope["schema"] == "tos.br1.quote.v1", "quote envelope schema");
            let bytes = protocol::canonical(&envelope["terms"])?;
            // Historical validation authenticates the original terms even after
            // their expiry; current admission enforces freshness separately.
            quotes::validate(&bytes, &config, &identity, None)?;
            let public =
                envelope["public_key_b64"].as_str().ok_or_else(|| anyhow::anyhow!("worker key"))?;
            let signature = envelope["signature_b64"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("quote signature"))?;
            identity.verify(&bytes, public, signature)
        }
        "preflight" => {
            protocol::fields(payload, &["release", "request", "quote"])?;
            let terms = crate::prepared::check_quote(&config, &identity, &payload["quote"], true)?;
            let candidate = crate::candidate::Candidate::parse(
                &payload["request"],
                &config,
                &identity,
                &terms,
            )?;
            let chain = Chain::new(&config)?;
            let simulated = crate::simulation::run(&config, &chain, &candidate).await?;
            let proof = simulated.pool.evidence();
            Ok(
                json!({"scope":scope,"request":candidate.identity,"body_sha256":candidate.request.body_sha256,"funding":simulated.funding,"checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime}}),
            )
        }
        "prepare" => crate::prepared::prepare(&config, &identity, &directory, payload).await,
        "validate_prepared" => crate::prepared::validate(&config, &identity, &directory, payload),
        "recheck" => {
            protocol::fields(payload, &["release", "request", "prepared"])?;
            let mut bytes = b"TOS-BR1-REQUEST\0".to_vec();
            bytes.extend(protocol::canonical(&payload["request"])?);
            let id = protocol::hash(&bytes);
            let mut store = crate::store::Store::open(&directory.join("leases.db"), &scope)?;
            let lease =
                store.lookup(&id)?.ok_or_else(|| anyhow::anyhow!("unknown native lease"))?;
            let record = protocol::parse(&store.record(&id)?)?;
            crate::prepared::validate(
                &config,
                &identity,
                &directory,
                &json!({"release":payload["release"],"request":payload["request"],"prepared":payload["prepared"],"slot":record["slot"],"issued_at":record["issued_at"],"funding":record["funding"]}),
            )?;
            let terms = crate::prepared::check_quote(&config, &identity, &record["quote"], true)?;
            let candidate = crate::candidate::Candidate::parse(
                &payload["request"],
                &config,
                &identity,
                &terms,
            )?;
            let chain = Chain::new(&config)?;
            let simulated = crate::simulation::run(&config, &chain, &candidate).await?;
            let (_, sequence) = chain.funding(&config).await?;
            ensure!(sequence == lease.sequence, "funding sequence no longer current");
            let message = lease.message.ok_or_else(|| anyhow::anyhow!("unsigned lease"))?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            crate::prepared::require_live_wallet(&message, now, 5)?;
            let mut random = [0; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
            let permit = hex::encode(random);
            store.permit(&id, &permit, &protocol::hash(&message), now)?;
            let proof = simulated.pool.evidence();
            Ok(
                json!({"scope":scope,"request":id,"message_hash":payload["prepared"]["message_hash"],"checkpoint":{"seqno":proof.checkpoint.seqno,"root_hash":proof.checkpoint.root_hash,"file_hash":proof.checkpoint.file_hash,"utime":proof.block_gen_utime},"permit":permit}),
            )
        }
        "broadcast" => {
            protocol::fields(payload, &["release", "message_b64", "permit"])?;
            let encoded =
                payload["message_b64"].as_str().ok_or_else(|| anyhow::anyhow!("message base64"))?;
            ensure!(encoded.len() <= 699052, "broadcast body bound");
            let bytes = STANDARD.decode(encoded)?;
            ensure!(STANDARD.encode(&bytes) == encoded, "broadcast canonical bytes");
            let permit = protocol::digest(&payload["permit"])?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let mut store = crate::store::Store::open(&directory.join("leases.db"), &scope)?;
            crate::prepared::require_live_wallet(&bytes, now, 0)?;
            store.consume(permit, &bytes, now)?;
            let url = config.rpc_url.clone();
            let encoded = encoded.to_owned();
            tokio::task::spawn_blocking(move || {
                crate::transport::rpc(&url, "sendBoc", json!({"boc":encoded}))
            })
            .await??;
            Ok(json!({"submitted_sha256":protocol::hash(&bytes)}))
        }
        "evidence" => crate::evidence::run(&config, &identity, &directory, payload).await,
        _ => bail!("native provider integration incomplete"),
    }
}
