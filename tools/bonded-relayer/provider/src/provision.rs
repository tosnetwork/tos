// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Explicit creation of fresh network-bound test custody; never repairs/reset keys.
use crate::{
    config::{Config, Release},
    protocol,
    store::Store,
};
use anyhow::{ensure, Result};
use chain_block::{write_boc, Serializable, StateInit};
use common::WalletVersion;
use ed25519_dalek::SigningKey;
use fips204::{
    ml_dsa_44,
    traits::{KeyGen as _, SerDes as _, Signer as _},
};
use node_contracts::{
    relayer_bond::{BondInit, RelayerBond, CONTEXT, POP_TAG},
    wallet::wallet_contract::WalletContract,
    Wallet,
};
use rand::RngCore as _;
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn hash32(v: &Value) -> Result<[u8; 32]> {
    let s = protocol::digest(v)?;
    hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("hash width"))
}
pub async fn run(input: &Path, out: &Path) -> Result<()> {
    let bytes = crate::private_io::read(input, 64 * 1024)?;
    let t = protocol::parse(&bytes)?;
    protocol::fields(
        &t,
        &[
            "schema",
            "global_id",
            "genesis_root",
            "genesis_file",
            "pool",
            "pool_code_hash",
            "pool_config_hash",
            "execution_domain",
            "endpoint",
            "fee",
            "funding_cap",
            "rpc_url",
            "proof_verifier",
            "proof_verifier_sha256",
        ],
    )?;
    ensure!(t["schema"] == "tos.br1.provision.v1", "provisioning schema");
    let global_id = i32::try_from(
        t["global_id"].as_i64().ok_or_else(|| anyhow::anyhow!("provision network integer"))?,
    )?;
    crate::config::validate_global_id(global_id)?;
    let get = |k: &str| -> Result<String> {
        Ok(t[k].as_str().ok_or_else(|| anyhow::anyhow!("provision string"))?.to_owned())
    };
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    let mut rng = rand::rngs::OsRng;
    let mut worker = Zeroizing::new([0u8; 32]);
    let mut funding = Zeroizing::new([0u8; 32]);
    let mut recipient = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut *worker);
    rng.fill_bytes(&mut *funding);
    rng.fill_bytes(&mut *recipient);
    rng.fill_bytes(&mut salt);
    write(&out.join("worker.seed"), worker.as_slice())?;
    write(&out.join("funding.seed"), funding.as_slice())?;
    write(&out.join("fee-owner.seed"), recipient.as_slice())?;
    let (public, secret) = ml_dsa_44::KG::keygen_from_seed(&worker);
    let public = public.into_bytes();
    let address = WalletContract::calculate_address(
        WalletVersion::V3R2,
        0,
        3,
        &SigningKey::from_bytes(&funding).verifying_key().to_bytes(),
    )?;
    let bond = BondInit {
        global_id,
        salt,
        owner: address.clone(),
        worker: address.clone(),
        worker_key: public.to_vec(),
        genesis_root: hash32(&t["genesis_root"])?,
        genesis_file: hash32(&t["genesis_file"])?,
        native_agent: [0; 32],
        minimum: 1_000_000_000,
        reserve: 100_000_000,
        exit_delay: 86700,
        endpoint: get("endpoint")?,
    };
    let bond_address = RelayerBond::address(&bond)?;
    let code = RelayerBond::code()?;
    let data = RelayerBond::initial_data(RelayerBond::config(&bond)?)?;
    let init = StateInit::with_code_and_data(code.clone(), data);
    write(&out.join("bond-init.boc"), &write_boc(&init.serialize()?)?)?;
    let signature = secret
        .try_sign(&RelayerBond::signing_hash(&bond, POP_TAG, &[0; 32])?, CONTEXT)
        .map_err(|_| anyhow::anyhow!("activation signing refused"))?;
    write(
        &out.join("bond-activate.boc"),
        &write_boc(&RelayerBond::activation(1_000_000_000, &signature, 1)?)?,
    )?;
    let release = Release {
        global_id,
        genesis_root: get("genesis_root")?,
        genesis_file: get("genesis_file")?,
        bond: bond_address.to_string(),
        bond_code_hash: code.repr_hash().to_hex_string(),
        policy_hash: RelayerBond::policy(&bond)?.repr_hash().to_hex_string(),
        worker_key_hash: protocol::hash(&public),
        pool: get("pool")?,
        pool_code_hash: get("pool_code_hash")?,
        pool_config_hash: get("pool_config_hash")?,
    };
    release.validate()?;
    let value = json!({"schema":"tos.br1.provider.config.v1","release":release,"execution_domain":t["execution_domain"],"fee":t["fee"],"funding_cap":t["funding_cap"],"rpc_url":t["rpc_url"],"funding_wallet":address.to_string(),"proof_verifier":t["proof_verifier"],"proof_verifier_sha256":t["proof_verifier_sha256"]});
    let config: Config = serde_json::from_value(value.clone())?;
    let wallet = crate::funding::wallet(&config, out).await?;
    write(&out.join("funding-init.boc"), &write_boc(&wallet.state_init().await?.serialize()?)?)?;
    Store::create(&out.join("leases.db"), &config.release.scope()?)?;
    write(&out.join("provider.json"), &protocol::canonical(&value)?)?;
    let directory = std::fs::File::open(out)?;
    directory.sync_all()?;
    println!("{}",protocol::canonical(&json!({"scope":config.release.scope()?,"funding_wallet":address.to_string(),"bond":bond_address.to_string()}))?.iter().map(|b|char::from(*b)).collect::<String>());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{read_single_root_boc, Deserializable, MsgAddressInt};
    use std::str::FromStr;

    #[test]
    fn fresh_custody_bond_and_signed_wallet_share_explicit_network() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        for global_id in [0, 2, 3, 42] {
            let temporary = tempfile::tempdir()?;
            let input = temporary.path().join("input.json");
            let out = temporary.path().join("custody");
            let pool = format!("0:{}", "22".repeat(32));
            let domain = shielded_pool_circuit::wire::execution_domain(global_id, &[0x22; 32]);
            let template = json!({"schema":"tos.br1.provision.v1","global_id":global_id,
                "genesis_root":"11".repeat(32),"genesis_file":"12".repeat(32),
                "pool":pool,"pool_code_hash":"33".repeat(32),"pool_config_hash":"44".repeat(32),
                "execution_domain":hex::encode(shielded_pool_wallet::keys::fr_be32(domain)),"endpoint":"http://127.0.0.1:34911",
                "fee":1,"funding_cap":250000000,"rpc_url":"http://127.0.0.1:34811/jsonRPC",
                "proof_verifier":{"executable":temporary.path().join("unused-helper"),
                "anchor_file":temporary.path().join("unused-anchor"),
                "liteserver_config":temporary.path().join("unused-lite"),
                "live_state_file":temporary.path().join("unused-live"),"live_max_age_seconds":60},
                "proof_verifier_sha256":"55".repeat(32)});
            write(&input, &protocol::canonical(&template)?)?;
            let allowed =
                global_id == 3 || (global_id == 2 && cfg!(feature = "public-testnet-pilot"));
            let result = runtime.block_on(run(&input, &out));
            if !allowed {
                let error =
                    result.err().ok_or_else(|| anyhow::anyhow!("unexpected provisioning"))?;
                assert!(error.to_string().contains("explicitly built public-testnet pilot"));
                assert!(!out.exists(), "refusal must precede custody creation");
                continue;
            }
            result?;
            let raw = crate::private_io::read(&out.join("provider.json"), 65536)?;
            let value = protocol::parse(&raw)?;
            let config = Config::load(&out, &json!({"release":value["release"]}))?;
            assert_eq!(config.release.global_id, global_id);
            let init = StateInit::construct_from_cell(read_single_root_boc(
                &crate::private_io::read(&out.join("bond-init.boc"), 65536)?,
            )?)?;
            let data = init.data.ok_or_else(|| anyhow::anyhow!("bond data absent"))?;
            let bond = RelayerBond::decode(&MsgAddressInt::from_str(&config.release.bond)?, &data)?;
            assert_eq!(bond.init.global_id, global_id);
            assert_eq!(bond.init.owner.to_string(), config.funding_wallet);
            assert_eq!(hex::encode(bond.init.genesis_root), config.release.genesis_root);
            let wallet = runtime.block_on(crate::funding::wallet(&config, &out))?;
            let message = runtime.block_on(wallet.build_message(
                MsgAddressInt::from_str(&pool)?,
                1,
                chain_block::Cell::default(),
                true,
                Some(1),
                None,
                None,
            ))?;
            let message = chain_block::Message::construct_from_cell(message)?;
            let mut body = message.body().ok_or_else(|| anyhow::anyhow!("wallet body"))?.clone();
            let signature: [u8; 64] = body
                .get_next_bytes(64)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("wallet signature width"))?;
            let seed = crate::private_io::seed(&out.join("funding.seed"))?;
            SigningKey::from_bytes(&seed).verifying_key().verify_strict(
                body.clone().into_cell()?.repr_hash().as_slice(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )?;
            assert_eq!(body.get_next_i32()?, global_id);
            assert_eq!(body.get_next_u32()?, 3, "subwallet is distinct from global ID");
        }
        Ok(())
    }
}
