// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Explicit creation of fresh, isolated local custody; never repairs/reset keys.
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
    ensure!(
        t["schema"] == "tos.br1.provision.v1" && t["global_id"] == 3,
        "local provisioning scope"
    );
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
        global_id: 3,
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
        global_id: 3,
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
