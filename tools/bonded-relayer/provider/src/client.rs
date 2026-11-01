// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Public, offline wallet verification. No custody, journal, RPC or helper access.
use crate::{config::Release, protocol};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{Deserializable, MsgAddressInt, Serializable, StateInit};
use node_contracts::relayer_bond::{BondInit, RelayerBond};
use serde_json::{json, Value};
use std::str::FromStr;

fn identity(payload: &Value) -> Result<(Release, BondInit)> {
    let release: Release = serde_json::from_value(payload["release"].clone())?;
    release.validate()?;
    let text = payload["bond_init_b64"].as_str().ok_or_else(|| anyhow::anyhow!("Bond init"))?;
    ensure!(!text.is_empty() && text.len() <= 87384, "Bond init byte bound");
    let bytes = STANDARD.decode(text)?;
    ensure!(bytes.len() <= 65536 && STANDARD.encode(&bytes) == text, "Bond init encoding");
    let cell = crate::candidate::ordinary_boc(&bytes)?;
    let state = StateInit::construct_from_cell(cell.clone())?;
    let address = MsgAddressInt::from_str(&release.bond)?;
    let data = state.data.as_ref().ok_or_else(|| anyhow::anyhow!("Bond initial data"))?;
    let bond = RelayerBond::decode(&address, data)?;
    let canonical = RelayerBond::state_init(&bond.init)?.serialize()?;
    ensure!(canonical.repr_hash() == cell.repr_hash(), "noncanonical Bond StateInit");
    ensure!(RelayerBond::address(&bond.init)? == address, "wallet Bond address pin");
    ensure!(
        RelayerBond::code()?.repr_hash().to_hex_string() == release.bond_code_hash,
        "wallet Bond code pin"
    );
    ensure!(
        RelayerBond::policy(&bond.init)?.repr_hash().to_hex_string() == release.policy_hash,
        "wallet Bond policy pin"
    );
    ensure!(
        bond.init.global_id == release.global_id
            && hex::encode(bond.init.genesis_root) == release.genesis_root
            && hex::encode(bond.init.genesis_file) == release.genesis_file,
        "wallet Bond network pin"
    );
    ensure!(
        protocol::hash(&bond.init.worker_key) == release.worker_key_hash,
        "wallet Bond worker pin"
    );
    Ok((release, bond.init))
}

pub fn dispatch(operation: &str, payload: &Value) -> Result<Value> {
    if operation == "client_identity" {
        protocol::fields(payload, &["release", "bond_init_b64"])?;
        let (release, init) = identity(payload)?;
        return Ok(
            json!({"scope":release.scope()?,"endpoint":init.endpoint,"worker_key_hash":release.worker_key_hash}),
        );
    }
    ensure!(operation == "client_quote", "unsupported public operation");
    protocol::fields(payload, &["release", "bond_init_b64", "envelope"])?;
    let (release, init) = identity(payload)?;
    let envelope = &payload["envelope"];
    protocol::fields(envelope, &["schema", "terms", "public_key_b64", "signature_b64"])?;
    ensure!(envelope["schema"] == "tos.br1.quote.v1", "quote envelope schema");
    let terms = protocol::canonical(&envelope["terms"])?;
    ensure!(envelope["terms"]["release"] == release.scope()?, "wallet quote release pin");
    let public = crate::identity::decode(
        envelope["public_key_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote key"))?,
        1312,
    )?;
    ensure!(public == init.worker_key, "wallet quote worker pin");
    let signature = crate::identity::decode(
        envelope["signature_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote signature"))?,
        2420,
    )?;
    let public: [u8; 1312] = public.try_into().map_err(|_| anyhow::anyhow!("key width"))?;
    let signature: [u8; 2420] =
        signature.try_into().map_err(|_| anyhow::anyhow!("signature width"))?;
    shielded_pool_wallet::relayer_quote::verify_terms(&public, &terms, &signature)?;
    // The wallet transport checks the complete terms schema, time, capability,
    // fee slot and request binding after authenticating these exact terms.
    Ok(json!({"terms":envelope["terms"]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::{
        ml_dsa_44,
        traits::{KeyGen, SerDes},
    };

    fn fixture() -> Result<(Value, ml_dsa_44::PrivateKey)> {
        let (public, private) = ml_dsa_44::KG::keygen_from_seed(&[37; 32]);
        let init = BondInit {
            global_id: 3,
            salt: [1; 32],
            owner: format!("0:{}", "11".repeat(32)).parse()?,
            worker: format!("0:{}", "22".repeat(32)).parse()?,
            worker_key: public.into_bytes().to_vec(),
            genesis_root: [4; 32],
            genesis_file: [5; 32],
            native_agent: [0; 32],
            minimum: 10_000_000_000,
            reserve: 1_000_000_000,
            exit_delay: 90000,
            endpoint: "http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
                .into(),
        };
        let release = Release {
            global_id: 3,
            genesis_root: hex::encode(init.genesis_root),
            genesis_file: hex::encode(init.genesis_file),
            bond: RelayerBond::address(&init)?.to_string(),
            bond_code_hash: RelayerBond::code()?.repr_hash().to_hex_string(),
            policy_hash: RelayerBond::policy(&init)?.repr_hash().to_hex_string(),
            worker_key_hash: protocol::hash(&init.worker_key),
            pool: format!("0:{}", "77".repeat(32)),
            pool_code_hash: "88".repeat(32),
            pool_config_hash: "99".repeat(32),
        };
        let bytes = chain_block::write_boc(&RelayerBond::state_init(&init)?.serialize()?)?;
        Ok((json!({"release":release,"bond_init_b64":STANDARD.encode(bytes)}), private))
    }

    #[test]
    fn public_identity_binds_all_wallet_pins_without_custody() -> Result<()> {
        let (payload, _) = fixture()?;
        let result = dispatch("client_identity", &payload)?;
        assert!(result["endpoint"].as_str().is_some_and(|s| s.ends_with(".onion")));
        for field in [
            "bond",
            "bond_code_hash",
            "policy_hash",
            "genesis_root",
            "genesis_file",
            "worker_key_hash",
        ] {
            let mut altered = payload.clone();
            altered["release"][field] = if field == "bond" {
                json!(format!("0:{}", "66".repeat(32)))
            } else {
                json!("66".repeat(32))
            };
            assert!(dispatch("client_identity", &altered).is_err(), "accepted changed {field}");
        }
        let mut wrong = payload.clone();
        wrong["release"]["global_id"] = json!(4);
        assert!(dispatch("client_identity", &wrong).is_err());
        Ok(())
    }

    #[test]
    fn public_quote_authenticates_exact_terms_and_pinned_worker() -> Result<()> {
        let (mut payload, private) = fixture()?;
        let (release, init) = identity(&payload)?;
        let terms = json!({"release":release.scope()?,"amount":7});
        let signature = shielded_pool_wallet::relayer_quote::sign_terms(
            &private,
            &protocol::canonical(&terms)?,
        )?;
        payload["envelope"] = json!({"schema":"tos.br1.quote.v1","terms":terms,"public_key_b64":STANDARD.encode(init.worker_key),"signature_b64":STANDARD.encode(signature)});
        assert_eq!(dispatch("client_quote", &payload)?["terms"], terms);
        let mut wrong = payload.clone();
        wrong["envelope"]["terms"]["amount"] = json!(8);
        assert!(dispatch("client_quote", &wrong).is_err());
        let (other, _) = ml_dsa_44::KG::keygen_from_seed(&[38; 32]);
        wrong = payload.clone();
        wrong["envelope"]["public_key_b64"] = json!(STANDARD.encode(other.into_bytes()));
        assert!(dispatch("client_quote", &wrong).is_err());
        Ok(())
    }
    #[test]
    fn public_fixture_for_process_boundary() -> Result<()> {
        let (mut payload, private) = fixture()?;
        let (release, init) = identity(&payload)?;
        let terms = json!({"release":release.scope()?,"amount":7});
        let signature = shielded_pool_wallet::relayer_quote::sign_terms(
            &private,
            &protocol::canonical(&terms)?,
        )?;
        payload["envelope"] = json!({"schema":"tos.br1.quote.v1","terms":terms,"public_key_b64":STANDARD.encode(init.worker_key),"signature_b64":STANDARD.encode(signature)});
        assert_eq!(dispatch("client_quote", &payload)?["terms"], terms);
        // Public, deterministic test identity only. The process-boundary runner
        // consumes this without importing any test custody into the provider.
        if let Some(path) = std::env::var_os("BR1_PUBLIC_FIXTURE") {
            std::fs::write(path, protocol::canonical(&payload)?)?;
        }
        Ok(())
    }
}
