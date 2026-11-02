// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The Bond's immutable identity from its public StateInit, checked against
//! the release pins. No custody, no network: this proves which Bond the pins
//! name and what endpoint it declared, not that it is active or backed.
use crate::{release::Release, request::ordinary_boc, wire};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{Deserializable, MsgAddressInt, Serializable, StateInit};
use node_contracts::relayer_bond::{BondInit, RelayerBond};
use std::str::FromStr;

/// The most bytes a Bond StateInit BOC may have, and its base64 length.
pub const MAX_INIT_BYTES: usize = 65536;
pub const MAX_INIT_BASE64: usize = 87384;

/// The Bond `release` pins, from the StateInit text as a wallet or an
/// operator supplies it.
pub fn identity(release: &Release, bond_init_b64: &str) -> Result<BondInit> {
    release.validate()?;
    ensure!(
        !bond_init_b64.is_empty() && bond_init_b64.len() <= MAX_INIT_BASE64,
        "Bond init byte bound"
    );
    let bytes = STANDARD.decode(bond_init_b64)?;
    ensure!(
        bytes.len() <= MAX_INIT_BYTES && STANDARD.encode(&bytes) == bond_init_b64,
        "Bond init encoding"
    );
    identity_from_bytes(release, &bytes)
}

/// The same from the BOC bytes.
pub fn identity_from_bytes(release: &Release, bytes: &[u8]) -> Result<BondInit> {
    release.validate()?;
    ensure!(!bytes.is_empty() && bytes.len() <= MAX_INIT_BYTES, "Bond init byte bound");
    let cell = ordinary_boc(bytes)?;
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
    ensure!(wire::hash(&bond.init.worker_key) == release.worker_key_hash, "wallet Bond worker pin");
    Ok(bond.init)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use fips204::{
        ml_dsa_44,
        traits::{KeyGen, SerDes},
    };

    pub(crate) const ENDPOINT: &str =
        "http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    /// A deterministic public Bond and its worker's private key; the same
    /// values the provider's public fixture is built from.
    pub(crate) fn fixture() -> Result<(Release, String, BondInit, ml_dsa_44::PrivateKey)> {
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
            endpoint: ENDPOINT.into(),
        };
        let release = Release {
            global_id: 3,
            genesis_root: hex::encode(init.genesis_root),
            genesis_file: hex::encode(init.genesis_file),
            bond: RelayerBond::address(&init)?.to_string(),
            bond_code_hash: RelayerBond::code()?.repr_hash().to_hex_string(),
            policy_hash: RelayerBond::policy(&init)?.repr_hash().to_hex_string(),
            worker_key_hash: wire::hash(&init.worker_key),
            pool: format!("0:{}", "77".repeat(32)),
            pool_code_hash: "88".repeat(32),
            pool_config_hash: "99".repeat(32),
        };
        let bytes = chain_block::write_boc(&RelayerBond::state_init(&init)?.serialize()?)?;
        Ok((release, STANDARD.encode(bytes), init, private))
    }

    #[test]
    fn identity_binds_all_pins_and_yields_the_declared_endpoint() -> Result<()> {
        let (release, text, init, _) = fixture()?;
        let found = identity(&release, &text)?;
        assert_eq!(found, init);
        assert_eq!(found.endpoint, ENDPOINT);
        for field in [
            "bond",
            "bond_code_hash",
            "policy_hash",
            "genesis_root",
            "genesis_file",
            "worker_key_hash",
        ] {
            let mut altered = release.clone();
            let value =
                if field == "bond" { format!("0:{}", "66".repeat(32)) } else { "66".repeat(32) };
            match field {
                "bond" => altered.bond = value,
                "bond_code_hash" => altered.bond_code_hash = value,
                "policy_hash" => altered.policy_hash = value,
                "genesis_root" => altered.genesis_root = value,
                "genesis_file" => altered.genesis_file = value,
                _ => altered.worker_key_hash = value,
            }
            assert!(identity(&altered, &text).is_err(), "accepted changed {field}");
        }
        let mut wrong = release.clone();
        wrong.global_id = 4;
        assert!(identity(&wrong, &text).is_err());
        assert!(identity(&release, &text[..text.len() - 4]).is_err());
        assert!(identity(&release, "").is_err());
        Ok(())
    }
}
