// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Deterministic PQ-only genesis: module -> wallet -> paired fee vault.
//!
//! Code hashes must come from an independently reviewed release bundle, not
//! untrusted RPC data or hashes computed from untrusted supplied code. Matching
//! pins verifies identity, not that the three programs implement the protocol.
//! Construction proves neither key possession nor safe LMS custody. Verify
//! deployment and fresh per-key POP before treating a wallet as operational.
use crate::wallet_v5r2_pop::RescuePolicy;
use chain_block::{BuilderData, Cell, CellType, IBitstring, SliceData};

pub struct CodeHashes {
    pub wallet: [u8; 32],
    pub module: [u8; 32],
    pub vault: [u8; 32],
}
pub struct CodeBundle {
    wallet: Cell,
    module: Cell,
    vault: Cell,
}
impl CodeBundle {
    pub fn new(wallet: Cell, module: Cell, vault: Cell, pins: CodeHashes) -> anyhow::Result<Self> {
        for (code, pin) in [(&wallet, pins.wallet), (&module, pins.module), (&vault, pins.vault)] {
            anyhow::ensure!(
                code.cell_type() == CellType::Ordinary && code.level() == 0,
                "ordinary level-zero code required"
            );
            anyhow::ensure!(*code.repr_hash().as_array() == pin, "genesis code pin mismatch");
        }
        Ok(Self { wallet, module, vault })
    }
}

pub struct GenesisParameters {
    pub global_id: i32,
    pub network: [u8; 32],
    pub wallet_id: u32,
    pub primary_key: [u8; 1312],
    pub rescue_key: [u8; 32],
    pub policy: RescuePolicy,
    pub fee_tree_id: [u8; 32],
    pub fee_public_key: [u8; 60],
    pub epoch0: u32,
}

pub struct WalletGenesis {
    module_data: Cell,
    module_init: Cell,
    metadata: Cell,
    wallet_data: Cell,
    wallet_init: Cell,
    vault_data: Cell,
    vault_init: Cell,
    config_hash: [u8; 32],
}
fn state_init(code: Cell, data: Cell) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_raw(&[0x30], 5)?; // No split/special/libraries; code and data present.
    b.checked_append_reference(code)?;
    b.checked_append_reference(data)?;
    b.into_cell()
}
fn address(b: &mut BuilderData, hash: &[u8; 32]) -> anyhow::Result<()> {
    b.append_raw(&[0x80, 0], 11)?;
    b.append_u256(hash)?;
    Ok(())
}
fn key_chain(bytes: &[u8]) -> anyhow::Result<Cell> {
    let mut tail = None;
    for chunk in bytes.chunks(127).rev() {
        let mut b = BuilderData::new();
        b.append_raw(
            chunk,
            chunk.len().checked_mul(8).ok_or_else(|| anyhow::anyhow!("size overflow"))?,
        )?;
        if let Some(cell) = tail {
            b.checked_append_reference(cell)?;
        }
        tail = Some(b.into_cell()?);
    }
    tail.ok_or_else(|| anyhow::anyhow!("empty public key"))
}
fn paired_vault_data(
    global_id: i32,
    network: [u8; 32],
    wallet: [u8; 32],
    module: [u8; 32],
    metadata: &Cell,
    epoch0: u32,
    key: Cell,
) -> anyhow::Result<(Cell, [u8; 32])> {
    let mut config = BuilderData::new();
    config.append_u8(1)?;
    config.append_i32(global_id)?;
    config.append_u256(&network)?;
    address(&mut config, &wallet)?;
    address(&mut config, &module)?;
    config.checked_append_reference(metadata.clone())?;
    let config_hash = *config.into_cell()?.repr_hash().as_array();
    let mut prefix = BuilderData::new();
    prefix.append_u32(0x41553252)?;
    prefix.append_i32(global_id)?;
    prefix.append_u256(&network)?;
    address(&mut prefix, &wallet)?;
    prefix.append_u256(&module)?;
    prefix.append_u8(2)?;
    let mut parties = BuilderData::new();
    address(&mut parties, &wallet)?;
    parties.append_u256(&module)?;
    let parties_hash = *parties.into_cell()?.repr_hash().as_array();
    let mut vault = BuilderData::new();
    vault.append_u8(3)?;
    vault.append_u32(0)?;
    vault.append_u256(&config_hash)?;
    vault.append_u32(epoch0)?;
    address(&mut vault, &module)?;
    vault.append_u256(&parties_hash)?;
    vault.checked_append_reference(key)?;
    vault.checked_append_reference(prefix.into_cell()?)?;
    let vault_data = vault.into_cell()?;
    Ok((vault_data, config_hash))
}
impl WalletGenesis {
    pub fn new(code: CodeBundle, p: GenesisParameters) -> anyhow::Result<Self> {
        anyhow::ensure!(
            p.fee_public_key[..4] == 1u32.to_be_bytes()
                && p.fee_public_key[4..8] == 8u32.to_be_bytes()
                && p.fee_public_key[8..12] == 3u32.to_be_bytes(),
            "genesis requires HSS L1 H20/W4"
        );
        let mut module = BuilderData::new();
        module.append_u8(1)?;
        module.append_i32(p.global_id)?;
        module.append_u256(&p.network)?;
        module.append_u8(1)?;
        module.checked_append_reference(key_chain(&p.primary_key)?)?;
        module.append_u256(&p.rescue_key)?;
        module.append_u8(match p.policy {
            RescuePolicy::Ready => 1,
            RescuePolicy::Required => 2,
        })?;
        let module_data = module.into_cell()?;
        let module_init = state_init(code.module, module_data.clone())?;
        let module_hash = *module_init.repr_hash().as_array();
        let key = key_chain(&p.fee_public_key)?;
        let mut fee = BuilderData::new();
        fee.append_u8(1)?;
        fee.append_u8(1)?;
        fee.append_u256(&p.fee_tree_id)?;
        fee.append_u32(p.epoch0)?;
        fee.append_u32(3600)?;
        fee.append_u16(4)?;
        fee.checked_append_reference(key.clone())?;
        let metadata = fee.into_cell()?;
        let mut auth = BuilderData::new();
        auth.append_u8(4)?;
        auth.append_raw(&[0x80], 2)?;
        auth.append_u16(0)?;
        auth.append_u64(1)?;
        auth.append_u64(0)?;
        auth.append_u64(0)?;
        auth.checked_append_reference(module_init.clone())?;
        auth.checked_append_reference(metadata.clone())?;
        let mut wallet = BuilderData::new();
        wallet.append_bit_zero()?; // Classic signature entry is disabled.
        wallet.append_u32(0)?;
        wallet.append_u32(p.wallet_id)?;
        wallet.append_u256(&[0; 32])?; // Inert V5-shaped classic-key field.
        wallet.append_bit_zero()?; // No legacy extensions.
        wallet.checked_append_reference(auth.into_cell()?)?;
        let wallet_data = wallet.into_cell()?;
        let wallet_init = state_init(code.wallet, wallet_data.clone())?;
        let wallet_hash = *wallet_init.repr_hash().as_array();
        let (vault_data, config_hash) = paired_vault_data(
            p.global_id,
            p.network,
            wallet_hash,
            module_hash,
            &metadata,
            p.epoch0,
            key,
        )?;
        let vault_init = state_init(code.vault, vault_data.clone())?;
        Ok(Self {
            module_data,
            module_init,
            metadata,
            wallet_data,
            wallet_init,
            vault_data,
            vault_init,
            config_hash,
        })
    }
    pub fn module_data(&self) -> &Cell {
        &self.module_data
    }
    pub fn module_init(&self) -> &Cell {
        &self.module_init
    }
    pub fn metadata(&self) -> &Cell {
        &self.metadata
    }
    pub fn wallet_data(&self) -> &Cell {
        &self.wallet_data
    }
    pub fn wallet_init(&self) -> &Cell {
        &self.wallet_init
    }
    pub fn vault_data(&self) -> &Cell {
        &self.vault_data
    }
    pub fn vault_init(&self) -> &Cell {
        &self.vault_init
    }
    pub fn config_hash(&self) -> &[u8; 32] {
        &self.config_hash
    }
}

/// Canonical successor witnesses for an existing wallet address. Construction
/// establishes pairing only, not approval, deployment, POP or migration success.
/// The template carries locally enrolled new keys and trusted release code pins.
pub struct SuccessorDeployment {
    template: WalletGenesis,
    wallet: [u8; 32],
    vault_data: Cell,
    vault_init: Cell,
    config_hash: [u8; 32],
}
impl SuccessorDeployment {
    pub fn new(template: WalletGenesis, wallet: [u8; 32]) -> anyhow::Result<Self> {
        let module_hash = *template.module_init().repr_hash().as_array();
        anyhow::ensure!(wallet != module_hash, "successor wallet and module must differ");
        let mut module = SliceData::load_cell(template.module_data().clone())?;
        module.move_by(8)?;
        let global_id = i32::from_be_bytes(module.get_next_u32()?.to_be_bytes());
        let network = *module.get_next_hash()?.as_array();
        let mut metadata = SliceData::load_cell(template.metadata().clone())?;
        metadata.move_by(16 + 256)?;
        let epoch0 = metadata.get_next_u32()?;
        let key = metadata.checked_drain_reference()?;
        let (vault_data, config_hash) = paired_vault_data(
            global_id,
            network,
            wallet,
            module_hash,
            template.metadata(),
            epoch0,
            key,
        )?;
        let mut old_init = SliceData::load_cell(template.vault_init().clone())?;
        let vault_init = state_init(old_init.checked_drain_reference()?, vault_data.clone())?;
        Ok(Self { template, wallet, vault_data, vault_init, config_hash })
    }
    pub fn wallet(&self) -> &[u8; 32] {
        &self.wallet
    }
    pub fn module_data(&self) -> &Cell {
        self.template.module_data()
    }
    pub fn module_init(&self) -> &Cell {
        self.template.module_init()
    }
    pub fn metadata(&self) -> &Cell {
        self.template.metadata()
    }
    pub fn vault_data(&self) -> &Cell {
        &self.vault_data
    }
    pub fn vault_init(&self) -> &Cell {
        &self.vault_init
    }
    pub fn config_hash(&self) -> &[u8; 32] {
        &self.config_hash
    }
    /// Exact paired witnesses for the SLH-signed preparation request. Amounts
    /// remain subject to canonical encoding and network fee validation.
    pub fn preparation_plan(
        &self,
        module_amount: u128,
        vault_amount: u128,
    ) -> crate::wallet_v5r2_prepare::PreparationPlan {
        crate::wallet_v5r2_prepare::PreparationPlan {
            module_amount,
            vault_amount,
            module_init: self.module_init().clone(),
            metadata: self.metadata().clone(),
            vault_init: self.vault_init().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash(v: u8) -> [u8; 32] {
        let mut h = [0; 32];
        h[31] = v;
        h
    }
    fn byte(v: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u8(v).expect("byte");
        b.into_cell().expect("cell")
    }
    fn bundle() -> CodeBundle {
        CodeBundle::new(
            byte(1),
            byte(2),
            byte(3),
            CodeHashes {
                wallet: *byte(1).repr_hash().as_array(),
                module: *byte(2).repr_hash().as_array(),
                vault: *byte(3).repr_hash().as_array(),
            },
        )
        .expect("fixture pins")
    }
    fn parameters() -> GenesisParameters {
        let mut key = [0; 60];
        key[..4].copy_from_slice(&1u32.to_be_bytes());
        key[4..8].copy_from_slice(&8u32.to_be_bytes());
        key[8..12].copy_from_slice(&3u32.to_be_bytes());
        key[12..28].fill(0x33);
        key[28..].fill(0x44);
        let mut tree = [0; 32];
        tree[30..].copy_from_slice(&456u16.to_be_bytes());
        GenesisParameters {
            global_id: 42,
            network: hash(123),
            wallet_id: 42,
            primary_key: [0x11; 1312],
            rescue_key: [0x22; 32],
            policy: RescuePolicy::Ready,
            fee_tree_id: tree,
            fee_public_key: key,
            epoch0: 1_779_992_790,
        }
    }
    #[test]
    fn independent_genesis_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/genesis-wire.json"))
                .expect("vectors");
        for c in cases.as_array().expect("array") {
            let mut p = parameters();
            p.policy = if c["policy"] == 1 { RescuePolicy::Ready } else { RescuePolicy::Required };
            p.wallet_id =
                u32::try_from(c["wallet_id"].as_u64().expect("wallet id")).expect("width");
            p.fee_tree_id[30..].copy_from_slice(
                &u16::try_from(c["tree_id"].as_u64().expect("tree")).expect("width").to_be_bytes(),
            );
            let g = WalletGenesis::new(bundle(), p).expect("genesis");
            for (name, cell) in [
                ("module_data", g.module_data()),
                ("module_init", g.module_init()),
                ("metadata", g.metadata()),
                ("wallet_data", g.wallet_data()),
                ("wallet_init", g.wallet_init()),
                ("vault_data", g.vault_data()),
                ("vault_init", g.vault_init()),
            ] {
                assert_eq!(hex::encode(cell.repr_hash().as_array()), c[name], "{name}");
            }
            assert_eq!(hex::encode(g.config_hash()), c["config_hash"]);
        }
    }
    #[test]
    fn independent_successor_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/successor-wire.json"))
                .unwrap();
        for c in cases.as_array().unwrap() {
            let mut p = parameters();
            p.policy = if c["policy"] == 1 { RescuePolicy::Ready } else { RescuePolicy::Required };
            p.wallet_id = u32::try_from(c["wallet_id"].as_u64().unwrap()).unwrap();
            p.fee_tree_id[30..].copy_from_slice(
                &u16::try_from(c["tree_id"].as_u64().unwrap()).unwrap().to_be_bytes(),
            );
            let wallet: [u8; 32] =
                hex::decode(c["wallet_address"].as_str().unwrap()).unwrap().try_into().unwrap();
            let successor =
                SuccessorDeployment::new(WalletGenesis::new(bundle(), p).unwrap(), wallet).unwrap();
            assert_eq!(successor.wallet(), &wallet);
            for (name, cell) in [
                ("module_data", successor.module_data()),
                ("module_init", successor.module_init()),
                ("metadata", successor.metadata()),
                ("vault_data", successor.vault_data()),
                ("vault_init", successor.vault_init()),
            ] {
                assert_eq!(cell.repr_hash().to_hex_string(), c[name], "{name}");
            }
            assert_eq!(hex::encode(successor.config_hash()), c["config_hash"]);
            let plan = successor.preparation_plan(100, 200);
            assert_eq!(plan.module_amount, 100);
            assert_eq!(plan.vault_amount, 200);
            assert_eq!(plan.module_init.repr_hash(), successor.module_init().repr_hash());
            assert_eq!(plan.metadata.repr_hash(), successor.metadata().repr_hash());
            assert_eq!(plan.vault_init.repr_hash(), successor.vault_init().repr_hash());
        }
        let g = WalletGenesis::new(bundle(), parameters()).unwrap();
        let module = *g.module_init().repr_hash().as_array();
        assert!(SuccessorDeployment::new(g, module).is_err());
    }

    #[test]
    fn wrong_code_and_fee_profile_refused() {
        for which in 0..3 {
            let mut codes = [byte(1), byte(2), byte(3)];
            codes[which] = byte(4);
            let expected = bundle();
            let pins = CodeHashes {
                wallet: *expected.wallet.repr_hash().as_array(),
                module: *expected.module.repr_hash().as_array(),
                vault: *expected.vault.repr_hash().as_array(),
            };
            assert!(
                CodeBundle::new(codes[0].clone(), codes[1].clone(), codes[2].clone(), pins)
                    .is_err()
            );
        }
        for offset in [0, 4, 8] {
            let mut p = parameters();
            p.fee_public_key[offset] ^= 1;
            assert!(WalletGenesis::new(bundle(), p).is_err());
        }
    }
    #[test]
    fn matching_pin_does_not_allow_exotic_code() {
        let mut b = BuilderData::new();
        b.set_type(CellType::LibraryReference);
        b.append_u8(2).expect("tag");
        b.append_u256(&[0; 32]).expect("hash");
        let exotic = b.into_cell().expect("valid exotic fixture");
        let pins = CodeHashes {
            wallet: *exotic.repr_hash().as_array(),
            module: *byte(2).repr_hash().as_array(),
            vault: *byte(3).repr_hash().as_array(),
        };
        assert!(CodeBundle::new(exotic, byte(2), byte(3), pins).is_err());
    }
}
