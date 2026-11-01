// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Canonical BR1 deployment and read-only identity decoding. Indexer observations
//! are candidates, never proof of live eligibility or permission to sign.
use chain_block::{
    BuilderData, Cell, CellType, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable,
    SliceData, StateInit,
};
use sha2::{Digest, Sha256};

pub const ACTIVATE: u32 = 0x4252_0001;
pub const STAKE: u32 = 0x4252_0002;
pub const RETIRE: u32 = 0x4252_0003;
pub const WITHDRAW: u32 = 0x4252_0004;
pub const METADATA: u32 = 0x4252_0005;
pub const SLASH: u32 = 0x4252_0006;
pub const CONTEXT: &[u8] = b"TOS-BONDED-RELAYER-v1";
pub const POP_TAG: u32 = 0x4252_4150;
pub const ACCEPTANCE_TAG: u32 = 0x4252_4143;
pub const MAX_COINS: u128 = (1u128 << 120) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondInit {
    pub global_id: i32,
    pub salt: [u8; 32],
    pub owner: MsgAddressInt,
    pub worker: MsgAddressInt,
    pub worker_key: Vec<u8>,
    pub genesis_root: [u8; 32],
    pub genesis_file: [u8; 32],
    pub native_agent: [u8; 32],
    pub minimum: u128,
    pub reserve: u128,
    pub exit_delay: u32,
    /// Stable public HTTPS endpoint or an HTTP v3 onion endpoint. A local
    /// test endpoint is permitted by the codec, never by production policy.
    pub endpoint: String,
}

#[derive(Clone, Debug)]
pub struct BondState {
    pub init: BondInit,
    pub phase: u8,
    pub principal: u128,
    pub activated: u32,
    pub exit_requested: u32,
    pub exit_after: u32,
    pub metadata_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub config: Cell,
}

pub struct RelayerBond;

pub fn ordinary(cell: &Cell) -> anyhow::Result<SliceData> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary && cell.level() == 0,
        "ordinary level-zero cell required"
    );
    Ok(SliceData::load_cell(cell.clone())?)
}
pub fn end(slice: &SliceData) -> anyhow::Result<()> {
    anyhow::ensure!(
        slice.remaining_bits() == 0 && slice.remaining_references() == 0,
        "trailing cell data"
    );
    Ok(())
}
pub fn byte_chain(bytes: &[u8]) -> anyhow::Result<Cell> {
    anyhow::ensure!(!bytes.is_empty() && bytes.len() <= 1 << 20, "byte-chain size");
    let mut tail = None;
    for chunk in bytes.chunks(127).rev() {
        let mut b = BuilderData::new();
        b.append_raw(
            chunk,
            chunk.len().checked_mul(8).ok_or_else(|| anyhow::anyhow!("bit overflow"))?,
        )?;
        if let Some(next) = tail {
            b.checked_append_reference(next)?;
        }
        tail = Some(b.into_cell()?);
    }
    tail.ok_or_else(|| anyhow::anyhow!("empty byte chain"))
}
pub fn chain_bytes(cell: &Cell, expected: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(expected > 0 && expected <= 1 << 20, "byte-chain bound");
    let mut current = cell.clone();
    let mut out = Vec::with_capacity(expected);
    loop {
        let mut s = ordinary(&current)?;
        let bytes = s.remaining_bits() / 8;
        anyhow::ensure!(
            s.remaining_bits() % 8 == 0
                && bytes > 0
                && bytes <= 127
                && s.remaining_references() <= 1,
            "noncanonical byte chain"
        );
        anyhow::ensure!(
            out.len().checked_add(bytes).is_some_and(|n| n <= expected),
            "byte-chain length"
        );
        out.extend_from_slice(&s.get_next_bytes(bytes)?);
        if s.remaining_references() == 0 {
            break;
        }
        anyhow::ensure!(bytes == 127, "short non-final byte chunk");
        current = s.checked_drain_reference()?;
    }
    anyhow::ensure!(out.len() == expected, "byte-chain length");
    Ok(out)
}
pub fn stored_bytes(bytes: &[u8]) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(u32::try_from(bytes.len())?)?.checked_append_reference(byte_chain(bytes)?)?;
    Ok(b.into_cell()?)
}
pub fn read_stored(cell: &Cell, expected: usize) -> anyhow::Result<Vec<u8>> {
    let mut s = ordinary(cell)?;
    anyhow::ensure!(s.get_next_u32()? as usize == expected, "stored byte width");
    let child = s.checked_drain_reference()?;
    end(&s)?;
    chain_bytes(&child, expected)
}
fn address(addr: &MsgAddressInt) -> anyhow::Result<()> {
    let (wc, _) = addr.extract_std_address(true)?;
    anyhow::ensure!(wc == 0, "basechain standard address required");
    Ok(())
}
fn coins(b: &mut BuilderData, amount: u128) -> anyhow::Result<()> {
    anyhow::ensure!(amount <= MAX_COINS, "coins overflow");
    Coins::try_from(amount)?.write_to(b)?;
    Ok(())
}

impl RelayerBond {
    pub fn code() -> anyhow::Result<Cell> {
        Ok(chain_block::read_single_root_boc(chain_block::base64_decode(
            include_str!("../../../../../crypto/smartcont/relayer-bond-v1.boc.base64").trim(),
        )?)?)
    }
    pub fn policy(init: &BondInit) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            init.minimum > 0 && init.reserve > 0 && (86700..=2592000).contains(&init.exit_delay),
            "invalid bond policy"
        );
        let mut b = BuilderData::new();
        coins(&mut b, init.minimum)?;
        coins(&mut b, init.reserve)?;
        b.append_u32(init.exit_delay)?;
        Ok(b.into_cell()?)
    }
    pub fn config(init: &BondInit) -> anyhow::Result<Cell> {
        address(&init.owner)?;
        address(&init.worker)?;
        anyhow::ensure!(
            init.salt != [0; 32] && init.genesis_root != [0; 32] && init.genesis_file != [0; 32],
            "zero identity field"
        );
        anyhow::ensure!(init.worker_key.len() == 1312, "ML-DSA-44 worker key width");
        anyhow::ensure!(
            (1..=256).contains(&init.endpoint.len())
                && init.endpoint.is_ascii()
                && !init.endpoint.bytes().any(|b| b <= 0x20 || b == 0x7f),
            "invalid endpoint encoding"
        );
        let mut identity = BuilderData::new();
        identity
            .append_u256(&init.genesis_root)?
            .append_u256(&init.genesis_file)?
            .append_u256(&init.native_agent)?;
        let mut endpoint = BuilderData::new();
        endpoint
            .append_u8(1)?
            .append_u16(u16::try_from(init.endpoint.len())?)?
            .checked_append_reference(byte_chain(init.endpoint.as_bytes())?)?;
        let mut b = BuilderData::new();
        b.append_i32(init.global_id)?.append_u256(&init.salt)?;
        init.owner.write_to(&mut b)?;
        init.worker.write_to(&mut b)?;
        b.checked_append_reference(stored_bytes(&init.worker_key)?)?
            .checked_append_reference(identity.into_cell()?)?
            .checked_append_reference(Self::policy(init)?)?
            .checked_append_reference(endpoint.into_cell()?)?;
        Ok(b.into_cell()?)
    }
    pub fn initial_data(config: Cell) -> anyhow::Result<Cell> {
        let mut b = BuilderData::new();
        b.append_bits(0, 3)?;
        coins(&mut b, 0)?;
        b.append_u32(0)?
            .append_u32(0)?
            .append_u32(0)?
            .append_u256(&[0; 32])?
            .append_u256(&[0; 32])?
            .checked_append_reference(config)?;
        Ok(b.into_cell()?)
    }
    pub fn state_init(init: &BondInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::initial_data(Self::config(init)?)?))
    }
    pub fn address(init: &BondInit) -> anyhow::Result<MsgAddressInt> {
        Ok(MsgAddressInt::with_params(0, Self::state_init(init)?.serialize()?.repr_hash())?)
    }
    pub fn decode_config(config: &Cell) -> anyhow::Result<BondInit> {
        let mut s = ordinary(config)?;
        let global_id = s.get_next_i32()?;
        let salt = *s.get_next_hash()?.as_array();
        let owner = MsgAddressInt::construct_from(&mut s)?;
        let worker = MsgAddressInt::construct_from(&mut s)?;
        let worker_key = read_stored(&s.checked_drain_reference()?, 1312)?;
        let mut identity = ordinary(&s.checked_drain_reference()?)?;
        let genesis_root = *identity.get_next_hash()?.as_array();
        let genesis_file = *identity.get_next_hash()?.as_array();
        let native_agent = *identity.get_next_hash()?.as_array();
        end(&identity)?;
        let mut policy = ordinary(&s.checked_drain_reference()?)?;
        let minimum = Coins::construct_from(&mut policy)?.as_u128();
        let reserve = Coins::construct_from(&mut policy)?.as_u128();
        let exit_delay = policy.get_next_u32()?;
        end(&policy)?;
        let mut endpoint = ordinary(&s.checked_drain_reference()?)?;
        anyhow::ensure!(endpoint.get_next_byte()? == 1, "endpoint schema");
        let count = usize::from(endpoint.get_next_u16()?);
        anyhow::ensure!((1..=256).contains(&count), "endpoint length");
        let text = chain_bytes(&endpoint.checked_drain_reference()?, count)?;
        end(&endpoint)?;
        end(&s)?;
        let init = BondInit {
            global_id,
            salt,
            owner,
            worker,
            worker_key,
            genesis_root,
            genesis_file,
            native_agent,
            minimum,
            reserve,
            exit_delay,
            endpoint: String::from_utf8(text)?,
        };
        anyhow::ensure!(
            Self::config(&init)?.repr_hash() == config.repr_hash(),
            "noncanonical bond config"
        );
        Ok(init)
    }
    pub fn decode(address: &MsgAddressInt, data: &Cell) -> anyhow::Result<BondState> {
        let mut s = ordinary(data)?;
        let phase = s.get_next_int(3)? as u8;
        anyhow::ensure!(phase <= 4, "bond phase");
        let principal = Coins::construct_from(&mut s)?.as_u128();
        let activated = s.get_next_u32()?;
        let exit_requested = s.get_next_u32()?;
        let exit_after = s.get_next_u32()?;
        let metadata_hash = *s.get_next_hash()?.as_array();
        let evidence_hash = *s.get_next_hash()?.as_array();
        let config = s.checked_drain_reference()?;
        end(&s)?;
        let init = Self::decode_config(&config)?;
        anyhow::ensure!(&Self::address(&init)? == address, "noncanonical bond address");
        Ok(BondState {
            init,
            phase,
            principal,
            activated,
            exit_requested,
            exit_after,
            metadata_hash,
            evidence_hash,
            config,
        })
    }
    pub fn signing_hash(init: &BondInit, tag: u32, payload: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        let mut b = BuilderData::new();
        b.append_u32(tag)?.append_i32(init.global_id)?;
        Self::address(init)?.write_to(&mut b)?;
        b.append_u256(Self::config(init)?.repr_hash().as_array())?.append_u256(payload)?;
        Ok(*b.into_cell()?.repr_hash().as_array())
    }
    pub fn header(op: u32, query: u64) -> anyhow::Result<BuilderData> {
        anyhow::ensure!((ACTIVATE..=SLASH).contains(&op), "bond opcode");
        let mut b = BuilderData::new();
        b.append_u32(op)?.append_u64(query)?;
        Ok(b)
    }
    pub fn activation(amount: u128, signature: &[u8], query: u64) -> anyhow::Result<Cell> {
        anyhow::ensure!(signature.len() == 2420 && amount > 0, "activation fields");
        let mut b = Self::header(ACTIVATE, query)?;
        coins(&mut b, amount)?;
        b.checked_append_reference(stored_bytes(signature)?)?;
        Ok(b.into_cell()?)
    }
    pub fn acceptance(
        slot: u64,
        issued: u32,
        expires: u32,
        intent: &[u8; 32],
        body: &[u8; 32],
        quote: &[u8; 32],
        fee: &[u8; 32],
    ) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            slot > 0 && expires > issued && issued.checked_add(300).is_some_and(|v| expires <= v),
            "acceptance time/slot"
        );
        for hash in [intent, body, quote, fee] {
            anyhow::ensure!(*hash != [0; 32], "zero acceptance field");
        }
        let mut terms = BuilderData::new();
        terms.append_u256(body)?.append_u256(quote)?.append_u256(fee)?;
        let mut b = BuilderData::new();
        b.append_u64(slot)?
            .append_u32(issued)?
            .append_u32(expires)?
            .append_u256(intent)?
            .checked_append_reference(terms.into_cell()?)?;
        Ok(b.into_cell()?)
    }
    pub fn conflict(
        a: Cell,
        sig_a: &[u8],
        b: Cell,
        sig_b: &[u8],
        query: u64,
    ) -> anyhow::Result<Cell> {
        anyhow::ensure!(sig_a.len() == 2420 && sig_b.len() == 2420, "signature width");
        let mut message = Self::header(SLASH, query)?;
        message
            .checked_append_reference(a)?
            .checked_append_reference(stored_bytes(sig_a)?)?
            .checked_append_reference(b)?
            .checked_append_reference(stored_bytes(sig_b)?)?;
        Ok(message.into_cell()?)
    }
    pub fn worker_key_hash(key: &[u8]) -> anyhow::Result<[u8; 32]> {
        anyhow::ensure!(key.len() == 1312, "worker key length");
        Ok(Sha256::digest(key).into())
    }
}

impl BondState {
    pub fn backed(&self, balance: u128) -> u128 {
        self.principal.min(balance.checked_sub(self.init.reserve).unwrap_or(0))
    }
    pub fn eligible(&self, balance: u128) -> bool {
        self.phase == 1 && self.backed(balance) >= self.init.minimum
    }
    pub fn status(&self) -> &'static str {
        match self.phase {
            0 => "unfunded",
            1 => "active",
            2 => "exiting",
            3 => "closed",
            4 => "slashed",
            _ => "invalid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn init() -> BondInit {
        BondInit {
            global_id: 42,
            salt: [1; 32],
            owner: "0:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .expect("address"),
            worker: "0:2222222222222222222222222222222222222222222222222222222222222222"
                .parse()
                .expect("address"),
            worker_key: vec![3; 1312],
            genesis_root: [4; 32],
            genesis_file: [5; 32],
            native_agent: [0; 32],
            minimum: 10_000_000_000,
            reserve: 1_000_000_000,
            exit_delay: 90000,
            endpoint: "https://relay.example".into(),
        }
    }
    #[test]
    fn config_roundtrip_and_deployment_identity() {
        let i = init();
        let config = RelayerBond::config(&i).expect("config");
        assert_eq!(RelayerBond::decode_config(&config).expect("decode"), i);
        let address = RelayerBond::address(&i).expect("address");
        let state =
            RelayerBond::decode(&address, &RelayerBond::initial_data(config).expect("data"))
                .expect("state");
        assert!(!state.eligible(u128::MAX));
        let mut other = i.clone();
        other.salt = [9; 32];
        assert!(
            RelayerBond::decode(
                &RelayerBond::address(&other).expect("other"),
                &RelayerBond::initial_data(RelayerBond::config(&i).expect("config")).expect("data")
            )
            .is_err()
        );
    }
    #[test]
    fn signatures_bind_network_actor_and_purpose() {
        let i = init();
        let hash = RelayerBond::signing_hash(&i, POP_TAG, &[0; 32]).expect("hash");
        let mut other = i.clone();
        other.global_id += 1;
        assert_ne!(hash, RelayerBond::signing_hash(&other, POP_TAG, &[0; 32]).expect("other"));
        assert_ne!(hash, RelayerBond::signing_hash(&i, ACCEPTANCE_TAG, &[0; 32]).expect("purpose"));
    }
    #[test]
    fn canonical_byte_chains_and_policy_bounds() {
        for n in [1, 127, 128, 256, 1312, 2420] {
            let bytes = vec![7; n];
            assert_eq!(chain_bytes(&byte_chain(&bytes).expect("chain"), n).expect("read"), bytes);
        }
        let mut i = init();
        i.exit_delay = 86699;
        assert!(RelayerBond::config(&i).is_err());
        i.exit_delay = 90000;
        i.endpoint = "https://evil\r\n".into();
        assert!(RelayerBond::config(&i).is_err());
    }
}
