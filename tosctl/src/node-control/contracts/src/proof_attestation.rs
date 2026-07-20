/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Deserializable, IBitstring, MsgAddressInt,
    Serializable, StateInit,
};
use common::tvm_stack_parser::TvmStackParser;

pub const PROOF_ATTESTATION_CODE_B64: &str = "te6cckECBQEAAS0AART/APSkE/S88sgLAQIBYgIDAfbQMiHHAJFb4AHTH9M/MQLQdNch+kAw7UTQ+kDT/9MA0wDTP9QB0NP/0//RAtEBKIIQQVRUAbqOQRNfAzQ0gQg0JMAA8vQE0/+DCNcY0SGBCDVRJ/kQ8vQUE3FAE/gjAgHIy//L/8nIUAbPFhTL/xLLAMsAyz/Mye1U4CgEADWgGG/aiaH0gaf/pgGmAaZ/qAOhp/+n/6IFogMA/IIQQVRUArqONhNfAzI0gQg2UTLHBRPy9APT/9FwUwAQNRA0QTAByMv/y//JyFAGzxYUy/8SywDLAMs/zMntVOA0B4IQQVRUA7qOK4EINlFlxwUW8vQG0UVAcUREAcjL/8v/ychQBs8WFMv/EssAywDLP8zJ7VTgXwiBCDfy8Ng8IJk=";
pub const ATT_ATTEST_OPCODE: u32 = 0x4154_5401;
pub const ATT_ROTATE_KEY_OPCODE: u32 = 0x4154_5402;
pub const ATT_REVOKE_OPCODE: u32 = 0x4154_5403;

/// Deployment parameters for a Proof Attestation actor.
///
/// One instance is deployed per attestation subject -- the same per-actor
/// pattern as `AgentAccountContract` / `TaskEscrowContract` /
/// `CapabilityRegistryContract` / `ServiceActorContract` / `DisputeContract`.
/// A standalone, additive proof adapter: it does not modify Task Escrow or
/// Dispute, which keep accepting bare hash commitments unchanged.
#[derive(Clone, Debug)]
pub struct ProofAttestationInit {
    pub owner: MsgAddressInt,
    /// The ed25519 public key expected to sign attestations.
    pub public_key: [u8; 32],
    /// Reference to what this attestation is about, e.g. a Task Escrow or
    /// Dispute address's hash.
    pub subject_hash: [u8; 32],
}

pub struct ProofAttestationContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofAttestationData {
    pub owner: MsgAddressInt,
    pub public_key: [u8; 32],
    pub revoked: bool,
    pub has_attestation: bool,
    pub attested_at: u64,
    pub subject_hash: [u8; 32],
    pub attested_hash: [u8; 32],
}

impl ProofAttestationContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(PROOF_ATTESTATION_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &ProofAttestationInit) -> anyhow::Result<chain_block::Cell> {
        let mut data = BuilderData::new();
        init.owner.write_to(&mut data)?;
        data.append_u256(&init.public_key)?;
        data.append_bit_zero()?; // revoked = 0
        data.append_bit_zero()?; // has_attestation = 0
        data.append_u64(0)?; // attested_at
        let mut sub = BuilderData::new();
        sub.append_u256(&init.subject_hash)?.append_u256(&[0; 32])?;
        data.checked_append_reference(sub.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &ProofAttestationInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &ProofAttestationInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_proof_attestation_data`; transport and RPC
    /// concerns stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<ProofAttestationData> {
        let mut owner_slice = stack.slice(0)?;
        Ok(ProofAttestationData {
            owner: MsgAddressInt::construct_from(&mut owner_slice)?,
            public_key: parse_hash(stack, 1)?,
            revoked: stack.u64(2)? != 0,
            has_attestation: stack.u64(3)? != 0,
            attested_at: stack.u64(4)?,
            subject_hash: parse_hash(stack, 5)?,
            attested_hash: parse_hash(stack, 6)?,
        })
    }

    /// `signature` must be a valid 64-byte ed25519 signature over the raw
    /// 32 bytes of `attested_hash` (matching TVM's `CHKSIGNU`, the same
    /// convention `AgentAccountContract`'s controller-signed actions use).
    pub fn attest(
        query_id: u64,
        attested_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(ATT_ATTEST_OPCODE, query_id, |b| {
            b.append_u256(&attested_hash)?.append_raw(signature, 512).map(|_| ())
        })
    }

    pub fn rotate_key(query_id: u64, new_public_key: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        message(ATT_ROTATE_KEY_OPCODE, query_id, |b| b.append_u256(&new_public_key).map(|_| ()))
    }

    pub fn revoke(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(ATT_REVOKE_OPCODE, query_id, |_| Ok(()))
    }
}

fn parse_hash(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 256-bit value", index))
}

fn message<F>(opcode: u32, query_id: u64, append: F) -> anyhow::Result<chain_block::Cell>
where
    F: FnOnce(&mut BuilderData) -> anyhow::Result<()>,
{
    let mut body = BuilderData::new();
    body.append_u32(opcode)?.append_u64(query_id)?;
    append(&mut body)?;
    Ok(body.into_cell()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Serializable, SliceData};
    use common::tvm_stack_parser::TvmStackParser;
    use ed25519_dalek::{Signer, SigningKey};
    use tl_api::tos::tvm::{
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
        Number, StackEntry,
    };

    fn number(value: impl Into<String>) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.into() }),
        })
    }

    fn hash_number(value: [u8; 32]) -> StackEntry {
        number(format!("0x{}", hex::encode(value)))
    }

    fn address_slice_entry(address: &MsgAddressInt) -> StackEntry {
        let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
        let bytes = SliceData::load_cell(cell).unwrap().get_bytestring(0);
        StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } })
    }

    fn init() -> ProofAttestationInit {
        ProofAttestationInit {
            owner: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            public_key: [0x22; 32],
            subject_hash: [0x33; 32],
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let a = init();
        let first = ProofAttestationContract::build_state_init(&a)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = ProofAttestationContract::build_state_init(&a)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
    }

    #[test]
    fn encodes_attest_message_with_a_real_ed25519_signature() {
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let attested_hash = [0x55; 32];
        let signature = signing_key.sign(&attested_hash).to_bytes();

        let body = ProofAttestationContract::attest(1, attested_hash, &signature).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), ATT_ATTEST_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), attested_hash.to_vec());
        assert_eq!(slice.get_next_bytes(64).unwrap(), signature.to_vec());
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_rotate_key_and_revoke_messages() {
        let rotate = ProofAttestationContract::rotate_key(2, [0x66; 32]).unwrap();
        let mut slice = SliceData::load_cell(rotate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), ATT_ROTATE_KEY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x66; 32]);
        assert_eq!(slice.remaining_bits(), 0);

        let revoke = ProofAttestationContract::revoke(3).unwrap();
        let mut slice = SliceData::load_cell(revoke).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), ATT_REVOKE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn decodes_proof_attestation_data_stack() {
        let a = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&a.owner),
            hash_number(a.public_key),
            number("0"),
            number("1"),
            number("1700000000"),
            hash_number(a.subject_hash),
            hash_number([0x77; 32]),
        ]);
        let data = ProofAttestationContract::decode_data(&stack).unwrap();
        assert_eq!(data.owner, a.owner);
        assert_eq!(data.public_key, a.public_key);
        assert!(!data.revoked);
        assert!(data.has_attestation);
        assert_eq!(data.attested_at, 1_700_000_000);
        assert_eq!(data.subject_hash, a.subject_hash);
        assert_eq!(data.attested_hash, [0x77; 32]);
    }
}
