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

pub const DISPUTE_CODE_B64: &str = "te6cckECBgEAAXoAART/APSkE/S88sgLAQIBYgIDArzQMiHHAJFb4AHTH9M/MQLQdNch+kAw7UTQ+kD6QPpA0wfTB9MP0z/UAdDT/9P/0QLUAdDT/9P/0wDT/9EE0RBFVQIughBEU1ABuuMCMjY2C4IQRFNQArrjAl8M8sfVBAUAXaEzEdqJofSB9IH0gaYPpg+mH6Z/qAOhp/+n/6IFqAOhp/+n/6YBp/+iCaIgiqoFAKgzPVG5xwXy59AGwwLy59IL0//REIsQehBpcQkQWBBHEDZFFEADA8jL/xLL/8sAy//JAsjL/8v/ychQCc8WUAfPFlAFzxYTywfLB8sPyz8SzMzJ7VQA+lGWxwXy59EEwwLy59IJ0wfTD9P/JJyDCNcYUiIn+RDy59be0SLAASPAArEjwAOx8ufTIsMDfyOBJxC7sLHy59QQixB6EGlyCRA4RxZBRQPIy/8Sy//LAMv/yQLIy//L/8nIUAnPFlAHzxZQBc8WE8sHywfLD8s/EszMye1UgOMl6A==";
pub const DSP_SUBMIT_RESPONDENT_EVIDENCE_OPCODE: u32 = 0x4453_5001;
pub const DSP_RULE_OPCODE: u32 = 0x4453_5002;

pub const DISPUTE_STATUS_OPEN: u8 = 0;
pub const DISPUTE_STATUS_EVIDENCE_SUBMITTED: u8 = 1;
pub const DISPUTE_STATUS_RESOLVED: u8 = 2;

pub const RULING_NONE: u8 = 0;
pub const RULING_CLAIMANT: u8 = 1;
pub const RULING_RESPONDENT: u8 = 2;
pub const RULING_SPLIT: u8 = 3;

/// Deployment parameters for a Dispute case.
///
/// One instance is deployed per dispute -- the same per-actor pattern as
/// `AgentAccountContract` / `TaskEscrowContract` / `CapabilityRegistryContract`
/// / `ServiceActorContract`. This contract is a pure adjudication ledger: it
/// does not hold or move funds, it only records evidence and a reviewer's
/// ruling for a subject (typically a Task Escrow address, but any 32-byte
/// reference works).
#[derive(Clone, Debug)]
pub struct DisputeInit {
    pub claimant: MsgAddressInt,
    pub respondent: MsgAddressInt,
    pub reviewer: MsgAddressInt,
    /// Informational: expected ruling deadline (not enforced on-chain).
    pub deadline: u64,
    /// Reference to what is being disputed, e.g. a Task Escrow address's hash.
    pub subject_hash: [u8; 32],
    pub claimant_evidence_hash: [u8; 32],
    /// Optional ed25519 public key. When set, `rule` additionally requires a
    /// signature over the new `ruling_hash` under this key -- on top of,
    /// never instead of, the existing reviewer sender authorization.
    pub attestor_pubkey: Option<[u8; 32]>,
}

pub struct DisputeContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeData {
    pub claimant: MsgAddressInt,
    pub respondent: MsgAddressInt,
    pub reviewer: MsgAddressInt,
    pub status: u8,
    pub ruling: u8,
    /// Basis points awarded to the claimant; only meaningful when `ruling == RULING_SPLIT`.
    pub split_bps: u16,
    pub deadline: u64,
    pub subject_hash: [u8; 32],
    pub claimant_evidence_hash: [u8; 32],
    pub respondent_evidence_hash: [u8; 32],
    pub ruling_hash: [u8; 32],
    pub attestor_pubkey: Option<[u8; 32]>,
}

impl DisputeContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(DISPUTE_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &DisputeInit) -> anyhow::Result<chain_block::Cell> {
        let mut data = BuilderData::new();
        init.claimant.write_to(&mut data)?;
        init.respondent.write_to(&mut data)?;
        init.reviewer.write_to(&mut data)?;
        data.append_u8(DISPUTE_STATUS_OPEN)?;
        data.append_u8(RULING_NONE)?;
        data.append_u16(0)?; // split_bps
        data.append_u64(init.deadline)?;
        let mut claim = BuilderData::new();
        claim.append_u256(&init.subject_hash)?.append_u256(&init.claimant_evidence_hash)?;
        data.checked_append_reference(claim.into_cell()?)?;
        let mut res = BuilderData::new();
        res.append_u256(&[0; 32])?.append_u256(&[0; 32])?;
        match init.attestor_pubkey {
            Some(pubkey) => {
                res.append_bit_one()?.append_raw(&pubkey, 256)?;
            }
            None => {
                res.append_bit_zero()?.append_raw(&[0; 32], 256)?;
            }
        }
        data.checked_append_reference(res.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &DisputeInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &DisputeInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_dispute_data`; transport and RPC concerns
    /// stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<DisputeData> {
        let mut claimant_slice = stack.slice(0)?;
        let mut respondent_slice = stack.slice(1)?;
        let mut reviewer_slice = stack.slice(2)?;
        Ok(DisputeData {
            claimant: MsgAddressInt::construct_from(&mut claimant_slice)?,
            respondent: MsgAddressInt::construct_from(&mut respondent_slice)?,
            reviewer: MsgAddressInt::construct_from(&mut reviewer_slice)?,
            status: stack.u64(3)? as u8,
            ruling: stack.u64(4)? as u8,
            split_bps: stack.u64(5)? as u16,
            deadline: stack.u64(6)?,
            subject_hash: parse_hash(stack, 7)?,
            claimant_evidence_hash: parse_hash(stack, 8)?,
            respondent_evidence_hash: parse_hash(stack, 9)?,
            ruling_hash: parse_hash(stack, 10)?,
            attestor_pubkey: if stack.u64(11)? == 0 { None } else { Some(parse_hash(stack, 12)?) },
        })
    }

    pub fn submit_respondent_evidence(
        query_id: u64,
        respondent_evidence_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(DSP_SUBMIT_RESPONDENT_EVIDENCE_OPCODE, query_id, |b| {
            b.append_u256(&respondent_evidence_hash).map(|_| ())
        })
    }

    pub fn rule(
        query_id: u64,
        ruling: u8,
        split_bps: u16,
        ruling_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(DSP_RULE_OPCODE, query_id, |b| {
            b.append_u8(ruling)?.append_u16(split_bps)?.append_u256(&ruling_hash).map(|_| ())
        })
    }

    /// Rule on a dispute deployed with an `attestor_pubkey`: `signature` must
    /// be a valid ed25519 signature over `ruling_hash` under that key, or the
    /// contract rejects the message.
    pub fn rule_signed(
        query_id: u64,
        ruling: u8,
        split_bps: u16,
        ruling_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(DSP_RULE_OPCODE, query_id, |b| {
            b.append_u8(ruling)?.append_u16(split_bps)?.append_u256(&ruling_hash)?;
            b.append_raw(signature, 512).map(|_| ())
        })
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

    fn init() -> DisputeInit {
        DisputeInit {
            claimant: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            respondent: MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap(),
            reviewer: MsgAddressInt::with_standart(None, -1, [0x33; 32].into()).unwrap(),
            deadline: 1_700_000_000,
            subject_hash: [0x44; 32],
            claimant_evidence_hash: [0x55; 32],
            attestor_pubkey: None,
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let d = init();
        let first = DisputeContract::build_state_init(&d)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = DisputeContract::build_state_init(&d)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
    }

    #[test]
    fn encodes_submit_respondent_evidence_message() {
        let body = DisputeContract::submit_respondent_evidence(1, [0xAA; 32]).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), DSP_SUBMIT_RESPONDENT_EVIDENCE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_rule_message() {
        let body = DisputeContract::rule(2, RULING_SPLIT, 6000, [0xBB; 32]).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), DSP_RULE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.get_next_byte().unwrap(), RULING_SPLIT);
        assert_eq!(slice.get_next_int(16).unwrap() as u16, 6000);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xBB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn decodes_dispute_data_stack() {
        let d = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&d.claimant),
            address_slice_entry(&d.respondent),
            address_slice_entry(&d.reviewer),
            number("2"),
            number(RULING_SPLIT.to_string()),
            number("6000"),
            number(d.deadline.to_string()),
            hash_number(d.subject_hash),
            hash_number(d.claimant_evidence_hash),
            hash_number([0x66; 32]),
            hash_number([0x77; 32]),
            number("1"),
            hash_number([0x88; 32]),
        ]);
        let data = DisputeContract::decode_data(&stack).unwrap();
        assert_eq!(data.claimant, d.claimant);
        assert_eq!(data.respondent, d.respondent);
        assert_eq!(data.reviewer, d.reviewer);
        assert_eq!(data.status, DISPUTE_STATUS_RESOLVED);
        assert_eq!(data.ruling, RULING_SPLIT);
        assert_eq!(data.split_bps, 6000);
        assert_eq!(data.deadline, d.deadline);
        assert_eq!(data.subject_hash, d.subject_hash);
        assert_eq!(data.claimant_evidence_hash, d.claimant_evidence_hash);
        assert_eq!(data.respondent_evidence_hash, [0x66; 32]);
        assert_eq!(data.ruling_hash, [0x77; 32]);
        assert_eq!(data.attestor_pubkey, Some([0x88; 32]));
    }
}
