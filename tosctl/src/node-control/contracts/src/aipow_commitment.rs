/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::Deserializable;
use chain_block::{
    BuilderData, IBitstring, MsgAddressInt, Serializable, StateInit, base64_decode,
    read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;

pub const AIPOW_COMMITMENT_CODE_B64: &str = "te6cckECCAEAAkcAART/APSkE/S88sgLAQIBYgIDA9DQAdDTAwFxsJJfA+D6QDAhxwCSXwPgAdMf0z8x7UTQ+kD6QNMH0z/TP/oA+gDUAdDT/9P/0QLUAdD6QNP/0QLRQwAsghBBUFcBuuMCPiuCEEFQVwK64wILghBBUFcDuuMCXw2BCDvy8AQFBgBRoZcB2omh9IH0gaYPpn+mf/QB9AGoA6Gn/6f/ogWoA6H0gaf/ogWihgEAwFsyOYEINAXAABXy9IEINfgjI7ny9IEINlOhvvL0BtP/0YEIPCHDAPL0EFkQSHEIEDdeMkQzyFjPFsv/yQLIy//L/8nIUAnPFlAHzxYVywcTyz/LPwH6AgH6AhLMzMntVADQOzuBCDQGwAAW8vSBCDf4IyS+8vQH0XImCRBoVBcCEFcQRgUESxMMyFjPFsv/yQLIy//L/8nIUAnPFlAHzxYVywcTyz/LPwH6AgH6AhLMzMntVAFxcIAQyMsFUATPFlj6AhLLaskB+wAB8oEIOVHIxwUc8vSBCDgGwAEW8vQH0wfRgQg6IcAAIsABsfL0jlJyJlBoVBcCEFYEVEFkTD0byFjPFsv/yQLIy//L/8nIUAnPFlAHzxYVywcTyz/LPwH6AgH6AhLMzMntVFmgcXCAEMjLBVAEzxZY+gISy2rJAfsA4w0HAKYQVhBFc1FREEUDVEFTQbBSrchYzxbL/8kCyMv/y//JyFAJzxZQB88WFcsHE8s/yz8B+gIB+gISzMzJ7VRZoHFwgBDIywVQBM8WWPoCEstqyQH7ALt32zU=";

pub const APW_CHALLENGE_OPCODE: u32 = 0x4150_5701;
pub const APW_FINALIZE_OPCODE: u32 = 0x4150_5702;
pub const APW_RULE_OPCODE: u32 = 0x4150_5703;

pub const AIPOW_COMMITMENT_STATUS_COMMITTED: u8 = 0;
pub const AIPOW_COMMITMENT_STATUS_CHALLENGED: u8 = 1;
pub const AIPOW_COMMITMENT_STATUS_FINAL: u8 = 2;
pub const AIPOW_COMMITMENT_STATUS_REJECTED: u8 = 3;

/// Deployment parameters for one AIPoW epoch score commitment.
///
/// One instance is deployed per committed epoch score root -- the same
/// per-actor pattern as the other native AI-actor contracts. The deploy
/// value funds the committer's bond (plus fee/storage margin); anyone may
/// challenge with at least a matching bond before `window_deadline`, an
/// unchallenged commitment finalizes permissionlessly afterwards, and the
/// reviewer rules a challenged one. The contract records and adjudicates
/// commitments only; it never creates or distributes AIPoW rewards.
#[derive(Clone, Debug)]
pub struct AipowCommitmentInit {
    pub committer: MsgAddressInt,
    pub reviewer: MsgAddressInt,
    pub epoch: u64,
    /// Unix time: challenges land strictly before, finalize at or after.
    pub window_deadline: u64,
    /// Bond (nanotos) held for the committer; a challenge must attach at
    /// least this much.
    pub commit_bond: u64,
    pub score_root: [u8; 32],
    pub methodology_hash: [u8; 32],
}

pub struct AipowCommitmentContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowCommitmentData {
    pub committer: MsgAddressInt,
    pub reviewer: MsgAddressInt,
    pub status: u8,
    pub epoch: u64,
    pub window_deadline: u64,
    pub commit_bond: u64,
    pub challenge_bond: u64,
    pub score_root: [u8; 32],
    pub methodology_hash: [u8; 32],
    /// The zero address until a challenge is recorded.
    pub challenger: MsgAddressInt,
    pub challenge_evidence_hash: [u8; 32],
}

impl AipowCommitmentContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(AIPOW_COMMITMENT_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &AipowCommitmentInit) -> anyhow::Result<chain_block::Cell> {
        if init.score_root == [0; 32] {
            anyhow::bail!("score_root must not be the all-zero digest");
        }
        if init.commit_bond == 0 {
            anyhow::bail!("commit_bond must be positive");
        }
        let mut data = BuilderData::new();
        init.committer.write_to(&mut data)?;
        init.reviewer.write_to(&mut data)?;
        data.append_u8(AIPOW_COMMITMENT_STATUS_COMMITTED)?;
        data.append_u64(init.epoch)?;
        data.append_u64(init.window_deadline)?;
        append_tomis(&mut data, init.commit_bond)?;
        append_tomis(&mut data, 0)?;
        let mut root = BuilderData::new();
        root.append_u256(&init.score_root)?.append_u256(&init.methodology_hash)?;
        data.checked_append_reference(root.into_cell()?)?;
        let mut challenge = BuilderData::new();
        MsgAddressInt::default().write_to(&mut challenge)?;
        challenge.append_u256(&[0; 32])?;
        data.checked_append_reference(challenge.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &AipowCommitmentInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &AipowCommitmentInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_aipow_commitment_data`; transport and RPC
    /// concerns stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<AipowCommitmentData> {
        let mut committer_slice = stack.slice(0)?;
        let mut reviewer_slice = stack.slice(1)?;
        let mut challenger_slice = stack.slice(9)?;
        Ok(AipowCommitmentData {
            committer: MsgAddressInt::construct_from(&mut committer_slice)?,
            reviewer: MsgAddressInt::construct_from(&mut reviewer_slice)?,
            status: stack.u64(2)? as u8,
            epoch: stack.u64(3)?,
            window_deadline: stack.u64(4)?,
            commit_bond: stack.u64(5)?,
            challenge_bond: stack.u64(6)?,
            score_root: parse_hash(stack, 7)?,
            methodology_hash: parse_hash(stack, 8)?,
            challenger: MsgAddressInt::construct_from(&mut challenger_slice)?,
            challenge_evidence_hash: parse_hash(stack, 10)?,
        })
    }

    /// Anyone may challenge a committed root before the window deadline;
    /// the attached message value (at least the commit bond) becomes the
    /// challenger's bond. The evidence hash must be nonzero.
    pub fn challenge(
        query_id: u64,
        challenge_evidence_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(APW_CHALLENGE_OPCODE, query_id, |b| {
            b.append_u256(&challenge_evidence_hash).map(|_| ())
        })
    }

    /// Anyone may finalize an unchallenged commitment once the window has
    /// passed; the bond always returns to the committer.
    pub fn finalize(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(APW_FINALIZE_OPCODE, query_id, |_| Ok(()))
    }

    /// Reviewer-only ruling on a challenged commitment: upholding rejects
    /// the root and awards both bonds to the challenger; dismissing
    /// finalizes the root and awards both bonds to the committer.
    pub fn rule(query_id: u64, uphold: bool) -> anyhow::Result<chain_block::Cell> {
        message(APW_RULE_OPCODE, query_id, |b| b.append_u8(u8::from(uphold)).map(|_| ()))
    }
}

fn append_tomis(builder: &mut BuilderData, amount: u64) -> anyhow::Result<()> {
    chain_block::Coins::new(amount).write_to(builder)?;
    Ok(())
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
    use chain_block::SliceData;

    fn init() -> AipowCommitmentInit {
        AipowCommitmentInit {
            committer: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            reviewer: MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap(),
            epoch: 27_260,
            window_deadline: 1_800_000_000,
            commit_bond: 5_000_000_000,
            score_root: [0x33; 32],
            methodology_hash: [0x44; 32],
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let i = init();
        let first = AipowCommitmentContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = AipowCommitmentContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
    }

    #[test]
    fn build_data_rejects_zero_root_and_zero_bond() {
        let mut zero_root = init();
        zero_root.score_root = [0; 32];
        assert!(AipowCommitmentContract::build_data(&zero_root).is_err());
        let mut zero_bond = init();
        zero_bond.commit_bond = 0;
        assert!(AipowCommitmentContract::build_data(&zero_bond).is_err());
    }

    #[test]
    fn encodes_challenge_finalize_and_rule_messages() {
        let body = AipowCommitmentContract::challenge(1, [0xAA; 32]).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), APW_CHALLENGE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
        assert_eq!(slice.remaining_bits(), 0);

        let body = AipowCommitmentContract::finalize(2).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), APW_FINALIZE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.remaining_bits(), 0);

        let body = AipowCommitmentContract::rule(3, true).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), APW_RULE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(slice.get_next_byte().unwrap(), 1);
        assert_eq!(slice.remaining_bits(), 0);
    }
}
