/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::Deserializable;
use chain_block::{
    base64_decode, read_single_root_boc, BuilderData, Coins, IBitstring, MsgAddressInt,
    Serializable, StateInit,
};
use common::tvm_stack_parser::TvmStackParser;

use crate::aipow_merkle::ProofStep;

pub const AIPOW_DISTRIBUTOR_CODE_B64: &str = "te6cckECCAEAAYAAART/APSkE/S88sgLAQIBYgIDAYjQMtDTAwFxsJFb4PpAWyDHAJEw4NMf0z8x7UTQ+kDTP9N/+gDTH9QB0NP/0//RAvQE0RIJghBBUEQBuuMCXwmBCJzy8AQCASAGBwHegQiYJcIA8vQH0//Tf9TRUyqDB/QOb6GBCJky8vJTIXDIywcSy//Lf8nQ+QIB2zyBCJpRFLry9FRkYamEyAH6AkAZgwf0QwGkEFcQRhA1RBNZAsjL/8v/ychQB88WFcs/E8t/AfoCyx8SzPQAye1UBQC2cCCTIMAAjlCBCJsiwjzy8iLQINdJgQEBuZJbcY450//TAAGeBXHIywcSy//L/8nQ+QKfUFVxyMsHEsv/y//J0PkC4iTXSsIAljMD1DABpJQxcTRZ4lUC4uhfAwBhve2naiaH0gaZ/pv/0AaY/qAOhp/+n/6IF6AmiJNjjBg/oHN9DgAEmYOBBwfQAYOIDAA7vSkPaiaH0gaZ/pv/0AaY/qAOhp/+n/6IF6AmiJGEnp8Jqw==";

pub const AIPOW_DISTRIBUTOR_CLAIM_OPCODE: u32 = 0x4150_4401;

/// Deployment parameters for one epoch reward distributor.
///
/// One instance is deployed per finalized epoch score root -- the same
/// per-actor pattern as the other native AIPoW contracts. This slice is
/// deliberately zero-emission: it records claims but neither holds nor
/// moves reward funds.
#[derive(Clone, Debug)]
pub struct AipowDistributorInit {
    pub operator: MsgAddressInt,
    pub epoch: u64,
    /// Pro-rata denominator: the epoch's total score. Must be positive.
    pub total_score: u128,
    /// Nominal epoch pool this slice records against but does not move.
    pub pool: u64,
    /// The finalized epoch score root beneficiaries prove membership in.
    pub score_root: [u8; 32],
    /// Reference (a 32-byte address hash) to the finalized score-commitment
    /// instance the root came from, for off-chain cross-checking.
    pub commitment_ref: [u8; 32],
}

pub struct AipowDistributorContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowDistributorData {
    pub operator: MsgAddressInt,
    pub epoch: u64,
    pub total_score: u128,
    pub pool: u64,
    pub claimed_count: u32,
    pub score_root: [u8; 32],
    pub commitment_ref: [u8; 32],
}

impl AipowDistributorContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(AIPOW_DISTRIBUTOR_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &AipowDistributorInit) -> anyhow::Result<chain_block::Cell> {
        if init.total_score == 0 {
            anyhow::bail!("total_score must be positive");
        }
        if init.score_root == [0; 32] {
            anyhow::bail!("score_root must not be the all-zero digest");
        }
        let mut data = BuilderData::new();
        init.operator.write_to(&mut data)?;
        data.append_u64(init.epoch)?;
        append_u128(&mut data, init.total_score)?;
        Coins::new(init.pool).write_to(&mut data)?;
        data.append_u32(0)?; // claimed_count
        let mut roots = BuilderData::new();
        roots.append_u256(&init.score_root)?.append_u256(&init.commitment_ref)?;
        data.checked_append_reference(roots.into_cell()?)?;
        // Empty claims dictionary.
        data.append_bit_zero()?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &AipowDistributorInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(
        wc: i32,
        init: &AipowDistributorInit,
    ) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_aipow_distributor_data`.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<AipowDistributorData> {
        let mut operator_slice = stack.slice(0)?;
        Ok(AipowDistributorData {
            operator: MsgAddressInt::construct_from(&mut operator_slice)?,
            epoch: stack.u64(1)?,
            total_score: parse_u128(stack, 2)?,
            pool: stack.u64(3)?,
            claimed_count: stack.u64(4)? as u32,
            score_root: parse_hash(stack, 5)?,
            commitment_ref: parse_hash(stack, 6)?,
        })
    }

    /// Decode the result of `get_claim`: `(found, amount)`.
    pub fn decode_claim(stack: &TvmStackParser) -> anyhow::Result<Option<u64>> {
        let found = stack.u64(0)? != 0;
        if !found {
            return Ok(None);
        }
        Ok(Some(stack.u64(1)?))
    }

    /// A beneficiary claim: `(identity, score)` plus a merkle inclusion
    /// proof against the distributor's score root. The proof is encoded as
    /// a chain of cells `sibling(256) sibling_is_left(1) [next:^cell]?`,
    /// exactly the shape the contract folds; an empty proof (single-member
    /// tree) is an empty cell.
    pub fn claim(
        query_id: u64,
        identity: [u8; 32],
        score: u128,
        proof: &[ProofStep],
    ) -> anyhow::Result<chain_block::Cell> {
        let proof_cell = encode_proof(proof)?;
        let mut body = BuilderData::new();
        body.append_u32(AIPOW_DISTRIBUTOR_CLAIM_OPCODE)?;
        body.append_u64(query_id)?;
        body.append_raw(&identity, 256)?;
        append_u128(&mut body, score)?;
        body.checked_append_reference(proof_cell)?;
        Ok(body.into_cell()?)
    }
}

/// Encode an inclusion proof into the contract's cell chain.
pub fn encode_proof(proof: &[ProofStep]) -> anyhow::Result<chain_block::Cell> {
    // Build from the tail so each step references the next.
    let mut next: Option<chain_block::Cell> = None;
    for step in proof.iter().rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(&step.sibling, 256)?;
        if step.sibling_is_left {
            cell.append_bit_one()?;
        } else {
            cell.append_bit_zero()?;
        }
        if let Some(next_cell) = next.take() {
            cell.checked_append_reference(next_cell)?;
        }
        next = Some(cell.into_cell()?);
    }
    match next {
        Some(cell) => Ok(cell),
        None => Ok(BuilderData::new().into_cell()?),
    }
}

fn append_u128(builder: &mut BuilderData, value: u128) -> anyhow::Result<()> {
    builder.append_raw(&value.to_be_bytes(), 128)?;
    Ok(())
}

fn parse_u128(stack: &TvmStackParser, index: usize) -> anyhow::Result<u128> {
    let bytes = stack.number_bytes(index, 16)?;
    let array: [u8; 16] =
        bytes.try_into().map_err(|_| anyhow::anyhow!("stack entry {} is not a 128-bit value", index))?;
    Ok(u128::from_be_bytes(array))
}

fn parse_hash(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 256-bit value", index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aipow_merkle::{inclusion_proof, score_root, ScoreEntry};
    use chain_block::SliceData;

    fn init() -> AipowDistributorInit {
        AipowDistributorInit {
            operator: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            epoch: 27_260,
            total_score: 1_000_000,
            pool: 5_000_000_000,
            score_root: [0x33; 32],
            commitment_ref: [0x44; 32],
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let i = init();
        let a = AipowDistributorContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let b = AipowDistributorContract::build_state_init(&i)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(a.hash(0), b.hash(0));
    }

    #[test]
    fn build_data_rejects_zero_total_score_and_zero_root() {
        let mut zero_score = init();
        zero_score.total_score = 0;
        assert!(AipowDistributorContract::build_data(&zero_score).is_err());
        let mut zero_root = init();
        zero_root.score_root = [0; 32];
        assert!(AipowDistributorContract::build_data(&zero_root).is_err());
    }

    #[test]
    fn claim_message_encodes_identity_score_and_proof_reference() {
        let entries = [
            ScoreEntry { identity: [1; 32], score: 1000 },
            ScoreEntry { identity: [2; 32], score: 2000 },
            ScoreEntry { identity: [3; 32], score: 3000 },
        ];
        let _root = score_root(&entries).unwrap();
        let proof = inclusion_proof(&entries, &[2; 32]).unwrap();
        let body = AipowDistributorContract::claim(7, [2; 32], 2000, &proof).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), AIPOW_DISTRIBUTOR_CLAIM_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![2u8; 32]);
        assert_eq!(slice.get_next_bytes(16).unwrap(), 2000u128.to_be_bytes().to_vec());
        // The proof chain is a reference.
        assert_eq!(slice.remaining_references(), 1);
    }

    #[test]
    fn empty_proof_is_an_empty_cell() {
        let cell = encode_proof(&[]).unwrap();
        let slice = SliceData::load_cell(cell).unwrap();
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 0);
    }
}
