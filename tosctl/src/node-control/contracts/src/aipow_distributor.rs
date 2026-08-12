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

pub const AIPOW_DISTRIBUTOR_CODE_B64: &str = "te6cckECDgEAA0AAART/APSkE/S88sgLAQIBYgIDAqjQAdDTAwFxsJJfA+D6QDAhxwCSXwPgAdMf0z8x7UTQ+kDTP9N/+gDTH9N/1AHQ0//T/9EC9ATREiqCEEFQRAG64wI8CYIQQVBEArrjAl8LgQic8vAEBQIBIAgJAv46OoEIoguCCvrwgL4b8vSBCJgkwgDy9AbT/9N/1NGBCKEiwgDy9IEIoFOSoCe78vRTKYMH9A5voYEImTLy8lMhcMjLBxLL/8t/ydD5AgHbPIEImlEcuvL0VHMEqYRwIPgjyFAE+gITyz8SywDLP0AJgwf0QwGkUGegEEgQN0ZQBgcAzoEInVGnxwUa8vQG0//RUwmDB/QOb6GBCJ4B8vT6ANM/0wAwgQifAfLy+CNxyFAE+gISyz8SywDLP0Aagwf0QxBIEDdGUEMwAsjL/8v/ychQCM8WFss/FMt/WPoCyx/LfxLM9ADJ7VQA6HAgkyDAAI5pItAg10kh10ohwACbbCGBCKMywADy9HGOT4EIowKBAQG6IcECsBLy9IEImyTCO/LyAdP/0wABngZxyMsHEsv/y//J0PkCn1BmccjLBxLL/8v/ydD5AuIBwAGWMwPUMAGklDFxNFniVQLi6F8DAEREMwLIy//L/8nIUAjPFhbLPxTLf1j6Assfy38SzPQAye1UAgFICgsAP70pD2omh9IGmf6b/9AGmP6b/qAOhp/+n/6IF6AmiJGEAN+2Ab2omh9IGmf6b/9AGmP6b/qAOhp/+n/6IF6AmiJNkDBg/oHN9DgAEmYOBBwfQBpn+mAaZ+YIYm4qBJ8EYFMKYDcyJjImHFImHERQITiQJOIVMIpiV3JNhjHCYFQ1YeQYQRJGDxvKJDQrFTaAVBxQAgEgDA0A17Mau1E0PpA0z/Tf/oA0x/Tf9QB0NP/0//RAvQE0RJsgRKDB/QOb6HAAJNbcCDg+gDTP9MA0z8wcQUCmFMBuZExkTDikTDiIoEJxIEnEKmEUxK7kmwxjhMCoasPIMIIkjB43lEhoViptAKg4oAB5s207UTQ+kDTP9N/+gDTH9N/1AHQ0//T/9EC9ATREmyBgwf0Dm+hwACWMHBUcAAg4PoA0z/TANM/MHFVMIKTvvHo=";

pub const AIPOW_DISTRIBUTOR_CLAIM_OPCODE: u32 = 0x4150_4401;
pub const AIPOW_DISTRIBUTOR_FORFEIT_OPCODE: u32 = 0x4150_4402;

/// Maturation parameters (methodology v0 draft). Kept in sync with the
/// contract's constants; a divergence would make the SDK's `compute_matured`
/// disagree with `get_matured` on chain.
pub const AIPOW_MATURATION_IMMEDIATE_BPS: u128 = 2_500;
pub const AIPOW_MATURATION_STREAM_EPOCHS: u128 = 8;
pub const AIPOW_MATURATION_EPOCH_SECONDS: u64 = 65_536;

/// Minimum value a claim message must carry (nanotos), mirroring the
/// contract's `min_claim_value`: a permissionless claim must fund its own gas
/// and a share of the dict's storage rent. Callers should attach at least
/// this much plus a forwarding margin.
pub const AIPOW_MIN_CLAIM_VALUE: u64 = 50_000_000;

/// One recorded claim's maturation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AipowClaim {
    pub amount: u64,
    pub claimed_at: u64,
    pub forfeited: bool,
    pub forfeit_at: u64,
}

/// The matured amount of a claim at `at_time`, computed identically to the
/// contract's `compute_matured`: an immediate fraction plus a linear stream
/// over the maturation epochs from claim time, frozen at forfeit time when
/// forfeited. Pure integer arithmetic, so the SDK and the on-chain
/// get-method agree.
pub fn compute_matured(claim: &AipowClaim, at_time: u64) -> u64 {
    let effective = if claim.forfeited {
        at_time.min(claim.forfeit_at)
    } else {
        at_time
    };
    let amount = u128::from(claim.amount);
    let immediate = amount * AIPOW_MATURATION_IMMEDIATE_BPS / 10_000;
    if effective <= claim.claimed_at {
        return immediate as u64;
    }
    let elapsed = u128::from((effective - claim.claimed_at) / AIPOW_MATURATION_EPOCH_SECONDS)
        .min(AIPOW_MATURATION_STREAM_EPOCHS);
    let streamed = (amount - immediate) * elapsed / AIPOW_MATURATION_STREAM_EPOCHS;
    (immediate + streamed) as u64
}

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
    /// Running sum of claimed scores; the claim path holds it at or below
    /// `total_score` so the aggregate recorded amount cannot exceed `pool`.
    pub claimed_score: u128,
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
        append_u128(&mut data, 0)?; // claimed_score
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
            claimed_score: parse_u128(stack, 5)?,
            score_root: parse_hash(stack, 6)?,
            commitment_ref: parse_hash(stack, 7)?,
        })
    }

    /// Decode `get_claim`: `(found, amount, claimed_at, forfeited, forfeit_at)`.
    pub fn decode_claim(stack: &TvmStackParser) -> anyhow::Result<Option<AipowClaim>> {
        let found = stack.u64(0)? != 0;
        if !found {
            return Ok(None);
        }
        Ok(Some(AipowClaim {
            amount: stack.u64(1)?,
            claimed_at: stack.u64(2)?,
            forfeited: stack.u64(3)? != 0,
            forfeit_at: stack.u64(4)?,
        }))
    }

    /// Decode `get_matured`: `(found, matured)`.
    pub fn decode_matured(stack: &TvmStackParser) -> anyhow::Result<Option<u64>> {
        let found = stack.u64(0)? != 0;
        if !found {
            return Ok(None);
        }
        Ok(Some(stack.u64(1)?))
    }

    /// Operator-only forfeit of a claim's unmatured remainder.
    pub fn forfeit(query_id: u64, identity: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        let mut body = BuilderData::new();
        body.append_u32(AIPOW_DISTRIBUTOR_FORFEIT_OPCODE)?;
        body.append_u64(query_id)?;
        body.append_raw(&identity, 256)?;
        Ok(body.into_cell()?)
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

    #[test]
    fn maturation_curve_matches_the_methodology() {
        let e = AIPOW_MATURATION_EPOCH_SECONDS;
        let claim = AipowClaim { amount: 8000, claimed_at: 1_000, forfeited: false, forfeit_at: 0 };
        // Immediately: 25% only.
        assert_eq!(compute_matured(&claim, 1_000), 2000);
        assert_eq!(compute_matured(&claim, 500), 2000); // before claim clamps to immediate
        // After 1 epoch: 25% + 1/8 of the 75% stream (6000) = 2000 + 750.
        assert_eq!(compute_matured(&claim, 1_000 + e), 2750);
        // After 4 epochs: 2000 + 3000.
        assert_eq!(compute_matured(&claim, 1_000 + 4 * e), 5000);
        // After 8+ epochs: fully matured.
        assert_eq!(compute_matured(&claim, 1_000 + 8 * e), 8000);
        assert_eq!(compute_matured(&claim, 1_000 + 100 * e), 8000);
    }

    #[test]
    fn forfeit_freezes_maturation_at_the_forfeit_time() {
        let e = AIPOW_MATURATION_EPOCH_SECONDS;
        // Forfeited at 2 epochs: matured is frozen at 25% + 2/8 of 6000.
        let claim = AipowClaim {
            amount: 8000,
            claimed_at: 1_000,
            forfeited: true,
            forfeit_at: 1_000 + 2 * e,
        };
        let frozen = 2000 + 6000 * 2 / 8;
        assert_eq!(compute_matured(&claim, 1_000 + 2 * e), frozen);
        // Later than the forfeit: still frozen, the remainder is voided.
        assert_eq!(compute_matured(&claim, 1_000 + 100 * e), frozen);
        // Earlier than the forfeit: the normal (smaller) matured value.
        assert_eq!(compute_matured(&claim, 1_000 + e), 2750);
    }

    #[test]
    fn forfeit_message_encodes_identity() {
        let body = AipowDistributorContract::forfeit(9, [0x55; 32]).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), AIPOW_DISTRIBUTOR_FORFEIT_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0x55; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }
}
