/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
use chain_block::Deserializable;
use chain_block::{
    BuilderData, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, base64_decode,
    read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;

use crate::aipow_merkle::ProofStep;

pub const AIPOW_DISTRIBUTOR_CODE_B64: &str = "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";

pub const AIPOW_DISTRIBUTOR_CLAIM_OPCODE: u32 = 0x4150_4401;
pub const AIPOW_DISTRIBUTOR_FORFEIT_OPCODE: u32 = 0x4150_4402;
pub const AIPOW_DISTRIBUTOR_PAYOUT_OPCODE: u32 = 0x4150_4403;

/// The distributor layout version this SDK writes and the contract understands.
pub const AIPOW_DISTRIBUTOR_VERSION: u16 = 1;

/// Default maturation parameters (methodology v0 draft). These are the values a
/// deployer snapshots into a distributor unless governance overrides them; each
/// deployed instance freezes its own copy, and the SDK reads the frozen values
/// back for `compute_matured` so the SDK and `get_matured` cannot diverge.
pub const AIPOW_MATURATION_IMMEDIATE_BPS: u16 = 2_500;
pub const AIPOW_MATURATION_STREAM_EPOCHS: u16 = 8;
pub const AIPOW_MATURATION_EPOCH_SECONDS: u32 = 65_536;

/// The maturation curve a distributor snapshots at deploy: an immediate
/// fraction (`immediate_bps` / 10000) paid at claim time, and the remainder
/// streamed linearly over `stream_epochs` epochs of `epoch_seconds` each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AipowMaturation {
    pub immediate_bps: u16,
    pub stream_epochs: u16,
    pub epoch_seconds: u32,
}

impl AipowMaturation {
    /// The methodology v0 default snapshot (25% immediate, 8 epochs of 65,536s).
    pub fn methodology_v0() -> Self {
        Self {
            immediate_bps: AIPOW_MATURATION_IMMEDIATE_BPS,
            stream_epochs: AIPOW_MATURATION_STREAM_EPOCHS,
            epoch_seconds: AIPOW_MATURATION_EPOCH_SECONDS,
        }
    }
}

/// Minimum value a claim message must carry (nanotos), mirroring the
/// contract's `min_claim_value`: a permissionless claim must fund its own gas
/// and a share of the dict's storage rent. Callers should attach at least
/// this much plus a forwarding margin.
pub const AIPOW_MIN_CLAIM_VALUE: u64 = 50_000_000;

/// One recorded claim's maturation state. `paid` is the cumulative amount
/// already sent to the identity, so a payout only sends newly-matured value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AipowClaim {
    pub amount: u64,
    pub claimed_at: u64,
    pub forfeited: bool,
    pub forfeit_at: u64,
    pub paid: u64,
}

/// The matured amount of a claim at `at_time` under a maturation snapshot,
/// computed identically to the contract's `compute_matured`: an immediate
/// fraction plus a linear stream over the maturation epochs from claim time,
/// frozen at forfeit time when forfeited. Pure integer arithmetic, so the SDK
/// and the on-chain get-method agree.
pub fn compute_matured(claim: &AipowClaim, mat: &AipowMaturation, at_time: u64) -> u64 {
    let effective = if claim.forfeited { at_time.min(claim.forfeit_at) } else { at_time };
    let amount = u128::from(claim.amount);
    let immediate = amount * u128::from(mat.immediate_bps) / 10_000;
    if effective <= claim.claimed_at {
        return immediate as u64;
    }
    let elapsed = u128::from((effective - claim.claimed_at) / u64::from(mat.epoch_seconds))
        .min(u128::from(mat.stream_epochs));
    let streamed = (amount - immediate) * elapsed / u128::from(mat.stream_epochs);
    (immediate + streamed) as u64
}

/// Deployment parameters for one epoch reward distributor.
///
/// One instance is deployed per finalized epoch score root -- the same
/// per-actor pattern as the other native AIPoW contracts. It holds the epoch
/// pool (forwarded to it as native issuance) and pays matured reward out to
/// each beneficiary's own committed identity address on the earner workchain.
#[derive(Clone, Debug)]
pub struct AipowDistributorInit {
    pub operator: MsgAddressInt,
    pub epoch: u64,
    /// The workchain the scored identities are paid on (e.g. 0 for basechain).
    pub earner_workchain: i8,
    /// Pro-rata denominator: the epoch's total score. Must be positive.
    pub total_score: u128,
    /// Nominal epoch pool: the pro-rata numerator base. Funded to the instance
    /// as native issuance (plus a gas/fee reserve) before payouts.
    pub pool: u64,
    /// The maturation curve frozen into this instance at deploy.
    pub maturation: AipowMaturation,
    /// The finalized epoch score root beneficiaries prove membership in.
    pub score_root: [u8; 32],
    /// Reference (a 32-byte address hash) to the finalized score-commitment
    /// instance the root came from, for off-chain cross-checking.
    pub commitment_ref: [u8; 32],
}

pub struct AipowDistributorContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowDistributorData {
    pub version: u16,
    pub operator: MsgAddressInt,
    pub epoch: u64,
    pub earner_workchain: i8,
    pub total_score: u128,
    pub pool: u64,
    pub claimed_count: u32,
    /// Running sum of claimed scores; the claim path holds it at or below
    /// `total_score` so the aggregate recorded amount cannot exceed `pool`.
    pub claimed_score: u128,
    /// The maturation curve this instance froze at deploy.
    pub maturation: AipowMaturation,
    /// Wall-clock time the operator (settlement) funded the pool; 0 until then.
    /// Claims are refused before it, so vesting cannot start ahead of issuance.
    pub activated_at: u64,
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
        if init.maturation.epoch_seconds == 0 || init.maturation.stream_epochs == 0 {
            anyhow::bail!("maturation epoch_seconds and stream_epochs must be positive");
        }
        if init.maturation.immediate_bps > 10_000 {
            anyhow::bail!("maturation immediate_bps must not exceed 10000");
        }
        let mut data = BuilderData::new();
        data.append_u16(AIPOW_DISTRIBUTOR_VERSION)?;
        init.operator.write_to(&mut data)?;
        data.append_u64(init.epoch)?;
        data.append_i8(init.earner_workchain)?;
        append_u128(&mut data, init.total_score)?;
        Coins::new(init.pool).write_to(&mut data)?;
        data.append_u32(0)?; // claimed_count
        append_u128(&mut data, 0)?; // claimed_score
        data.append_u16(init.maturation.immediate_bps)?;
        data.append_u16(init.maturation.stream_epochs)?;
        data.append_u32(init.maturation.epoch_seconds)?;
        data.append_u64(0)?; // activated_at: 0 until the settlement funds the pool
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
        let mut operator_slice = stack.slice(1)?;
        Ok(AipowDistributorData {
            version: stack.u64(0)? as u16,
            operator: MsgAddressInt::construct_from(&mut operator_slice)?,
            epoch: stack.u64(2)?,
            earner_workchain: stack.i64(3)? as i8,
            total_score: parse_u128(stack, 4)?,
            pool: stack.u64(5)?,
            claimed_count: stack.u64(6)? as u32,
            claimed_score: parse_u128(stack, 7)?,
            maturation: AipowMaturation {
                immediate_bps: stack.u64(8)? as u16,
                stream_epochs: stack.u64(9)? as u16,
                epoch_seconds: stack.u64(10)? as u32,
            },
            activated_at: stack.u64(11)?,
            score_root: parse_hash(stack, 12)?,
            commitment_ref: parse_hash(stack, 13)?,
        })
    }

    /// Decode `get_claim`: `(found, amount, claimed_at, forfeited, forfeit_at, paid)`.
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
            paid: stack.u64(5)?,
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

    /// Permissionless payout of an already-claimed identity's newly-matured
    /// delta to that identity's own address. Must carry at least
    /// `AIPOW_MIN_CLAIM_VALUE` to fund its own gas.
    pub fn payout(query_id: u64, identity: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        let mut body = BuilderData::new();
        body.append_u32(AIPOW_DISTRIBUTOR_PAYOUT_OPCODE)?;
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
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {} is not a 128-bit value", index))?;
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
    use crate::aipow_merkle::{ScoreEntry, inclusion_proof, score_root};
    use chain_block::SliceData;

    fn init() -> AipowDistributorInit {
        AipowDistributorInit {
            operator: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            epoch: 27_260,
            earner_workchain: 0,
            total_score: 1_000_000,
            pool: 5_000_000_000,
            maturation: AipowMaturation::methodology_v0(),
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
        let m = AipowMaturation::methodology_v0();
        let e = u64::from(m.epoch_seconds);
        let claim = AipowClaim {
            amount: 8000,
            claimed_at: 1_000,
            forfeited: false,
            forfeit_at: 0,
            paid: 0,
        };
        // Immediately: 25% only.
        assert_eq!(compute_matured(&claim, &m, 1_000), 2000);
        assert_eq!(compute_matured(&claim, &m, 500), 2000); // before claim clamps to immediate
        // After 1 epoch: 25% + 1/8 of the 75% stream (6000) = 2000 + 750.
        assert_eq!(compute_matured(&claim, &m, 1_000 + e), 2750);
        // After 4 epochs: 2000 + 3000.
        assert_eq!(compute_matured(&claim, &m, 1_000 + 4 * e), 5000);
        // After 8+ epochs: fully matured.
        assert_eq!(compute_matured(&claim, &m, 1_000 + 8 * e), 8000);
        assert_eq!(compute_matured(&claim, &m, 1_000 + 100 * e), 8000);
    }

    #[test]
    fn forfeit_freezes_maturation_at_the_forfeit_time() {
        let m = AipowMaturation::methodology_v0();
        let e = u64::from(m.epoch_seconds);
        // Forfeited at 2 epochs: matured is frozen at 25% + 2/8 of 6000.
        let claim = AipowClaim {
            amount: 8000,
            claimed_at: 1_000,
            forfeited: true,
            forfeit_at: 1_000 + 2 * e,
            paid: 0,
        };
        let frozen = 2000 + 6000 * 2 / 8;
        assert_eq!(compute_matured(&claim, &m, 1_000 + 2 * e), frozen);
        // Later than the forfeit: still frozen, the remainder is voided.
        assert_eq!(compute_matured(&claim, &m, 1_000 + 100 * e), frozen);
        // Earlier than the forfeit: the normal (smaller) matured value.
        assert_eq!(compute_matured(&claim, &m, 1_000 + e), 2750);
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
