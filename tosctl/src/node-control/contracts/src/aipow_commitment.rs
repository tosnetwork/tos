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

pub const AIPOW_COMMITMENT_CODE_B64: &str = "te6cckECDwEABOMAART/APSkE/S88sgLAQIBYgIDAfbQAdDTAwFxsJJfA+D6QDAhxwCSXwPgAdMf0z8x7UTQ0w/6QPpA0wfTP9M/0z/6APoA1AHQ0//T/9N/03/UAdDT/9EB0QXUAdD6QNP/0QLUAdD6QNEB0Q8REA8Q7xDeEM0QvBCrEJoQiRBoEFcQVhBFExRWEoIQQVBXAboEALGhlwHaiaGmH/SB9IGmD6Z/pn+mf/QB9AGoA6Gn/6f/pv+m/6gDoaf/ogOiC6gDofSBp/+iBagDofSBogOiHiIgHiHeIbwhmiF4IVYhNCESINAgriCsIIomKQT2jt45Ols+gQg0CsAAGvL0gQg1+CMoufL0gQg9U+vHBVP7xwWx8vKBCDZT9b7y9AvT/9GBCDwhwwDy9HH4I4IICTqAoBDNGxwQmghRllGHEGcQVhA1ECQDERADVhFVIBER4FcUVhGCEEFQVwW64wJWEYIQQVBXArrjAlYRBQYHCADMyAHPFsnIUATPFhLL/8kFyMv/yQfIy/8Wy/8Ty3/LfxTMyQLIyw9QC88WUAnPFhfLBxXLPxPLP8s/AfoCAfoCEswSzMzJ7VQSoSDCAI4VcXCAEMjLBVAEzxZY+gISy2rJAfsAkVviAPpfAzU2WzQ2Njc3gQg0AsAAEvL0A9GBCED4J28QI4IQI8NGAKC+8vQBcPsCQzAk1wsBwQKSXwWORCOEH7ySXwXg7URwghBBUFMByMsfyz8Vyx8Ty//Lf8t/zMlxcCCAGMjLBVAFzxaCECPDRgD6AhTLaBPLABLLAMzJcfsA4gH+VxFXEYEINAzAABzy9IEIN/gjKr7y9A3RciwPEM5UHQcQvRCsEJsKEHkQaBBXEEYDBQQCERECERLIAc8WychQBM8WEsv/yQXIy//JB8jL/xbL/xPLf8t/FMzJAsjLD1ALzxZQCc8WF8sHFcs/E8s/yz8B+gIB+gISzBLMzMntVAkDqIIQQVBXA7qPNFcRgQg5ERIuxwUBERIB8vSBCDgMwAEc8vSBCD/4Iym58vQN0wfRgQg6IcAAIsABsfL04w/gVxIREIIQQVBXBLrjAl8PXwOBCDvy8AoLDAAsAXFwgBDIywVQBM8WWPoCEstqyQH7AAHcELwQq3NRthCrEJoIUZYIEGchEGcQVhBFAwQCERICARERARETyAHPFsnIUATPFhLL/8kFyMv/yQfIy/8Wy/8Ty3/LfxTMyQLIyw9QC88WUAnPFhfLBxXLPxPLP8s/AfoCAfoCEswSzMzJ7VRYoHENAeI2PXBUcAAtERAQ3xBOEL0QrBA7EIoQKRBoEFcGEREGXiIDEREDWBESyAHPFsnIUATPFhLL/8kFyMv/yQfIy/8Wy/8Ty3/LfxTMyQLIyw9QC88WUAnPFhfLBxXLPxPLP8s/AfoCAfoCEswSzMzJ7VQBcQ0B6IEIOAzAARzy9IEIPvgjKb7y9A3Rc1Q6xicDERADVhADAhESAgEREwERFMgBzxbJyFAEzxYSy//JBcjL/8kHyMv/Fsv/E8t/y38UzMkCyMsPUAvPFlAJzxYXywcVyz8Tyz/LPwH6AgH6AhLMEszMye1UUDNxDgAocIAQyMsFUATPFlj6AhLLaskB+wAAUnCAEMjLBVAEzxZY+gISy2rJAfsAcXCAEMjLBVAEzxZY+gISy2rJAfsAlNyvQA==";

/// The commitment layout version this SDK writes and the contract understands.
pub const AIPOW_COMMITMENT_VERSION: u16 = 1;

pub const APW_CHALLENGE_OPCODE: u32 = 0x4150_5701;
pub const APW_FINALIZE_OPCODE: u32 = 0x4150_5702;
pub const APW_RULE_OPCODE: u32 = 0x4150_5703;
pub const APW_TIMEOUT_OPCODE: u32 = 0x4150_5704;
pub const APW_ANNOUNCE_OPCODE: u32 = 0x4150_5705;

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
    pub rate_card_hash: [u8; 32],
    /// The epoch's total score (pro-rata denominator) the committer binds and
    /// bonds, so a distributor over this finalized root can be checked against
    /// the denominator that was staked on rather than a free operator param.
    pub total_score: u128,
    /// The epoch's organic settled value the committer binds; the phase C
    /// native path derives the pool from it and the on-chain schedule params.
    pub organic_settled_value: u128,
    /// The AIPoW settlement account this commitment registers to on
    /// finalization (D6), or `None` to not advertise (stored as `addr_none`).
    /// The native settlement path re-verifies the commitment independently, so
    /// this is only a routing hint.
    pub settlement: Option<MsgAddressInt>,
}

pub struct AipowCommitmentContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AipowCommitmentData {
    pub committer: MsgAddressInt,
    pub reviewer: MsgAddressInt,
    pub status: u8,
    pub epoch: u64,
    pub window_deadline: u64,
    /// Zero until challenged; then the challenge time plus the review window.
    /// A challenged commitment may be failed safe permissionlessly at or after
    /// this time if the reviewer never rules.
    pub review_deadline: u64,
    pub commit_bond: u64,
    pub challenge_bond: u64,
    pub score_root: [u8; 32],
    pub methodology_hash: [u8; 32],
    pub rate_card_hash: [u8; 32],
    /// The committed pro-rata denominator (decimal via Display; a u128).
    pub total_score: u128,
    /// The committed epoch organic settled value (a u128).
    pub organic_settled_value: u128,
    /// The zero address until a challenge is recorded.
    pub challenger: MsgAddressInt,
    pub challenge_evidence_hash: [u8; 32],
    /// Layout version tag (D9).
    pub version: u16,
    /// The settlement account this commitment registers to on finalization, or
    /// `None` when registration is disabled (`addr_none`).
    pub settlement: Option<MsgAddressInt>,
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
        // The finalize registration narrows the epoch to the settlement's
        // uint32 register field (`store_uint(epoch, 32)` on-chain). An epoch
        // above u32::MAX would raise a range-check exception when finalizing,
        // permanently stranding the bond, so reject it at deploy time -- the
        // address is derived from this data, so a valid commitment can never be
        // deployed past this bound.
        if init.epoch > u64::from(u32::MAX) {
            anyhow::bail!("epoch must fit in u32 (the settlement registration epoch width)");
        }
        let mut data = BuilderData::new();
        data.append_u16(AIPOW_COMMITMENT_VERSION)?;
        init.committer.write_to(&mut data)?;
        init.reviewer.write_to(&mut data)?;
        data.append_u8(AIPOW_COMMITMENT_STATUS_COMMITTED)?;
        data.append_u64(init.epoch)?;
        data.append_u64(init.window_deadline)?;
        // review_deadline: zero until a challenge sets it.
        data.append_u64(0)?;
        append_tomis(&mut data, init.commit_bond)?;
        append_tomis(&mut data, 0)?;
        let mut root = BuilderData::new();
        root.append_u256(&init.score_root)?.append_u256(&init.methodology_hash)?;
        append_u128(&mut root, init.total_score)?;
        append_u128(&mut root, init.organic_settled_value)?;
        // rate_card_hash in a nested ref: the four inline fields already fill 768
        // bits, so a fifth 256-bit field would exceed the 1023-bit cell limit.
        let mut rate_card = BuilderData::new();
        rate_card.append_u256(&init.rate_card_hash)?;
        root.checked_append_reference(rate_card.into_cell()?)?;
        data.checked_append_reference(root.into_cell()?)?;
        let mut challenge = BuilderData::new();
        MsgAddressInt::default().write_to(&mut challenge)?;
        challenge.append_u256(&[0; 32])?;
        data.checked_append_reference(challenge.into_cell()?)?;
        let mut settlement = BuilderData::new();
        match &init.settlement {
            // A real internal address is the register destination.
            Some(addr) => addr.write_to(&mut settlement)?,
            // addr_none$00: registration is disabled (best-effort, skipped
            // on-chain), so finalization still returns the bond.
            None => {
                settlement.append_bits(0, 2)?;
            }
        }
        data.checked_append_reference(settlement.into_cell()?)?;
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
        // rate_card_hash at index 10 shifts challenger/settlement/version/etc. by one.
        let mut challenger_slice = stack.slice(13)?;
        let settlement_slice = stack.slice(16)?;
        // The stack->bytes roundtrip byte-pads a short slice, so detect the
        // MsgAddress form by its 2-bit tag: 0=addr_none / 1=addr_extern are not
        // internal (registration disabled) -> None; 2=addr_std / 3=addr_var are.
        let settlement = if settlement_slice.get_bits(0, 2).unwrap_or(0) < 2 {
            None
        } else {
            let mut s = settlement_slice;
            Some(MsgAddressInt::construct_from(&mut s)?)
        };
        Ok(AipowCommitmentData {
            committer: MsgAddressInt::construct_from(&mut committer_slice)?,
            reviewer: MsgAddressInt::construct_from(&mut reviewer_slice)?,
            status: stack.u64(2)? as u8,
            epoch: stack.u64(3)?,
            window_deadline: stack.u64(4)?,
            review_deadline: stack.u64(5)?,
            commit_bond: stack.u64(6)?,
            challenge_bond: stack.u64(7)?,
            score_root: parse_hash(stack, 8)?,
            methodology_hash: parse_hash(stack, 9)?,
            rate_card_hash: parse_hash(stack, 10)?,
            total_score: parse_u128(stack, 11)?,
            organic_settled_value: parse_u128(stack, 12)?,
            challenger: MsgAddressInt::construct_from(&mut challenger_slice)?,
            challenge_evidence_hash: parse_hash(stack, 14)?,
            version: stack.u64(15)? as u16,
            settlement,
        })
    }

    /// Anyone but the committer and reviewer may challenge a committed root
    /// before the window deadline. The bond is fixed at the commit bond; the
    /// attached value must cover it and any excess is refunded. The evidence
    /// hash must be nonzero.
    pub fn challenge(
        query_id: u64,
        challenge_evidence_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(APW_CHALLENGE_OPCODE, query_id, |b| {
            b.append_u256(&challenge_evidence_hash).map(|_| ())
        })
    }

    /// Anyone may announce a still-committed commitment to its settlement,
    /// which records the nomination's registered_at with its own clock EARLY --
    /// the native challenge-window provenance floor runs from that trusted time.
    /// Normally sent once, right after deploy; the settlement dedups repeats.
    pub fn announce(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(APW_ANNOUNCE_OPCODE, query_id, |_| Ok(()))
    }

    /// Anyone may finalize an unchallenged commitment once the window has
    /// passed; the bond always returns to the committer. Finalize is local (the
    /// nomination was already sent at announce).
    pub fn finalize(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(APW_FINALIZE_OPCODE, query_id, |_| Ok(()))
    }

    /// Reviewer-only ruling on a challenged commitment: upholding rejects
    /// the root and awards both bonds to the challenger; dismissing
    /// finalizes the root and awards both bonds to the committer.
    pub fn rule(query_id: u64, uphold: bool) -> anyhow::Result<chain_block::Cell> {
        message(APW_RULE_OPCODE, query_id, |b| b.append_u8(u8::from(uphold)).map(|_| ()))
    }

    /// Anyone may fail a challenged commitment safe once the review deadline
    /// passes without a ruling: the root is rejected and each party recovers
    /// its own bond, so an absent reviewer cannot freeze the epoch.
    pub fn timeout(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(APW_TIMEOUT_OPCODE, query_id, |_| Ok(()))
    }
}

fn append_tomis(builder: &mut BuilderData, amount: u64) -> anyhow::Result<()> {
    chain_block::Coins::new(amount).write_to(builder)?;
    Ok(())
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
            rate_card_hash: [0x66; 32],
            total_score: 1_000_000,
            organic_settled_value: 42_000_000_000,
            settlement: Some(MsgAddressInt::with_standart(None, -1, [0x55; 32].into()).unwrap()),
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
    fn build_data_bounds_the_epoch_to_u32() {
        // The finalize registration stores the epoch in a uint32 field; an
        // epoch above u32::MAX would abort finalize and strand the bond, so the
        // boundary value is accepted but one past it is rejected at deploy.
        let mut max = init();
        max.epoch = u64::from(u32::MAX);
        assert!(AipowCommitmentContract::build_data(&max).is_ok());
        let mut over = init();
        over.epoch = u64::from(u32::MAX) + 1;
        assert!(AipowCommitmentContract::build_data(&over).is_err());
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

        let body = AipowCommitmentContract::timeout(4).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), APW_TIMEOUT_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 4);
        assert_eq!(slice.remaining_bits(), 0);

        let body = AipowCommitmentContract::announce(5).unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), APW_ANNOUNCE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 5);
        assert_eq!(slice.remaining_bits(), 0);
    }
}
