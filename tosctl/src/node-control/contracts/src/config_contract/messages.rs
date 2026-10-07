/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! A validator's vote on a configuration proposal.
//!
//! The configuration contract authorises these against the current post-quantum
//! validator set. The identity of the voter is read from the descriptor at the index the
//! vote names, so nothing here states who is voting: the index and what is being voted
//! on are all the message carries, besides the signature.
use chain_block::{BuilderData, Cell, IBitstring, UInt256, pq_bytes};

pub mod opcodes {
    /// `PQvo`: a post-quantum configuration vote, as an internal message.
    pub const VOTE_FOR_PROPOSAL: u32 = 0x5051766f;
}

/// `PQVO`: the domain tag inside the signed bytes, distinct from the operation so that a
/// message body can never be mistaken for a preimage.
const VOTE_SIGN_TAG: u32 = 0x5051564f;

/// ML-DSA-44 signatures are this long. A signature of any other length is not one.
const MLDSA44_SIGNATURE_BYTES: usize = 2420;

/// Exactly the bytes a validator signs to vote for a proposal.
///
/// `validator_set_id` is the hash of the validator set the vote will be counted against,
/// and `validator_id` is the identity the set records at `idx`. Both come from the set,
/// not from the voter: a vote is bound to one set, so a signature made under an earlier
/// one cannot be replayed, and it is bound to one validator, so it cannot be counted for
/// another.
///
/// The layout is the one the contract builds; the two are held to each other by the
/// shared preimage vectors.
pub fn unsigned_vote(
    global_id: i32,
    validator_set_id: &UInt256,
    validator_id: &UInt256,
    validator_idx: u16,
    proposal_hash: &[u8; 32],
) -> anyhow::Result<BuilderData> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(VOTE_SIGN_TAG)?
        .append_i32(global_id)?
        .append_raw(validator_set_id.as_slice(), 256)?
        .append_raw(validator_id.as_slice(), 256)?
        .append_u16(validator_idx)?
        .append_raw(proposal_hash, 256)?;
    Ok(builder)
}

/// Builds the vote message body.
///
/// The signature travels as a length and a chain of ordinary cells, which is the shape
/// the verification instruction takes; it does not fit in one cell.
pub fn signed_vote(
    query_id: u64,
    validator_idx: u16,
    proposal_hash: &[u8; 32],
    signature: &[u8],
) -> anyhow::Result<Cell> {
    if signature.len() != MLDSA44_SIGNATURE_BYTES {
        anyhow::bail!(
            "a validator vote is signed with ML-DSA-44, which is {MLDSA44_SIGNATURE_BYTES} \
             bytes, and this signature is {}",
            signature.len()
        );
    }

    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::VOTE_FOR_PROPOSAL)?
        .append_u64(query_id)?
        .append_u16(validator_idx)?
        .append_raw(proposal_hash, 256)?;
    builder.checked_append_reference(pq_bytes::pack_pq_bytes(
        signature,
        pq_bytes::PQ_BYTES_HARD_MAX,
    )?)?;
    builder.into_cell()
}

/// A configuration proposal, as `register_voting_proposal` in `config-code.fc` reads it.
///
/// The message is `[op:uint32 = 0x6e565052][query_id:uint64][expire_at:uint32]
/// [^cfg_proposal][critical:int1]`, where `cfg_proposal#f3 param_id:int32
/// param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)`. Only a masterchain sender
/// is heard: from any other workchain the contract keeps the value and does nothing.
pub mod proposal {
    use chain_block::{BuilderData, Cell, ConfigProposalSetup, IBitstring, UInt256};
    use std::collections::HashSet;

    /// `nVPR`: register a new configuration proposal.
    pub const NEW_PROPOSAL: u32 = 0x6e56_5052;
    /// The answer tag for a registered proposal; a refusal answers `-price` (an error).
    pub const PROPOSAL_ACCEPTED: u32 = 0xee56_5052;
    /// `cfg_proposal#f3`.
    pub const PROPOSAL_TAG: u8 = 0xf3;
    /// The contract treats an `expire_at` with either of the top two bits set as an
    /// absolute time; a duration must stay below this.
    pub const MAX_RELATIVE_EXPIRY: u32 = 1 << 30;
    /// `if (msg_value - price < (1 << 30))`: the value a proposal must carry beyond its
    /// storage price.
    pub const MIN_VALUE_ABOVE_PRICE: u128 = 1 << 30;
    /// `param_val.cell_depth() >= 128` is refused as a bad value.
    pub const MAX_VALUE_DEPTH: u16 = 127;
    /// `compute_data_size(param_val, 1024)`.
    pub const MAX_VALUE_CELLS: usize = 1024;

    /// `cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)`.
    /// `value: None` proposes removing the parameter; `if_hash_equal` binds the proposal
    /// to the current value (zero when the parameter is absent).
    pub fn proposal_cell(
        param_id: i32,
        value: Option<Cell>,
        if_hash_equal: Option<[u8; 32]>,
    ) -> anyhow::Result<Cell> {
        let mut proposal = BuilderData::new();
        proposal.append_u8(PROPOSAL_TAG)?.append_i32(param_id)?;
        match value {
            Some(value) => {
                proposal.append_bit_one()?;
                proposal.checked_append_reference(value)?;
            }
            None => {
                proposal.append_bit_zero()?;
            }
        }
        match if_hash_equal {
            Some(hash) => {
                proposal.append_bit_one()?.append_raw(&hash, 256)?;
            }
            None => {
                proposal.append_bit_zero()?;
            }
        }
        proposal.into_cell()
    }

    /// The internal message body that registers `proposal` for `ttl_secs` seconds.
    pub fn new_proposal_body(
        query_id: u64,
        ttl_secs: u32,
        proposal: Cell,
        critical: bool,
    ) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            ttl_secs > 0 && ttl_secs < MAX_RELATIVE_EXPIRY,
            "a proposal's lifetime must be between 1 and {} seconds",
            MAX_RELATIVE_EXPIRY - 1
        );
        let mut body = BuilderData::new();
        body.append_u32(NEW_PROPOSAL)?.append_u64(query_id)?.append_u32(ttl_secs)?;
        body.checked_append_reference(proposal)?;
        if critical {
            body.append_bit_one()?;
        } else {
            body.append_bit_zero()?;
        }
        body.into_cell()
    }

    /// `compute_data_size(value, 1024)`: the distinct cells, and their data bits and
    /// references, that the contract prices. A missing value costs nothing.
    pub fn value_size(value: Option<&Cell>) -> anyhow::Result<(u64, u64, u64)> {
        let Some(root) = value else {
            return Ok((0, 0, 0));
        };
        let mut seen: HashSet<UInt256> = HashSet::new();
        let mut stack = vec![root.clone()];
        let (mut cells, mut bits, mut refs) = (0u64, 0u64, 0u64);
        while let Some(cell) = stack.pop() {
            if !seen.insert(cell.repr_hash()) {
                continue;
            }
            anyhow::ensure!(
                seen.len() <= MAX_VALUE_CELLS,
                "the proposed value has more than {MAX_VALUE_CELLS} distinct cells"
            );
            cells = cells.checked_add(1).ok_or_else(|| anyhow::anyhow!("cell count overflows"))?;
            bits = bits
                .checked_add(cell.bit_length() as u64)
                .ok_or_else(|| anyhow::anyhow!("bit count overflows"))?;
            let count = cell.references_count();
            refs = refs
                .checked_add(count as u64)
                .ok_or_else(|| anyhow::anyhow!("reference count overflows"))?;
            for index in 0..count {
                stack.push(cell.reference(index)?);
            }
        }
        Ok((cells, bits, refs))
    }

    /// What the contract charges to store a proposal, and for how long it will keep it:
    /// `(bit_price * (bits + 1024) + cell_price * (refs + 2)) * min(ttl, max_store_sec)`.
    /// A lifetime below `min_store_sec` is refused.
    pub fn storage_price(
        setup: &ConfigProposalSetup,
        value: Option<&Cell>,
        ttl_secs: u32,
    ) -> anyhow::Result<(u128, u32)> {
        anyhow::ensure!(
            ttl_secs >= setup.min_store_sec,
            "a proposal must be stored for at least {} seconds; {} were requested",
            setup.min_store_sec,
            ttl_secs
        );
        if let Some(value) = value {
            anyhow::ensure!(
                value.repr_depth() <= MAX_VALUE_DEPTH,
                "the proposed value is {} cells deep; the contract refuses 128 or more",
                value.repr_depth()
            );
        }
        let stored = ttl_secs.min(setup.max_store_sec);
        let (_, bits, refs) = value_size(value)?;
        let overflow = || anyhow::anyhow!("proposal storage price overflows");
        let per_second = u128::from(setup.bit_price)
            .checked_mul(u128::from(bits.checked_add(1024).ok_or_else(overflow)?))
            .and_then(|bit_part| {
                u128::from(setup.cell_price)
                    .checked_mul(u128::from(refs.checked_add(2)?))
                    .and_then(|cell_part| bit_part.checked_add(cell_part))
            })
            .ok_or_else(overflow)?;
        let price = per_second.checked_mul(u128::from(stored)).ok_or_else(overflow)?;
        Ok((price, stored))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::SliceData;

    fn signature() -> Vec<u8> {
        (0..MLDSA44_SIGNATURE_BYTES).map(|i| (i % 251) as u8).collect()
    }

    /// The signed bytes, field by field. This is the half of the preimage that lives
    /// outside the contract, so it is checked against the layout rather than against
    /// itself: a field reordered here would still round-trip through this module while
    /// every vote it produced was refused on chain.
    #[test]
    fn the_signed_bytes_are_the_frozen_layout() {
        let set_id = UInt256::from_slice(&[0x11; 32]);
        let validator_id = UInt256::from_slice(&[0x22; 32]);
        let builder = unsigned_vote(-239, &set_id, &validator_id, 42, &[0xAB; 32]).unwrap();
        assert_eq!(builder.length_in_bits(), 106 * 8, "the preimage is 106 bytes");

        let mut slice = SliceData::load_cell(builder.into_cell().unwrap()).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), VOTE_SIGN_TAG);
        assert_eq!(slice.get_next_i32().unwrap(), -239);
        assert_eq!(slice.get_next_bits(256).unwrap(), set_id.as_slice().to_vec());
        assert_eq!(slice.get_next_bits(256).unwrap(), validator_id.as_slice().to_vec());
        assert_eq!(slice.get_next_u16().unwrap(), 42);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xAB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    /// The message carries the index and what is being voted on, and nothing that states
    /// who is voting: the contract reads that from the set.
    #[test]
    fn the_message_carries_the_index_the_proposal_and_the_signature() {
        let query_id: u64 = 0x1234_5678_90AB_CDEF;
        let cell = signed_vote(query_id, 123, &[0xCD; 32], &signature()).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), opcodes::VOTE_FOR_PROPOSAL);
        assert_eq!(slice.get_next_u64().unwrap(), query_id);
        assert_eq!(slice.get_next_u16().unwrap(), 123);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xCD; 32]);
        assert_eq!(slice.remaining_bits(), 0, "nothing else is stated in the body");

        // The signature travels as a length and a chain, which is the shape the
        // verification instruction takes.
        let stored = slice.checked_drain_reference().unwrap();
        assert_eq!(
            pq_bytes::unpack_pq_bytes(&stored, pq_bytes::PQ_BYTES_HARD_MAX).unwrap(),
            signature()
        );
    }

    /// An Ed25519 signature is 64 bytes. Handing one to this builder is what a caller
    /// that has not been converted would do, and it fails here rather than on chain,
    /// where it would have cost the sender the message.
    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        for wrong in [32usize, 64, MLDSA44_SIGNATURE_BYTES - 1, MLDSA44_SIGNATURE_BYTES + 1] {
            let result = signed_vote(1, 1, &[0x00; 32], &vec![0u8; wrong]);
            assert!(result.is_err(), "a {wrong}-byte signature was accepted");
            assert!(
                result.unwrap_err().to_string().contains("ML-DSA-44"),
                "the refusal should name what was expected"
            );
        }
        assert!(signed_vote(1, 1, &[0x00; 32], &signature()).is_ok(), "the right length fails");
    }
}

#[cfg(test)]
mod proposal_tests {
    use super::proposal::*;
    use chain_block::{BuilderData, Cell, ConfigProposalSetup, IBitstring, SliceData};

    fn value(word: u32) -> Cell {
        let mut b = BuilderData::new();
        b.append_u32(word).unwrap();
        b.into_cell().unwrap()
    }

    fn setup() -> ConfigProposalSetup {
        ConfigProposalSetup {
            min_tot_rounds: 2,
            max_tot_rounds: 6,
            min_wins: 2,
            max_losses: 2,
            min_store_sec: 1_000_000,
            max_store_sec: 10_000_000,
            bit_price: 1,
            cell_price: 500,
        }
    }

    /// Read back the way `parse_config_proposal` and `register_voting_proposal` do.
    #[test]
    fn the_body_is_the_layout_the_contract_parses() {
        let proposal = proposal_cell(-71, Some(value(7)), Some([0xAB; 32])).unwrap();
        let body = new_proposal_body(42, 2_000_000, proposal.clone(), true).unwrap();
        let mut cs = SliceData::load_cell(body).unwrap();
        assert_eq!(cs.get_next_u32().unwrap(), NEW_PROPOSAL);
        assert_eq!(cs.get_next_u64().unwrap(), 42);
        assert_eq!(cs.get_next_u32().unwrap(), 2_000_000);
        let reference = cs.checked_drain_reference().unwrap();
        assert_eq!(reference.repr_hash(), proposal.repr_hash());
        assert!(cs.get_next_bit().unwrap(), "critical flag");
        assert_eq!(cs.remaining_bits(), 0);
        assert_eq!(cs.remaining_references(), 0);

        let mut ps = SliceData::load_cell(reference).unwrap();
        assert_eq!(ps.get_next_byte().unwrap(), PROPOSAL_TAG);
        assert_eq!(ps.get_next_i32().unwrap(), -71);
        assert!(ps.get_next_bit().unwrap());
        assert_eq!(ps.checked_drain_reference().unwrap().repr_hash(), value(7).repr_hash());
        assert!(ps.get_next_bit().unwrap());
        assert_eq!(ps.get_next_bits(256).unwrap(), vec![0xAB; 32]);
        assert_eq!(ps.remaining_bits(), 0);
    }

    #[test]
    fn a_removal_without_a_hash_is_two_zero_bits() {
        let proposal = proposal_cell(100, None, None).unwrap();
        assert_eq!(proposal.bit_length(), 8 + 32 + 2);
        assert_eq!(proposal.references_count(), 0);
        let body = new_proposal_body(1, 5, proposal, false).unwrap();
        let mut cs = SliceData::load_cell(body).unwrap();
        cs.get_next_bits(32 + 64 + 32).unwrap();
        assert!(!cs.get_next_bit().unwrap(), "not critical");
    }

    #[test]
    fn a_lifetime_that_reads_as_an_absolute_time_is_refused() {
        let proposal = proposal_cell(100, None, None).unwrap();
        assert!(new_proposal_body(1, MAX_RELATIVE_EXPIRY, proposal.clone(), false).is_err());
        assert!(new_proposal_body(1, 0, proposal.clone(), false).is_err());
        assert!(new_proposal_body(1, MAX_RELATIVE_EXPIRY - 1, proposal, false).is_ok());
    }

    #[test]
    fn the_price_counts_distinct_cells_like_cdatasize() {
        // A root with the same child twice: one distinct child, two references.
        let child = value(1);
        let mut root = BuilderData::new();
        root.append_u16(3).unwrap();
        root.checked_append_reference(child.clone()).unwrap();
        root.checked_append_reference(child).unwrap();
        let root = root.into_cell().unwrap();
        assert_eq!(value_size(Some(&root)).unwrap(), (2, 16 + 32, 2));
        assert_eq!(value_size(None).unwrap(), (0, 0, 0));

        let (price, stored) = storage_price(&setup(), Some(&root), 2_000_000).unwrap();
        assert_eq!(stored, 2_000_000);
        assert_eq!(price, (1 * (48 + 1024) + 500 * (2 + 2)) * 2_000_000);
        // Capped at max_store_sec.
        let (price, stored) = storage_price(&setup(), None, 20_000_000).unwrap();
        assert_eq!(stored, 10_000_000);
        assert_eq!(price, (1024 + 500 * 2) * 10_000_000);
        // Below min_store_sec the contract refuses it as expired.
        assert!(storage_price(&setup(), None, 999_999).is_err());
    }

    #[test]
    fn a_value_too_deep_for_the_contract_is_refused() {
        let mut cell = value(0);
        for _ in 0..128 {
            let mut b = BuilderData::new();
            b.checked_append_reference(cell).unwrap();
            cell = b.into_cell().unwrap();
        }
        assert_eq!(cell.repr_depth(), 128);
        assert!(storage_price(&setup(), Some(&cell), 2_000_000).is_err());
    }
}
