/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! A validator's vote on a complaint against a validator of a past election.
//!
//! The elector authorises these against the current post-quantum validator set. The
//! identity of the voter is read from the descriptor at the index the vote names, so
//! nothing here states who is voting: the index, the election and the complaint are all
//! the message carries, besides the signature.
use chain_block::{BuilderData, Cell, IBitstring, UInt256, pq_bytes};

pub mod opcodes {
    /// `PQco`: a post-quantum complaint vote, as an internal message.
    pub const VOTE_FOR_COMPLAINT: u32 = 0x5051636f;
}

/// `PQCO`: the domain tag inside the signed bytes, distinct from the operation so that a
/// message body can never be mistaken for a preimage.
const COMPLAINT_VOTE_SIGN_TAG: u32 = 0x5051434f;

/// ML-DSA-44 signatures are this long. A signature of any other length is not one.
const MLDSA44_SIGNATURE_BYTES: usize = 2420;

/// Exactly the bytes a validator signs to vote on a complaint.
///
/// `validator_set_id` is the hash of the validator set the vote will be counted against,
/// and `validator_id` is the identity the set records at `idx`. Both come from the set,
/// not from the voter: a vote is bound to one set, so a signature made under an earlier
/// one cannot be replayed, and it is bound to one validator, so it cannot be counted for
/// another. `election_id` names the past election the complaint is about, which is not
/// the set doing the voting.
///
/// The layout is the one the contract builds; the two are held to each other by the
/// shared preimage vectors.
pub fn unsigned_complaint_vote(
    global_id: i32,
    validator_set_id: &UInt256,
    validator_id: &UInt256,
    validator_idx: u16,
    election_id: u32,
    complaint_hash: &[u8; 32],
) -> anyhow::Result<BuilderData> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(COMPLAINT_VOTE_SIGN_TAG)?
        .append_i32(global_id)?
        .append_raw(validator_set_id.as_slice(), 256)?
        .append_raw(validator_id.as_slice(), 256)?
        .append_u16(validator_idx)?
        .append_u32(election_id)?
        .append_raw(complaint_hash, 256)?;
    Ok(builder)
}

/// Builds the complaint vote message body.
///
/// The signature travels as a length and a chain of ordinary cells, which is the shape
/// the verification instruction takes; it does not fit in one cell.
pub fn signed_complaint_vote(
    query_id: u64,
    validator_idx: u16,
    election_id: u32,
    complaint_hash: &[u8; 32],
    signature: &[u8],
) -> anyhow::Result<Cell> {
    if signature.len() != MLDSA44_SIGNATURE_BYTES {
        anyhow::bail!(
            "a complaint vote is signed with ML-DSA-44, which is {MLDSA44_SIGNATURE_BYTES} \
             bytes, and this signature is {}",
            signature.len()
        );
    }

    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::VOTE_FOR_COMPLAINT)?
        .append_u64(query_id)?
        .append_u16(validator_idx)?
        .append_u32(election_id)?
        .append_raw(complaint_hash, 256)?;
    builder.checked_append_reference(pq_bytes::pack_pq_bytes(
        signature,
        pq_bytes::PQ_BYTES_HARD_MAX,
    )?)?;
    builder.into_cell()
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
        let builder =
            unsigned_complaint_vote(-239, &set_id, &validator_id, 42, 0x89AB_CDEF, &[0xAB; 32])
                .unwrap();
        assert_eq!(builder.length_in_bits(), 110 * 8, "the preimage is 110 bytes");

        let mut slice = SliceData::load_cell(builder.into_cell().unwrap()).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), COMPLAINT_VOTE_SIGN_TAG);
        assert_eq!(slice.get_next_i32().unwrap(), -239);
        assert_eq!(slice.get_next_bits(256).unwrap(), set_id.as_slice().to_vec());
        assert_eq!(slice.get_next_bits(256).unwrap(), validator_id.as_slice().to_vec());
        assert_eq!(slice.get_next_u16().unwrap(), 42);
        assert_eq!(slice.get_next_u32().unwrap(), 0x89AB_CDEF);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xAB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    /// The two votes a validator casts share a shape, and their tags are one byte apart.
    /// Anything that made them equal would make a complaint vote countable as a
    /// configuration vote.
    #[test]
    fn the_complaint_tags_are_not_the_configuration_tags() {
        assert_ne!(COMPLAINT_VOTE_SIGN_TAG, 0x5051564f, "PQCO is not PQVO");
        assert_ne!(opcodes::VOTE_FOR_COMPLAINT, 0x5051766f, "PQco is not PQvo");
        assert_ne!(COMPLAINT_VOTE_SIGN_TAG, opcodes::VOTE_FOR_COMPLAINT);
    }

    /// The message carries the index, the election and the complaint, and nothing that
    /// states who is voting: the contract reads that from the set.
    #[test]
    fn the_message_carries_the_index_the_election_the_complaint_and_the_signature() {
        let query_id: u64 = 0x1234_5678_90AB_CDEF;
        let cell = signed_complaint_vote(query_id, 123, 5000, &[0xCD; 32], &signature()).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), opcodes::VOTE_FOR_COMPLAINT);
        assert_eq!(slice.get_next_u64().unwrap(), query_id);
        assert_eq!(slice.get_next_u16().unwrap(), 123);
        assert_eq!(slice.get_next_u32().unwrap(), 5000);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xCD; 32]);
        assert_eq!(slice.remaining_bits(), 0, "nothing else is stated in the body");

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
            let result = signed_complaint_vote(1, 1, 1, &[0x00; 32], &vec![0u8; wrong]);
            assert!(result.is_err(), "a {wrong}-byte signature was accepted");
            assert!(
                result.unwrap_err().to_string().contains("ML-DSA-44"),
                "the refusal should name what was expected"
            );
        }
        assert!(
            signed_complaint_vote(1, 1, 1, &[0x00; 32], &signature()).is_ok(),
            "the right length fails"
        );
    }
}
