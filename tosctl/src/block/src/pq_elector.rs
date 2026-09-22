/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! The wire constants of the post-quantum election and governance messages, and the exact
//! bytes their signatures are made over.
//!
//! A contract, a node and a piece of tooling each build these bytes for themselves. If
//! their field orders drift, a signature made by one verifies for none of the others, and
//! the failure looks like a bad key rather than a bad layout. The shared vectors in
//! `test/pq-native/authorisation-preimage-vectors.tsv` hold what this produces, and the other
//! implementation is held to the same file.
//!
//! Every field is big-endian, which is what a contract's `store_uint` writes, and every
//! preimage is byte-aligned, which the signature instructions require.

use crate::UInt256;

/// Internal message operations, lowercase; signed-preimage domains, uppercase.
pub const ELECTOR_PQ_STAKE_OP: u32 = 0x5051_7374; // "PQst"
pub const ELECTOR_PQ_STAKE_SIGN_TAG: u32 = 0x5051_5354; // "PQST"
pub const CONFIG_PQ_VOTE_OP: u32 = 0x5051_766f; // "PQvo"
pub const CONFIG_PQ_VOTE_SIGN_TAG: u32 = 0x5051_564f; // "PQVO"
pub const ELECTOR_PQ_COMPLAINT_OP: u32 = 0x5051_636f; // "PQco"
pub const ELECTOR_PQ_COMPLAINT_SIGN_TAG: u32 = 0x5051_434f; // "PQCO"

/// What a stake request signs.
///
/// The validator identity is the controlling account the contract saw, and the key
/// identity is derived by the contract from the key presented: neither is taken from the
/// request, and binding both is what stops a request naming one validator while carrying
/// another's key.
///
/// The stake owner is the account the money came from, which need not be the validator: a
/// pool holds nominators' funds and has no authority, and a controller has authority and
/// need not hold the funds. It is bound here so an authorisation issued for one funding
/// account cannot be presented by another. The contract reads it from the sender rather
/// than from the request, so a signature and a sender that disagree do not verify.
pub fn stake_preimage(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    validator_id: &UInt256,
    stake_owner: &UInt256,
    algorithm_id: u16,
    key_id: &UInt256,
    adnl_addr: &UInt256,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(146);
    out.extend_from_slice(&ELECTOR_PQ_STAKE_SIGN_TAG.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(&stake_at.to_be_bytes());
    out.extend_from_slice(&max_factor.to_be_bytes());
    out.extend_from_slice(validator_id.as_slice());
    out.extend_from_slice(stake_owner.as_slice());
    out.extend_from_slice(&algorithm_id.to_be_bytes());
    out.extend_from_slice(key_id.as_slice());
    out.extend_from_slice(adnl_addr.as_slice());
    out
}

/// What a configuration vote signs. The current set's identity is bound so a vote
/// collected under one validator set cannot be replayed under the next.
pub fn config_vote_preimage(
    global_id: i32,
    validator_set_id: &UInt256,
    validator_id: &UInt256,
    idx: u16,
    proposal_hash: &UInt256,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(106);
    out.extend_from_slice(&CONFIG_PQ_VOTE_SIGN_TAG.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(validator_set_id.as_slice());
    out.extend_from_slice(validator_id.as_slice());
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(proposal_hash.as_slice());
    out
}

/// What a complaint vote signs. The same shape as a configuration vote, plus the election
/// the complaint belongs to, and a distinct domain so neither can be replayed as the other.
pub fn complaint_vote_preimage(
    global_id: i32,
    validator_set_id: &UInt256,
    validator_id: &UInt256,
    idx: u16,
    election_id: u32,
    complaint_hash: &UInt256,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(110);
    out.extend_from_slice(&ELECTOR_PQ_COMPLAINT_SIGN_TAG.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(validator_set_id.as_slice());
    out.extend_from_slice(validator_id.as_slice());
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(&election_id.to_be_bytes());
    out.extend_from_slice(complaint_hash.as_slice());
    out
}

#[cfg(test)]
#[path = "tests/test_pq_elector.rs"]
mod tests;
