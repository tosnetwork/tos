/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Proposals read from the configuration contract's stored account instead of its
//! getters: the large-state path, used when the getter's answer exceeds the
//! transport limit. It mirrors `unpack_proposal`, `get_proposal` and
//! `list_proposals` of `crypto/smartcont/config-code.fc` exactly, including that
//! `list_proposals` walks downward from 2^256 - 1 exclusive and so never lists that
//! hash, while `get_proposal` returns it when present.
//!
//! The storage is interpreted only for code this crate knows the layout of; any
//! other code is refused before its data is read.

use super::{
    ConfigProposal, ProposalHash,
    proposal_read::{ProposalParts, assemble},
    proposal_transport::{ProposalAnswer, ProposalRead},
};
use anyhow::Context;
use chain_block::{Cell, HashmapE, HashmapType, SliceData, read_single_root_boc};

/// Representation hashes of the configuration-contract code whose storage layout
/// this module decodes (`config-code.fc`, as the zerostate deploys it). Pinned by a
/// test against a generated zerostate.
pub const SUPPORTED_CONFIG_CODE_HASHES: [[u8; 32]; 1] = [CONFIG_CODE_HASH];

const CONFIG_CODE_HASH: [u8; 32] =
    hex_literal("2774a7cc7850cfb8dd1023b725c1e44182a9bae39da547fb8724b2f72562ff7a");

/// The hash `list_proposals` starts its downward walk from, exclusive.
const LIST_SENTINEL: ProposalHash = [0xff; 32];

/// The proposals the stored account holds, as the getters would return them.
pub fn decode_state(
    code: &[u8],
    data: &[u8],
    read: ProposalRead,
) -> anyhow::Result<ProposalAnswer> {
    let code = read_single_root_boc(code).context("the account code is not a cell")?;
    let code_hash: [u8; 32] = code.repr_hash().inner();
    anyhow::ensure!(
        SUPPORTED_CONFIG_CODE_HASHES.contains(&code_hash),
        "the configuration contract runs unsupported code {}: its storage is not interpreted",
        hex::encode(code_hash)
    );
    let votes =
        vote_dictionary(read_single_root_boc(data).context("the account data is not a cell")?)?;
    match read {
        ProposalRead::List => {
            let mut proposals: Vec<ConfigProposal> = Vec::new();
            let mut failure: Option<anyhow::Error> = None;
            votes.iterate_slices(|mut key, record| {
                let hash = match key.get_next_u256() {
                    Ok(hash) => hash,
                    Err(error) => {
                        failure = Some(anyhow::anyhow!("a vote key is not 256 bits: {error}"));
                        return Ok(false);
                    }
                };
                if hash == LIST_SENTINEL {
                    return Ok(true);
                }
                match decode_record(hash, record) {
                    Ok(proposal) => {
                        proposals.push(proposal);
                        Ok(true)
                    }
                    Err(error) => {
                        failure =
                            Some(error.context(format!("stored proposal {}", hex::encode(hash))));
                        Ok(false)
                    }
                }
            })?;
            if let Some(error) = failure {
                return Err(error);
            }
            anyhow::ensure!(
                proposals.windows(2).all(|pair| pair[0].hash < pair[1].hash),
                "the vote dictionary did not iterate in ascending key order"
            );
            Ok(ProposalAnswer::List(proposals))
        }
        ProposalRead::One(hash) => Ok(ProposalAnswer::One(
            lookup(&votes, hash)?.map(|record| decode_record(hash, record)).transpose()?,
        )),
        ProposalRead::Expiry(hash) => Ok(ProposalAnswer::Expiry(
            lookup(&votes, hash)?
                .map(|record| decode_record(hash, record).map(|p| p.expires))
                .transpose()?,
        )),
    }
}

fn lookup(votes: &HashmapE, hash: ProposalHash) -> anyhow::Result<Option<SliceData>> {
    votes
        .get(SliceData::from_raw(hash.to_vec(), 256))
        .map_err(|error| anyhow::anyhow!("the vote dictionary cannot be read: {error}"))
}

/// `load_data`: a reference to the parameter dictionary, then the vote dictionary,
/// and nothing else.
fn vote_dictionary(data: Cell) -> anyhow::Result<HashmapE> {
    let mut slice = SliceData::load_cell(data).context("the account data")?;
    slice.checked_drain_reference().context("the account data has no parameter dictionary")?;
    let votes = slice.get_next_dictionary().context("the account data has no vote dictionary")?;
    anyhow::ensure!(
        slice.is_empty_cell(),
        "the account data has bits or references past its layout"
    );
    Ok(HashmapE::with_hashmap(256, votes))
}

/// `cfg_proposal_status#ce expires:uint32 proposal:^ConfigProposal is_critical:Bool
/// voters:(HashmapE 16 True) remaining_weight:int64 validator_set_id:uint256
/// rounds_remaining:uint8 wins:uint8 losses:uint8`, as `unpack_proposal` reads it.
fn decode_record(hash: ProposalHash, mut record: SliceData) -> anyhow::Result<ConfigProposal> {
    let field =
        |what: &'static str| move |error: chain_block::Error| anyhow::anyhow!("{what}: {error}");
    let tag = record.get_next_byte().map_err(field("status tag"))?;
    anyhow::ensure!(tag == 0xce, "the proposal status tag is {tag:#04x}, not 0xce");
    let expires = record.get_next_u32().map_err(field("expiry"))?;
    let proposal = record.checked_drain_reference().map_err(field("proposal reference"))?;
    let critical = record.get_next_bit().map_err(field("critical flag"))?;
    let voters = HashmapE::with_hashmap(16, record.get_next_dictionary().map_err(field("voters"))?);
    let weight_remaining = record.get_next_i64().map_err(field("remaining weight"))?;
    let vset_id = record.get_next_u256().map_err(field("validator set id"))?;
    let rounds_remaining = record.get_next_byte().map_err(field("rounds remaining"))?;
    let wins = record.get_next_byte().map_err(field("wins"))?;
    let losses = record.get_next_byte().map_err(field("losses"))?;
    anyhow::ensure!(
        record.is_empty_cell(),
        "the proposal status has bits or references past its layout"
    );

    let mut voter_indices = Vec::new();
    let mut bad_key: Option<String> = None;
    voters.iterate_slices(|mut key, _| match key.get_next_u16() {
        Ok(index) => {
            voter_indices.push(index);
            Ok(true)
        }
        Err(error) => {
            bad_key = Some(error.to_string());
            Ok(false)
        }
    })?;
    if let Some(error) = bad_key {
        anyhow::bail!("a voter key is not 16 bits: {error}");
    }

    // parse_config_proposal: cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell)
    // if_hash_equal:(Maybe uint256)
    let mut proposal = SliceData::load_cell(proposal).context("the proposal cell")?;
    let tag = proposal.get_next_byte().map_err(field("proposal tag"))?;
    anyhow::ensure!(tag == 0xf3, "the proposal tag is {tag:#04x}, not 0xf3");
    let param_id = proposal.get_next_i32().map_err(field("parameter id"))?;
    let value = proposal.get_next_maybe_reference().map_err(field("parameter value"))?;
    let value_hash = if proposal.get_next_bit().map_err(field("value hash flag"))? {
        Some(proposal.get_next_u256().map_err(field("value hash"))?)
    } else {
        None
    };
    anyhow::ensure!(
        proposal.is_empty_cell(),
        "the proposal has bits or references past its layout"
    );

    assemble(
        hash,
        ProposalParts {
            expires,
            critical,
            param_id,
            value,
            value_hash,
            vset_id,
            voters: voter_indices,
            weight_remaining,
            rounds_remaining,
            losses,
            wins,
        },
    )
}

/// A 64-character hex string as 32 bytes, at compile time.
const fn hex_literal(text: &str) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "a code hash is 64 hex digits");
    let mut out = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = nibble(bytes[2 * index]) * 16 + nibble(bytes[2 * index + 1]);
        index += 1;
    }
    out
}
