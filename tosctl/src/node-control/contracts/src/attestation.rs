/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
//! Domain separation for the inline ed25519 attestation scheme shared by
//! Task Escrow, Dispute and Service Actor.
//!
//! Each contract's `settle`/`rule`/`respond` verifies a signature over
//! `domain_bound_hash(contract_address, original_hash)` rather than the bare
//! `original_hash` -- binding the signature to one specific contract
//! instance so it cannot be replayed against another instance that happens
//! to share the same attestor key and the same original hash value. This
//! must match each contract's own FunC computation byte-for-byte:
//! `cell_hash(begin_cell().store_int(wc, 8).store_uint(addr, 256).store_uint(original_hash, 256).end_cell())`.

use chain_block::{BuilderData, IBitstring, MsgAddressInt};

/// Compute the domain-bound hash that the attestor key must sign for
/// `contract_address`, given the contract's on-chain `original_hash`
/// (`result_hash` / `ruling_hash` / `response_hash`).
pub fn domain_bound_hash(
    contract_address: &MsgAddressInt,
    original_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let wc = contract_address.workchain_id();
    let addr_bytes = contract_address.address().get_bytestring(0);
    let addr: [u8; 32] =
        addr_bytes.try_into().map_err(|_| anyhow::anyhow!("address must be 32 bytes"))?;

    let mut b = BuilderData::new();
    b.append_i8(wc as i8)?;
    b.append_u256(&addr)?;
    b.append_u256(original_hash)?;
    let cell = b.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}
