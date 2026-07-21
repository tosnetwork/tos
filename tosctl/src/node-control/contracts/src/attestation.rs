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

use chain_block::{BuilderData, Coins, IBitstring, MsgAddressInt, Serializable};

/// Extracts the (workchain, 32-byte address) pair every domain-bound hash
/// in this module starts with, matching each contract's own
/// `my_address().parse_std_addr()` in FunC.
fn wc_and_addr(contract_address: &MsgAddressInt) -> anyhow::Result<(i8, [u8; 32])> {
    let wc = contract_address.workchain_id();
    let addr_bytes = contract_address.address().get_bytestring(0);
    let addr: [u8; 32] =
        addr_bytes.try_into().map_err(|_| anyhow::anyhow!("address must be 32 bytes"))?;
    Ok((wc as i8, addr))
}

/// Compute the domain-bound hash that the attestor key must sign for
/// `contract_address`, given the contract's on-chain `original_hash`
/// (`ruling_hash` / `response_hash` / `attested_hash`). Used by Dispute's
/// `rule`, Service Actor's `respond`, Proof Attestation's `attest`, and
/// Agent Account's controller signature (over its own payload hash, not a
/// contract-recorded one) -- none of which carry a payout the signature
/// needs to bind.
pub fn domain_bound_hash(
    contract_address: &MsgAddressInt,
    original_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let (wc, addr) = wc_and_addr(contract_address)?;
    let mut b = BuilderData::new();
    b.append_i8(wc)?;
    b.append_u256(&addr)?;
    b.append_u256(original_hash)?;
    let cell = b.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}

/// Compute the domain-bound hash Task Escrow's `settle` attestor signature
/// must cover: contract address, `result_hash`, and the exact `payout`.
/// Binding only `result_hash` (as an earlier version of this scheme did)
/// would let one attestor signature over a result authorize *any* payout up
/// to the task's budget, since the signature check never depended on the
/// amount actually paid out. Must match `crypto/smartcont/task-escrow-code.fc`'s
/// `settle` computation byte-for-byte.
pub fn settle_domain_hash(
    contract_address: &MsgAddressInt,
    result_hash: &[u8; 32],
    payout: u64,
) -> anyhow::Result<[u8; 32]> {
    let (wc, addr) = wc_and_addr(contract_address)?;
    let mut b = BuilderData::new();
    b.append_i8(wc)?;
    b.append_u256(&addr)?;
    b.append_u256(result_hash)?;
    Coins::new(payout).write_to(&mut b)?;
    let cell = b.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}

/// Compute the domain-bound hash Task Escrow's `resolve` attestor signature
/// must cover: contract address, `result_hash`, `dispute_hash`, and the
/// exact `payout`. `resolve` is reached via `dispute` -> `resolve`, a
/// separate payout-authorizing path from `settle` with its own state (the
/// dispute being resolved); binding all three means the signature is only
/// meaningful for this specific result, this specific dispute, and this
/// specific payout amount -- not just "an attestor signed this result at
/// some point". Must match `crypto/smartcont/task-escrow-code.fc`'s
/// `resolve` computation byte-for-byte.
pub fn resolve_domain_hash(
    contract_address: &MsgAddressInt,
    result_hash: &[u8; 32],
    dispute_hash: &[u8; 32],
    payout: u64,
) -> anyhow::Result<[u8; 32]> {
    let (wc, addr) = wc_and_addr(contract_address)?;
    let mut b = BuilderData::new();
    b.append_i8(wc)?;
    b.append_u256(&addr)?;
    b.append_u256(result_hash)?;
    b.append_u256(dispute_hash)?;
    Coins::new(payout).write_to(&mut b)?;
    let cell = b.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}
