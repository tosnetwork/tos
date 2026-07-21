/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
//! Domain separation for the inline ed25519 attestation scheme shared by
//! Task Escrow, Dispute and Service Actor.
//!
//! Every variant here binds a signature to one specific contract instance
//! (via `contract_address`) so it cannot be replayed against another
//! instance sharing the same attestor key, plus whatever additional state
//! that particular check needs to be meaningful: `settle`/`resolve` also
//! bind the exact payout, `respond` also binds which request it answers.
//! `domain_bound_hash` is the plain two-field form (contract + one hash)
//! used where nothing else needs binding. Each variant must match its
//! contract's own FunC computation byte-for-byte.

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
/// (`ruling_hash` / `attested_hash`). Used by Dispute's `rule`, Proof
/// Attestation's `attest`, and Agent Account's controller signature (over
/// its own payload hash, not a contract-recorded one) -- none of which
/// carry a payout, or a second piece of state like a request, the signature
/// needs to additionally bind.
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

/// Compute the domain-bound hash Service Actor's `respond` attestor
/// signature must cover: contract address, the `request_hash` of the call
/// being answered, and the `response_hash`. Binding only `response_hash`
/// (as an earlier version of this scheme did) would let a signature the
/// attestor gave for one request's response be replayed by the owner to
/// "answer" a later, unrelated request whenever the response content is
/// reused -- with nothing on chain to show the attestor ever saw that later
/// request. Must match `crypto/smartcont/service-actor-code.fc`'s `respond`
/// computation byte-for-byte.
pub fn service_respond_domain_hash(
    contract_address: &MsgAddressInt,
    request_hash: &[u8; 32],
    response_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let (wc, addr) = wc_and_addr(contract_address)?;
    let mut b = BuilderData::new();
    b.append_i8(wc)?;
    b.append_u256(&addr)?;
    b.append_u256(request_hash)?;
    b.append_u256(response_hash)?;
    let cell = b.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}
