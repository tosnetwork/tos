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

/// Compute the `terms_hash` a Service Actor request snapshots at `call`
/// time: every policy field that determines what a valid response has to
/// satisfy and what it costs, plus the attestor configuration in force.
/// `has_attestor = false` canonicalizes `attestor_pubkey` to all-zero so two
/// semantically-identical no-attestor policies always hash the same,
/// regardless of leftover bits from a since-revoked key. Split across a root
/// + one reference cell (the flat encoding exceeds the 1023-bit single-cell
/// limit); must match `crypto/smartcont/service-actor-code.fc`'s
/// `compute_terms_hash` byte-for-byte, including the exact cell split.
#[allow(clippy::too_many_arguments)]
pub fn service_actor_terms_hash(
    policy_version: u32,
    price_per_call: u64,
    storage_fee: u64,
    cleanup_bounty: u64,
    response_sla: u32,
    refund_claim_window: u32,
    metadata_hash: &[u8; 32],
    proof_scheme_hash: &[u8; 32],
    has_attestor: bool,
    attestor_pubkey: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let canonical_attestor_pubkey = if has_attestor { *attestor_pubkey } else { [0u8; 32] };
    let mut tail = BuilderData::new();
    tail.append_u256(metadata_hash)?;
    tail.append_u256(proof_scheme_hash)?;
    if has_attestor {
        tail.append_bit_one()?;
    } else {
        tail.append_bit_zero()?;
    }
    tail.append_raw(&canonical_attestor_pubkey, 256)?;

    let mut root = BuilderData::new();
    root.append_u32(policy_version)?;
    Coins::new(price_per_call).write_to(&mut root)?;
    Coins::new(storage_fee).write_to(&mut root)?;
    Coins::new(cleanup_bounty).write_to(&mut root)?;
    root.append_u32(response_sla)?;
    root.append_u32(refund_claim_window)?;
    root.checked_append_reference(tail.into_cell()?)?;

    let cell = root.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}

/// Compute the domain-bound hash Service Actor's `respond` attestor
/// signature must cover: contract address, `request_id`, `caller_address`,
/// `request_hash`, `response_hash`, `terms_hash`, `price`, and both
/// deadlines -- every field that determines what request this response
/// answers, under what terms, for how much. A signature for one request,
/// caller, policy, amount, or deadline must not authorize any other
/// request. Split across a root + one reference cell for the same 1023-bit
/// reason as `service_actor_terms_hash`; must match
/// `crypto/smartcont/service-actor-code.fc`'s `compute_response_domain_hash`
/// byte-for-byte, including the exact cell split.
#[allow(clippy::too_many_arguments)]
pub fn service_respond_domain_hash(
    contract_address: &MsgAddressInt,
    caller: &MsgAddressInt,
    request_id: u64,
    request_hash: &[u8; 32],
    response_hash: &[u8; 32],
    terms_hash: &[u8; 32],
    price: u64,
    response_deadline: u64,
    refund_claim_deadline: u64,
) -> anyhow::Result<[u8; 32]> {
    let (wc, addr) = wc_and_addr(contract_address)?;

    let mut tail = BuilderData::new();
    caller.write_to(&mut tail)?;
    tail.append_u256(terms_hash)?;
    Coins::new(price).write_to(&mut tail)?;
    tail.append_u64(response_deadline)?;
    tail.append_u64(refund_claim_deadline)?;

    let mut root = BuilderData::new();
    root.append_i8(wc)?;
    root.append_u256(&addr)?;
    root.append_u64(request_id)?;
    root.append_u256(request_hash)?;
    root.append_u256(response_hash)?;
    root.checked_append_reference(tail.into_cell()?)?;

    let cell = root.into_cell()?;
    Ok(*cell.repr_hash().as_array())
}
