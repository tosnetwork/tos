/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
//! Rust SDK for the concurrent-escrow Service Actor -- see
//! `https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md` for the full design.
//! This is a direct, incompatible replacement of the single-pending-slot
//! Service Actor: every request is identified by a contract-assigned
//! `request_id` and snapshots the policy/attestor key in force at `call`
//! time, so it resolves independently of every other outstanding request.
use chain_block::{
    BuilderData, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, StateInit,
    base64_decode, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;

pub const SERVICE_ACTOR_CODE_B64: &str = "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Ib6w8ueHoXD7AijCAJIwN+MNIMIAkTDjDREbcDM0NQAuUAhxcIAQyMsFUATPFlj6AhLLaskB+wAAMFYcAXFwgBDIywVQBM8WWPoCEstqyQH7AAHSgwZwgBDIywVQBM8WWPoCEstqyQH7ABETpREXERsRFxEWERoRFhEVERkRFREVERgRFREXERIRFhESERERFRERERARFBEQDxETDw4REg4NERENDBEQDBC/EK4QnRCMEHsQahBZRxgQNkBUPAGq8udyERKkERcRGxEXBhEaBhEVERkRFREUERgRFBETERcRExEWCxEVCwoRFAoJERMJCBESCAcREQcFERAFEE8QPhAtEIwbEHoQWRBIEDcQJhBFEDQQIzwB1jk5VxtXHBEaVhfHBfLnbBEX0W34YXAgERcRGxEXERYRGhEWERURGREVERQRGBEUERMRFxETERIRFhESERERFRERERARFBEQDxETDw4REg4NERENDBEQDBC/EK4QnRCMEHtQqRBIEDdAZgQFPAEighBTVkMJuuMCXw9fDzDyx3Y5AfxWHVYbxwXy52wRG/oA0VYegQeC+CdvEFMCvhLy9AEgwv9TIb6w8ueHoVRwBr7y54InIML/UyG+sPLnh6FTBr7y54ImIML/UyG+sPLnh6FTCL7y54IoIML/UyG+sPLnh6EgghA7msoAvvLngoIQO5rKACDC/1MhvrDy54ehUpA6Afy2CFIgu/LnghEfghAL68IAvvLniVYaAgERHgERH1YeZiDC/1MhvrDy54ehcPsCIMIAjhYScXCAEMjLBVAEzxZY+gISy2rJAfsAkjAx4nCDBnCAEMjLBVAEzxZY+gISy2rJAfsAERsVIML/UyG+sPLnh6ERFxEbERcRFhEaERY7AZIRFREZERURFBEYERQRExEXERMREhEWERIREREVEREREBEUERAPERMPDhESDg0REQ0MERAMEL8QrhCdEIwQexBqEFkIEDdGUEMAPADq+EENyMv/HMv/GssAGMv/GvQAyRETyMsfARES+gIBERD6AlAO+gIcyx8ayx8YywAWywBQBM8WEssfGszJyFAF+gJQBfoCUAX6AlAF+gIVyx8Vyx/JAsj0APQAE/QAychQCM8WFssAFMs/Essfyx8SzMzMye1UAJlX+RII5AItc58n8g10kh10ohd7DyfyDCAfJ/AasCUwS88n8BwAGYNCPAf/K/1DCOEGwhIMIAIYEAgLmw8r8CcAHiUCOhAegwMcAA8r+AIBID9AAEEIcAB8r3XOfJ/0x/U0QLAAZOBBSCRcOJSELryvlzwBQGAAMQBwAHyvdc58n/TH9TRIYEJdLryvlIC8AWDHFItz";

pub const SVC_CALL_OPCODE: u32 = 0x5356_4301;
pub const SVC_RESPOND_OPCODE: u32 = 0x5356_4302;
pub const SVC_EXPIRE_OPCODE: u32 = 0x5356_4303;
pub const SVC_CLAIM_REFUND_OPCODE: u32 = 0x5356_4304;
pub const SVC_SWEEP_EXPIRED_REQUEST_OPCODE: u32 = 0x5356_4305;
pub const SVC_UPDATE_POLICY_OPCODE: u32 = 0x5356_4306;
pub const SVC_ROTATE_ATTESTOR_KEY_OPCODE: u32 = 0x5356_4307;
pub const SVC_REVOKE_ATTESTOR_OPCODE: u32 = 0x5356_4308;
pub const SVC_WITHDRAW_REVENUE_OPCODE: u32 = 0x5356_4309;

/// Protocol constants the contract enforces itself -- not owner-configurable
/// policy fields, and not (re)validated here beyond `build_data`'s own
/// client-side sanity checks. Must match the `const int` values in
/// `crypto/smartcont/service-actor-code.fc` exactly; see that file's own
/// comments for the masterchain-fee grounding behind each number.
pub mod protocol_constants {
    pub const MINIMUM_CLEANUP_BOUNTY: u64 = 100_000_000; // 0.1 TOS
    pub const MAXIMUM_CLEANUP_BOUNTY: u64 = 1_000_000_000; // 1 TOS
    pub const MINIMUM_STORAGE_FEE: u64 = 100_000_000; // 0.1 TOS
    pub const MINIMUM_OPERATING_RESERVE: u64 = 1_000_000_000; // 1 TOS
    /// Attached in addition to the quoted price and storage fee. Unused execution
    /// funding is returned to the caller after the transaction's fees.
    pub const ADMISSION_GAS_ALLOWANCE: u64 = 200_000_000; // 0.2 TOS
    /// Attached to refund, sweep and withdrawal messages so their transaction fees
    /// are paid by the sender instead of reducing the payout or existing backing.
    pub const PAYOUT_GAS_ALLOWANCE: u64 = 200_000_000; // 0.2 TOS
    pub const MIN_RESPONSE_SLA_SECS: u32 = 3_600; // 1 hour
    pub const MAX_RESPONSE_SLA_SECS: u32 = 2_592_000; // 30 days
    pub const MIN_REFUND_CLAIM_WINDOW_SECS: u32 = 3_600; // 1 hour
    pub const MAX_REFUND_CLAIM_WINDOW_SECS: u32 = 2_592_000; // 30 days
    pub const MAX_LIVE_GLOBAL: u32 = 100_000;
    pub const MAX_LIVE_PER_CALLER: u32 = 1_000;
}

/// Deployment parameters for a Service Actor.
///
/// One instance is deployed per registered service (model, data, or tool
/// provider) -- the same per-actor pattern as `AgentAccountContract` /
/// `TaskEscrowContract` / `CapabilityRegistryContract`.
///
/// `open_access`/`authorized_caller`/`rate_limit_per_day` are carried
/// forward from the current single-slot Service Actor unchanged (ported,
/// not redesigned): they gate admission to `call` only and are excluded
/// from `terms_hash` and the attestation response domain, since they don't
/// change what a valid response to an already-accepted request has to
/// satisfy. See the header comment in `service-actor-code.fc`.
#[derive(Clone, Debug)]
pub struct ServiceActorInit {
    pub owner: MsgAddressInt,
    /// Optional single authorized caller when `open_access` is `false`.
    pub authorized_caller: Option<MsgAddressInt>,
    /// When `true`, any caller may send `call`; otherwise only
    /// `authorized_caller` may.
    pub open_access: bool,
    pub price_per_call: u64,
    /// Fixed, non-refundable fee collected alongside `price_per_call` at
    /// `call` time; must satisfy
    /// `storage_fee >= MINIMUM_STORAGE_FEE + cleanup_bounty` on chain.
    pub storage_fee: u64,
    /// Paid to whoever calls `sweep_expired_request` once an entry's rights
    /// window has fully lapsed; must be within
    /// `[MINIMUM_CLEANUP_BOUNTY, MAXIMUM_CLEANUP_BOUNTY]` on chain.
    pub cleanup_bounty: u64,
    /// Maximum `call`s accepted per UTC day; `0` means unlimited.
    pub rate_limit_per_day: u32,
    /// Seconds a submitted call has to be `respond`ed to; must be within
    /// `[MIN_RESPONSE_SLA_SECS, MAX_RESPONSE_SLA_SECS]` on chain.
    pub response_sla: u32,
    /// Seconds after `response_deadline` an expired request's refund stays
    /// claimable; must be within
    /// `[MIN_REFUND_CLAIM_WINDOW_SECS, MAX_REFUND_CLAIM_WINDOW_SECS]`.
    pub refund_claim_window: u32,
    pub metadata_hash: [u8; 32],
    pub proof_scheme_hash: [u8; 32],
    /// Optional ML-DSA-44 attestor public key (1,312 bytes). When set,
    /// `respond` additionally requires an ML-DSA-44 signature over the full
    /// request-bound domain under this key -- on top of, never instead of,
    /// the owner sender authorization. State keeps its key id and the
    /// stored key, which each request snapshots by reference.
    pub attestor_pubkey: Option<Vec<u8>>,
}

/// The ML-DSA-44 context of an attestor `respond` signature.
pub const SERVICE_ACTOR_RESPOND_CONTEXT: &[u8] = b"TOS-SERVICE-ACTOR-RESPOND-V1";

/// Tag of the request snapshot every accepted `call` emits ("SAR1").
pub const SERVICE_ACTOR_REQUEST_SNAPSHOT_TAG: u32 = 0x5341_5231;

impl ServiceActorInit {
    /// The key id of the attestor key, when one is set.
    pub fn attestor_key_id(&self) -> anyhow::Result<Option<[u8; 32]>> {
        self.attestor_pubkey.as_deref().map(crate::native_registry::controller_key_id).transpose()
    }
}

/// Signs a Service Actor response domain hash with the ML-DSA-44 attestor
/// whose key-generation seed is `seed` (hedged). Returns the public key and
/// the 2,420-byte signature.
pub fn sign_service_response(
    seed: &[u8; 32],
    domain_hash: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes, Signer};
    let (public_key, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
    let signature = secret
        .try_sign(domain_hash, SERVICE_ACTOR_RESPOND_CONTEXT)
        .map_err(|e| anyhow::anyhow!("Service Actor response signing failed: {e}"))?;
    Ok((public_key.into_bytes().to_vec(), signature.to_vec()))
}

/// Verifies a Service Actor response signature exactly as `respond` will.
pub fn verify_service_response(
    public_key: &[u8],
    signature: &[u8],
    domain_hash: &[u8; 32],
) -> anyhow::Result<()> {
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};
    let key: [u8; 1312] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("an attestor key is 1,312 bytes, not {}", public_key.len()))?;
    let signature: [u8; 2420] = signature.try_into().map_err(|_| {
        anyhow::anyhow!("an attestor signature is 2,420 bytes, not {}", signature.len())
    })?;
    let key = ml_dsa_44::PublicKey::try_from_bytes(key)
        .map_err(|e| anyhow::anyhow!("attestor key: {e}"))?;
    anyhow::ensure!(
        key.verify(domain_hash, &signature, SERVICE_ACTOR_RESPOND_CONTEXT),
        "Service Actor response signature verification failed"
    );
    Ok(())
}

pub struct ServiceActorContract;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceActorData {
    pub owner: MsgAddressInt,
    pub active: bool,
    pub policy_version: u32,
    pub price_per_call: u64,
    pub storage_fee: u64,
    pub cleanup_bounty: u64,
    pub response_sla: u32,
    pub refund_claim_window: u32,
    pub open_access: bool,
    pub authorized_caller: Option<MsgAddressInt>,
    pub rate_limit_per_day: u32,
    pub metadata_hash: [u8; 32],
    pub proof_scheme_hash: [u8; 32],
    /// Key id of the current attestor key, when an attestor is set.
    pub attestor_key_id: Option<[u8; 32]>,
    pub next_request_id: u64,
    pub pending_count: u32,
    /// Pending + refundable entries combined -- the quantity
    /// `max_live_global`/`max_live_per_caller` actually cap.
    pub live_count: u32,
    pub withdrawable_revenue: u64,
    pub locked_storage_fees: u64,
    pub pending_liability: u64,
    pub refundable_liability: u64,
    /// UTC day (`now() / 86400`) `calls_today` was last reset for.
    pub call_day: u32,
    pub calls_today: u32,
}

/// Decoded `get_request` result: a still-outstanding, unanswered call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequestData {
    pub caller: MsgAddressInt,
    pub price: u64,
    pub storage_fee: u64,
    pub cleanup_bounty: u64,
    pub response_deadline: u64,
    pub refund_claim_deadline: u64,
    pub policy_version: u32,
    pub request_hash: [u8; 32],
    pub terms_hash: [u8; 32],
    /// Key id of the attestor key the request snapshotted at `call`.
    pub attestor_key_id: Option<[u8; 32]>,
}

/// Decoded `get_refund` result: an expired, not-yet-claimed-or-swept request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundData {
    pub caller: MsgAddressInt,
    pub price: u64,
    pub storage_fee: u64,
    pub cleanup_bounty: u64,
    pub refund_claim_deadline: u64,
}

impl ServiceActorContract {
    pub fn code() -> anyhow::Result<chain_block::Cell> {
        read_single_root_boc(base64_decode(SERVICE_ACTOR_CODE_B64)?).map_err(Into::into)
    }

    pub fn build_data(init: &ServiceActorInit) -> anyhow::Result<chain_block::Cell> {
        let attestor_key_id = init.attestor_key_id()?;
        // Mirrors ServiceActorInit's V1 convention: authorized_caller always
        // carries a concrete address on chain, defaulting to the owner when
        // none is explicitly given (meaningful only while has_authorized_caller
        // is set, i.e. open_access is false).
        let authorized_caller = init.authorized_caller.as_ref().unwrap_or(&init.owner);

        let mut commitments = BuilderData::new();
        commitments.append_u256(&init.metadata_hash)?;
        commitments.append_u256(&init.proof_scheme_hash)?;
        match (attestor_key_id, init.attestor_pubkey.as_deref()) {
            (Some(key_id), Some(public_key)) => {
                commitments.append_bit_one()?;
                commitments.append_raw(&key_id, 256)?;
                commitments.append_bit_one()?;
                commitments
                    .checked_append_reference(crate::native_registry::stored_bytes(public_key)?)?;
            }
            _ => {
                commitments.append_bit_zero()?;
                commitments.append_raw(&[0u8; 32], 256)?;
                commitments.append_bit_zero()?;
            }
        }

        let mut policy = BuilderData::new();
        policy.append_u32(0)?; // policy_version = 0 at deploy
        Coins::new(init.price_per_call).write_to(&mut policy)?;
        Coins::new(init.storage_fee).write_to(&mut policy)?;
        Coins::new(init.cleanup_bounty).write_to(&mut policy)?;
        policy.append_u32(init.response_sla)?;
        policy.append_u32(init.refund_claim_window)?;
        if init.open_access {
            policy.append_bit_one()?;
        } else {
            policy.append_bit_zero()?;
        }
        if init.authorized_caller.is_some() {
            policy.append_bit_one()?;
        } else {
            policy.append_bit_zero()?;
        }
        authorized_caller.write_to(&mut policy)?;
        policy.append_u32(init.rate_limit_per_day)?;
        policy.checked_append_reference(commitments.into_cell()?)?;

        let mut accounting = BuilderData::new();
        Coins::new(0).write_to(&mut accounting)?; // withdrawable_revenue
        Coins::new(0).write_to(&mut accounting)?; // locked_storage_fees
        Coins::new(0).write_to(&mut accounting)?; // pending_liability
        Coins::new(0).write_to(&mut accounting)?; // refundable_liability
        accounting.append_u32(0)?; // call_day
        accounting.append_u32(0)?; // calls_today

        let mut dicts = BuilderData::new();
        dicts.append_bit_zero()?; // pending_requests: empty HashmapE
        dicts.append_bit_zero()?; // refunds: empty HashmapE
        dicts.append_bit_zero()?; // caller_live_counts: empty HashmapE

        let mut data = BuilderData::new();
        init.owner.write_to(&mut data)?;
        data.append_bit_one()?; // active = 1 at deploy
        data.append_u64(0)?; // next_request_id
        data.append_u32(0)?; // pending_count
        data.append_u32(0)?; // live_count
        data.checked_append_reference(policy.into_cell()?)?;
        data.checked_append_reference(accounting.into_cell()?)?;
        data.checked_append_reference(dicts.into_cell()?)?;
        Ok(data.into_cell()?)
    }

    pub fn build_state_init(init: &ServiceActorInit) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(init)?))
    }

    pub fn calculate_address(wc: i32, init: &ServiceActorInit) -> anyhow::Result<MsgAddressInt> {
        let cell = Self::build_state_init(init)?.write_to_new_cell()?.into_cell()?;
        Ok(MsgAddressInt::with_params(wc, cell.hash(0))?)
    }

    /// Decode the result of `get_service_data`; transport and RPC concerns
    /// stay outside this module.
    pub fn decode_data(stack: &TvmStackParser) -> anyhow::Result<ServiceActorData> {
        let mut owner_slice = stack.slice(0)?;
        let owner = MsgAddressInt::construct_from(&mut owner_slice)?;
        let has_authorized_caller = stack.bool(9)?;
        let authorized_caller = if has_authorized_caller {
            let mut caller_slice = stack.slice(10)?;
            Some(MsgAddressInt::construct_from(&mut caller_slice)?)
        } else {
            None
        };
        Ok(ServiceActorData {
            owner,
            active: stack.bool(1)?,
            policy_version: stack.u64(2)? as u32,
            price_per_call: stack.u64(3)?,
            storage_fee: stack.u64(4)?,
            cleanup_bounty: stack.u64(5)?,
            response_sla: stack.u64(6)? as u32,
            refund_claim_window: stack.u64(7)? as u32,
            open_access: stack.bool(8)?,
            authorized_caller,
            rate_limit_per_day: stack.u64(11)? as u32,
            metadata_hash: parse_hash(stack, 12)?,
            proof_scheme_hash: parse_hash(stack, 13)?,
            attestor_key_id: if stack.bool(14)? { Some(parse_hash(stack, 15)?) } else { None },
            next_request_id: stack.u64(16)?,
            pending_count: stack.u64(17)? as u32,
            live_count: stack.u64(18)? as u32,
            withdrawable_revenue: stack.u64(19)?,
            locked_storage_fees: stack.u64(20)?,
            pending_liability: stack.u64(21)?,
            refundable_liability: stack.u64(22)?,
            call_day: stack.u64(23)? as u32,
            calls_today: stack.u64(24)? as u32,
        })
    }

    /// Decode the result of `get_request(request_id)`; `None` when the
    /// request is not (or no longer) pending.
    pub fn decode_request(stack: &TvmStackParser) -> anyhow::Result<Option<PendingRequestData>> {
        if !stack.bool(0)? {
            return Ok(None);
        }
        let mut caller_slice = stack.slice(1)?;
        let caller = MsgAddressInt::construct_from(&mut caller_slice)?;
        Ok(Some(PendingRequestData {
            caller,
            price: stack.u64(2)?,
            storage_fee: stack.u64(3)?,
            cleanup_bounty: stack.u64(4)?,
            response_deadline: stack.u64(5)?,
            refund_claim_deadline: stack.u64(6)?,
            policy_version: stack.u64(7)? as u32,
            request_hash: parse_hash(stack, 8)?,
            terms_hash: parse_hash(stack, 9)?,
            attestor_key_id: if stack.bool(10)? { Some(parse_hash(stack, 11)?) } else { None },
        }))
    }

    /// Decode the result of `get_refund(request_id)`; `None` when the
    /// request is not an outstanding, unclaimed refund.
    pub fn decode_refund(stack: &TvmStackParser) -> anyhow::Result<Option<RefundData>> {
        if !stack.bool(0)? {
            return Ok(None);
        }
        let mut caller_slice = stack.slice(1)?;
        let caller = MsgAddressInt::construct_from(&mut caller_slice)?;
        Ok(Some(RefundData {
            caller,
            price: stack.u64(2)?,
            storage_fee: stack.u64(3)?,
            cleanup_bounty: stack.u64(4)?,
            refund_claim_deadline: stack.u64(5)?,
        }))
    }

    /// Minimum value to attach to a call under the quoted policy, including the
    /// refundable execution allowance. Refuse client-side overflow explicitly.
    pub fn minimum_call_payment(price: u64, storage_fee: u64) -> anyhow::Result<u64> {
        price
            .checked_add(storage_fee)
            .and_then(|amount| amount.checked_add(protocol_constants::ADMISSION_GAS_ALLOWANCE))
            .ok_or_else(|| anyhow::anyhow!("Service Actor call funding exceeds u64"))
    }

    /// A `call` commits to the terms the caller was quoted: the contract refuses
    /// it unless `expected_terms_hash` equals the hash of its current terms.
    /// Attach at least `minimum_call_payment(price, storage_fee)`. The unused
    /// execution allowance returns to the caller after transaction fees.
    pub fn call(
        query_id: u64,
        request_hash: [u8; 32],
        expected_terms_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_CALL_OPCODE, query_id, |b| {
            b.append_u256(&request_hash)
                .and_then(|b| b.append_u256(&expected_terms_hash))
                .map(|_| ())
        })
    }

    /// The terms hash a `call` must commit to under the policy the service
    /// currently publishes (`get_service_data`).
    pub fn terms_hash_of_data(data: &ServiceActorData) -> anyhow::Result<[u8; 32]> {
        crate::service_actor_terms_hash(
            data.policy_version,
            data.price_per_call,
            data.storage_fee,
            data.cleanup_bounty,
            data.response_sla,
            data.refund_claim_window,
            &data.metadata_hash,
            &data.proof_scheme_hash,
            data.attestor_key_id.is_some(),
            &data.attestor_key_id.unwrap_or([0u8; 32]),
        )
    }

    /// The terms hash of a service as deployed from `init` (policy version 0,
    /// before any `update_policy`).
    pub fn terms_hash_of_init(init: &ServiceActorInit) -> anyhow::Result<[u8; 32]> {
        crate::service_actor_terms_hash(
            0,
            init.price_per_call,
            init.storage_fee,
            init.cleanup_bounty,
            init.response_sla,
            init.refund_claim_window,
            &init.metadata_hash,
            &init.proof_scheme_hash,
            init.attestor_pubkey.is_some(),
            &init.attestor_key_id()?.unwrap_or([0u8; 32]),
        )
    }

    pub fn respond(
        query_id: u64,
        request_id: u64,
        response_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_RESPOND_OPCODE, query_id, |b| {
            b.append_u64(request_id)?;
            b.append_u256(&response_hash).map(|_| ())
        })
    }

    /// Respond on a request whose snapshotted attestor requires a
    /// signature: `signature` (ML-DSA-44, 2,420 bytes) must be valid over
    /// `contracts::service_respond_domain_hash(..)` under that key with
    /// [`SERVICE_ACTOR_RESPOND_CONTEXT`], or the contract rejects the message.
    pub fn respond_signed(
        query_id: u64,
        request_id: u64,
        response_hash: [u8; 32],
        signature: &[u8],
    ) -> anyhow::Result<chain_block::Cell> {
        anyhow::ensure!(
            signature.len() == 2420,
            "an attestor signature is 2,420 bytes, not {}",
            signature.len()
        );
        let stored = crate::native_registry::stored_bytes(signature)?;
        message(SVC_RESPOND_OPCODE, query_id, |b| {
            b.append_u64(request_id)?;
            b.append_u256(&response_hash)?;
            b.checked_append_reference(stored).map(|_| ())
        })
    }

    /// Permissionless: moves a `response_deadline`-passed pending request
    /// into the refundable set. Both deadlines were fixed at `call` time and
    /// never move regardless of when `expire` is actually called.
    pub fn expire(query_id: u64, request_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_EXPIRE_OPCODE, query_id, |b| b.append_u64(request_id).map(|_| ()))
    }

    /// Caller-only: claims `price` (not the locked `storage_fee`) to a
    /// chosen destination before `refund_claim_deadline`.
    /// Attach at least `protocol_constants::PAYOUT_GAS_ALLOWANCE`. The destination
    /// receives the exact price; unused execution funding returns to the caller. Other
    /// callers' liabilities and locked fees stay protected; the operator's reserve
    /// does not take priority over a backed refund. Refusal does not pause the claim
    /// window; after expiry, sweep returns the unclaimed price to the caller.
    pub fn claim_refund(
        query_id: u64,
        request_id: u64,
        destination: &MsgAddressInt,
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_CLAIM_REFUND_OPCODE, query_id, |b| {
            b.append_u64(request_id)?;
            destination.write_to(b).map(|_| ())
        })
    }

    /// Permissionless once `refund_claim_deadline` has passed: deletes a
    /// still-pending or still-refundable entry and pays `cleanup_bounty` to
    /// the sender, so cleanup does not depend on owner or caller
    /// cooperation. Accepts a `request_id` found in either dictionary.
    /// Attach at least `protocol_constants::PAYOUT_GAS_ALLOWANCE`; the sender
    /// receives the exact bounty and a separate return of unused execution funding.
    pub fn sweep_expired_request(
        query_id: u64,
        request_id: u64,
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_SWEEP_EXPIRED_REQUEST_OPCODE, query_id, |b| {
            b.append_u64(request_id).map(|_| ())
        })
    }

    /// Owner-only. Affects only requests accepted after this call --
    /// already-outstanding requests keep the policy (and attestor key) they
    /// snapshotted at `call` time, so this never needs to freeze while
    /// requests are pending.
    /// `filler` is written in the authorized-caller slot when
    /// `authorized_caller` is `None` (mirroring how `ServiceActorInit`
    /// always carries a concrete address).
    #[allow(clippy::too_many_arguments)]
    pub fn update_policy(
        query_id: u64,
        price_per_call: u64,
        storage_fee: u64,
        cleanup_bounty: u64,
        response_sla: u32,
        refund_claim_window: u32,
        active: bool,
        open_access: bool,
        authorized_caller: Option<&MsgAddressInt>,
        filler: &MsgAddressInt,
        rate_limit_per_day: u32,
        metadata_hash: [u8; 32],
        proof_scheme_hash: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_UPDATE_POLICY_OPCODE, query_id, |b| {
            Coins::new(price_per_call).write_to(b)?;
            Coins::new(storage_fee).write_to(b)?;
            Coins::new(cleanup_bounty).write_to(b)?;
            b.append_u32(response_sla)?;
            b.append_u32(refund_claim_window)?;
            if active {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            if open_access {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            if authorized_caller.is_some() {
                b.append_bit_one()?;
            } else {
                b.append_bit_zero()?;
            }
            authorized_caller.unwrap_or(filler).write_to(b)?;
            b.append_u32(rate_limit_per_day)?;
            let mut meta = BuilderData::new();
            meta.append_u256(&metadata_hash)?.append_u256(&proof_scheme_hash)?;
            b.checked_append_reference(meta.into_cell()?)?;
            Ok(())
        })
    }

    /// Owner-only. Attach `protocol_constants::PAYOUT_GAS_ALLOWANCE` separately
    /// from the requested amount. The owner receives the exact amount and a
    /// separate return of unused execution funding; zero withdrawals return only
    /// that funding. Other liabilities and the operating reserve stay protected.
    pub fn withdraw_revenue(query_id: u64, amount: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_WITHDRAW_REVENUE_OPCODE, query_id, |b| Coins::new(amount).write_to(b))
    }

    /// Owner-only: set or replace the attestor key `respond` checks against
    /// for requests accepted from now on. Purely local state -- no
    /// cross-contract messaging, and (unlike the single-slot predecessor)
    /// never frozen, since already-outstanding requests keep their own
    /// snapshot regardless of later rotation.
    pub fn rotate_attestor_key(
        query_id: u64,
        new_attestor_pubkey: &[u8],
    ) -> anyhow::Result<chain_block::Cell> {
        crate::native_registry::controller_key_id(new_attestor_pubkey)?;
        let stored = crate::native_registry::stored_bytes(new_attestor_pubkey)?;
        message(SVC_ROTATE_ATTESTOR_KEY_OPCODE, query_id, |b| {
            b.checked_append_reference(stored).map(|_| ())
        })
    }

    /// Owner-only: drop the attestation requirement for requests accepted
    /// from now on -- `respond` reverts to sender-authorization-only until
    /// `rotate_attestor_key` is called again.
    pub fn revoke_attestor(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_REVOKE_ATTESTOR_OPCODE, query_id, |_| Ok(()))
    }
}

/// Decoded `request_snapshot#53415231` external-out event, emitted once by
/// every accepted `call`. It carries the terms a buyer accepted so an index can
/// be rebuilt from transactions alone; the contract state stays authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSnapshot {
    pub request_id: u64,
    pub caller: MsgAddressInt,
    pub request_hash: [u8; 32],
    pub terms_hash: [u8; 32],
    pub price: u128,
    pub response_deadline: u64,
    pub refund_claim_deadline: u64,
    /// Key id of the attestor key the request snapshotted, if any.
    pub attestor_key_id: Option<[u8; 32]>,
}

/// Decode a request snapshot event body, refusing any other tag, a missing or
/// extra field, and trailing bits or references in either cell.
pub fn decode_request_snapshot(body: &chain_block::Cell) -> anyhow::Result<RequestSnapshot> {
    let mut slice = chain_block::SliceData::load_cell_ref(body)?;
    let tag = slice.get_next_u32()?;
    if tag != SERVICE_ACTOR_REQUEST_SNAPSHOT_TAG {
        anyhow::bail!("not a Service Actor request snapshot (tag {tag:#010x})");
    }
    let request_id = slice.get_next_u64()?;
    let caller = MsgAddressInt::construct_from(&mut slice)?;
    let request_hash = next_hash(&mut slice)?;
    let terms_hash = next_hash(&mut slice)?;
    let tail_cell = slice.checked_drain_reference()?;
    exhausted(&slice, "request snapshot")?;
    let mut tail = chain_block::SliceData::load_cell(tail_cell)?;
    let price = Coins::construct_from(&mut tail)?.as_u128();
    let response_deadline = tail.get_next_u64()?;
    let refund_claim_deadline = tail.get_next_u64()?;
    let has_attestor = tail.get_next_bit()?;
    let key_id = next_hash(&mut tail)?;
    exhausted(&tail, "request snapshot terms")?;
    let attestor_key_id = match (has_attestor, key_id == [0u8; 32]) {
        (true, false) => Some(key_id),
        (false, true) => None,
        (true, true) => anyhow::bail!("request snapshot names an attestor with a zero key id"),
        (false, false) => anyhow::bail!("request snapshot carries a key id without an attestor"),
    };
    if refund_claim_deadline <= response_deadline {
        anyhow::bail!("request snapshot refund deadline does not follow the response deadline");
    }
    Ok(RequestSnapshot {
        request_id,
        caller,
        request_hash,
        terms_hash,
        price,
        response_deadline,
        refund_claim_deadline,
        attestor_key_id,
    })
}

fn next_hash(slice: &mut chain_block::SliceData) -> anyhow::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    slice.get_next_bytes_to_slice(&mut out)?;
    Ok(out)
}

fn exhausted(slice: &chain_block::SliceData, what: &str) -> anyhow::Result<()> {
    if slice.remaining_bits() != 0 || slice.remaining_references() != 0 {
        anyhow::bail!("{what} has trailing data");
    }
    Ok(())
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
    use chain_block::{Deserializable, Serializable, SliceData};
    use common::tvm_stack_parser::TvmStackParser;
    use tl_api::tos::tvm::{
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };

    fn snapshot_body(
        tag: u32,
        has_attestor: bool,
        key_id: [u8; 32],
        deadlines: (u64, u64),
        trailing: bool,
    ) -> chain_block::Cell {
        let mut tail = BuilderData::new();
        Coins::from(7_u64).write_to(&mut tail).unwrap();
        tail.append_u64(deadlines.0).unwrap();
        tail.append_u64(deadlines.1).unwrap();
        tail.append_bit_bool(has_attestor).unwrap();
        tail.append_raw(&key_id, 256).unwrap();
        if trailing {
            tail.append_bit_one().unwrap();
        }
        let mut body = BuilderData::new();
        body.append_u32(tag).unwrap();
        body.append_u64(5).unwrap();
        MsgAddressInt::standard(0, [0x33; 32]).write_to(&mut body).unwrap();
        body.append_raw(&[0x44; 32], 256).unwrap();
        body.append_raw(&[0x55; 32], 256).unwrap();
        body.checked_append_reference(tail.into_cell().unwrap()).unwrap();
        body.into_cell().unwrap()
    }

    #[test]
    fn request_snapshots_decode_exactly_and_refuse_every_inconsistency() {
        let tag = SERVICE_ACTOR_REQUEST_SNAPSHOT_TAG;
        let ok =
            decode_request_snapshot(&snapshot_body(tag, true, [9; 32], (10, 20), false)).unwrap();
        assert_eq!(ok.request_id, 5);
        assert_eq!(ok.caller, MsgAddressInt::standard(0, [0x33; 32]));
        assert_eq!((ok.request_hash, ok.terms_hash), ([0x44; 32], [0x55; 32]));
        assert_eq!((ok.price, ok.response_deadline, ok.refund_claim_deadline), (7, 10, 20));
        assert_eq!(ok.attestor_key_id, Some([9; 32]));
        let open =
            decode_request_snapshot(&snapshot_body(tag, false, [0; 32], (10, 20), false)).unwrap();
        assert_eq!(open.attestor_key_id, None);

        for (name, body) in [
            ("tag", snapshot_body(tag ^ 1, false, [0; 32], (10, 20), false)),
            ("trailing", snapshot_body(tag, false, [0; 32], (10, 20), true)),
            ("zero key", snapshot_body(tag, true, [0; 32], (10, 20), false)),
            ("orphan key", snapshot_body(tag, false, [9; 32], (10, 20), false)),
            ("deadlines", snapshot_body(tag, false, [0; 32], (20, 20), false)),
        ] {
            assert!(decode_request_snapshot(&body).is_err(), "{name} was accepted");
        }
    }

    #[test]
    fn service_actor_minimum_call_payment_checks_all_components() {
        let allowance = protocol_constants::ADMISSION_GAS_ALLOWANCE;
        assert_eq!(ServiceActorContract::minimum_call_payment(0, 0).unwrap(), allowance);
        assert_eq!(
            ServiceActorContract::minimum_call_payment(100_000_000, 200_000_000).unwrap(),
            300_000_000u64.checked_add(allowance).unwrap()
        );
        assert!(ServiceActorContract::minimum_call_payment(u64::MAX, 1).is_err());
        assert!(ServiceActorContract::minimum_call_payment(u64::MAX - allowance + 1, 0).is_err());
    }

    fn number(value: impl Into<String>) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.into() }),
        })
    }

    fn hash_number(value: [u8; 32]) -> StackEntry {
        number(format!("0x{}", hex::encode(value)))
    }

    fn address_slice_entry(address: &MsgAddressInt) -> StackEntry {
        let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
        let bytes = SliceData::load_cell(cell).unwrap().get_bytestring(0);
        StackEntry::Tvm_StackEntrySlice(StackEntrySlice { slice: slice::Slice { bytes } })
    }

    fn init() -> ServiceActorInit {
        ServiceActorInit {
            owner: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap(),
            authorized_caller: Some(
                MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap(),
            ),
            open_access: false,
            price_per_call: 100_000_000,
            storage_fee: 150_000_000,
            cleanup_bounty: 100_000_000,
            rate_limit_per_day: 1_000,
            response_sla: 3_600,
            refund_claim_window: 3_600,
            metadata_hash: [0x33; 32],
            proof_scheme_hash: [0x44; 32],
            attestor_pubkey: None,
        }
    }

    #[test]
    fn state_init_and_address_are_deterministic() {
        let svc = init();
        let first = ServiceActorContract::build_state_init(&svc)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        let second = ServiceActorContract::build_state_init(&svc)
            .unwrap()
            .write_to_new_cell()
            .unwrap()
            .into_cell()
            .unwrap();
        assert_eq!(first.hash(0), second.hash(0));
    }

    #[test]
    fn encodes_call_message() {
        let call = ServiceActorContract::call(1, [0xAA; 32], [0xBB; 32]).unwrap();
        let mut slice = SliceData::load_cell(call).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_CALL_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xBB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_respond_and_respond_signed_messages() {
        let respond = ServiceActorContract::respond(2, 7, [0xBB; 32]).unwrap();
        let mut slice = SliceData::load_cell(respond).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_RESPOND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 2);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xBB; 32]);
        assert_eq!(slice.remaining_bits(), 0);

        let signature = [0x5Au8; 2420];
        let respond_signed =
            ServiceActorContract::respond_signed(3, 7, [0xCC; 32], &signature).unwrap();
        let mut slice = SliceData::load_cell(respond_signed).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_RESPOND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xCC; 32]);
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(
            crate::native_registry::read_stored_bytes(
                &slice.checked_drain_reference().unwrap(),
                2420
            )
            .unwrap(),
            signature.to_vec()
        );
        assert!(ServiceActorContract::respond_signed(3, 7, [0xCC; 32], &[0u8; 64]).is_err());
    }

    #[test]
    fn encodes_expire_claim_refund_and_sweep_messages() {
        let expire = ServiceActorContract::expire(4, 9).unwrap();
        let mut slice = SliceData::load_cell(expire).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_EXPIRE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 4);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.remaining_bits(), 0);

        let destination = MsgAddressInt::with_standart(None, -1, [0x77; 32].into()).unwrap();
        let claim = ServiceActorContract::claim_refund(5, 9, &destination).unwrap();
        let mut slice = SliceData::load_cell(claim).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_CLAIM_REFUND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 5);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(MsgAddressInt::construct_from(&mut slice).unwrap(), destination);
        assert_eq!(slice.remaining_bits(), 0);

        let sweep = ServiceActorContract::sweep_expired_request(6, 9).unwrap();
        let mut slice = SliceData::load_cell(sweep).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_SWEEP_EXPIRED_REQUEST_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 6);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn encodes_update_policy_message() {
        let svc = init();
        let body = ServiceActorContract::update_policy(
            7,
            200_000_000,
            150_000_000,
            120_000_000,
            7_200,
            7_200,
            true,
            true,
            svc.authorized_caller.as_ref(),
            &svc.owner,
            50,
            [0xCC; 32],
            [0xDD; 32],
        )
        .unwrap();
        let mut slice = SliceData::load_cell(body).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_UPDATE_POLICY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 200_000_000);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 150_000_000);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 120_000_000);
        assert_eq!(slice.get_next_u32().unwrap(), 7_200);
        assert_eq!(slice.get_next_u32().unwrap(), 7_200);
        assert_eq!(slice.get_next_bit().unwrap(), true); // active
        assert_eq!(slice.get_next_bit().unwrap(), true); // open_access
        assert_eq!(slice.get_next_bit().unwrap(), true); // has_authorized_caller
        assert_eq!(
            MsgAddressInt::construct_from(&mut slice).unwrap(),
            svc.authorized_caller.unwrap()
        );
        assert_eq!(slice.get_next_u32().unwrap(), 50);
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 1);
        let mut meta_slice = SliceData::load_cell(slice.reference(0).unwrap()).unwrap();
        assert_eq!(meta_slice.get_next_bytes(32).unwrap(), vec![0xCC; 32]);
        assert_eq!(meta_slice.get_next_bytes(32).unwrap(), vec![0xDD; 32]);
    }

    #[test]
    fn encodes_withdraw_and_attestor_lifecycle_messages() {
        let withdraw = ServiceActorContract::withdraw_revenue(8, 500_000_000).unwrap();
        let mut slice = SliceData::load_cell(withdraw).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_WITHDRAW_REVENUE_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 8);
        assert_eq!(Coins::construct_from(&mut slice).unwrap().as_u128(), 500_000_000);
        assert_eq!(slice.remaining_bits(), 0);

        let key = crate::native_registry::native_public_key_from_seed(&[0xEE; 32]);
        let rotate = ServiceActorContract::rotate_attestor_key(9, &key).unwrap();
        let mut slice = SliceData::load_cell(rotate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_ROTATE_ATTESTOR_KEY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(
            crate::native_registry::read_stored_bytes(
                &slice.checked_drain_reference().unwrap(),
                1312
            )
            .unwrap(),
            key
        );
        assert!(ServiceActorContract::rotate_attestor_key(9, &[0xEE; 32]).is_err());

        let revoke = ServiceActorContract::revoke_attestor(10).unwrap();
        let mut slice = SliceData::load_cell(revoke).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_REVOKE_ATTESTOR_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 10);
    }

    #[test]
    fn decodes_service_data_stack() {
        let svc = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&svc.owner),
            number("1"),
            number("3"),
            number(svc.price_per_call.to_string()),
            number(svc.storage_fee.to_string()),
            number(svc.cleanup_bounty.to_string()),
            number(svc.response_sla.to_string()),
            number(svc.refund_claim_window.to_string()),
            number("0"),
            number("1"),
            address_slice_entry(svc.authorized_caller.as_ref().unwrap()),
            number(svc.rate_limit_per_day.to_string()),
            hash_number(svc.metadata_hash),
            hash_number(svc.proof_scheme_hash),
            number("1"),
            hash_number([0x99; 32]),
            number("42"),
            number("2"),
            number("5"),
            number("1500000000"),
            number("450000000"),
            number("300000000"),
            number("700000000"),
            number("19700"),
            number("3"),
        ]);
        let data = ServiceActorContract::decode_data(&stack).unwrap();
        assert_eq!(data.owner, svc.owner);
        assert!(data.active);
        assert_eq!(data.policy_version, 3);
        assert_eq!(data.price_per_call, svc.price_per_call);
        assert_eq!(data.storage_fee, svc.storage_fee);
        assert_eq!(data.cleanup_bounty, svc.cleanup_bounty);
        assert_eq!(data.response_sla, svc.response_sla);
        assert_eq!(data.refund_claim_window, svc.refund_claim_window);
        assert!(!data.open_access);
        assert_eq!(data.authorized_caller, svc.authorized_caller);
        assert_eq!(data.rate_limit_per_day, svc.rate_limit_per_day);
        assert_eq!(data.metadata_hash, svc.metadata_hash);
        assert_eq!(data.proof_scheme_hash, svc.proof_scheme_hash);
        assert_eq!(data.attestor_key_id, Some([0x99; 32]));
        assert_eq!(data.next_request_id, 42);
        assert_eq!(data.pending_count, 2);
        assert_eq!(data.live_count, 5);
        assert_eq!(data.withdrawable_revenue, 1_500_000_000);
        assert_eq!(data.locked_storage_fees, 450_000_000);
        assert_eq!(data.pending_liability, 300_000_000);
        assert_eq!(data.refundable_liability, 700_000_000);
        assert_eq!(data.call_day, 19700);
        assert_eq!(data.calls_today, 3);
    }

    #[test]
    fn decodes_service_data_without_authorized_caller() {
        let svc = init();
        let stack = TvmStackParser::new(vec![
            address_slice_entry(&svc.owner),
            number("1"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number(svc.response_sla.to_string()),
            number(svc.refund_claim_window.to_string()),
            number("1"),                     // open_access
            number("0"),                     // has_authorized_caller
            address_slice_entry(&svc.owner), // filler, unused when has_authorized_caller = 0
            number("0"),
            hash_number([0; 32]),
            hash_number([0; 32]),
            number("0"),
            hash_number([0; 32]),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
            number("0"),
        ]);
        let data = ServiceActorContract::decode_data(&stack).unwrap();
        assert!(data.open_access);
        assert_eq!(data.authorized_caller, None);
        assert_eq!(data.attestor_key_id, None);
    }

    #[test]
    fn decodes_request_and_refund_not_found() {
        let not_found = TvmStackParser::new(vec![number("0")]);
        assert_eq!(ServiceActorContract::decode_request(&not_found).unwrap(), None);
        assert_eq!(ServiceActorContract::decode_refund(&not_found).unwrap(), None);
    }

    #[test]
    fn decodes_pending_request_stack() {
        let caller = MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap();
        let stack = TvmStackParser::new(vec![
            number("1"),
            address_slice_entry(&caller),
            number("100000000"),
            number("150000000"),
            number("100000000"),
            number("1700000000"),
            number("1703600000"),
            number("3"),
            hash_number([0xAA; 32]),
            hash_number([0xBB; 32]),
            number("1"),
            hash_number([0x99; 32]),
        ]);
        let data = ServiceActorContract::decode_request(&stack).unwrap().unwrap();
        assert_eq!(data.caller, caller);
        assert_eq!(data.price, 100_000_000);
        assert_eq!(data.storage_fee, 150_000_000);
        assert_eq!(data.cleanup_bounty, 100_000_000);
        assert_eq!(data.response_deadline, 1_700_000_000);
        assert_eq!(data.refund_claim_deadline, 1_703_600_000);
        assert_eq!(data.policy_version, 3);
        assert_eq!(data.request_hash, [0xAA; 32]);
        assert_eq!(data.terms_hash, [0xBB; 32]);
        assert_eq!(data.attestor_key_id, Some([0x99; 32]));
    }

    #[test]
    fn decodes_refund_stack() {
        let caller = MsgAddressInt::with_standart(None, -1, [0x22; 32].into()).unwrap();
        let stack = TvmStackParser::new(vec![
            number("1"),
            address_slice_entry(&caller),
            number("100000000"),
            number("150000000"),
            number("100000000"),
            number("1703600000"),
        ]);
        let data = ServiceActorContract::decode_refund(&stack).unwrap().unwrap();
        assert_eq!(data.caller, caller);
        assert_eq!(data.price, 100_000_000);
        assert_eq!(data.storage_fee, 150_000_000);
        assert_eq!(data.cleanup_bounty, 100_000_000);
        assert_eq!(data.refund_claim_deadline, 1_703_600_000);
    }
}
