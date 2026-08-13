/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
//! Rust SDK for the concurrent-escrow Service Actor -- see
//! `doc/service-actor-concurrent-escrow-upgrade.md` for the full design.
//! This is a direct, incompatible replacement of the single-pending-slot
//! Service Actor: every request is identified by a contract-assigned
//! `request_id` and snapshots the policy/attestor key in force at `call`
//! time, so it resolves independently of every other outstanding request.
use chain_block::{
    BuilderData, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, StateInit,
    base64_decode, read_single_root_boc,
};
use common::tvm_stack_parser::TvmStackParser;

pub const SERVICE_ACTOR_CODE_B64: &str = "te6ccgECLAEAC0oAART/APSkE/S88sgLAQIBYgIDBH7QAdDTAwFxsJJfA+D6QDAhxwCSXwPgAdMf0z8x2zxWHYIQU1ZDAbrjAlcfVhyCEFNWQwK64wJWHIIQU1ZDA7oqBAUGAgEgICEB+lcdVhnAAfLnbVYRgQ4QvlYSgggnjQC7sPLnb1YQgQ4QvlYRgggnjQC7sPLncFYSghAF9eEAvlYTghA7msoAu7Dy53GCEAX14QBWE6BWFAG+8udyL8ABVh4vxwVWEAGwsfLng1YUVhSgVh8BvvLnblYWggGGoLny53NWHFYeBwK0VxwRHFYZxwXy52wRGdM/IVYdgED0D2+h8ud50PpA+gD6APoA0z/TP9Mf1AHQAdHT/9P/0wDT/9E0NvgjJbny53gJ0/8Gk18FNOMNA9ERHhOAQPRbMAERHgECCwwC/o78VxxXHBEZ0z/RIFYcgED0D2+h8ud50PpA+gD6APoA0z/TP9Mf1AHQAdHT/9P/0wDT/9FfBQH4I7vy53r4IyG58ud7UlARIYBA9FswIxBFVSARIchQBc8WUAP6AgH6AgH6Ass/yVkRHIBA9BcRFaUDVhqhERoSoBEXERsRF+AODwHE+QEBgwf0Dm+hk9MfMJIwcOKBA+i58ud0VhiEP7ny53X4I4IBUYCpBFMEvZM0cDORMOIswABTPbmx8ueEAqQRG9P/0VYY+CNWE6AgVhOgVhhWGFYYVhhWGFYYVhRWFFYUVhQIAdQhkjBw3wPIy/8Sy//LAMv/yQbIyx9QBfoCUAP6AgH6Assfyx/MyfkAViEEVhkEVhkEVhlBNFYdQJlWElYSA8jL/xLL/8sAy//JyFAIzxZQBvoCUAT6Alj6Ass/yz/LH8zJAoBA9BcRG1YcCQH4XPkBAYMH9A5voZPTHzCSMHDipMjLHwH5AViDB/RDER1WE6FWEqEgwgCOGQERHAFxcIAQyMsFUATPFlj6AhLLaskB+wCTMFcb4hEVpBEUpBETpANWEKACVhGgERcRGxEXERYRGhEWERQRGREUERMRGBETAxEXAxESERYREgoBZBERERUREREQERQREA8REw8OERIODRERDQwREAwQvxCuEJ0QjBB7EGoQWRBIR2YFRBQDHwB6BYMI1xgpUVxRWhBJED1Qgvgo+kTIUArPFhXL/1AD+gLLP8s/yQHIygcVy/8Tyz/L/8v/zMn5AFn5EPLndwH4XPkBAYMH9A5voZPTHzCSMHDiIMECmTD5AQGDB/RbMJylyMsfAfkBWIMH9EPiERalERWlBlYcoFYdoBEdFaERGxOhERcRGxEXERYRGhEWERURGREVERMRGBETBBEXBBESERYREhERERUREREQERQREA8REw8OERIODRERDQ0BMgwREAwQvxCuEJ0QjBB7EGoQWRBIBkRXQxMfAZ4RFhEaERYRFREZERUCERgCERMRFxETERIRFhESERERFRERERARFBEQDxETDw4REg4NERENDBEQDBC/EK4QnRCMEHsQahBZEEgQNwVGFlBDHwRUVhyCEFNWQwS64wJWHIIQU1ZDBbrjAlYcghBTVkMGuuMCVhyCEFNWQwe6EBESEwP+VxwRGtM/+kDRIVYdgED0D2+h8ud90PpA+gD6APoA0z/RMREhI8cF8ud++CMBESG58ud8+CdvEFIQu/LngREeE4BA9FswAREfAQJc+QEBgwf0Dm+hk9MfMJIwcOIgwQKZMPkBAYMH9FswnKXIyx8B+QFYgwf0Q+JWHMIA4w8RFRQVFgL+VxwRGtM/0SBWG4BA9A9voSJWHoBA9A9voVIgsfLngHACjiNb0PpA+gD6APoA0z/TP9Mf1AHQAdHT/9P/0wDT/9EQVl8GcY4QbBLQ+kD6APoA+gDTP9FVBOL4I1i+8ud/+CdvEFIgu/LngZ4RHhSAQPRbMBEZpVFxoeMOAREgARcYAfhsqjo+VxAREC3HBfLnbA36APoA+gDTH9Mf0wDTANMA+kDTH9QB0NP/0//RAtEogQ4QvimCCCeNALuw8udvJ4EOEL4ogggnjQC7sPLncCmCEAX14QC+KoIQO5rKALuw8udxghAF9eEAKqBSsL7y53IREqQRFxEbERcGERoGGgT+juQ4OFcaERpWF8cF8udsERfT/9ERFhEaERYRFREZERURFBEYERQRExEXERMREhEWERIREREVEREREBEUERAPERMPDhESDg0REQ0MERAMEL8QrhCdEIwQexBqcVCaEEgQN0YUUFUD4FYcghBTVkMIuuMCERyCEFNWQwm64wJfDx8bHB0AMhEeVhxxcIAQyMsFUATPFlj6AhLLaskB+wAABFceAbylBlYcoBEcFaERGhKhERcRGxEXERYRGhEWERURGREVERQRGBEUBBEXBBESERYREhERERUREREQERQREA8REw8OERIODRERDQwREAwQvxCuEJ0QjBB7EGpeNRBXRlUEHwAmER8UgED0WzBRYaEGER4RHREZBwH4Alz5AQGDB/QOb6GT0x8wkjBw4iDBApkw+QEBgwf0WzCcpcjLHwH5AViDB/RD4hEfGKAhoFYboVBmoVYawgCOGwERHAERGnFwgBDIywVQBM8WWPoCEstqyQH7AJRXGlcb4hETpREXERsRFxEWERoRFhEVERkRFQIRGAIRFxkBdBESERYREhERERUREREQERQREA8REw8OERIODRERDQwREAwQvxCuEJ0QjBB7EGoQWRA4ECcQRl4xECMfAYARFREZERURFBEYERQRExEXERMRFgsRFQsKERQKCRETCQgREggHEREHBREQBRBPED4QLRCMGxBaEEkQOEB3AwYEHwHAOVcbERtWGMcF8udsERjRERYRGhEWERURGREVERQRGBEUERMRFxETERIRFhESERERFRERERARFBEQDxETDw4REg4NERENDBEQDBC/EK4QnRCMEHsQanAKEFkQSBA3RlMSHwH+ERxWGccF8udsERn6ANH4J28QJKEjoYIQO5rKAKFSYLYIUhC78ueCIMIAjhhWGCFxcIAQyMsFUATPFlj6AhLLaskB+wDeFaERFxEbERcRFhEaERYRFREZERURFBEYERQRExEXERMREhEWERIREREVEREREBEUERAPERMPDhESDh4ACl8P8sd2ATYNERENDBEQDBC/EK4QnRCMEHsQahBZCBA3RlMfAOIMyMv/G8v/GcsAF8v/yRETyMsfARES+gIBERD6AlAO+gIcyx8ayx8YywAWywBQBM8WEssfGszJyFAF+gJQBfoCUAX6AlAF+gIVyx8Tyx/JAcj0ABL0ABP0AMnIUAjPFhbLABTLPxLLH8sfEszMzMntVAIBICIjAgEgKCkBFbrr3bPF8PEJxfDIKgIBICQlATm2drtniuIL4e2WID8gIDBg/oHN9DJ6Y+YSRg4cUCoCAWImJwF0qqvbPF8DERMRFhETERIRFRESERERFBERERARExEQDxESDw4REQ4NERANEM8QvhCtEJwQixB6XiYQZyoBFKg+2zxfDxCMXwwqAVG7r42zwfXw9swYBA9A9vobOXMHBtVHERIODQ+kD6APoA+gDTP9FxVUCCoBgbiRnbPBAvXw9swYBA9A9vobOdMHBtVHERVHAAVHAAIODQ+kD6APoA+gDTP9M/0x/UAdAB0dP/0//TANP/0XFVoIKgH07UTQ+kDTANM/0x/TH9QB0NMf+gD6APoA0x/TH9MA0wD6QNMf1AHQAdHT/9P/0wDT/9EO1AHQ+gD6APoA+gDTH9Mf0QbUAdAB0fQE9AT0BNERFREWERURFBEVERQRExEUERMREhETERIRERESEREREBERERAPERAPEO8rACgQ3hDNELwQqxCaEHgQZxBWEEUQNA==";

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
    /// Optional ed25519 public key. When set, `respond` additionally
    /// requires a signature over the full request-bound domain under this
    /// key -- on top of, never instead of, the existing owner sender
    /// authorization.
    pub attestor_pubkey: Option<[u8; 32]>,
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
    pub attestor_pubkey: Option<[u8; 32]>,
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
    pub attestor_pubkey: Option<[u8; 32]>,
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
        let has_attestor = init.attestor_pubkey.is_some();
        let attestor_pubkey = init.attestor_pubkey.unwrap_or([0u8; 32]);
        // Mirrors ServiceActorInit's V1 convention: authorized_caller always
        // carries a concrete address on chain, defaulting to the owner when
        // none is explicitly given (meaningful only while has_authorized_caller
        // is set, i.e. open_access is false).
        let authorized_caller = init.authorized_caller.as_ref().unwrap_or(&init.owner);

        let mut commitments = BuilderData::new();
        commitments.append_u256(&init.metadata_hash)?;
        commitments.append_u256(&init.proof_scheme_hash)?;
        if has_attestor {
            commitments.append_bit_one()?;
        } else {
            commitments.append_bit_zero()?;
        }
        commitments.append_raw(&attestor_pubkey, 256)?;

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
            attestor_pubkey: if stack.bool(14)? { Some(parse_hash(stack, 15)?) } else { None },
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
            attestor_pubkey: if stack.bool(10)? { Some(parse_hash(stack, 11)?) } else { None },
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

    pub fn call(query_id: u64, request_hash: [u8; 32]) -> anyhow::Result<chain_block::Cell> {
        message(SVC_CALL_OPCODE, query_id, |b| b.append_u256(&request_hash).map(|_| ()))
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
    /// signature: `signature` must be valid over
    /// `contracts::service_respond_domain_hash(..)` under that key, or the
    /// contract rejects the message.
    pub fn respond_signed(
        query_id: u64,
        request_id: u64,
        response_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_RESPOND_OPCODE, query_id, |b| {
            b.append_u64(request_id)?;
            b.append_u256(&response_hash)?;
            b.append_raw(signature, 512).map(|_| ())
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
        new_attestor_pubkey: [u8; 32],
    ) -> anyhow::Result<chain_block::Cell> {
        message(SVC_ROTATE_ATTESTOR_KEY_OPCODE, query_id, |b| {
            b.append_raw(&new_attestor_pubkey, 256).map(|_| ())
        })
    }

    /// Owner-only: drop the attestation requirement for requests accepted
    /// from now on -- `respond` reverts to sender-authorization-only until
    /// `rotate_attestor_key` is called again.
    pub fn revoke_attestor(query_id: u64) -> anyhow::Result<chain_block::Cell> {
        message(SVC_REVOKE_ATTESTOR_OPCODE, query_id, |_| Ok(()))
    }
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
        let call = ServiceActorContract::call(1, [0xAA; 32]).unwrap();
        let mut slice = SliceData::load_cell(call).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_CALL_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 1);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xAA; 32]);
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

        let signature = [0x5Au8; 64];
        let respond_signed =
            ServiceActorContract::respond_signed(3, 7, [0xCC; 32], &signature).unwrap();
        let mut slice = SliceData::load_cell(respond_signed).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_RESPOND_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 3);
        assert_eq!(slice.get_next_u64().unwrap(), 7);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xCC; 32]);
        assert_eq!(slice.get_next_bytes(64).unwrap(), signature.to_vec());
        assert_eq!(slice.remaining_bits(), 0);
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

        let rotate = ServiceActorContract::rotate_attestor_key(9, [0xEE; 32]).unwrap();
        let mut slice = SliceData::load_cell(rotate).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), SVC_ROTATE_ATTESTOR_KEY_OPCODE);
        assert_eq!(slice.get_next_u64().unwrap(), 9);
        assert_eq!(slice.get_next_bytes(32).unwrap(), vec![0xEE; 32]);

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
        assert_eq!(data.attestor_pubkey, Some([0x99; 32]));
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
        assert_eq!(data.attestor_pubkey, None);
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
        assert_eq!(data.attestor_pubkey, Some([0x99; 32]));
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
