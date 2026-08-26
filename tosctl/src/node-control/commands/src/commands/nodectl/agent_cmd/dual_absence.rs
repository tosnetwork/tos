/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Snapshot-bound, lower-assurance absence evidence for Agent relay
//! sponsorship. This module contains no broadcaster and never writes to the
//! chain. The sponsorship-component producer atomically terminalizes the exact
//! local custody record before output. Dual aggregation consumes that immutable
//! tombstone without rewriting it; transaction-only production and every
//! independent verifier are query-only.

use super::*;
use chain_rpc_client::v2::{
    client_json_rpc::ClientJsonRpc,
    data_models::{BlockIdExt, RunGetMethodParams},
};
use std::sync::Arc;

const DUAL_ABSENCE_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-dual-absence.v1";
const DUAL_ABSENCE_VERIFICATION_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-proof-verification.v1";
const DUAL_ABSENCE_CAPABILITY_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-capability.v1";
const SPONSORSHIP_COMPONENT_ABSENCE_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1";
const TRANSACTION_COMPONENT_ABSENCE_SCHEMA: &str =
    "tosctl.agent-account.relay-transaction-component-absence.v1";
const SPONSORSHIP_COMPONENT_ABSENCE_VERIFICATION_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-component-absence-proof-verification.v1";
const TRANSACTION_COMPONENT_ABSENCE_VERIFICATION_SCHEMA: &str =
    "tosctl.agent-account.relay-transaction-component-absence-proof-verification.v1";
const DUAL_ABSENCE_PROOF_BUNDLE_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-proof-bundle.v1";
const ABSENCE_PROOF_BUNDLE_DOMAIN: &str = "tos.agent-relay-absence-proof-bundle.v1";
const ABSENCE_PROOF_PAYLOAD_DOMAIN: &str = "tos.agent-relay-absence-proof-payload.v1";
const ABSENCE_PROOF_PROFILE_URI: &str = "tos.relay-absence.tosctl-rpc-snapshot.v1";
const ABSENCE_PROOF_PROFILE_DOMAIN: &str = "tos.agent-relay-absence-proof-profile.v1";
const ABSENCE_PROOF_PROFILE_DIGEST: &str =
    "sha256:f13a22b086f91309ac9ea9abad1d9dcf005e2d7a8818637cb7350734af8c2216";
const DUAL_ABSENCE_OBSERVATION_DOMAIN: &str = "tos.agent-relay-absence-observation.v1";
const ABSENCE_REFERENCE_DOMAIN: &str = "tos.agent-relay-absence-observation-reference.v1";
const RELAY_EXECUTION_REQUEST_DOMAIN: &str = "tos.agent-relay-execution-request.v1";
const RELAY_QUOTE_REQUEST_DOMAIN: &str = "tos.agent-relay-quote-request.v1";
const RELAY_TRANSACTION_PROFILE_DOMAIN: &str = "tos.agent-relay-transaction-profile.v1";
const RELAY_TRANSACTION_INTENT_DOMAIN: &str =
    "tos.agent-relay-transaction-intent.agent-account-native-send.v1";
const RELAY_TRANSACTION_PROFILE_URI: &str = "tos.transaction.agent-account-native-send.v1";
const RELAY_CORROBORATED_TERMINAL_PROFILE_URI: &str = "tos.relay.provider-corroborated-terminal.v1";

#[derive(clap::Args, Clone)]
#[command(
    about = "Aggregate exact dual-absence evidence from an existing sponsorship custody tombstone and a frozen Provider RPC snapshot (query-only; no custody or chain write)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipDualAbsenceCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable sponsorship action ID")]
    stable_action_id: String,
    #[arg(long = "agreement-payment-request-cbor")]
    agreement_payment_request_cbor: String,
    #[arg(long = "relay-execution-request-cbor")]
    relay_execution_request_cbor: String,
    #[arg(long = "sponsorship-terminal-profile-cbor")]
    sponsorship_terminal_profile_cbor: String,
    #[arg(long = "relay-finality-profile-cbor")]
    relay_finality_profile_cbor: Option<String>,
    #[arg(long = "corroboration-snapshot")]
    corroboration_snapshot: String,
    #[arg(long)]
    corroboration_snapshot_identity: String,
    #[arg(long)]
    sponsorship_release_profile_digest: String,
    #[arg(
        long = "existing-sponsorship-proof-bundle-cbor",
        help = "Exact prior sponsorship-only proof wrapper; required only for dual aggregation"
    )]
    existing_sponsorship_proof_bundle_cbor: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Produce exact sponsorship-component absence evidence from a frozen Provider RPC snapshot (query plus custody terminalization)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipComponentAbsenceCmd {
    #[command(flatten)]
    input: AgentAccountEconomicPaymentSponsorshipDualAbsenceCmd,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Produce exact client-transaction component absence evidence from an owner-frozen RPC snapshot (query-only)"
)]
pub struct AgentAccountEconomicPaymentRelayTransactionComponentAbsenceCmd {
    #[arg(long = "agreement-payment-request-cbor")]
    agreement_payment_request_cbor: String,
    #[arg(long = "relay-execution-request-cbor")]
    relay_execution_request_cbor: String,
    #[arg(long = "sponsorship-terminal-profile-cbor")]
    sponsorship_terminal_profile_cbor: String,
    #[arg(long = "relay-finality-profile-cbor")]
    relay_finality_profile_cbor: Option<String>,
    #[arg(long = "corroboration-snapshot")]
    corroboration_snapshot: String,
    #[arg(long)]
    corroboration_snapshot_identity: String,
    #[arg(long)]
    sponsorship_release_profile_digest: String,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Independently re-query a Provider dual-absence proof from a client-owned frozen RPC snapshot (query-only)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd {
    #[arg(long = "proof-bundle-cbor")]
    proof_bundle_cbor: String,
    #[arg(long = "agreement-payment-request-cbor")]
    agreement_payment_request_cbor: String,
    #[arg(long = "relay-execution-request-cbor")]
    relay_execution_request_cbor: String,
    #[arg(long = "sponsorship-terminal-profile-cbor")]
    sponsorship_terminal_profile_cbor: String,
    #[arg(long = "relay-finality-profile-cbor")]
    relay_finality_profile_cbor: Option<String>,
    #[arg(long = "corroboration-snapshot")]
    corroboration_snapshot: String,
    #[arg(long)]
    corroboration_snapshot_identity: String,
    #[arg(long)]
    sponsorship_release_profile_digest: String,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Independently re-query a Provider sponsorship-component absence proof (query-only)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipComponentAbsenceProofVerifyCmd {
    #[command(flatten)]
    input: AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Independently re-query a Provider client-transaction-component absence proof (query-only)"
)]
pub struct AgentAccountEconomicPaymentRelayTransactionComponentAbsenceProofVerifyCmd {
    #[command(flatten)]
    input: AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Preflight one exact lower-assurance sponsorship dual-absence tuple (query-only)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipDualAbsenceCapabilityCmd {
    #[arg(long, value_parser = ["sponsor_only", "sponsor_and_relay"])]
    mode: String,
    #[arg(long, value_parser = ["trusted-local", "authorized-single-provider"])]
    assurance_level: String,
    #[arg(long, default_value = "payment.direct")]
    underlying_action_kind: String,
    #[arg(long, default_value = RELAY_TRANSACTION_PROFILE_URI)]
    transaction_profile_uri: String,
    #[arg(long)]
    transaction_profile_digest: String,
    #[arg(long, default_value = "observed_unproven")]
    sponsorship_release_evidence_class: String,
    #[arg(long, default_value = ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI)]
    sponsorship_release_profile_uri: String,
    #[arg(long)]
    sponsorship_release_profile_digest: String,
    #[arg(long, default_value = "client_corroborated")]
    sponsorship_terminal_evidence_class: String,
    #[arg(long = "sponsorship-terminal-profile-cbor")]
    sponsorship_terminal_profile_cbor: String,
    #[arg(long)]
    relay_terminal_evidence_class: Option<String>,
    #[arg(long = "relay-finality-profile-cbor")]
    relay_finality_profile_cbor: Option<String>,
    #[arg(long = "corroboration-snapshot")]
    corroboration_snapshot: String,
    #[arg(long)]
    corroboration_snapshot_identity: String,
    #[arg(long, value_parser = ["producer", "verifier"])]
    role: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RelayAbsenceObservationReferenceV1 {
    schema_version: u16,
    observation_kind: String,
    conclusion: String,
    provider_agent_id: String,
    network_digest: String,
    relay_stable_action_id: String,
    relay_exact_request_digest: String,
    relay_execution_request_digest: String,
    sponsorship_stable_action_id: String,
    sponsorship_exact_request_digest: String,
    sponsorship_valid_until_unix: u64,
    signed_transaction_digest: String,
    signed_transaction_cell_hash: String,
    terminal_profile_uri: String,
    terminal_profile_digest: String,
    terminal_evidence_class: String,
    finalized_checkpoint_id: String,
    finalized_checkpoint_sequence: u64,
    finalized_checkpoint_unix: u64,
    observer_id: String,
    operator_domain_id: String,
    observation_evidence_profile_uri: String,
    observation_evidence_profile_digest: String,
    observation_digest: String,
    observed_at_unix: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DualAbsenceRawObservationV1 {
    schema_version: u16,
    observation_kind: String,
    conclusion: String,
    observer_id: String,
    operator_domain_id: String,
    provider_agent_id: String,
    network_digest: String,
    relay_stable_action_id: String,
    relay_exact_request_digest: String,
    relay_execution_request_digest: String,
    sponsorship_stable_action_id: String,
    sponsorship_exact_request_digest: String,
    sponsorship_valid_until_unix: u64,
    signed_transaction_digest: String,
    signed_transaction_cell_hash: String,
    transaction_valid_until_unix: u64,
    terminal_profile_uri: String,
    terminal_profile_digest: String,
    terminal_evidence_class: String,
    checkpoint_id: String,
    checkpoint_sequence: u64,
    checkpoint_unix: u64,
    source_account: String,
    source_effect_digest: String,
    source_effect_cell_hash: String,
    source_effect_valid_until_unix: u64,
    signed_controller_epoch: u64,
    signed_source_sequence: u64,
    checkpoint_controller_epoch: u64,
    checkpoint_source_sequence: u64,
    checkpoint_deployment_id: String,
    exact_message_observed_executed: bool,
    history_complete_when_required: bool,
    history_transactions_inspected: u32,
    invalidation_reason: String,
    observation_evidence_profile_uri: String,
    observation_evidence_profile_digest: String,
    observed_at_unix: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DualAbsenceProofBundleV1 {
    schema: String,
    proof_scope: String,
    provider_snapshot_identity: String,
    evidence_profile_uri: String,
    evidence_profile_digest: String,
    evidence_profile: serde_json::Value,
    network_domain: RelayNetworkDomainPin,
    network_digest: String,
    agreement_payment_request: SponsorshipAgreementPaymentRequestV3,
    agreement_payment_request_digest: String,
    sponsorship_stable_action_id: String,
    sponsorship_exact_request_digest: String,
    sponsorship_valid_until_unix: u64,
    signed_top_up_transaction_boc: String,
    signed_top_up_transaction_digest: String,
    signed_top_up_transaction_cell_hash: String,
    provider_sponsor_source_account: String,
    provider_sponsor_source_sequence: u64,
    relay_execution_request_digest: String,
    relay_stable_action_id: String,
    relay_exact_request_digest: String,
    provider_agent_id: String,
    mode: String,
    assurance_level: String,
    signed_transaction_digest: String,
    signed_transaction_cell_hash: String,
    signed_transaction_source_account: String,
    signed_transaction_source_sequence: u64,
    transaction_valid_until_unix: u64,
    sponsorship_terminal_profile: SponsorshipFinalityProfile,
    relay_finality_profile: Option<SponsorshipFinalityProfile>,
    outcome: String,
    sponsorship_observations: Vec<DualAbsenceRawObservationV1>,
    transaction_observations: Vec<DualAbsenceRawObservationV1>,
    sponsorship_absence_observations: Vec<RelayAbsenceObservationReferenceV1>,
    transaction_absence_observations: Vec<RelayAbsenceObservationReferenceV1>,
    evidence_set_digest: String,
    produced_at_unix: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayAbsenceProofBundleV1 {
    schema_version: u16,
    proof_scope: String,
    proof_profile_uri: String,
    proof_profile_digest: String,
    proof_payload_digest: String,
    proof_payload: String,
    sponsorship_absence_observations: Vec<RelayAbsenceObservationReferenceV1>,
    transaction_absence_observations: Vec<RelayAbsenceObservationReferenceV1>,
}

#[derive(Clone, Debug)]
struct ParsedNativeSend {
    source_account: String,
    global_id: i32,
    controller_epoch: u64,
    source_sequence: u32,
    valid_until: u32,
    destination: String,
    value_atomic: u64,
    digest: String,
    cell_hash: String,
}

#[derive(Clone, Debug)]
struct RelayAbsenceContext {
    network: RelayNetworkDomainPin,
    network_digest: String,
    provider_agent_id: String,
    requester_agent_id: String,
    mode: String,
    assurance_level: String,
    relay_stable_action_id: String,
    relay_exact_request_digest: String,
    relay_execution_digest: String,
    signed_transaction: ParsedNativeSend,
    sponsorship_stable_action_id: String,
    sponsorship_exact_request_digest: String,
    sponsorship_valid_until_unix: u64,
    sponsorship_terminal_profile: SponsorshipFinalityProfile,
    relay_finality_profile: Option<SponsorshipFinalityProfile>,
}

#[derive(Clone)]
struct CommonCheckpoint {
    id: String,
    block: BlockIdExt,
    unix: u32,
}

#[derive(Clone)]
struct CheckpointMember {
    member: LoadedEconomicPaymentCorroborationMember,
    rpc: Arc<ClientJsonRpc>,
}

#[derive(Clone, Debug)]
struct AbsenceEvidenceSet {
    conclusion: String,
    raw: Vec<DualAbsenceRawObservationV1>,
    references: Vec<RelayAbsenceObservationReferenceV1>,
    reference_digests: Vec<String>,
}

#[derive(Clone, Debug)]
enum DualAbsenceQuery<T> {
    Terminal(T),
    NotMature(String),
    TemporarilyUnavailable(String),
}

fn object<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> anyhow::Result<&'a serde_json::Map<String, serde_json::Value>> {
    value.as_object().with_context(|| format!("{name} must be an object"))
}

fn member<'a>(
    value: &'a serde_json::Value,
    key: &str,
    name: &str,
) -> anyhow::Result<&'a serde_json::Value> {
    object(value, name)?.get(key).with_context(|| format!("{name}.{key} is missing"))
}

fn text_member<'a>(value: &'a serde_json::Value, key: &str, name: &str) -> anyhow::Result<&'a str> {
    member(value, key, name)?.as_str().with_context(|| format!("{name}.{key} must be a string"))
}

fn u64_member(value: &serde_json::Value, key: &str, name: &str) -> anyhow::Result<u64> {
    member(value, key, name)?
        .as_u64()
        .with_context(|| format!("{name}.{key} must be an unsigned integer"))
}

fn require_exact_keys(
    value: &serde_json::Value,
    name: &str,
    required: &[&str],
    optional: &[&str],
) -> anyhow::Result<()> {
    let value = object(value, name)?;
    for key in required {
        if !value.contains_key(*key) {
            anyhow::bail!("{name}.{key} is missing");
        }
    }
    let allowed = required.iter().chain(optional.iter()).copied().collect::<BTreeSet<_>>();
    if let Some(key) = value.keys().find(|key| !allowed.contains(key.as_str())) {
        anyhow::bail!("{name} contains unknown field {key:?}");
    }
    Ok(())
}

fn decode_exact_protocol_cbor_bytes(bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
    if bytes.is_empty() || bytes.len() > 1 << 20 {
        anyhow::bail!("canonical protocol CBOR has invalid size");
    }
    let mut cursor = Cursor::new(bytes);
    let value: ciborium::Value = ciborium::de::from_reader(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        anyhow::bail!("canonical protocol CBOR contains trailing bytes");
    }
    let value = cbor_value_to_protocol_json(value)?;
    let mut canonical = Vec::new();
    encode_protocol_json_cbor(&value, &mut canonical, 0)?;
    if canonical != bytes {
        anyhow::bail!("protocol CBOR is not the exact Core Deterministic representation");
    }
    Ok(value)
}

fn protocol_value_digest(domain: &str, value: &serde_json::Value) -> anyhow::Result<String> {
    let mut encoded = Vec::new();
    encode_protocol_json_cbor(value, &mut encoded, 0)?;
    protocol_cbor_digest(domain, &encoded)
}

fn absence_proof_profile_digest() -> anyhow::Result<String> {
    let digest = protocol_value_digest(
        ABSENCE_PROOF_PROFILE_DOMAIN,
        &serde_json::json!({
            "schema_version": 1u16,
            "profile_uri": ABSENCE_PROOF_PROFILE_URI,
            "independent_snapshot_query": true,
            "maximum_bundle_bytes": 128u32 << 10,
            "chain_side_effect": false,
        }),
    )?;
    if digest != ABSENCE_PROOF_PROFILE_DIGEST {
        anyhow::bail!("released absence proof-profile vector drifted");
    }
    Ok(digest)
}

fn wrap_absence_proof_payload(
    proof_scope: &str,
    payload_cbor: &[u8],
    sponsorship: &[RelayAbsenceObservationReferenceV1],
    transaction: &[RelayAbsenceObservationReferenceV1],
) -> anyhow::Result<(RelayAbsenceProofBundleV1, Vec<u8>, String)> {
    if payload_cbor.is_empty() || payload_cbor.len() > 128 << 10 {
        anyhow::bail!("absence proof payload exceeds its released bound");
    }
    let payload_digest = protocol_cbor_digest(ABSENCE_PROOF_PAYLOAD_DOMAIN, payload_cbor)?;
    let bundle = RelayAbsenceProofBundleV1 {
        schema_version: 1,
        proof_scope: proof_scope.to_owned(),
        proof_profile_uri: ABSENCE_PROOF_PROFILE_URI.to_owned(),
        proof_profile_digest: absence_proof_profile_digest()?,
        proof_payload_digest: payload_digest,
        proof_payload: base64::engine::general_purpose::STANDARD.encode(payload_cbor),
        sponsorship_absence_observations: sponsorship.to_vec(),
        transaction_absence_observations: transaction.to_vec(),
    };
    let value = serde_json::to_value(&bundle)?;
    let mut cbor = Vec::new();
    encode_protocol_json_cbor(&value, &mut cbor, 0)?;
    if cbor.len() > 128 << 10 {
        anyhow::bail!("absence proof bundle exceeds its released 128 KiB bound");
    }
    let digest = protocol_cbor_digest(ABSENCE_PROOF_BUNDLE_DOMAIN, &cbor)?;
    Ok((bundle, cbor, digest))
}

fn decode_absence_proof_bundle(
    path: &Path,
    expected_scope: &str,
) -> anyhow::Result<(RelayAbsenceProofBundleV1, DualAbsenceProofBundleV1, Vec<u8>, String)> {
    let (wrapper_cbor, wrapper_value) = decode_exact_protocol_cbor(path)?;
    if wrapper_cbor.len() > 128 << 10 {
        anyhow::bail!("absence proof wrapper exceeds the released 128 KiB bound");
    }
    let wrapper: RelayAbsenceProofBundleV1 = serde_json::from_value(wrapper_value)
        .context("decode generic relay absence proof wrapper")?;
    if wrapper.schema_version != 1
        || wrapper.proof_scope != expected_scope
        || wrapper.proof_profile_uri != ABSENCE_PROOF_PROFILE_URI
        || wrapper.proof_profile_digest != absence_proof_profile_digest()?
    {
        anyhow::bail!("absence proof wrapper selects an unsupported profile or scope");
    }
    let payload_cbor = base64::engine::general_purpose::STANDARD
        .decode(&wrapper.proof_payload)
        .context("decode canonical absence proof payload")?;
    if base64::engine::general_purpose::STANDARD.encode(&payload_cbor) != wrapper.proof_payload
        || protocol_cbor_digest(ABSENCE_PROOF_PAYLOAD_DOMAIN, &payload_cbor)?
            != wrapper.proof_payload_digest
    {
        anyhow::bail!("absence proof payload is not canonical or digest-bound");
    }
    let payload_value = decode_exact_protocol_cbor_bytes(&payload_cbor)?;
    let payload: DualAbsenceProofBundleV1 = serde_json::from_value(payload_value)
        .context("decode exact tosctl absence proof payload")?;
    if payload.proof_scope != expected_scope
        || wrapper.sponsorship_absence_observations != payload.sponsorship_absence_observations
        || wrapper.transaction_absence_observations != payload.transaction_absence_observations
    {
        anyhow::bail!("absence proof wrapper conflicts with its exact typed payload");
    }
    let digest = protocol_cbor_digest(ABSENCE_PROOF_BUNDLE_DOMAIN, &wrapper_cbor)?;
    Ok((wrapper, payload, wrapper_cbor, digest))
}

fn released_transaction_profile_digest() -> anyhow::Result<String> {
    protocol_value_digest(
        RELAY_TRANSACTION_PROFILE_DOMAIN,
        &serde_json::json!({
            "profile_uri": RELAY_TRANSACTION_PROFILE_URI,
            "opcode": contracts::agent_account::AGENT_NATIVE_SEND_OPCODE,
            "maximum_signed_bytes": 64u32 << 10,
            "inspectable_source_sequence": true,
            "inspectable_transaction_expiry": true,
            "canonical_boc_required": true,
        }),
    )
}

fn parse_agent_account_native_send(bytes: &[u8]) -> anyhow::Result<ParsedNativeSend> {
    if bytes.is_empty() || bytes.len() > 64 << 10 {
        anyhow::bail!("signed client transaction has invalid size");
    }
    validate_exact_boc_before_broadcast(bytes)
        .context("signed client transaction failed the shared exact-BOC gate")?;
    let root = read_single_root_boc(bytes)?;
    if write_boc(&root)? != bytes {
        anyhow::bail!("signed client transaction BOC is not canonically serialized");
    }
    let message = Message::construct_from_cell(root.clone())
        .context("decode signed client Agent Account transaction")?;
    let header = message
        .ext_in_header()
        .context("signed client transaction is not an external inbound message")?;
    let source_account = header.dst.to_string();
    let mut body = message.body().cloned().context("signed client transaction has no body")?;
    body.move_by(512).context("signed client transaction has a truncated controller signature")?;
    let opcode = body.get_next_u32()?;
    let global_id = body.get_next_i32()?;
    let controller_epoch = body.get_next_u64()?;
    let source_sequence = body.get_next_u32()?;
    let valid_until = body.get_next_u32()?;
    let destination = MsgAddressInt::construct_from(&mut body)
        .context("signed client transaction has an invalid destination")?
        .to_string();
    let value_atomic_u128 = Coins::construct_from(&mut body)?.as_u128();
    let value_atomic = u64::try_from(value_atomic_u128)
        .context("signed client transaction amount does not fit the released profile")?;
    if opcode != contracts::agent_account::AGENT_NATIVE_SEND_OPCODE
        || value_atomic == 0
        || body.remaining_bits() != 0
        || body.remaining_references() != 0
    {
        anyhow::bail!(
            "signed client transaction is not the released Agent Account native-send profile"
        );
    }
    Ok(ParsedNativeSend {
        source_account,
        global_id,
        controller_epoch,
        source_sequence,
        valid_until,
        destination,
        value_atomic,
        digest: canonical_file_digest(bytes),
        cell_hash: format!("tvm-cell-sha256:{}", hex::encode(root.hash(0))),
    })
}

fn transaction_intent_digest(
    network_digest: &str,
    transaction: &ParsedNativeSend,
) -> anyhow::Result<String> {
    protocol_value_digest(
        RELAY_TRANSACTION_INTENT_DOMAIN,
        &serde_json::json!({
            "schema_version": 1,
            "network_digest": network_digest,
            "source_account": transaction.source_account,
            "controller_epoch": transaction.controller_epoch,
            "source_sequence": transaction.source_sequence,
            "valid_until_unix": transaction.valid_until,
            "destination": transaction.destination,
            "value_atomic": transaction.value_atomic.to_string(),
        }),
    )
}

fn relay_execution_projection(value: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    require_exact_keys(
        value,
        "RelayExecutionRequestV1",
        &[
            "schema_version",
            "quote_request",
            "provider_quote",
            "signed_transaction_bytes",
            "agreement_body_digest",
            "agreement_expires_at_unix",
            "fee_obligation_ids",
            "underlying_action_request",
            "semantic_fields",
            "authorized_action",
            "writer_fence",
            "admission_receipt",
            "created_at_unix",
            "expires_at_unix",
        ],
        &["relay_obligation_id", "sponsorship_obligation_id"],
    )?;
    let root = object(value, "RelayExecutionRequestV1")?;
    let mut projection = serde_json::Map::new();
    for key in [
        "schema_version",
        "quote_request",
        "provider_quote",
        "signed_transaction_bytes",
        "agreement_body_digest",
        "agreement_expires_at_unix",
        "fee_obligation_ids",
        "underlying_action_request",
        "semantic_fields",
        "created_at_unix",
        "expires_at_unix",
    ] {
        projection.insert(key.to_owned(), root.get(key).expect("required key").clone());
    }
    for key in ["relay_obligation_id", "sponsorship_obligation_id"] {
        if let Some(value) =
            root.get(key).filter(|value| value.as_str().is_some_and(|v| !v.is_empty()))
        {
            projection.insert(key.to_owned(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(projection))
}

fn validate_lower_finality_profile(
    profile: &SponsorshipFinalityProfile,
    profile_kind: &str,
    available_members: usize,
) -> anyhow::Result<()> {
    let (uri, evidence_class) = match profile_kind {
        "sponsorship" => (SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI, "client_corroborated"),
        "relay" => (RELAY_CORROBORATED_TERMINAL_PROFILE_URI, "provider_corroborated"),
        _ => anyhow::bail!("unknown terminal profile kind"),
    };
    if profile.profile_uri != uri
        || profile.terminal_evidence_class != evidence_class
        || validate_sha256_digest("terminal_profile.profile_digest", &profile.profile_digest)
            .is_err()
        || profile.minimum_confirmation_depth != 1
        || profile.minimum_observers == 0
        || profile.minimum_operator_domains == 0
        || profile.minimum_operator_domains > profile.minimum_observers
        || usize::from(profile.minimum_observers) > available_members
        || usize::from(profile.minimum_operator_domains) > available_members
        || profile.maximum_resolution_seconds == 0
        || profile.maximum_resolution_seconds > 24 * 60 * 60
        || profile.reorg_window_seconds > profile.maximum_resolution_seconds
    {
        anyhow::bail!("selected {profile_kind} terminal predicate is invalid or unsupported");
    }
    Ok(())
}

fn decode_selected_profile(
    path: &str,
    name: &str,
) -> anyhow::Result<(Vec<u8>, serde_json::Value, SponsorshipFinalityProfile)> {
    let (bytes, value) = decode_exact_protocol_cbor(Path::new(path))?;
    let profile = serde_json::from_value(value.clone())
        .with_context(|| format!("decode exact selected {name} FinalityProfile"))?;
    Ok((bytes, value, profile))
}

fn validate_sponsorship_payment_against_execution(
    payment: &SponsorshipAgreementPaymentRequestV3,
    context: &RelayAbsenceContext,
    execution: &serde_json::Value,
) -> anyhow::Result<()> {
    let agreement_body_digest =
        text_member(execution, "agreement_body_digest", "RelayExecutionRequestV1")?;
    let sponsorship_obligation_id =
        text_member(execution, "sponsorship_obligation_id", "RelayExecutionRequestV1")?;
    let destination = base64::engine::general_purpose::STANDARD
        .decode(&payment.destination)
        .context("decode sponsorship AgreementPaymentRequestV3 destination")?;
    if base64::engine::general_purpose::STANDARD.encode(&destination) != payment.destination {
        anyhow::bail!("sponsorship AgreementPaymentRequestV3 destination is not canonical base64");
    }
    let destination = String::from_utf8(destination)
        .context("sponsorship AgreementPaymentRequestV3 destination is not UTF-8")?;
    let provider_quote = member(execution, "provider_quote", "RelayExecutionRequestV1")?;
    let provider_body = member(provider_quote, "body", "SignedProviderRelayQuote")?;
    let reserved = member(provider_body, "reserved_sponsorship", "ProviderRelayQuoteBodyV1")?;
    let reserved_amount = text_member(reserved, "amount_atomic", "reserved_sponsorship")?;
    let reserved_asset = member(reserved, "asset", "reserved_sponsorship")?;
    let amount = payment.amount.amount_atomic.parse::<u64>()?;
    if amount == 0
        || amount.to_string() != payment.amount.amount_atomic
        || payment.schema_version != 3
        || payment.settlement_adapter_uri != "tos.payment.direct.v1"
        || !payment.semantic_action_kind.is_empty()
        || !payment.adapter_profile_digest.is_empty()
        || !payment.external_system_id.is_empty()
        || payment.agreement_body_digest != agreement_body_digest
        || payment.agreement_obligation_id != sponsorship_obligation_id
        || payment.agent_id != context.provider_agent_id
        || payment.payer_agent_id != context.provider_agent_id
        || payment.payee_agent_id != context.requester_agent_id
        || payment.network_id != context.network.network_id
        || payment.network_domain_digest != context.network_digest
        || destination != context.signed_transaction.source_account
        || payment.amount.asset_namespace != "tos.native"
        || payment.amount.asset_identifier != context.network.network_id
        || payment.amount.unit != "nanotos"
        || reserved_amount != payment.amount.amount_atomic
        || text_member(reserved_asset, "asset_namespace", "reserved_sponsorship.asset")?
            != payment.amount.asset_namespace
        || text_member(reserved_asset, "asset_identifier", "reserved_sponsorship.asset")?
            != payment.amount.asset_identifier
        || text_member(reserved_asset, "unit", "reserved_sponsorship.asset")? != payment.amount.unit
    {
        anyhow::bail!(
            "sponsorship AgreementPaymentRequestV3 conflicts with the exact relay execution"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_relay_absence_context(
    execution_path: &str,
    sponsorship_payment: &SponsorshipAgreementPaymentRequestV3,
    sponsorship_stable_action_id: &str,
    sponsorship_exact_request_digest: &str,
    sponsorship_profile_value: &serde_json::Value,
    sponsorship_profile: SponsorshipFinalityProfile,
    relay_profile_value: Option<&serde_json::Value>,
    relay_profile: Option<SponsorshipFinalityProfile>,
) -> anyhow::Result<(Vec<u8>, serde_json::Value, RelayAbsenceContext)> {
    let (execution_bytes, execution) = decode_exact_protocol_cbor(Path::new(execution_path))?;
    let execution_projection = relay_execution_projection(&execution)?;
    let relay_execution_digest =
        protocol_value_digest(RELAY_EXECUTION_REQUEST_DOMAIN, &execution_projection)?;
    let quote_request = member(&execution, "quote_request", "RelayExecutionRequestV1")?;
    let quote_body = member(quote_request, "body", "SignedRelayQuoteRequest")?;
    let provider_quote = member(&execution, "provider_quote", "RelayExecutionRequestV1")?;
    let provider_body = member(provider_quote, "body", "SignedProviderRelayQuote")?;
    let authorized_action = member(&execution, "authorized_action", "RelayExecutionRequestV1")?;

    let network: RelayNetworkDomainPin =
        serde_json::from_value(member(quote_body, "network", "RelayQuoteRequestBodyV1")?.clone())?;
    let network_digest = relay_network_domain_digest(&network)?;
    let signed_transaction_text =
        text_member(&execution, "signed_transaction_bytes", "RelayExecutionRequestV1")?;
    let signed_transaction_bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_transaction_text)
        .context("decode exact signed client transaction")?;
    if base64::engine::general_purpose::STANDARD.encode(&signed_transaction_bytes)
        != signed_transaction_text
    {
        anyhow::bail!("signed client transaction does not use canonical base64");
    }
    let signed_transaction = parse_agent_account_native_send(&signed_transaction_bytes)?;
    let mode = text_member(quote_body, "mode", "RelayQuoteRequestBodyV1")?.to_owned();
    let assurance_level =
        text_member(quote_body, "assurance_level", "RelayQuoteRequestBodyV1")?.to_owned();
    let provider_agent_id =
        text_member(quote_body, "provider_agent_id", "RelayQuoteRequestBodyV1")?.to_owned();
    let requester_agent_id =
        text_member(quote_body, "requester_agent_id", "RelayQuoteRequestBodyV1")?.to_owned();
    let relay_stable_action_id =
        text_member(quote_body, "stable_action_id", "RelayQuoteRequestBodyV1")?.to_owned();
    let relay_exact_request_digest =
        text_member(quote_body, "exact_request_digest", "RelayQuoteRequestBodyV1")?.to_owned();
    let transaction_profile_digest = released_transaction_profile_digest()?;
    let transaction_intent_digest =
        transaction_intent_digest(&network_digest, &signed_transaction)?;

    let quote_request_digest = protocol_value_digest(RELAY_QUOTE_REQUEST_DOMAIN, quote_body)?;
    let underlying_action_cbor = base64::engine::general_purpose::STANDARD
        .decode(text_member(&execution, "underlying_action_request", "RelayExecutionRequestV1")?)
        .context("decode underlying payment.direct request")?;
    let underlying_action = decode_exact_protocol_cbor_bytes(&underlying_action_cbor)?;
    let underlying_payment: SponsorshipAgreementPaymentRequestV3 =
        serde_json::from_value(underlying_action)
            .context("decode underlying AgreementPaymentRequestV3")?;
    let underlying_destination =
        base64::engine::general_purpose::STANDARD.decode(&underlying_payment.destination)?;
    if base64::engine::general_purpose::STANDARD.encode(&underlying_destination)
        != underlying_payment.destination
    {
        anyhow::bail!("underlying payment destination is not canonical base64");
    }
    let underlying_destination = String::from_utf8(underlying_destination)?;
    let underlying_amount = underlying_payment.amount.amount_atomic.parse::<u64>()?;
    let exact_underlying_request_digest =
        exact_protocol_action_request_digest(&underlying_action_cbor)?;

    let provider_sponsorship_profile =
        member(provider_body, "sponsorship_terminal_profile", "ProviderRelayQuoteBodyV1")?;
    let quote_sponsorship_profile_uri =
        text_member(quote_body, "sponsorship_terminal_profile_uri", "RelayQuoteRequestBodyV1")?;
    let quote_sponsorship_profile_digest =
        text_member(quote_body, "sponsorship_terminal_profile_digest", "RelayQuoteRequestBodyV1")?;
    let expected_relay_profile_value = match mode.as_str() {
        "sponsor_only" => {
            if relay_profile.is_some()
                || relay_profile_value.is_some()
                || object(provider_body, "ProviderRelayQuoteBodyV1")?
                    .contains_key("relay_finality_profile")
            {
                anyhow::bail!("sponsor_only must not select a relay finality profile");
            }
            None
        }
        "sponsor_and_relay" => Some(
            relay_profile_value.context("sponsor_and_relay requires a relay FinalityProfile")?,
        ),
        _ => anyhow::bail!("dual absence is valid only for sponsorship relay modes"),
    };
    if assurance_level == "autonomous-decentralized"
        || (assurance_level != "trusted-local" && assurance_level != "authorized-single-provider")
        || text_member(provider_body, "mode", "ProviderRelayQuoteBodyV1")? != mode
        || text_member(provider_body, "assurance_level", "ProviderRelayQuoteBodyV1")?
            != assurance_level
        || text_member(provider_body, "provider_agent_id", "ProviderRelayQuoteBodyV1")?
            != provider_agent_id
        || text_member(provider_body, "quote_request_digest", "ProviderRelayQuoteBodyV1")?
            != quote_request_digest
        || provider_sponsorship_profile != sponsorship_profile_value
        || quote_sponsorship_profile_uri != sponsorship_profile.profile_uri
        || quote_sponsorship_profile_digest != sponsorship_profile.profile_digest
        || text_member(
            quote_body,
            "sponsorship_terminal_evidence_class",
            "RelayQuoteRequestBodyV1",
        )? != "client_corroborated"
        || text_member(
            provider_body,
            "sponsorship_terminal_evidence_class",
            "ProviderRelayQuoteBodyV1",
        )? != "client_corroborated"
        || network.global_id != signed_transaction.global_id
        || text_member(quote_body, "source_account", "RelayQuoteRequestBodyV1")?
            != signed_transaction.source_account
        || text_member(quote_body, "transaction_profile_uri", "RelayQuoteRequestBodyV1")?
            != RELAY_TRANSACTION_PROFILE_URI
        || text_member(quote_body, "transaction_profile_digest", "RelayQuoteRequestBodyV1")?
            != transaction_profile_digest
        || text_member(quote_body, "underlying_action_kind", "RelayQuoteRequestBodyV1")?
            != "payment.direct"
        || text_member(quote_body, "signed_transaction_digest", "RelayQuoteRequestBodyV1")?
            != signed_transaction.digest
        || text_member(quote_body, "signed_transaction_cell_hash", "RelayQuoteRequestBodyV1")?
            != signed_transaction.cell_hash
        || u64_member(quote_body, "signed_transaction_size", "RelayQuoteRequestBodyV1")?
            != signed_transaction_bytes.len() as u64
        || u64_member(quote_body, "source_sequence", "RelayQuoteRequestBodyV1")?
            != u64::from(signed_transaction.source_sequence)
        || u64_member(quote_body, "transaction_valid_until_unix", "RelayQuoteRequestBodyV1")?
            != u64::from(signed_transaction.valid_until)
        || text_member(quote_body, "transaction_intent_digest", "RelayQuoteRequestBodyV1")?
            != transaction_intent_digest
        || text_member(authorized_action, "action_kind", "AuthorizedActionV1")? != "payment.direct"
        || text_member(authorized_action, "stable_action_id", "AuthorizedActionV1")?
            != relay_stable_action_id
        || text_member(authorized_action, "exact_request_digest", "AuthorizedActionV1")?
            != relay_exact_request_digest
        || exact_underlying_request_digest != relay_exact_request_digest
        || underlying_payment.schema_version != 3
        || underlying_payment.stable_action_id != relay_stable_action_id
        || underlying_payment.agent_id != requester_agent_id
        || underlying_payment.network_id != network.network_id
        || underlying_payment.network_domain_digest != network_digest
        || underlying_payment.settlement_adapter_uri != "tos.payment.direct.v1"
        || underlying_destination != signed_transaction.destination
        || underlying_amount != signed_transaction.value_atomic
        || underlying_payment.amount.asset_namespace != "tos.native"
        || underlying_payment.amount.asset_identifier != network.network_id
        || underlying_payment.amount.unit != "nanotos"
        || underlying_payment.expires_at_unix < u64::from(signed_transaction.valid_until)
    {
        anyhow::bail!("RelayExecutionRequest conflicts with the released TOS native-send profile");
    }
    if let Some(expected) = expected_relay_profile_value {
        let provider = member(provider_body, "relay_finality_profile", "ProviderRelayQuoteBodyV1")?;
        let relay = relay_profile.as_ref().expect("checked relay profile");
        if provider != expected
            || text_member(quote_body, "relay_finality_profile_uri", "RelayQuoteRequestBodyV1")?
                != relay.profile_uri
            || text_member(quote_body, "relay_finality_profile_digest", "RelayQuoteRequestBodyV1")?
                != relay.profile_digest
            || text_member(quote_body, "relay_terminal_evidence_class", "RelayQuoteRequestBodyV1")?
                != "provider_corroborated"
            || text_member(
                provider_body,
                "relay_terminal_evidence_class",
                "ProviderRelayQuoteBodyV1",
            )? != "provider_corroborated"
        {
            anyhow::bail!("RelayExecutionRequest changes the selected relay terminal predicate");
        }
    }
    validate_sha256_digest("relay stable action", &relay_stable_action_id)?;
    validate_sha256_digest("relay exact request", &relay_exact_request_digest)?;
    validate_sha256_digest("relay execution digest", &relay_execution_digest)?;
    validate_sha256_digest("sponsorship stable action", sponsorship_stable_action_id)?;
    validate_sha256_digest("sponsorship exact request", sponsorship_exact_request_digest)?;

    let context = RelayAbsenceContext {
        network,
        network_digest,
        provider_agent_id,
        requester_agent_id,
        mode,
        assurance_level,
        relay_stable_action_id,
        relay_exact_request_digest,
        relay_execution_digest,
        signed_transaction,
        sponsorship_stable_action_id: sponsorship_stable_action_id.to_owned(),
        sponsorship_exact_request_digest: sponsorship_exact_request_digest.to_owned(),
        sponsorship_valid_until_unix: sponsorship_payment.expires_at_unix,
        sponsorship_terminal_profile: sponsorship_profile,
        relay_finality_profile: relay_profile,
    };
    validate_sponsorship_payment_against_execution(sponsorship_payment, &context, &execution)?;
    Ok((execution_bytes, execution, context))
}

fn block_id_equal(left: &BlockIdExt, right: &BlockIdExt) -> bool {
    left.workchain == right.workchain
        && left.shard == right.shard
        && left.seqno == right.seqno
        && left.root_hash == right.root_hash
        && left.file_hash == right.file_hash
}

fn checkpoint_id(block: &BlockIdExt) -> String {
    format!(
        "masterchain:{}:{}:{}:sha256:{}:sha256:{}",
        block.workchain,
        block.shard,
        block.seqno,
        hex::encode(&block.root_hash),
        hex::encode(&block.file_hash),
    )
}

async fn common_checkpoint(
    loaded: &[LoadedEconomicPaymentCorroborationMember],
    network: &RelayNetworkDomainPin,
    required: usize,
) -> anyhow::Result<DualAbsenceQuery<(CommonCheckpoint, Vec<CheckpointMember>)>> {
    let mut available = Vec::new();
    let mut temporary = Vec::new();
    for member in loaded {
        let rpc = match try_create_rpc_client(&member.config).await {
            Ok(rpc) => rpc,
            Err(error) => {
                temporary.push(format!("{}: {error:#}", member.endpoint));
                continue;
            }
        };
        if let Err(error) = rpc.verify_pinned_primary_network(network).await {
            let rendered = format!("{}: {error:#}", member.endpoint);
            if sponsorship_rpc_temporarily_unavailable(&rendered) {
                temporary.push(rendered);
                continue;
            }
            anyhow::bail!("frozen RPC member conflicts with the exact network domain: {rendered}");
        }
        match rpc.get_masterchain_info().await {
            Ok(head) => {
                let zero = head.init.as_ref().context("getMasterchainInfo omitted zero state")?;
                let zero_root = format!("sha256:{}", hex::encode(&zero.root_hash));
                let zero_file = format!("sha256:{}", hex::encode(&zero.file_hash));
                if zero_root != network.zero_state_root_hash
                    || zero_file != network.zero_state_file_hash
                {
                    anyhow::bail!("frozen RPC member changed the owner-pinned zero state");
                }
                available.push((member.clone(), rpc, head.last));
            }
            Err(error) => temporary.push(format!("{}: {error:#}", member.endpoint)),
        }
    }
    if available.len() < required {
        return Ok(DualAbsenceQuery::TemporarilyUnavailable(format!(
            "only {} of {} required frozen RPC members are available: {}",
            available.len(),
            required,
            temporary.join("; ")
        )));
    }
    let selected_seqno = available
        .iter()
        .map(|(_, _, head)| head.seqno)
        .min()
        .context("frozen RPC snapshot has no masterchain head")?;
    let selected_shard = available[0].2.shard;
    if available.iter().any(|(_, _, head)| {
        head.workchain != -1 || head.shard != selected_shard || head.seqno < selected_seqno
    }) {
        anyhow::bail!("frozen RPC members disagree on the masterchain namespace");
    }

    let mut checkpoint: Option<CommonCheckpoint> = None;
    let mut members = Vec::new();
    for (member, rpc, _) in available {
        let block = match rpc
            .get_block_transactions(-1, &selected_shard.to_string(), selected_seqno, 1)
            .await
        {
            Ok(value) => {
                value.id.context("getBlockTransactions omitted selected block identity")?
            }
            Err(error) => {
                temporary.push(format!("{}: {error:#}", member.endpoint));
                continue;
            }
        };
        let header =
            match rpc.get_block_header(-1, &selected_shard.to_string(), selected_seqno).await {
                Ok(value) => value,
                Err(error) => {
                    temporary.push(format!("{}: {error:#}", member.endpoint));
                    continue;
                }
            };
        if block.workchain != -1
            || block.shard != selected_shard
            || block.seqno != selected_seqno
            || header.gen_utime == 0
            || u64::from(header.gen_utime) > time_format::now().saturating_add(5 * 60)
        {
            anyhow::bail!("frozen RPC member returned an invalid selected checkpoint");
        }
        if let Some(expected) = &checkpoint {
            if !block_id_equal(&expected.block, &block) || expected.unix != header.gen_utime {
                anyhow::bail!("frozen RPC members disagree on the exact selected checkpoint");
            }
        } else {
            checkpoint = Some(CommonCheckpoint {
                id: checkpoint_id(&block),
                block: block.clone(),
                unix: header.gen_utime,
            });
        }
        members.push(CheckpointMember { member, rpc });
    }
    if members.len() < required {
        return Ok(DualAbsenceQuery::TemporarilyUnavailable(format!(
            "only {} of {} required members can query one exact checkpoint: {}",
            members.len(),
            required,
            temporary.join("; ")
        )));
    }
    Ok(DualAbsenceQuery::Terminal((
        checkpoint.context("no exact checkpoint could be selected")?,
        members,
    )))
}

async fn checkpoint_agent_account_data(
    rpc: &Arc<ClientJsonRpc>,
    source: &MsgAddressInt,
    checkpoint: &CommonCheckpoint,
) -> anyhow::Result<AgentAccountData> {
    let result = rpc
        .run_get_method(&RunGetMethodParams {
            address: source.to_string(),
            method_id: "get_agent_account_data".to_owned(),
            stack: Some(vec![]),
            seqno: Some(checkpoint.block.seqno),
        })
        .await
        .context("RPC temporarily unavailable: checkpoint-pinned Agent Account state")?;
    if result.exit_code != 0 {
        anyhow::bail!("checkpoint Agent Account get-method exit_code={}", result.exit_code);
    }
    let block = result
        .block_id
        .as_ref()
        .context("checkpoint Agent Account get-method omitted block identity")?;
    if !block_id_equal(block, &checkpoint.block) {
        anyhow::bail!("checkpoint Agent Account get-method substituted another block");
    }
    AgentAccountContract::decode_data(&common::tvm_stack_parser::TvmStackParser::new(
        result.stack.into_iter().rev().map(Into::into).collect::<Vec<_>>(),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HistoryConclusion {
    ExactExecuted,
    ExactAbsentComplete,
    Incomplete,
}

async fn scan_exact_message_history(
    rpc: &Arc<ClientJsonRpc>,
    source: &MsgAddressInt,
    exact_cell_hash: &str,
    maximum: u32,
) -> anyhow::Result<(HistoryConclusion, u32)> {
    let info = rpc
        .get_address_information(source)
        .await
        .context("RPC temporarily unavailable: query exact source history cursor")?;
    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let maximum = maximum.clamp(1, 10_000);
    while cursor_lt != 0 && inspected < maximum {
        let limit = (maximum - inspected).min(100);
        let page = rpc
            .get_transactions(source, cursor_lt, &cursor_hash, limit)
            .await
            .context("RPC temporarily unavailable: scan exact source history")?;
        if page.transactions.is_empty() {
            anyhow::bail!("RPC source history terminated before its advertised cursor");
        }
        let mut next = None;
        for raw in page.transactions {
            inspected = inspected.saturating_add(1);
            next = Some((raw.lt, raw.hash.clone()));
            if raw.data.is_empty() {
                anyhow::bail!("RPC source history omitted transaction BOC bytes");
            }
            let transaction_boc = base64::engine::general_purpose::STANDARD
                .decode(&raw.data)
                .context("decode source-history transaction BOC")?;
            let transaction_root = read_single_root_boc(&transaction_boc)?;
            let transaction = Transaction::construct_from_cell(transaction_root)?;
            let Some(inbound) = transaction.in_msg_cell() else {
                continue;
            };
            let inbound_hash = format!("tvm-cell-sha256:{}", hex::encode(inbound.hash(0)));
            if inbound_hash == exact_cell_hash {
                let description = transaction.read_description()?;
                let TransactionDescr::Ordinary(ordinary) = description else {
                    anyhow::bail!("exact signed message appeared in a non-ordinary transaction");
                };
                if !ordinary.aborted {
                    return Ok((HistoryConclusion::ExactExecuted, inspected));
                }
            }
        }
        let Some((next_lt, next_hash)) = next else {
            anyhow::bail!("RPC source history did not advance its cursor");
        };
        if next_lt == cursor_lt && next_hash == cursor_hash {
            anyhow::bail!("RPC source history repeated its cursor");
        }
        cursor_lt = next_lt;
        cursor_hash = next_hash;
    }
    if cursor_lt == 0 {
        Ok((HistoryConclusion::ExactAbsentComplete, inspected))
    } else {
        Ok((HistoryConclusion::Incomplete, inspected))
    }
}

fn observation_reference_digest(
    reference: &RelayAbsenceObservationReferenceV1,
) -> anyhow::Result<String> {
    protocol_value_digest(ABSENCE_REFERENCE_DOMAIN, &serde_json::to_value(reference)?)
}

fn evidence_set_digest(reference_digests: &[String]) -> anyhow::Result<String> {
    if reference_digests.is_empty()
        || reference_digests.len() > 64
        || reference_digests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        anyhow::bail!("absence reference digest set is not strictly sorted and unique");
    }
    let mut encoded = Vec::new();
    for digest in reference_digests {
        validate_sha256_digest("absence reference digest", digest)?;
        encoded.extend_from_slice(digest.as_bytes());
        encoded.push(0);
    }
    exact_protocol_action_request_digest(&encoded)
}

#[allow(clippy::too_many_arguments)]
async fn produce_absence_set(
    loaded: &[LoadedEconomicPaymentCorroborationMember],
    snapshot: &EconomicPaymentCorroborationSnapshot,
    snapshot_threshold: usize,
    context: &RelayAbsenceContext,
    observation_kind: &str,
    source_effect_digest: &str,
    source_effect_cell_hash: &str,
    source_account: &str,
    signed_controller_epoch: u64,
    signed_source_sequence: u32,
    source_effect_valid_until_unix: u64,
    profile: &SponsorshipFinalityProfile,
) -> anyhow::Result<DualAbsenceQuery<AbsenceEvidenceSet>> {
    let required = snapshot_threshold.max(usize::from(profile.minimum_observers));
    let (checkpoint, members) = match common_checkpoint(loaded, &context.network, required).await? {
        DualAbsenceQuery::Terminal(value) => value,
        DualAbsenceQuery::NotMature(reason) => {
            return Ok(DualAbsenceQuery::NotMature(reason));
        }
        DualAbsenceQuery::TemporarilyUnavailable(reason) => {
            return Ok(DualAbsenceQuery::TemporarilyUnavailable(reason));
        }
    };
    let source = source_account
        .parse::<MsgAddressInt>()
        .context("absence source account is not a canonical TOS address")?;
    if source.workchain_id() != context.network.workchain_id {
        anyhow::bail!("absence source account is outside the selected workchain");
    }
    let deadline = source_effect_valid_until_unix
        .checked_add(u64::from(profile.reorg_window_seconds))
        .context("absence terminal window overflows")?;
    let observed_at_unix = time_format::now();
    let mut raw = Vec::new();
    let mut temporary = Vec::new();
    let mut conclusions = BTreeSet::new();
    for checkpoint_member in members {
        let state =
            match checkpoint_agent_account_data(&checkpoint_member.rpc, &source, &checkpoint).await
            {
                Ok(state) => state,
                Err(error) => {
                    let rendered = format!("{}: {error:#}", checkpoint_member.member.endpoint);
                    if sponsorship_rpc_temporarily_unavailable(&rendered) {
                        temporary.push(rendered);
                        continue;
                    }
                    anyhow::bail!("checkpoint Agent Account proof is malformed: {rendered}");
                }
            };
        let (conclusion, history_complete, history_transactions_inspected, invalidation_reason) =
            if state.controller_epoch < signed_controller_epoch {
                anyhow::bail!(
                    "checkpoint Agent Account controller epoch rolled behind the signed action"
                );
            } else if state.controller_epoch == signed_controller_epoch
                && state.seqno <= signed_source_sequence
            {
                if u64::from(checkpoint.unix) < deadline {
                    return Ok(DualAbsenceQuery::NotMature(format!(
                        "{observation_kind} checkpoint {} predates expiry-plus-reorg {}",
                        checkpoint.unix, deadline
                    )));
                }
                (
                    "expired_without_inclusion".to_owned(),
                    false,
                    0,
                    "checkpoint_sequence_not_consumed_before_expiry".to_owned(),
                )
            } else {
                match scan_exact_message_history(
                    &checkpoint_member.rpc,
                    &source,
                    source_effect_cell_hash,
                    snapshot.maximum_history_transactions,
                )
                .await
                {
                    Ok((HistoryConclusion::ExactExecuted, _)) => {
                        anyhow::bail!(
                            "exact {observation_kind} executed; dual absence would be false"
                        );
                    }
                    Ok((HistoryConclusion::Incomplete, inspected)) => {
                        temporary.push(format!(
                            "{}: bounded source history ({inspected}) cannot exclude exact execution",
                            checkpoint_member.member.endpoint
                        ));
                        continue;
                    }
                    Ok((HistoryConclusion::ExactAbsentComplete, inspected)) => {
                        if observation_kind == "sponsorship_action" {
                            if u64::from(checkpoint.unix) < deadline {
                                return Ok(DualAbsenceQuery::NotMature(format!(
                                    "sponsorship checkpoint {} predates expiry-plus-reorg {}",
                                    checkpoint.unix, deadline
                                )));
                            }
                            (
                                "expired_without_inclusion".to_owned(),
                                true,
                                inspected,
                                "source_authority_or_sequence_advanced_without_exact_message"
                                    .to_owned(),
                            )
                        } else {
                            (
                                "invalidated_without_inclusion".to_owned(),
                                true,
                                inspected,
                                "source_authority_or_sequence_irreversibly_advanced_without_exact_message"
                                    .to_owned(),
                            )
                        }
                    }
                    Err(error) => {
                        let rendered = format!("{}: {error:#}", checkpoint_member.member.endpoint);
                        if sponsorship_rpc_temporarily_unavailable(&rendered) {
                            temporary.push(rendered);
                            continue;
                        }
                        anyhow::bail!("source-history absence proof is malformed: {rendered}");
                    }
                }
            };
        conclusions.insert(conclusion.clone());
        raw.push(DualAbsenceRawObservationV1 {
            schema_version: 1,
            observation_kind: observation_kind.to_owned(),
            conclusion,
            observer_id: checkpoint_member.member.content_digest.clone(),
            operator_domain_id: checkpoint_member.member.operator_provenance.clone(),
            provider_agent_id: context.provider_agent_id.clone(),
            network_digest: context.network_digest.clone(),
            relay_stable_action_id: context.relay_stable_action_id.clone(),
            relay_exact_request_digest: context.relay_exact_request_digest.clone(),
            relay_execution_request_digest: context.relay_execution_digest.clone(),
            sponsorship_stable_action_id: context.sponsorship_stable_action_id.clone(),
            sponsorship_exact_request_digest: context.sponsorship_exact_request_digest.clone(),
            sponsorship_valid_until_unix: context.sponsorship_valid_until_unix,
            signed_transaction_digest: context.signed_transaction.digest.clone(),
            signed_transaction_cell_hash: context.signed_transaction.cell_hash.clone(),
            transaction_valid_until_unix: u64::from(context.signed_transaction.valid_until),
            terminal_profile_uri: profile.profile_uri.clone(),
            terminal_profile_digest: profile.profile_digest.clone(),
            terminal_evidence_class: profile.terminal_evidence_class.clone(),
            checkpoint_id: checkpoint.id.clone(),
            checkpoint_sequence: u64::from(checkpoint.block.seqno),
            checkpoint_unix: u64::from(checkpoint.unix),
            source_account: source.to_string(),
            source_effect_digest: source_effect_digest.to_owned(),
            source_effect_cell_hash: source_effect_cell_hash.to_owned(),
            source_effect_valid_until_unix,
            signed_controller_epoch,
            signed_source_sequence: u64::from(signed_source_sequence),
            checkpoint_controller_epoch: state.controller_epoch,
            checkpoint_source_sequence: u64::from(state.seqno),
            checkpoint_deployment_id: format!("sha256:{}", hex::encode(state.deployment_id)),
            exact_message_observed_executed: false,
            history_complete_when_required: history_complete,
            history_transactions_inspected,
            invalidation_reason,
            observation_evidence_profile_uri: snapshot.evidence_profile_uri.clone(),
            observation_evidence_profile_digest: snapshot.evidence_profile_digest.clone(),
            observed_at_unix,
        });
    }
    if conclusions.len() > 1 {
        anyhow::bail!("frozen RPC members disagree on the exact {observation_kind} conclusion");
    }
    if raw.len() < required {
        return Ok(DualAbsenceQuery::TemporarilyUnavailable(format!(
            "only {} of {} required {observation_kind} observations are available: {}",
            raw.len(),
            required,
            temporary.join("; ")
        )));
    }
    let operators = raw
        .iter()
        .map(|observation| observation.operator_domain_id.clone())
        .collect::<BTreeSet<_>>();
    if operators.len() < usize::from(profile.minimum_operator_domains) {
        anyhow::bail!("{observation_kind} observations lack required operator-domain diversity");
    }
    let conclusion =
        conclusions.into_iter().next().context("absence query produced no conclusion")?;
    if conclusion != "invalidated_without_inclusion" && u64::from(checkpoint.unix) < deadline {
        return Ok(DualAbsenceQuery::NotMature(format!(
            "{observation_kind} checkpoint {} predates expiry-plus-reorg {}",
            checkpoint.unix, deadline
        )));
    }
    let mut pairs = Vec::with_capacity(raw.len());
    for observation in raw {
        let observation_digest = protocol_value_digest(
            DUAL_ABSENCE_OBSERVATION_DOMAIN,
            &serde_json::to_value(&observation)?,
        )?;
        let reference = RelayAbsenceObservationReferenceV1 {
            schema_version: 1,
            observation_kind: observation_kind.to_owned(),
            conclusion: conclusion.clone(),
            provider_agent_id: context.provider_agent_id.clone(),
            network_digest: context.network_digest.clone(),
            relay_stable_action_id: context.relay_stable_action_id.clone(),
            relay_exact_request_digest: context.relay_exact_request_digest.clone(),
            relay_execution_request_digest: context.relay_execution_digest.clone(),
            sponsorship_stable_action_id: context.sponsorship_stable_action_id.clone(),
            sponsorship_exact_request_digest: context.sponsorship_exact_request_digest.clone(),
            sponsorship_valid_until_unix: context.sponsorship_valid_until_unix,
            signed_transaction_digest: context.signed_transaction.digest.clone(),
            signed_transaction_cell_hash: context.signed_transaction.cell_hash.clone(),
            terminal_profile_uri: profile.profile_uri.clone(),
            terminal_profile_digest: profile.profile_digest.clone(),
            terminal_evidence_class: profile.terminal_evidence_class.clone(),
            finalized_checkpoint_id: checkpoint.id.clone(),
            finalized_checkpoint_sequence: u64::from(checkpoint.block.seqno),
            finalized_checkpoint_unix: u64::from(checkpoint.unix),
            observer_id: observation.observer_id.clone(),
            operator_domain_id: observation.operator_domain_id.clone(),
            observation_evidence_profile_uri: snapshot.evidence_profile_uri.clone(),
            observation_evidence_profile_digest: snapshot.evidence_profile_digest.clone(),
            observation_digest,
            observed_at_unix,
        };
        pairs.push((observation_reference_digest(&reference)?, reference, observation));
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    if pairs.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        anyhow::bail!("{observation_kind} produced duplicate absence references");
    }
    Ok(DualAbsenceQuery::Terminal(AbsenceEvidenceSet {
        conclusion,
        raw: pairs.iter().map(|(_, _, raw)| raw.clone()).collect(),
        references: pairs.iter().map(|(_, reference, _)| reference.clone()).collect(),
        reference_digests: pairs.into_iter().map(|(digest, _, _)| digest).collect(),
    }))
}

fn print_unknown(
    schema: &str,
    category: &str,
    reason: &str,
    context: Option<&RelayAbsenceContext>,
) {
    let mut value = serde_json::json!({
        "schema": schema,
        "state": "unknown",
        "category": category,
        "reason": reason,
        "chain_side_effect": false,
        "custody_side_effect": false,
    });
    if let Some(context) = context {
        let object = value.as_object_mut().expect("JSON object");
        object.insert(
            "relay_execution_request_digest".to_owned(),
            serde_json::Value::String(context.relay_execution_digest.clone()),
        );
        object.insert(
            "relay_stable_action_id".to_owned(),
            serde_json::Value::String(context.relay_stable_action_id.clone()),
        );
        object.insert(
            "relay_exact_request_digest".to_owned(),
            serde_json::Value::String(context.relay_exact_request_digest.clone()),
        );
        object.insert(
            "sponsorship_stable_action_id".to_owned(),
            serde_json::Value::String(context.sponsorship_stable_action_id.clone()),
        );
        object.insert(
            "sponsorship_exact_request_digest".to_owned(),
            serde_json::Value::String(context.sponsorship_exact_request_digest.clone()),
        );
    }
    println!("{value}");
}

fn controller_status_name(status: ControllerActionStatus) -> &'static str {
    match status {
        ControllerActionStatus::Claimed => "claimed",
        ControllerActionStatus::Signed => "signed",
        ControllerActionStatus::Broadcasting => "broadcasting",
        ControllerActionStatus::Resolved => "resolved",
    }
}

fn validate_absence_custody_status(
    proof_scope: &str,
    status: ControllerActionStatus,
) -> anyhow::Result<()> {
    match (proof_scope, status) {
        // Dual aggregation is downstream of the authoritative sponsorship
        // component tombstone. Caller-supplied proof bytes can never stand in
        // for that permanent custody fence.
        ("dual", ControllerActionStatus::Resolved) => Ok(()),
        ("dual", _) => anyhow::bail!(
            "dual aggregation requires an exact resolved sponsorship-component custody tombstone"
        ),
        ("sponsorship_only", ControllerActionStatus::Signed)
        | ("sponsorship_only", ControllerActionStatus::Broadcasting)
        | ("sponsorship_only", ControllerActionStatus::Resolved) => Ok(()),
        ("sponsorship_only", _) => anyhow::bail!(
            "sponsorship absence requires an exact signed or ambiguously broadcast custody action"
        ),
        _ => anyhow::bail!("unsupported custody-backed absence proof scope"),
    }
}

impl AgentAccountEconomicPaymentSponsorshipDualAbsenceCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.run_with_scope("dual").await
    }

    async fn run_with_scope(&self, proof_scope: &str) -> anyhow::Result<()> {
        if proof_scope != "dual" && proof_scope != "sponsorship_only" {
            anyhow::bail!("unsupported custody-backed absence proof scope");
        }
        let output_schema = if proof_scope == "dual" {
            DUAL_ABSENCE_SCHEMA
        } else {
            SPONSORSHIP_COMPONENT_ABSENCE_SCHEMA
        };
        let existing_component =
            match (proof_scope, self.existing_sponsorship_proof_bundle_cbor.as_deref()) {
                ("dual", Some(path)) => {
                    Some(decode_absence_proof_bundle(Path::new(path), "sponsorship_only")?)
                }
                ("dual", None) => anyhow::bail!(
                    "dual aggregation requires --existing-sponsorship-proof-bundle-cbor"
                ),
                ("sponsorship_only", None) => None,
                ("sponsorship_only", Some(_)) => anyhow::bail!(
                    "sponsorship-component production must not receive an existing component proof"
                ),
                _ => unreachable!("validated proof scope"),
            };
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        let (payment_cbor, payment_value) =
            decode_exact_protocol_cbor(Path::new(&self.agreement_payment_request_cbor))?;
        let payment: SponsorshipAgreementPaymentRequestV3 =
            serde_json::from_value(payment_value.clone())
                .context("decode exact sponsorship AgreementPaymentRequestV3")?;
        let payment_digest =
            protocol_cbor_digest(AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN, &payment_cbor)?;
        let payment_exact_request_digest = exact_protocol_action_request_digest(&payment_cbor)?;
        if payment.stable_action_id != self.stable_action_id {
            anyhow::bail!("supplied stable action differs from AgreementPaymentRequestV3");
        }
        let (sponsorship_profile_cbor, sponsorship_profile_value, sponsorship_profile) =
            decode_selected_profile(
                &self.sponsorship_terminal_profile_cbor,
                "sponsorship terminal",
            )?;
        let (relay_profile_value, relay_profile) = match &self.relay_finality_profile_cbor {
            Some(path) => {
                let (_, value, profile) = decode_selected_profile(path, "relay terminal")?;
                (Some(value), Some(profile))
            }
            None => (None, None),
        };
        let (snapshot, loaded, snapshot_threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        validate_lower_finality_profile(&sponsorship_profile, "sponsorship", loaded.len())?;
        if let Some(profile) = &relay_profile {
            validate_lower_finality_profile(profile, "relay", loaded.len())?;
        }
        let (_, execution_value, mut context) = decode_relay_absence_context(
            &self.relay_execution_request_cbor,
            &payment,
            &self.stable_action_id,
            &payment_exact_request_digest,
            &sponsorship_profile_value,
            sponsorship_profile,
            relay_profile_value.as_ref(),
            relay_profile,
        )?;
        if context.network != snapshot.network_domain {
            anyhow::bail!("relay execution network differs from the frozen Provider snapshot");
        }

        // The wallet and custody path are selected only from the safely read,
        // per-action frozen primary config. The process-wide --config is not
        // reopened and cannot rotate this recovery onto another action.
        let primary = &loaded[0];
        let wallet = primary.config.agent_wallets.get(&self.wallet).ok_or_else(|| {
            anyhow::anyhow!("Agent wallet '{}' not found in frozen snapshot", self.wallet)
        })?;
        let runtime = wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let source = wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let journal = open_economic_controller_journal(
            &primary.canonical_path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let record = journal
            .find_economic_payment_by_stable_action(&self.stable_action_id)?
            .context("prepared sponsorship Agreement payment was not found")?;
        if record.status == ControllerActionStatus::Resolved {
            let stored_schema = if proof_scope == "dual" {
                SPONSORSHIP_COMPONENT_ABSENCE_SCHEMA
            } else {
                output_schema
            };
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved sponsorship custody record lacks terminal evidence")?;
            if resolution.evidence_kind != stored_schema
                || text_member(&resolution.evidence, "schema", "stored absence resolution")?
                    != stored_schema
                || text_member(
                    &resolution.evidence,
                    "sponsorship_stable_action_id",
                    "stored absence resolution",
                )? != context.sponsorship_stable_action_id.as_str()
                || text_member(
                    &resolution.evidence,
                    "sponsorship_exact_request_digest",
                    "stored absence resolution",
                )? != context.sponsorship_exact_request_digest.as_str()
                || text_member(
                    &resolution.evidence,
                    "relay_execution_request_digest",
                    "stored absence resolution",
                )? != context.relay_execution_digest.as_str()
                || text_member(
                    &resolution.evidence,
                    "agreement_payment_request_digest",
                    "stored absence resolution",
                )? != payment_digest.as_str()
                || text_member(
                    &resolution.evidence,
                    "provider_snapshot_identity",
                    "stored absence resolution",
                )? != snapshot.snapshot_identity.as_str()
            {
                anyhow::bail!(
                    "stored sponsorship absence resolution conflicts with the exact replay inputs"
                );
            }
            let proof_bundle_cbor =
                base64::engine::general_purpose::STANDARD.decode(text_member(
                    &resolution.evidence,
                    "proof_bundle_cbor",
                    "stored absence resolution",
                )?)?;
            let wrapper_value = decode_exact_protocol_cbor_bytes(&proof_bundle_cbor)?;
            let wrapper: RelayAbsenceProofBundleV1 = serde_json::from_value(wrapper_value)?;
            let stored_scope = if proof_scope == "dual" { "sponsorship_only" } else { proof_scope };
            if wrapper.proof_scope != stored_scope
                || protocol_cbor_digest(ABSENCE_PROOF_BUNDLE_DOMAIN, &proof_bundle_cbor)?
                    != text_member(
                        &resolution.evidence,
                        "proof_bundle_digest",
                        "stored absence resolution",
                    )?
            {
                anyhow::bail!(
                    "stored sponsorship absence proof wrapper conflicts with replay scope"
                );
            }
            if proof_scope == "dual" {
                let (_, _, supplied_cbor, supplied_digest) = existing_component
                    .as_ref()
                    .context("dual aggregation lost its existing component proof")?;
                if supplied_cbor != &proof_bundle_cbor
                    || supplied_digest
                        != text_member(
                            &resolution.evidence,
                            "proof_bundle_digest",
                            "stored absence resolution",
                        )?
                {
                    anyhow::bail!(
                        "supplied sponsorship component proof differs from the custody tombstone"
                    );
                }
            } else {
                println!("{}", resolution.evidence);
                return Ok(());
            }
        }
        let custody_status = record.status.clone();
        validate_absence_custody_status(proof_scope, custody_status.clone()).with_context(
            || {
                format!(
                    "custody state {} cannot produce {proof_scope} absence",
                    controller_status_name(custody_status)
                )
            },
        )?;
        let authorization = record
            .economic_authorization
            .as_ref()
            .context("custody record is not an economic payment")?;
        let network = record
            .claim
            .network_domain
            .as_ref()
            .context("custody sponsorship payment has no full network-domain pin")?;
        validate_sponsorship_payment_request(
            &payment,
            &payment_digest,
            &payment_exact_request_digest,
            network,
            &record,
            authorization,
        )?;
        let sponsorship_profile_cbor_digest = canonical_file_digest(&sponsorship_profile_cbor);
        validate_sponsorship_custody_evidence_context(
            authorization,
            &sponsorship_profile_cbor_digest,
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        if network != &context.network || source.to_string() != record.claim.account {
            anyhow::bail!(
                "custody sponsorship differs from the exact relay execution network/source"
            );
        }
        context.sponsorship_valid_until_unix = u64::from(record.claim.valid_until);
        if context.sponsorship_valid_until_unix != payment.expires_at_unix {
            anyhow::bail!("sponsorship expiry differs between custody and PaymentRequestV3");
        }

        let signed_top_up_b64 = if proof_scope == "dual" {
            existing_component
                .as_ref()
                .context("dual aggregation lost its sponsorship component")?
                .1
                .signed_top_up_transaction_boc
                .clone()
        } else {
            record
                .exact_signed_boc_base64
                .as_ref()
                .context("custody sponsorship has no exact signed BOC")?
                .clone()
        };
        let signed_top_up = base64::engine::general_purpose::STANDARD
            .decode(&signed_top_up_b64)
            .context("decode custody sponsorship signed BOC")?;
        if base64::engine::general_purpose::STANDARD.encode(&signed_top_up) != signed_top_up_b64 {
            anyhow::bail!("custody sponsorship signed BOC is not canonical base64");
        }
        let signed_top_up_digest = canonical_file_digest(&signed_top_up);
        if proof_scope == "sponsorship_only"
            && record.exact_signed_boc_digest.as_deref() != Some(&signed_top_up_digest)
        {
            anyhow::bail!("custody sponsorship signed BOC digest is inconsistent");
        }
        let signed_top_up_root = read_single_root_boc(&signed_top_up)?;
        let signed_top_up_cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(signed_top_up_root.hash(0)));
        let destination = record.claim.target.parse::<MsgAddressInt>()?;
        let sponsor_controller_epoch = validate_exact_sponsorship_top_up_boc(
            &signed_top_up,
            &signed_top_up_b64,
            &signed_top_up_digest,
            &signed_top_up_cell_hash,
            &source,
            context.network.global_id,
            record.claim.seqno,
            record.claim.valid_until,
            &destination,
            record.claim.value_atomic,
            &payment_digest,
            &self.stable_action_id,
        )?;

        let prior_sponsorship = if let Some((wrapper, prior, _, _)) = &existing_component {
            if prior.schema != DUAL_ABSENCE_PROOF_BUNDLE_SCHEMA
                || prior.proof_scope != "sponsorship_only"
                || prior.provider_snapshot_identity != snapshot.snapshot_identity
                || prior.evidence_profile_uri != snapshot.evidence_profile_uri
                || prior.evidence_profile_digest != snapshot.evidence_profile_digest
                || prior.evidence_profile != snapshot.evidence_profile
                || prior.network_domain != context.network
                || prior.network_digest != context.network_digest
                || prior.agreement_payment_request_digest != payment_digest
                || serde_json::to_value(&prior.agreement_payment_request)? != payment_value
                || prior.sponsorship_stable_action_id != context.sponsorship_stable_action_id
                || prior.sponsorship_exact_request_digest
                    != context.sponsorship_exact_request_digest
                || prior.sponsorship_valid_until_unix != context.sponsorship_valid_until_unix
                || prior.signed_top_up_transaction_boc != signed_top_up_b64
                || prior.signed_top_up_transaction_digest != signed_top_up_digest
                || prior.signed_top_up_transaction_cell_hash != signed_top_up_cell_hash
                || prior.provider_sponsor_source_account != source.to_string()
                || prior.provider_sponsor_source_sequence != u64::from(record.claim.seqno)
                || prior.relay_execution_request_digest != context.relay_execution_digest
                || prior.relay_stable_action_id != context.relay_stable_action_id
                || prior.relay_exact_request_digest != context.relay_exact_request_digest
                || prior.provider_agent_id != context.provider_agent_id
                || prior.mode != context.mode
                || prior.assurance_level != context.assurance_level
                || prior.signed_transaction_digest != context.signed_transaction.digest
                || prior.signed_transaction_cell_hash != context.signed_transaction.cell_hash
                || prior.signed_transaction_source_account
                    != context.signed_transaction.source_account
                || prior.signed_transaction_source_sequence
                    != u64::from(context.signed_transaction.source_sequence)
                || prior.transaction_valid_until_unix
                    != u64::from(context.signed_transaction.valid_until)
                || prior.sponsorship_terminal_profile != context.sponsorship_terminal_profile
                || prior.relay_finality_profile != context.relay_finality_profile
                || prior.outcome != "corroborated_sponsorship_absent_component"
                || prior.produced_at_unix == 0
                || prior.produced_at_unix > time_format::now().saturating_add(5 * 60)
                || !prior.transaction_observations.is_empty()
                || !prior.transaction_absence_observations.is_empty()
                || wrapper.transaction_absence_observations.len() != 0
            {
                anyhow::bail!(
                    "existing sponsorship component proof conflicts with custody or exact relay inputs"
                );
            }
            let reference_digests = validate_bundled_absence_set(
                &prior.sponsorship_observations,
                &prior.sponsorship_absence_observations,
                &context,
                "sponsorship_action",
                "expired_without_inclusion",
                &context.sponsorship_terminal_profile,
                &prior.evidence_profile_uri,
                &prior.evidence_profile_digest,
                &prior.signed_top_up_transaction_digest,
                &prior.signed_top_up_transaction_cell_hash,
                &prior.provider_sponsor_source_account,
                prior.provider_sponsor_source_sequence,
                prior.sponsorship_valid_until_unix,
                prior.produced_at_unix,
            )?;
            if evidence_set_digest(&reference_digests)? != prior.evidence_set_digest {
                anyhow::bail!("existing sponsorship component evidence-set digest changed");
            }
            Some(AbsenceEvidenceSet {
                conclusion: "expired_without_inclusion".to_owned(),
                raw: prior.sponsorship_observations.clone(),
                references: prior.sponsorship_absence_observations.clone(),
                reference_digests,
            })
        } else {
            None
        };

        let fresh_sponsorship = match produce_absence_set(
            &loaded,
            &snapshot,
            snapshot_threshold,
            &context,
            "sponsorship_action",
            &signed_top_up_digest,
            &signed_top_up_cell_hash,
            &source.to_string(),
            sponsor_controller_epoch,
            record.claim.seqno,
            u64::from(record.claim.valid_until),
            &context.sponsorship_terminal_profile,
        )
        .await?
        {
            DualAbsenceQuery::Terminal(value) => value,
            DualAbsenceQuery::NotMature(reason) => {
                print_unknown(output_schema, "not_mature", &reason, Some(&context));
                return Ok(());
            }
            DualAbsenceQuery::TemporarilyUnavailable(reason) => {
                print_unknown(output_schema, "temporarily_unavailable", &reason, Some(&context));
                return Ok(());
            }
        };
        if let Some(prior) = &prior_sponsorship {
            if fresh_sponsorship.conclusion != prior.conclusion {
                anyhow::bail!(
                    "fresh Provider query disagrees with the persisted sponsorship component"
                );
            }
        }
        let sponsorship = prior_sponsorship.unwrap_or(fresh_sponsorship);
        let transaction = if proof_scope == "dual" {
            let transaction_profile = context
                .relay_finality_profile
                .as_ref()
                .unwrap_or(&context.sponsorship_terminal_profile);
            Some(
                match produce_absence_set(
                    &loaded,
                    &snapshot,
                    snapshot_threshold,
                    &context,
                    "client_transaction",
                    &context.signed_transaction.digest,
                    &context.signed_transaction.cell_hash,
                    &context.signed_transaction.source_account,
                    context.signed_transaction.controller_epoch,
                    context.signed_transaction.source_sequence,
                    u64::from(context.signed_transaction.valid_until),
                    transaction_profile,
                )
                .await?
                {
                    DualAbsenceQuery::Terminal(value) => value,
                    DualAbsenceQuery::NotMature(reason) => {
                        print_unknown(output_schema, "not_mature", &reason, Some(&context));
                        return Ok(());
                    }
                    DualAbsenceQuery::TemporarilyUnavailable(reason) => {
                        print_unknown(
                            output_schema,
                            "temporarily_unavailable",
                            &reason,
                            Some(&context),
                        );
                        return Ok(());
                    }
                },
            )
        } else {
            None
        };
        let outcome = match transaction.as_ref().map(|value| value.conclusion.as_str()) {
            Some("expired_without_inclusion") => "corroborated_expired",
            Some("invalidated_without_inclusion") => "corroborated_invalidated",
            Some("absent") => "corroborated_absent",
            None => "corroborated_sponsorship_absent_component",
            _ => anyhow::bail!("unsupported client-transaction absence conclusion"),
        };
        let mut merged = sponsorship.reference_digests.clone();
        if let Some(transaction) = &transaction {
            merged.extend(transaction.reference_digests.clone());
        }
        merged.sort();
        if merged.windows(2).any(|pair| pair[0] == pair[1]) {
            anyhow::bail!("one absence reference was reused across both side effects");
        }
        let evidence_set_digest = evidence_set_digest(&merged)?;
        let produced_at_unix = time_format::now();
        let bundle = DualAbsenceProofBundleV1 {
            schema: DUAL_ABSENCE_PROOF_BUNDLE_SCHEMA.to_owned(),
            proof_scope: proof_scope.to_owned(),
            provider_snapshot_identity: snapshot.snapshot_identity.clone(),
            evidence_profile_uri: snapshot.evidence_profile_uri.clone(),
            evidence_profile_digest: snapshot.evidence_profile_digest.clone(),
            evidence_profile: snapshot.evidence_profile.clone(),
            network_domain: context.network.clone(),
            network_digest: context.network_digest.clone(),
            agreement_payment_request: payment.clone(),
            agreement_payment_request_digest: payment_digest.clone(),
            sponsorship_stable_action_id: context.sponsorship_stable_action_id.clone(),
            sponsorship_exact_request_digest: context.sponsorship_exact_request_digest.clone(),
            sponsorship_valid_until_unix: context.sponsorship_valid_until_unix,
            signed_top_up_transaction_boc: signed_top_up_b64.clone(),
            signed_top_up_transaction_digest: signed_top_up_digest.clone(),
            signed_top_up_transaction_cell_hash: signed_top_up_cell_hash.clone(),
            provider_sponsor_source_account: source.to_string(),
            provider_sponsor_source_sequence: u64::from(record.claim.seqno),
            relay_execution_request_digest: context.relay_execution_digest.clone(),
            relay_stable_action_id: context.relay_stable_action_id.clone(),
            relay_exact_request_digest: context.relay_exact_request_digest.clone(),
            provider_agent_id: context.provider_agent_id.clone(),
            mode: context.mode.clone(),
            assurance_level: context.assurance_level.clone(),
            signed_transaction_digest: context.signed_transaction.digest.clone(),
            signed_transaction_cell_hash: context.signed_transaction.cell_hash.clone(),
            signed_transaction_source_account: context.signed_transaction.source_account.clone(),
            signed_transaction_source_sequence: u64::from(
                context.signed_transaction.source_sequence,
            ),
            transaction_valid_until_unix: u64::from(context.signed_transaction.valid_until),
            sponsorship_terminal_profile: context.sponsorship_terminal_profile.clone(),
            relay_finality_profile: context.relay_finality_profile.clone(),
            outcome: outcome.to_owned(),
            sponsorship_observations: sponsorship.raw.clone(),
            transaction_observations: transaction
                .as_ref()
                .map(|value| value.raw.clone())
                .unwrap_or_default(),
            sponsorship_absence_observations: sponsorship.references.clone(),
            transaction_absence_observations: transaction
                .as_ref()
                .map(|value| value.references.clone())
                .unwrap_or_default(),
            evidence_set_digest: evidence_set_digest.clone(),
            produced_at_unix,
        };
        let payload_value = serde_json::to_value(&bundle)?;
        let mut payload_cbor = Vec::new();
        encode_protocol_json_cbor(&payload_value, &mut payload_cbor, 0)?;
        if payload_cbor.len() > 128 << 10 {
            anyhow::bail!("dual-absence proof bundle exceeds the released 128 KiB bound");
        }
        let (proof_bundle, bundle_cbor, bundle_digest) = wrap_absence_proof_payload(
            proof_scope,
            &payload_cbor,
            &sponsorship.references,
            &transaction.as_ref().map(|value| value.references.clone()).unwrap_or_default(),
        )?;
        let predecessor_sponsorship_proof_bundle_digest =
            existing_component.as_ref().map(|(_, _, _, digest)| digest.clone());
        let mut output = serde_json::json!({
            "schema": output_schema,
            "state": if proof_scope == "dual" { "corroborated_absent" } else { "corroborated_sponsorship_absent" },
            "outcome": outcome,
            "terminal_evidence_class": "client_corroborated",
            "validator_authenticated_portable_proof": false,
            "network_domain": context.network,
            "network_digest": context.network_digest,
            "agreement_payment_request_digest": payment_digest,
            "sponsorship_stable_action_id": context.sponsorship_stable_action_id,
            "sponsorship_exact_request_digest": context.sponsorship_exact_request_digest,
            "sponsorship_valid_until_unix": context.sponsorship_valid_until_unix,
            "relay_stable_action_id": context.relay_stable_action_id,
            "relay_exact_request_digest": context.relay_exact_request_digest,
            "relay_execution_request_digest": context.relay_execution_digest,
            "signed_top_up_transaction_digest": signed_top_up_digest,
            "signed_top_up_transaction_cell_hash": signed_top_up_cell_hash,
            "signed_transaction_digest": context.signed_transaction.digest,
            "signed_transaction_cell_hash": context.signed_transaction.cell_hash,
            "transaction_valid_until_unix": context.signed_transaction.valid_until,
            "sponsorship_terminal_profile": context.sponsorship_terminal_profile,
            "relay_finality_profile": context.relay_finality_profile,
            "provider_snapshot_identity": snapshot.snapshot_identity,
            "evidence_profile_uri": snapshot.evidence_profile_uri,
            "evidence_profile_digest": snapshot.evidence_profile_digest,
            "sponsorship_absence_observations": sponsorship.references,
            "transaction_absence_observations": transaction.as_ref().map(|value| value.references.clone()).unwrap_or_default(),
            "evidence_set_digest": evidence_set_digest,
            "proof_bundle_digest_algorithm": "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic",
            "proof_bundle_digest_domain": ABSENCE_PROOF_BUNDLE_DOMAIN,
            "proof_bundle_digest": bundle_digest,
            "proof_bundle_cbor": base64::engine::general_purpose::STANDARD.encode(&bundle_cbor),
            "proof_bundle": proof_bundle,
            "proof_payload": payload_value,
            "produced_at_unix": produced_at_unix,
            "custody_state": if proof_scope == "dual" { "resolved_sponsorship_component" } else { "resolved" },
            "chain_side_effect": false,
            "custody_side_effect": proof_scope == "sponsorship_only",
        });
        if let Some(predecessor) = predecessor_sponsorship_proof_bundle_digest {
            output.as_object_mut().expect("absence output is an object").insert(
                "predecessor_sponsorship_proof_bundle_digest".to_owned(),
                serde_json::Value::String(predecessor),
            );
        }
        if proof_scope == "dual" {
            // Sponsorship custody was already terminalized by the exact
            // sponsorship-component producer. The dual object is a monotonic
            // relay-journal aggregation over that immutable tombstone; writing
            // custody again would create a second economic side effect and
            // would destroy crash-replay identity for the component proof.
            println!("{output}");
            drop(execution_value);
            return Ok(());
        }
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: output_schema.to_owned(),
            evidence_digest: controller_resolution_evidence_digest(output_schema, &output)?,
            evidence: output,
        };
        let checkpoint = sponsorship
            .raw
            .first()
            .context("sponsorship absence lost its checkpoint observation")?;
        let resolved = journal.resolve_exact_absence(
            &record.claim,
            &signed_top_up_digest,
            checkpoint.checkpoint_controller_epoch,
            u32::try_from(checkpoint.checkpoint_source_sequence)?,
            resolution,
            time_format::now(),
        )?;
        println!(
            "{}",
            resolved
                .exact_winner_resolution
                .context("resolved sponsorship absence lost replay evidence")?
                .evidence
        );
        // Keep the exact execution value live through all validation above;
        // this also makes accidental removal of the full-input binding visible
        // to compiler/test review.
        drop(execution_value);
        Ok(())
    }
}

impl AgentAccountEconomicPaymentSponsorshipComponentAbsenceCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.input.run_with_scope("sponsorship_only").await
    }
}

impl AgentAccountEconomicPaymentRelayTransactionComponentAbsenceCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let (payment_cbor, payment_value) =
            decode_exact_protocol_cbor(Path::new(&self.agreement_payment_request_cbor))?;
        let payment: SponsorshipAgreementPaymentRequestV3 =
            serde_json::from_value(payment_value.clone())?;
        let payment_digest =
            protocol_cbor_digest(AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN, &payment_cbor)?;
        let payment_exact_request_digest = exact_protocol_action_request_digest(&payment_cbor)?;
        let (_, sponsorship_profile_value, sponsorship_profile) = decode_selected_profile(
            &self.sponsorship_terminal_profile_cbor,
            "sponsorship terminal",
        )?;
        let (relay_profile_value, relay_profile) = match &self.relay_finality_profile_cbor {
            Some(path) => {
                let (_, value, profile) = decode_selected_profile(path, "relay terminal")?;
                (Some(value), Some(profile))
            }
            None => (None, None),
        };
        let (snapshot, loaded, snapshot_threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        validate_lower_finality_profile(&sponsorship_profile, "sponsorship", loaded.len())?;
        if let Some(profile) = &relay_profile {
            validate_lower_finality_profile(profile, "relay", loaded.len())?;
        }
        let (_, _, context) = decode_relay_absence_context(
            &self.relay_execution_request_cbor,
            &payment,
            &payment.stable_action_id,
            &payment_exact_request_digest,
            &sponsorship_profile_value,
            sponsorship_profile,
            relay_profile_value.as_ref(),
            relay_profile,
        )?;
        if snapshot.network_domain != context.network || context.mode != "sponsor_and_relay" {
            anyhow::bail!(
                "transaction component absence requires the exact combined-mode frozen network"
            );
        }
        let transaction_profile = context
            .relay_finality_profile
            .as_ref()
            .context("combined transaction absence lacks its signed relay profile")?;
        let transaction = match produce_absence_set(
            &loaded,
            &snapshot,
            snapshot_threshold,
            &context,
            "client_transaction",
            &context.signed_transaction.digest,
            &context.signed_transaction.cell_hash,
            &context.signed_transaction.source_account,
            context.signed_transaction.controller_epoch,
            context.signed_transaction.source_sequence,
            u64::from(context.signed_transaction.valid_until),
            transaction_profile,
        )
        .await?
        {
            DualAbsenceQuery::Terminal(value) => value,
            DualAbsenceQuery::NotMature(reason) => {
                print_unknown(
                    TRANSACTION_COMPONENT_ABSENCE_SCHEMA,
                    "not_mature",
                    &reason,
                    Some(&context),
                );
                return Ok(());
            }
            DualAbsenceQuery::TemporarilyUnavailable(reason) => {
                print_unknown(
                    TRANSACTION_COMPONENT_ABSENCE_SCHEMA,
                    "temporarily_unavailable",
                    &reason,
                    Some(&context),
                );
                return Ok(());
            }
        };
        let component_outcome = match transaction.conclusion.as_str() {
            "expired_without_inclusion" => "corroborated_transaction_expired",
            "invalidated_without_inclusion" => "corroborated_transaction_invalidated",
            "absent" => "corroborated_transaction_absent",
            _ => anyhow::bail!("unsupported client-transaction component conclusion"),
        };
        let evidence_set_digest = evidence_set_digest(&transaction.reference_digests)?;
        let produced_at_unix = time_format::now();
        let payload = DualAbsenceProofBundleV1 {
            schema: DUAL_ABSENCE_PROOF_BUNDLE_SCHEMA.to_owned(),
            proof_scope: "transaction_only".to_owned(),
            provider_snapshot_identity: snapshot.snapshot_identity.clone(),
            evidence_profile_uri: snapshot.evidence_profile_uri.clone(),
            evidence_profile_digest: snapshot.evidence_profile_digest.clone(),
            evidence_profile: snapshot.evidence_profile.clone(),
            network_domain: context.network.clone(),
            network_digest: context.network_digest.clone(),
            agreement_payment_request: payment.clone(),
            agreement_payment_request_digest: payment_digest.clone(),
            sponsorship_stable_action_id: context.sponsorship_stable_action_id.clone(),
            sponsorship_exact_request_digest: context.sponsorship_exact_request_digest.clone(),
            sponsorship_valid_until_unix: context.sponsorship_valid_until_unix,
            signed_top_up_transaction_boc: String::new(),
            signed_top_up_transaction_digest: String::new(),
            signed_top_up_transaction_cell_hash: String::new(),
            provider_sponsor_source_account: String::new(),
            provider_sponsor_source_sequence: 0,
            relay_execution_request_digest: context.relay_execution_digest.clone(),
            relay_stable_action_id: context.relay_stable_action_id.clone(),
            relay_exact_request_digest: context.relay_exact_request_digest.clone(),
            provider_agent_id: context.provider_agent_id.clone(),
            mode: context.mode.clone(),
            assurance_level: context.assurance_level.clone(),
            signed_transaction_digest: context.signed_transaction.digest.clone(),
            signed_transaction_cell_hash: context.signed_transaction.cell_hash.clone(),
            signed_transaction_source_account: context.signed_transaction.source_account.clone(),
            signed_transaction_source_sequence: u64::from(
                context.signed_transaction.source_sequence,
            ),
            transaction_valid_until_unix: u64::from(context.signed_transaction.valid_until),
            sponsorship_terminal_profile: context.sponsorship_terminal_profile.clone(),
            relay_finality_profile: context.relay_finality_profile.clone(),
            outcome: component_outcome.to_owned(),
            sponsorship_observations: Vec::new(),
            transaction_observations: transaction.raw.clone(),
            sponsorship_absence_observations: Vec::new(),
            transaction_absence_observations: transaction.references.clone(),
            evidence_set_digest: evidence_set_digest.clone(),
            produced_at_unix,
        };
        let payload_value = serde_json::to_value(&payload)?;
        let mut payload_cbor = Vec::new();
        encode_protocol_json_cbor(&payload_value, &mut payload_cbor, 0)?;
        let (proof_bundle, proof_bundle_cbor, proof_bundle_digest) = wrap_absence_proof_payload(
            "transaction_only",
            &payload_cbor,
            &[],
            &transaction.references,
        )?;
        println!(
            "{}",
            serde_json::json!({
                "schema": TRANSACTION_COMPONENT_ABSENCE_SCHEMA,
                "state": "corroborated_transaction_absent",
                "component_outcome": component_outcome,
                "terminal_evidence_class": "provider_corroborated",
                "validator_authenticated_portable_proof": false,
                "network_domain": context.network,
                "network_digest": context.network_digest,
                "agreement_payment_request_digest": payment_digest,
                "sponsorship_stable_action_id": context.sponsorship_stable_action_id,
                "sponsorship_exact_request_digest": context.sponsorship_exact_request_digest,
                "relay_stable_action_id": context.relay_stable_action_id,
                "relay_exact_request_digest": context.relay_exact_request_digest,
                "relay_execution_request_digest": context.relay_execution_digest,
                "signed_transaction_digest": context.signed_transaction.digest,
                "signed_transaction_cell_hash": context.signed_transaction.cell_hash,
                "transaction_valid_until_unix": context.signed_transaction.valid_until,
                "provider_snapshot_identity": snapshot.snapshot_identity,
                "transaction_absence_observations": transaction.references,
                "evidence_set_digest": evidence_set_digest,
                "proof_bundle_digest_algorithm": "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic",
                "proof_bundle_digest_domain": ABSENCE_PROOF_BUNDLE_DOMAIN,
                "proof_bundle_digest": proof_bundle_digest,
                "proof_bundle_cbor": base64::engine::general_purpose::STANDARD.encode(&proof_bundle_cbor),
                "proof_bundle": proof_bundle,
                "proof_payload": payload_value,
                "produced_at_unix": produced_at_unix,
                "chain_side_effect": false,
                "custody_side_effect": false,
            })
        );
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_bundled_absence_set(
    raw: &[DualAbsenceRawObservationV1],
    references: &[RelayAbsenceObservationReferenceV1],
    context: &RelayAbsenceContext,
    kind: &str,
    expected_conclusion: &str,
    profile: &SponsorshipFinalityProfile,
    evidence_profile_uri: &str,
    evidence_profile_digest: &str,
    source_effect_digest: &str,
    source_effect_cell_hash: &str,
    source_account: &str,
    source_sequence: u64,
    source_valid_until: u64,
    produced_at_unix: u64,
) -> anyhow::Result<Vec<String>> {
    if raw.len() != references.len()
        || raw.len() < usize::from(profile.minimum_observers)
        || raw.len() > 64
    {
        anyhow::bail!("bundled {kind} absence threshold is incomplete");
    }
    let mut observers = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let mut observation_digests = BTreeSet::new();
    let mut reference_digests = Vec::with_capacity(references.len());
    let first = references.first().context("empty bundled absence set")?;
    let deadline = source_valid_until
        .checked_add(u64::from(profile.reorg_window_seconds))
        .context("bundled absence deadline overflows")?;
    for (raw, reference) in raw.iter().zip(references) {
        let raw_digest =
            protocol_value_digest(DUAL_ABSENCE_OBSERVATION_DOMAIN, &serde_json::to_value(raw)?)?;
        if raw.schema_version != 1
            || raw.observation_kind != kind
            || raw.conclusion != expected_conclusion
            || raw.provider_agent_id != context.provider_agent_id
            || raw.network_digest != context.network_digest
            || raw.relay_stable_action_id != context.relay_stable_action_id
            || raw.relay_exact_request_digest != context.relay_exact_request_digest
            || raw.relay_execution_request_digest != context.relay_execution_digest
            || raw.sponsorship_stable_action_id != context.sponsorship_stable_action_id
            || raw.sponsorship_exact_request_digest != context.sponsorship_exact_request_digest
            || raw.sponsorship_valid_until_unix != context.sponsorship_valid_until_unix
            || raw.signed_transaction_digest != context.signed_transaction.digest
            || raw.signed_transaction_cell_hash != context.signed_transaction.cell_hash
            || raw.transaction_valid_until_unix != u64::from(context.signed_transaction.valid_until)
            || raw.terminal_profile_uri != profile.profile_uri
            || raw.terminal_profile_digest != profile.profile_digest
            || raw.terminal_evidence_class != profile.terminal_evidence_class
            || raw.source_effect_digest != source_effect_digest
            || raw.source_effect_cell_hash != source_effect_cell_hash
            || raw.source_account != source_account
            || raw.signed_source_sequence != source_sequence
            || raw.source_effect_valid_until_unix != source_valid_until
            || raw.exact_message_observed_executed
            || raw.observation_evidence_profile_uri != evidence_profile_uri
            || raw.observation_evidence_profile_digest != evidence_profile_digest
            || raw.observed_at_unix == 0
            || raw.observed_at_unix > produced_at_unix.saturating_add(5 * 60)
            || raw.checkpoint_unix > raw.observed_at_unix.saturating_add(5 * 60)
            || (expected_conclusion != "invalidated_without_inclusion"
                && raw.checkpoint_unix < deadline)
            || (expected_conclusion == "invalidated_without_inclusion"
                && !raw.history_complete_when_required)
        {
            anyhow::bail!("bundled {kind} raw observation conflicts with the exact action");
        }
        if reference.schema_version != 1
            || reference.observation_kind != kind
            || reference.conclusion != expected_conclusion
            || reference.provider_agent_id != context.provider_agent_id
            || reference.network_digest != context.network_digest
            || reference.relay_stable_action_id != context.relay_stable_action_id
            || reference.relay_exact_request_digest != context.relay_exact_request_digest
            || reference.relay_execution_request_digest != context.relay_execution_digest
            || reference.sponsorship_stable_action_id != context.sponsorship_stable_action_id
            || reference.sponsorship_exact_request_digest
                != context.sponsorship_exact_request_digest
            || reference.sponsorship_valid_until_unix != context.sponsorship_valid_until_unix
            || reference.signed_transaction_digest != context.signed_transaction.digest
            || reference.signed_transaction_cell_hash != context.signed_transaction.cell_hash
            || reference.terminal_profile_uri != profile.profile_uri
            || reference.terminal_profile_digest != profile.profile_digest
            || reference.terminal_evidence_class != profile.terminal_evidence_class
            || reference.finalized_checkpoint_id != first.finalized_checkpoint_id
            || reference.finalized_checkpoint_sequence != first.finalized_checkpoint_sequence
            || reference.finalized_checkpoint_unix != first.finalized_checkpoint_unix
            || reference.observer_id != raw.observer_id
            || reference.operator_domain_id != raw.operator_domain_id
            || reference.observation_evidence_profile_uri != evidence_profile_uri
            || reference.observation_evidence_profile_digest != evidence_profile_digest
            || reference.observation_digest != raw_digest
            || reference.observed_at_unix != raw.observed_at_unix
            || (expected_conclusion != "invalidated_without_inclusion"
                && reference.finalized_checkpoint_unix < deadline)
        {
            anyhow::bail!("bundled {kind} absence reference conflicts with its raw proof");
        }
        if !observers.insert(reference.observer_id.clone())
            || !operators.insert(reference.operator_domain_id.clone())
            || !observation_digests.insert(reference.observation_digest.clone())
        {
            anyhow::bail!("bundled {kind} absence repeats an observer, domain, or proof");
        }
        reference_digests.push(observation_reference_digest(reference)?);
    }
    if operators.len() < usize::from(profile.minimum_operator_domains)
        || reference_digests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        anyhow::bail!("bundled {kind} absence is not canonical or diverse enough");
    }
    Ok(reference_digests)
}

impl AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.run_with_scope("dual").await
    }

    async fn run_with_scope(&self, proof_scope: &str) -> anyhow::Result<()> {
        if proof_scope != "dual"
            && proof_scope != "sponsorship_only"
            && proof_scope != "transaction_only"
        {
            anyhow::bail!("unsupported absence verification scope");
        }
        let output_schema = match proof_scope {
            "dual" => DUAL_ABSENCE_VERIFICATION_SCHEMA,
            "sponsorship_only" => SPONSORSHIP_COMPONENT_ABSENCE_VERIFICATION_SCHEMA,
            "transaction_only" => TRANSACTION_COMPONENT_ABSENCE_VERIFICATION_SCHEMA,
            _ => unreachable!("validated proof scope"),
        };
        let (bundle_cbor, wrapper_value) =
            decode_exact_protocol_cbor(Path::new(&self.proof_bundle_cbor))?;
        if bundle_cbor.len() > 128 << 10 {
            anyhow::bail!("dual-absence proof bundle exceeds the released 128 KiB bound");
        }
        let bundle_digest = protocol_cbor_digest(ABSENCE_PROOF_BUNDLE_DOMAIN, &bundle_cbor)?;
        let wrapper: RelayAbsenceProofBundleV1 = serde_json::from_value(wrapper_value)
            .context("decode generic relay absence proof wrapper")?;
        if wrapper.schema_version != 1
            || wrapper.proof_scope != proof_scope
            || wrapper.proof_profile_uri != ABSENCE_PROOF_PROFILE_URI
            || wrapper.proof_profile_digest != absence_proof_profile_digest()?
        {
            anyhow::bail!("Provider absence proof wrapper selects an unsupported profile or scope");
        }
        let payload_cbor = base64::engine::general_purpose::STANDARD
            .decode(&wrapper.proof_payload)
            .context("decode canonical absence proof payload")?;
        if base64::engine::general_purpose::STANDARD.encode(&payload_cbor) != wrapper.proof_payload
            || protocol_cbor_digest(ABSENCE_PROOF_PAYLOAD_DOMAIN, &payload_cbor)?
                != wrapper.proof_payload_digest
        {
            anyhow::bail!("Provider absence proof payload is not canonical or digest-bound");
        }
        let bundle_value = decode_exact_protocol_cbor_bytes(&payload_cbor)?;
        let bundle: DualAbsenceProofBundleV1 = serde_json::from_value(bundle_value.clone())
            .context("decode exact Provider dual-absence proof bundle")?;
        if bundle.proof_scope != proof_scope
            || wrapper.sponsorship_absence_observations != bundle.sponsorship_absence_observations
            || wrapper.transaction_absence_observations != bundle.transaction_absence_observations
            || (proof_scope == "sponsorship_only"
                && (!bundle.transaction_observations.is_empty()
                    || !bundle.transaction_absence_observations.is_empty()))
            || (proof_scope == "transaction_only"
                && (!bundle.sponsorship_observations.is_empty()
                    || !bundle.sponsorship_absence_observations.is_empty()))
        {
            anyhow::bail!("generic absence wrapper conflicts with its exact typed payload");
        }
        let (payment_cbor, payment_value) =
            decode_exact_protocol_cbor(Path::new(&self.agreement_payment_request_cbor))?;
        let payment: SponsorshipAgreementPaymentRequestV3 =
            serde_json::from_value(payment_value.clone())?;
        let payment_digest =
            protocol_cbor_digest(AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN, &payment_cbor)?;
        let payment_exact_request_digest = exact_protocol_action_request_digest(&payment_cbor)?;
        let (_, sponsorship_profile_value, sponsorship_profile) = decode_selected_profile(
            &self.sponsorship_terminal_profile_cbor,
            "sponsorship terminal",
        )?;
        let (relay_profile_value, relay_profile) = match &self.relay_finality_profile_cbor {
            Some(path) => {
                let (_, value, profile) = decode_selected_profile(path, "relay terminal")?;
                (Some(value), Some(profile))
            }
            None => (None, None),
        };
        let (snapshot, loaded, snapshot_threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        validate_lower_finality_profile(&sponsorship_profile, "sponsorship", loaded.len())?;
        if let Some(profile) = &relay_profile {
            validate_lower_finality_profile(profile, "relay", loaded.len())?;
        }
        let (_, _, context) = decode_relay_absence_context(
            &self.relay_execution_request_cbor,
            &payment,
            &payment.stable_action_id,
            &payment_exact_request_digest,
            &sponsorship_profile_value,
            sponsorship_profile,
            relay_profile_value.as_ref(),
            relay_profile,
        )?;
        if snapshot.network_domain != context.network
            || bundle.schema != DUAL_ABSENCE_PROOF_BUNDLE_SCHEMA
            || bundle.network_domain != context.network
            || bundle.network_digest != context.network_digest
            || bundle.agreement_payment_request_digest != payment_digest
            || serde_json::to_value(&bundle.agreement_payment_request)? != payment_value
            || bundle.sponsorship_stable_action_id != context.sponsorship_stable_action_id
            || bundle.sponsorship_exact_request_digest != context.sponsorship_exact_request_digest
            || bundle.sponsorship_valid_until_unix != context.sponsorship_valid_until_unix
            || bundle.relay_execution_request_digest != context.relay_execution_digest
            || bundle.relay_stable_action_id != context.relay_stable_action_id
            || bundle.relay_exact_request_digest != context.relay_exact_request_digest
            || bundle.provider_agent_id != context.provider_agent_id
            || bundle.mode != context.mode
            || bundle.assurance_level != context.assurance_level
            || bundle.signed_transaction_digest != context.signed_transaction.digest
            || bundle.signed_transaction_cell_hash != context.signed_transaction.cell_hash
            || bundle.signed_transaction_source_account != context.signed_transaction.source_account
            || bundle.signed_transaction_source_sequence
                != u64::from(context.signed_transaction.source_sequence)
            || bundle.transaction_valid_until_unix
                != u64::from(context.signed_transaction.valid_until)
            || bundle.sponsorship_terminal_profile != context.sponsorship_terminal_profile
            || bundle.relay_finality_profile != context.relay_finality_profile
            || bundle.evidence_profile_uri != snapshot.evidence_profile_uri
            || bundle.evidence_profile_digest != snapshot.evidence_profile_digest
            || bundle.evidence_profile != snapshot.evidence_profile
            || bundle.produced_at_unix == 0
            || bundle.produced_at_unix > time_format::now().saturating_add(5 * 60)
        {
            anyhow::bail!(
                "Provider dual-absence bundle conflicts with the client-owned exact inputs or public snapshot descriptor"
            );
        }
        validate_sha256_digest("provider snapshot identity", &bundle.provider_snapshot_identity)?;

        let transaction_profile = context
            .relay_finality_profile
            .as_ref()
            .unwrap_or(&context.sponsorship_terminal_profile);
        let expected_transaction_conclusion = match proof_scope {
            "dual" => Some(match bundle.outcome.as_str() {
                "corroborated_expired" => "expired_without_inclusion",
                "corroborated_absent" => "absent",
                "corroborated_invalidated" => "invalidated_without_inclusion",
                _ => {
                    anyhow::bail!("Provider bundle uses an unsupported or upgraded absence outcome")
                }
            }),
            "sponsorship_only" => {
                if bundle.outcome != "corroborated_sponsorship_absent_component" {
                    anyhow::bail!(
                        "Provider sponsorship-component bundle uses an unsupported outcome"
                    );
                }
                None
            }
            "transaction_only" => Some(match bundle.outcome.as_str() {
                "corroborated_transaction_expired" => "expired_without_inclusion",
                "corroborated_transaction_absent" => "absent",
                "corroborated_transaction_invalidated" => "invalidated_without_inclusion",
                _ => {
                    anyhow::bail!(
                        "Provider transaction-component bundle uses an unsupported outcome"
                    )
                }
            }),
            _ => unreachable!("validated proof scope"),
        };

        let mut merged = Vec::new();
        let sponsor_epoch = if proof_scope == "transaction_only" {
            if !bundle.signed_top_up_transaction_boc.is_empty()
                || !bundle.signed_top_up_transaction_digest.is_empty()
                || !bundle.signed_top_up_transaction_cell_hash.is_empty()
                || !bundle.provider_sponsor_source_account.is_empty()
                || bundle.provider_sponsor_source_sequence != 0
            {
                anyhow::bail!(
                    "transaction-component proof smuggles an unverified sponsorship effect"
                );
            }
            None
        } else {
            let top_up = base64::engine::general_purpose::STANDARD
                .decode(&bundle.signed_top_up_transaction_boc)?;
            if base64::engine::general_purpose::STANDARD.encode(&top_up)
                != bundle.signed_top_up_transaction_boc
            {
                anyhow::bail!("Provider top-up BOC is not canonical base64");
            }
            let top_up_source = bundle.provider_sponsor_source_account.parse::<MsgAddressInt>()?;
            let payment_destination =
                base64::engine::general_purpose::STANDARD.decode(&payment.destination)?;
            let payment_destination = String::from_utf8(payment_destination)?;
            let payment_destination_address = payment_destination.parse::<MsgAddressInt>()?;
            let amount = payment.amount.amount_atomic.parse::<u64>()?;
            let epoch = validate_exact_sponsorship_top_up_boc(
                &top_up,
                &bundle.signed_top_up_transaction_boc,
                &bundle.signed_top_up_transaction_digest,
                &bundle.signed_top_up_transaction_cell_hash,
                &top_up_source,
                context.network.global_id,
                u32::try_from(bundle.provider_sponsor_source_sequence)?,
                u32::try_from(bundle.sponsorship_valid_until_unix)?,
                &payment_destination_address,
                amount,
                &payment_digest,
                &payment.stable_action_id,
            )?;
            merged.extend(validate_bundled_absence_set(
                &bundle.sponsorship_observations,
                &bundle.sponsorship_absence_observations,
                &context,
                "sponsorship_action",
                "expired_without_inclusion",
                &context.sponsorship_terminal_profile,
                &bundle.evidence_profile_uri,
                &bundle.evidence_profile_digest,
                &bundle.signed_top_up_transaction_digest,
                &bundle.signed_top_up_transaction_cell_hash,
                &bundle.provider_sponsor_source_account,
                bundle.provider_sponsor_source_sequence,
                bundle.sponsorship_valid_until_unix,
                bundle.produced_at_unix,
            )?);
            Some(epoch)
        };
        if let Some(expected_conclusion) = expected_transaction_conclusion {
            merged.extend(validate_bundled_absence_set(
                &bundle.transaction_observations,
                &bundle.transaction_absence_observations,
                &context,
                "client_transaction",
                expected_conclusion,
                transaction_profile,
                &bundle.evidence_profile_uri,
                &bundle.evidence_profile_digest,
                &context.signed_transaction.digest,
                &context.signed_transaction.cell_hash,
                &context.signed_transaction.source_account,
                u64::from(context.signed_transaction.source_sequence),
                u64::from(context.signed_transaction.valid_until),
                bundle.produced_at_unix,
            )?);
        }
        merged.sort();
        if merged.windows(2).any(|pair| pair[0] == pair[1])
            || evidence_set_digest(&merged)? != bundle.evidence_set_digest
        {
            anyhow::bail!("Provider bundle reuses a proof or changes its evidence-set digest");
        }

        // Fresh client queries use the client's private snapshot bytes. Only
        // the public descriptor/network must match the Provider bundle; the
        // private snapshot identity is intentionally allowed to differ.
        let sponsorship = if proof_scope == "transaction_only" {
            None
        } else {
            Some(
                match produce_absence_set(
                    &loaded,
                    &snapshot,
                    snapshot_threshold,
                    &context,
                    "sponsorship_action",
                    &bundle.signed_top_up_transaction_digest,
                    &bundle.signed_top_up_transaction_cell_hash,
                    &bundle.provider_sponsor_source_account,
                    sponsor_epoch
                        .context("verified sponsorship proof lost its controller epoch")?,
                    u32::try_from(bundle.provider_sponsor_source_sequence)?,
                    bundle.sponsorship_valid_until_unix,
                    &context.sponsorship_terminal_profile,
                )
                .await?
                {
                    DualAbsenceQuery::Terminal(value) => value,
                    DualAbsenceQuery::NotMature(reason) => {
                        print_unknown(output_schema, "not_mature", &reason, Some(&context));
                        return Ok(());
                    }
                    DualAbsenceQuery::TemporarilyUnavailable(reason) => {
                        print_unknown(
                            output_schema,
                            "temporarily_unavailable",
                            &reason,
                            Some(&context),
                        );
                        return Ok(());
                    }
                },
            )
        };
        let transaction = if proof_scope != "sponsorship_only" {
            Some(
                match produce_absence_set(
                    &loaded,
                    &snapshot,
                    snapshot_threshold,
                    &context,
                    "client_transaction",
                    &context.signed_transaction.digest,
                    &context.signed_transaction.cell_hash,
                    &context.signed_transaction.source_account,
                    context.signed_transaction.controller_epoch,
                    context.signed_transaction.source_sequence,
                    u64::from(context.signed_transaction.valid_until),
                    transaction_profile,
                )
                .await?
                {
                    DualAbsenceQuery::Terminal(value) => value,
                    DualAbsenceQuery::NotMature(reason) => {
                        print_unknown(output_schema, "not_mature", &reason, Some(&context));
                        return Ok(());
                    }
                    DualAbsenceQuery::TemporarilyUnavailable(reason) => {
                        print_unknown(
                            output_schema,
                            "temporarily_unavailable",
                            &reason,
                            Some(&context),
                        );
                        return Ok(());
                    }
                },
            )
        } else {
            None
        };
        let fresh_outcome = match (proof_scope, transaction.as_ref().map(|v| v.conclusion.as_str()))
        {
            ("dual", Some("expired_without_inclusion")) => "corroborated_expired",
            ("dual", Some("absent")) => "corroborated_absent",
            ("dual", Some("invalidated_without_inclusion")) => "corroborated_invalidated",
            ("sponsorship_only", None) => "corroborated_sponsorship_absent_component",
            ("transaction_only", Some("expired_without_inclusion")) => {
                "corroborated_transaction_expired"
            }
            ("transaction_only", Some("absent")) => "corroborated_transaction_absent",
            ("transaction_only", Some("invalidated_without_inclusion")) => {
                "corroborated_transaction_invalidated"
            }
            _ => anyhow::bail!("fresh client query returned an unsupported scoped conclusion"),
        };
        if fresh_outcome != bundle.outcome {
            anyhow::bail!("fresh client query disagrees with the Provider absence outcome");
        }
        let mut fresh_digests =
            sponsorship.as_ref().map(|value| value.reference_digests.clone()).unwrap_or_default();
        if let Some(transaction) = &transaction {
            fresh_digests.extend(transaction.reference_digests.clone());
        }
        fresh_digests.sort();
        let fresh_evidence_set_digest = evidence_set_digest(&fresh_digests)?;
        let verified_state = match proof_scope {
            "dual" => "corroborated_absent_verified",
            "sponsorship_only" => "corroborated_sponsorship_absent_verified",
            "transaction_only" => "corroborated_transaction_absent_verified",
            _ => unreachable!("validated proof scope"),
        };
        let terminal_evidence_class = if proof_scope == "transaction_only" {
            transaction_profile.terminal_evidence_class.as_str()
        } else {
            "client_corroborated"
        };
        println!(
            "{}",
            serde_json::json!({
                "schema": output_schema,
                "state": verified_state,
                "outcome": fresh_outcome,
                "terminal_evidence_class": terminal_evidence_class,
                "validator_authenticated_portable_proof": false,
                "network_domain": context.network,
                "network_digest": context.network_digest,
                "agreement_payment_request_digest": payment_digest,
                "sponsorship_stable_action_id": context.sponsorship_stable_action_id,
                "sponsorship_exact_request_digest": context.sponsorship_exact_request_digest,
                "relay_stable_action_id": context.relay_stable_action_id,
                "relay_exact_request_digest": context.relay_exact_request_digest,
                "relay_execution_request_digest": context.relay_execution_digest,
                "provider_snapshot_identity": bundle.provider_snapshot_identity,
                "client_snapshot_identity": snapshot.snapshot_identity,
                "provider_evidence_set_digest": bundle.evidence_set_digest,
                "client_evidence_set_digest": fresh_evidence_set_digest,
                "provider_sponsorship_absence_observations": bundle.sponsorship_absence_observations,
                "provider_transaction_absence_observations": bundle.transaction_absence_observations,
                "sponsorship_absence_observations": sponsorship.as_ref().map(|value| value.references.clone()).unwrap_or_default(),
                "transaction_absence_observations": transaction.as_ref().map(|value| value.references.clone()).unwrap_or_default(),
                "proof_bundle_digest_algorithm": "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic",
                "proof_bundle_digest_domain": ABSENCE_PROOF_BUNDLE_DOMAIN,
                "proof_bundle_digest": bundle_digest,
                "verified_at_unix": time_format::now(),
                "chain_side_effect": false,
                "custody_side_effect": false,
            })
        );
        Ok(())
    }
}

impl AgentAccountEconomicPaymentSponsorshipComponentAbsenceProofVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.input.run_with_scope("sponsorship_only").await
    }
}

impl AgentAccountEconomicPaymentRelayTransactionComponentAbsenceProofVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.input.run_with_scope("transaction_only").await
    }
}

impl AgentAccountEconomicPaymentSponsorshipDualAbsenceCapabilityCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let (_, _, sponsorship_profile) = decode_selected_profile(
            &self.sponsorship_terminal_profile_cbor,
            "sponsorship terminal",
        )?;
        let relay_profile = match &self.relay_finality_profile_cbor {
            Some(path) => Some(decode_selected_profile(path, "relay terminal")?.2),
            None => None,
        };
        let (snapshot, loaded, snapshot_threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        let released_transaction_profile_digest = released_transaction_profile_digest()?;
        validate_lower_finality_profile(&sponsorship_profile, "sponsorship", loaded.len())?;
        if self.underlying_action_kind != "payment.direct"
            || self.transaction_profile_uri != RELAY_TRANSACTION_PROFILE_URI
            || self.transaction_profile_digest != released_transaction_profile_digest
            || self.sponsorship_release_evidence_class != "observed_unproven"
            || self.sponsorship_release_profile_uri != ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI
            || self.sponsorship_release_profile_digest != snapshot.evidence_profile_digest
            || self.sponsorship_terminal_evidence_class != "client_corroborated"
            || sponsorship_profile.profile_uri != SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI
            || sponsorship_profile.terminal_evidence_class != "client_corroborated"
        {
            anyhow::bail!(
                "requested capability tuple is not the released TOS lower-assurance profile"
            );
        }
        match self.mode.as_str() {
            "sponsor_only" => {
                if relay_profile.is_some() || self.relay_terminal_evidence_class.is_some() {
                    anyhow::bail!("sponsor_only capability must not select a relay predicate");
                }
            }
            "sponsor_and_relay" => {
                let profile = relay_profile
                    .as_ref()
                    .context("sponsor_and_relay capability requires relay FinalityProfile")?;
                validate_lower_finality_profile(profile, "relay", loaded.len())?;
                if self.relay_terminal_evidence_class.as_deref() != Some("provider_corroborated") {
                    anyhow::bail!(
                        "combined capability requires provider_corroborated relay evidence"
                    );
                }
            }
            _ => anyhow::bail!("unsupported dual-absence mode"),
        }
        if let Err(error) =
            verify_economic_payment_corroboration_network(&loaded, &snapshot.network_domain).await
        {
            let rendered = format!("{error:#}");
            if sponsorship_rpc_temporarily_unavailable(&rendered) {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": DUAL_ABSENCE_CAPABILITY_SCHEMA,
                        "state": "not_ready",
                        "category": "temporarily_unavailable",
                        "reason": "one or more frozen RPC members cannot currently reproduce the network pin",
                        "mode": self.mode,
                        "assurance_level": self.assurance_level,
                        "role": self.role,
                        "dual_absence": self.mode == "sponsor_and_relay",
                        "sponsorship_component_absence": true,
                        "transaction_component_absence": self.mode == "sponsor_and_relay",
                        "side_effect": false,
                    })
                );
                return Ok(());
            }
            return Err(error.context("frozen RPC capability network mismatch"));
        }
        let network_digest = relay_network_domain_digest(&snapshot.network_domain)?;
        println!(
            "{}",
            serde_json::json!({
                "schema": DUAL_ABSENCE_CAPABILITY_SCHEMA,
                "state": "ready",
                "role": self.role,
                "mode": self.mode,
                "assurance_level": self.assurance_level,
                "network_domain": snapshot.network_domain,
                "network_digest": network_digest,
                "underlying_action_kind": self.underlying_action_kind,
                "transaction_profile_uri": self.transaction_profile_uri,
                "transaction_profile_digest": released_transaction_profile_digest,
                "sponsorship_release_evidence_class": self.sponsorship_release_evidence_class,
                "sponsorship_release_profile_uri": snapshot.evidence_profile_uri,
                "sponsorship_release_profile_digest": snapshot.evidence_profile_digest,
                "sponsorship_terminal_evidence_class": self.sponsorship_terminal_evidence_class,
                "sponsorship_terminal_profile": sponsorship_profile,
                "relay_terminal_evidence_class": self.relay_terminal_evidence_class,
                "relay_finality_profile": relay_profile,
                "snapshot_identity": snapshot.snapshot_identity,
                "snapshot_members": loaded.len(),
                "snapshot_threshold": snapshot_threshold,
                "absence_proof_profile_uri": ABSENCE_PROOF_PROFILE_URI,
                "absence_proof_profile_digest": absence_proof_profile_digest()?,
                "dual_absence": self.mode == "sponsor_and_relay",
                "sponsorship_component_absence": true,
                "transaction_component_absence": self.mode == "sponsor_and_relay",
                "all_reachable_component_outcomes": true,
                "producer_supported": true,
                "independent_verifier_supported": true,
                "validator_authenticated_portable_proof": false,
                "autonomous_decentralized_supported": false,
                "side_effect": false,
            })
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_absence_proof_profile_matches_the_cross_language_vector() {
        assert_eq!(
            absence_proof_profile_digest().expect("released absence proof profile"),
            ABSENCE_PROOF_PROFILE_DIGEST
        );
        assert_eq!(ABSENCE_PROOF_PROFILE_URI, "tos.relay-absence.tosctl-rpc-snapshot.v1");
        assert_ne!(
            ABSENCE_PROOF_PROFILE_URI, ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI,
            "outer absence verifier profile must remain distinct from the frozen observation profile"
        );
    }

    #[test]
    fn dual_aggregation_requires_the_authoritative_component_tombstone() {
        assert!(validate_absence_custody_status("dual", ControllerActionStatus::Resolved).is_ok());
        for status in [
            ControllerActionStatus::Claimed,
            ControllerActionStatus::Signed,
            ControllerActionStatus::Broadcasting,
        ] {
            assert!(validate_absence_custody_status("dual", status).is_err());
        }
        assert!(
            validate_absence_custody_status("sponsorship_only", ControllerActionStatus::Signed)
                .is_ok()
        );
        assert!(
            validate_absence_custody_status(
                "sponsorship_only",
                ControllerActionStatus::Broadcasting
            )
            .is_ok()
        );
    }
}
