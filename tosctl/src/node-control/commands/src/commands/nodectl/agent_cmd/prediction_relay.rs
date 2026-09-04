/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

//! PredictionMarket source-transaction recovery.
//!
//! This deliberately does not reuse the legacy "latest N transactions"
//! resolver.  Every observer walks the account's authenticated previous-
//! transaction chain until it reaches the exact cursor persisted before the
//! broadcast.  A missing link, a different boundary hash, or exhaustion of
//! the owner-selected capacity leaves the action ambiguous.

use super::*;
use chain_block::CommonMsgInfo;
use serde::{Deserialize, Serialize};

const SOURCE_REQUEST_SCHEMA: &str = "tosctl.prediction-relay-source-request.v1";
const SOURCE_EVIDENCE_SCHEMA: &str = "tosctl.prediction-relay-source-evidence.v1";
const PREDICTION_EFFECT_PROFILE: &str = "tos.prediction.checked-call.v1";
const NETWORK_DOMAIN_DIGEST_DOMAIN: &str = "tos.agent-relay-network-domain.v1";
const SOURCE_RECEIPT_DIGEST_DOMAIN: &[u8] = b"tosctl.prediction-source-observer.v1\0";
const SOURCE_VIEW_DIGEST_DOMAIN: &[u8] = b"tosctl.prediction-source-finality-view.v1\0";
const MAX_SOURCE_HISTORY_TRANSACTIONS: u32 = 1_000_000;
const SOURCE_HISTORY_PAGE_SIZE: u32 = 100;

#[derive(clap::Args, Clone)]
#[command(
    about = "Resolve a Prediction source transaction from an exact pre-broadcast cursor and RPC quorum"
)]
pub struct AgentAccountPredictionRelaySourceResolveCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable Prediction action ID")]
    stable_action_id: String,
    #[arg(long, help = "Absolute owner-private source-resolution request JSON")]
    relay_request: String,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Additional absolute tosctl configs; all members need distinct endpoint and operator pins"
    )]
    quorum_configs: Vec<String>,
    #[arg(
        long,
        default_value_t = 100_000,
        help = "Maximum hash-linked source transactions inspected per observer"
    )]
    max_transactions: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionRelaySourceRequest {
    schema: String,
    action_id: String,
    profile: PredictionRelayProfile,
    submitted_external_message_hash: String,
    pre_broadcast_source_cursor: PredictionAccountCursor,
    pre_broadcast_masterchain_checkpoint: PredictionBlockIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionRelayProfile {
    network_domain_hash: String,
    source_agent_account: String,
    source_agent_account_code_hash: String,
    market_address: String,
    market_id: String,
    market_code_hash: String,
    market_config_hash: String,
    observer_ids: Vec<String>,
    quorum_threshold: u32,
    maximum_outstanding: u32,
    maximum_signed_boc_bytes: u32,
    minimum_no_bounce_masterchain_blocks: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionAccountCursor {
    account_address: String,
    last_logical_time: u64,
    last_transaction_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionBlockIdentity {
    workchain_id: i32,
    shard: i64,
    sequence_number: u32,
    root_hash: String,
    file_hash: String,
    masterchain_sequence_number: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionQuorumFinality {
    network_domain_hash: String,
    finality_view_id: String,
    observer_ids: Vec<String>,
    agreeing_ids: Vec<String>,
    threshold: u32,
    masterchain_seqno: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionObservedMessage {
    message_hash: String,
    exact_message_boc_base64: String,
    source_address: String,
    destination_address: String,
    value_nanotos: u64,
    body_boc_base64: String,
    body_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    state_init_boc_base64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    state_init_hash: String,
    bounce: bool,
    bounced: bool,
    extra_flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PredictionSourceTransactionEvidence {
    submitted_external_message_hash: String,
    transaction_hash: String,
    transaction_boc_base64: String,
    block: PredictionBlockIdentity,
    finality: PredictionQuorumFinality,
    next_source_cursor: PredictionAccountCursor,
    outbound_messages: Vec<PredictionObservedMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PredictionSourceCandidate {
    transaction_hash: String,
    transaction_boc_base64: String,
    block_workchain: i32,
    block_shard: i64,
    block_seqno: u32,
    block_root_hash: String,
    block_file_hash: String,
    next_source_cursor: PredictionAccountCursor,
    outbound_messages: Vec<PredictionObservedMessage>,
}

impl PredictionSourceCandidate {
    fn quorum_key(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PredictionSourceObserverReceipt {
    observer_id: String,
    operator_provenance: String,
    observed_masterchain: PredictionBlockIdentity,
    finalized_deployment_id: String,
    finalized_controller_epoch: u64,
    finalized_seqno: u32,
    candidate_digest: String,
}

#[derive(Clone, Debug)]
struct PredictionSourceObservation {
    candidate: PredictionSourceCandidate,
    receipt: PredictionSourceObserverReceipt,
}

#[derive(Clone, Debug)]
struct ParsedHistoryStep {
    transaction_lt: u64,
    transaction_hash: [u8; 32],
    previous_lt: u64,
    previous_hash: [u8; 32],
    candidate: Option<PredictionSourceCandidate>,
}

#[derive(Clone, Debug)]
struct SourceHistoryWalk {
    expected_lt: u64,
    expected_hash: [u8; 32],
    boundary_lt: u64,
    boundary_hash: [u8; 32],
    inspected: u32,
    found: Option<PredictionSourceCandidate>,
    reached_boundary: bool,
}

impl SourceHistoryWalk {
    fn new(
        head_lt: u64,
        head_hash: [u8; 32],
        boundary_lt: u64,
        boundary_hash: [u8; 32],
    ) -> anyhow::Result<Self> {
        if head_lt < boundary_lt || (head_lt == 0) != (head_hash == [0; 32]) {
            anyhow::bail!("source account head predates or contradicts the durable cursor");
        }
        Ok(Self {
            expected_lt: head_lt,
            expected_hash: head_hash,
            boundary_lt,
            boundary_hash,
            inspected: 0,
            found: None,
            reached_boundary: false,
        })
    }

    fn consume(&mut self, step: ParsedHistoryStep) -> anyhow::Result<()> {
        if self.reached_boundary
            || step.transaction_lt != self.expected_lt
            || step.transaction_hash != self.expected_hash
        {
            anyhow::bail!("source account history is not one continuous authenticated chain");
        }
        if step.transaction_lt == self.boundary_lt {
            if step.transaction_hash != self.boundary_hash {
                anyhow::bail!("source account history reached a different pre-broadcast fork");
            }
            self.reached_boundary = true;
            return Ok(());
        }
        if step.transaction_lt < self.boundary_lt {
            anyhow::bail!("source account history skipped the durable pre-broadcast cursor");
        }
        self.inspected =
            self.inspected.checked_add(1).context("source history inspection count overflow")?;
        if let Some(candidate) = step.candidate {
            if self.found.replace(candidate).is_some() {
                anyhow::bail!(
                    "exact submitted external message appears in multiple source transactions"
                );
            }
        }
        if step.previous_lt == 0 {
            if self.boundary_lt != 0 || step.previous_hash != [0; 32] {
                anyhow::bail!("source account history terminated before the durable cursor");
            }
            self.reached_boundary = true;
            return Ok(());
        }
        if step.previous_lt >= step.transaction_lt {
            anyhow::bail!("source transaction previous cursor is not strictly older");
        }
        self.expected_lt = step.previous_lt;
        self.expected_hash = step.previous_hash;
        Ok(())
    }
}

impl AgentAccountPredictionRelaySourceResolveCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        anyhow::ensure!(
            (1..=MAX_SOURCE_HISTORY_TRANSACTIONS).contains(&self.max_transactions),
            "max_transactions must be between 1 and {MAX_SOURCE_HISTORY_TRANSACTIONS}"
        );
        let request_path = Path::new(&self.relay_request);
        anyhow::ensure!(request_path.is_absolute(), "relay-request must be an absolute path");
        let request_bytes = open_private_snapshot_file(request_path)?;
        anyhow::ensure!(
            !request_bytes.is_empty() && request_bytes.len() <= 1 << 20,
            "Prediction source request has an invalid size"
        );
        let mut decoder = serde_json::Deserializer::from_slice(&request_bytes);
        let request = PredictionRelaySourceRequest::deserialize(&mut decoder)
            .context("decode Prediction source request")?;
        decoder.end().context("Prediction source request has trailing JSON")?;

        let primary_path = Path::new(config_path);
        let members =
            load_economic_payment_corroboration_members(primary_path, &self.quorum_configs)?;
        validate_source_request(&request, &self.stable_action_id, &members)?;
        let primary = &members[0].config;
        let agent_wallet = primary
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        anyhow::ensure!(
            account.to_string() == request.profile.source_agent_account,
            "Prediction request source differs from the selected Agent Wallet"
        );
        let journal = open_economic_controller_journal(
            &members[0].canonical_path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let record = journal
            .find_economic_effect_by_stable_action(&self.stable_action_id)?
            .context("prepared Prediction effect was not found")?;
        validate_prediction_custody_record(&record, &request)?;

        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .context("resolved Prediction source has no replayable evidence")?;
            anyhow::ensure!(
                resolution.evidence_kind == SOURCE_EVIDENCE_SCHEMA,
                "Prediction action was resolved under a different evidence profile"
            );
            println!("{}", resolution.evidence);
            return Ok(());
        }
        anyhow::ensure!(
            record.status == ControllerActionStatus::Broadcasting,
            "only an ambiguously broadcast Prediction action may resolve its source"
        );
        let expected_network = record
            .claim
            .network_domain
            .as_ref()
            .context("Prediction custody record has no network-domain pin")?;
        let mut observations = Vec::new();
        let mut failures = Vec::new();
        for member in &members {
            match observe_prediction_source(
                member,
                expected_network,
                &account,
                &record,
                &request,
                self.max_transactions,
            )
            .await
            {
                Ok(observation) => observations.push(observation),
                Err(error) => failures.push(rpc_failure_diagnostic(&member.endpoint, &error)),
            }
        }
        let mut votes: BTreeMap<String, Vec<&PredictionSourceObservation>> = BTreeMap::new();
        for observation in &observations {
            votes.entry(observation.candidate.quorum_key()?).or_default().push(observation);
        }
        let winner = votes
            .values()
            .max_by_key(|group| group.len())
            .filter(|group| group.len() >= request.profile.quorum_threshold as usize)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Prediction source has no configured exact-evidence quorum; observations={}; failures={}",
                    observations.len(),
                    serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
                )
            })?;
        let candidate = winner[0].candidate.clone();
        let masterchain_seqno = winner
            .iter()
            .map(|value| value.receipt.observed_masterchain.sequence_number)
            .min()
            .context("Prediction source quorum has no finality head")?;
        let (finalized_controller_epoch, finalized_seqno) = winner
            .iter()
            .map(|value| (value.receipt.finalized_controller_epoch, value.receipt.finalized_seqno))
            .min()
            .context("Prediction source quorum has no finalized Agent Account state")?;
        anyhow::ensure!(
            masterchain_seqno >= request.pre_broadcast_masterchain_checkpoint.sequence_number,
            "Prediction source quorum did not advance past its durable checkpoint"
        );
        let mut agreeing_ids =
            winner.iter().map(|value| value.receipt.observer_id.clone()).collect::<Vec<_>>();
        agreeing_ids.sort();
        let mut receipts = winner.iter().map(|value| value.receipt.clone()).collect::<Vec<_>>();
        receipts.sort_by(|left, right| left.observer_id.cmp(&right.observer_id));
        let finality_view = serde_json::json!({
            "network_domain_hash": request.profile.network_domain_hash,
            "observer_ids": request.profile.observer_ids,
            "agreeing_ids": agreeing_ids,
            "threshold": request.profile.quorum_threshold,
            "masterchain_seqno": masterchain_seqno,
            "candidate": candidate,
            "receipts": receipts,
        });
        let finality_view_id = economic_payment_observation_digest(
            SOURCE_VIEW_DIGEST_DOMAIN,
            &recursively_sorted_json(finality_view),
        )?;
        let source_evidence = PredictionSourceTransactionEvidence {
            submitted_external_message_hash: request.submitted_external_message_hash.clone(),
            transaction_hash: candidate.transaction_hash.clone(),
            transaction_boc_base64: candidate.transaction_boc_base64.clone(),
            block: PredictionBlockIdentity {
                workchain_id: candidate.block_workchain,
                shard: candidate.block_shard,
                sequence_number: candidate.block_seqno,
                root_hash: candidate.block_root_hash.clone(),
                file_hash: candidate.block_file_hash.clone(),
                masterchain_sequence_number: masterchain_seqno,
            },
            finality: PredictionQuorumFinality {
                network_domain_hash: request.profile.network_domain_hash.clone(),
                finality_view_id,
                observer_ids: request.profile.observer_ids.clone(),
                agreeing_ids,
                threshold: request.profile.quorum_threshold,
                masterchain_seqno,
            },
            next_source_cursor: candidate.next_source_cursor,
            outbound_messages: candidate.outbound_messages,
        };
        let output = serde_json::json!({
            "schema": SOURCE_EVIDENCE_SCHEMA,
            "stable_action_id": self.stable_action_id,
            "source_evidence": source_evidence,
            "observer_receipts": receipts,
            "failures": failures,
            "state": if source_evidence.outbound_messages.is_empty() {
                "source_action_skipped"
            } else {
                "source_finalized"
            },
        });

        // Resolving custody before stdout is the no-rebroadcast boundary.  A
        // crash after this write replays the identical stored evidence.
        let exact_digest = record
            .exact_signed_boc_digest
            .as_deref()
            .context("Prediction custody record has no exact signed BOC digest")?;
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: SOURCE_EVIDENCE_SCHEMA.to_owned(),
            evidence_digest: controller_resolution_evidence_digest(
                SOURCE_EVIDENCE_SCHEMA,
                &output,
            )?,
            evidence: output,
        };
        let resolved = journal.resolve_exact_winner(
            &record.claim,
            exact_digest,
            finalized_controller_epoch,
            finalized_seqno,
            resolution,
            time_format::now(),
        )?;
        println!(
            "{}",
            resolved
                .exact_winner_resolution
                .context("resolved Prediction source lost its durable evidence")?
                .evidence
        );
        Ok(())
    }
}

fn validate_source_request(
    request: &PredictionRelaySourceRequest,
    stable_action_id: &str,
    members: &[LoadedEconomicPaymentCorroborationMember],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.schema == SOURCE_REQUEST_SCHEMA && request.action_id == stable_action_id,
        "Prediction source request identity is invalid"
    );
    validate_sha256_digest("action_id", &request.action_id)?;
    validate_sha256_digest("network_domain_hash", &request.profile.network_domain_hash)?;
    validate_sha256_digest("market_id", &request.profile.market_id)?;
    validate_cell_digest(
        "source_agent_account_code_hash",
        &request.profile.source_agent_account_code_hash,
    )?;
    validate_cell_digest("market_code_hash", &request.profile.market_code_hash)?;
    validate_cell_digest("market_config_hash", &request.profile.market_config_hash)?;
    validate_cell_digest(
        "submitted_external_message_hash",
        &request.submitted_external_message_hash,
    )?;
    let _: MsgAddressInt = request.profile.source_agent_account.parse()?;
    let _: MsgAddressInt = request.profile.market_address.parse()?;
    anyhow::ensure!(
        request.profile.source_agent_account != request.profile.market_address
            && request.pre_broadcast_source_cursor.account_address
                == request.profile.source_agent_account
            && request.profile.maximum_outstanding > 0
            && request.profile.maximum_outstanding <= 100_000
            && request.profile.maximum_signed_boc_bytes > 0
            && request.profile.maximum_signed_boc_bytes <= 1 << 20
            && request.profile.minimum_no_bounce_masterchain_blocks > 0
            && request.profile.minimum_no_bounce_masterchain_blocks <= 1_000_000,
        "Prediction relay profile or source cursor is invalid"
    );
    if request.pre_broadcast_source_cursor.last_logical_time == 0 {
        anyhow::ensure!(
            request.pre_broadcast_source_cursor.last_transaction_hash.is_empty(),
            "zero source cursor carries a transaction hash"
        );
    } else {
        validate_sha256_digest(
            "pre_broadcast_source_cursor.last_transaction_hash",
            &request.pre_broadcast_source_cursor.last_transaction_hash,
        )?;
    }
    let checkpoint = &request.pre_broadcast_masterchain_checkpoint;
    anyhow::ensure!(
        checkpoint.workchain_id == -1
            && checkpoint.sequence_number != 0
            && checkpoint.sequence_number == checkpoint.masterchain_sequence_number,
        "Prediction pre-broadcast checkpoint is not a masterchain identity"
    );
    validate_sha256_digest("checkpoint.root_hash", &checkpoint.root_hash)?;
    validate_sha256_digest("checkpoint.file_hash", &checkpoint.file_hash)?;

    let mut configured_ids =
        members.iter().map(|member| member.locator_identity_digest.clone()).collect::<Vec<_>>();
    configured_ids.sort();
    let mut supplied_ids = request.profile.observer_ids.clone();
    supplied_ids.sort();
    anyhow::ensure!(
        supplied_ids == request.profile.observer_ids
            && supplied_ids.windows(2).all(|pair| pair[0] < pair[1])
            && supplied_ids == configured_ids
            && request.profile.quorum_threshold as usize > supplied_ids.len() / 2
            && request.profile.quorum_threshold as usize <= supplied_ids.len(),
        "Prediction observer set or threshold differs from the frozen RPC capability"
    );
    for observer in &supplied_ids {
        validate_sha256_digest("observer_id", observer)?;
    }
    Ok(())
}

fn validate_prediction_custody_record(
    record: &ControllerActionRecord,
    request: &PredictionRelaySourceRequest,
) -> anyhow::Result<()> {
    let authorization = record
        .economic_effect_authorization
        .as_ref()
        .context("custody action is not an economic effect")?;
    let network = record
        .claim
        .network_domain
        .as_ref()
        .context("Prediction custody action has no network-domain pin")?;
    let network_digest = prediction_network_domain_digest(network)?;
    anyhow::ensure!(
        authorization.profile == PREDICTION_EFFECT_PROFILE
            && authorization.stable_action_id == request.action_id
            && record.claim.action_identity == request.action_id
            && record.claim.action_kind == "agent-checked-contract-call-v2"
            && record.claim.account == request.profile.source_agent_account
            && authorization.source_account == record.claim.account
            && authorization.source_agent_account_code_hash
                == request.profile.source_agent_account_code_hash
            && record.claim.target == request.profile.market_address
            && authorization.market_address == request.profile.market_address
            && authorization.market_id == request.profile.market_id
            && authorization.market_code_hash == request.profile.market_code_hash
            && authorization.market_config_hash == request.profile.market_config_hash
            && record.claim.value_atomic == authorization.amount_nanotos
            && record.claim.body_hash.as_deref() == Some(authorization.body_hash.as_str())
            && record.claim.state_init_hash.is_none()
            && network_digest == request.profile.network_domain_hash,
        "Prediction relay request conflicts with durable custody authority"
    );
    let Some(encoded) = record.exact_signed_boc_base64.as_ref() else {
        anyhow::ensure!(
            record.status == ControllerActionStatus::Resolved
                && record.exact_winner_resolution.as_ref().is_some_and(|resolution| {
                    resolution.evidence_kind == SOURCE_EVIDENCE_SCHEMA
                        && resolution
                            .evidence
                            .get("stable_action_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(request.action_id.as_str())
                        && resolution
                            .evidence
                            .pointer("/source_evidence/submitted_external_message_hash")
                            .and_then(serde_json::Value::as_str)
                            == Some(request.submitted_external_message_hash.as_str())
                }),
            "resolved Prediction custody record has no matching source evidence"
        );
        return Ok(());
    };
    let boc = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode Prediction custody exact BOC")?;
    let root = read_single_root_boc(&boc).context("parse Prediction custody exact BOC")?;
    anyhow::ensure!(
        boc.len() <= request.profile.maximum_signed_boc_bytes as usize,
        "Prediction custody BOC exceeds the frozen relay profile"
    );
    let exact_boc_digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
    anyhow::ensure!(
        record.exact_signed_boc_digest.as_deref() == Some(exact_boc_digest.as_str())
            && format!("tvm-cell-sha256:{}", hex::encode(root.hash(0)))
                == request.submitted_external_message_hash,
        "Prediction request does not identify the custody-signed external message"
    );
    Ok(())
}

async fn observe_prediction_source(
    member: &LoadedEconomicPaymentCorroborationMember,
    expected_network: &RelayNetworkDomainPin,
    account: &MsgAddressInt,
    record: &ControllerActionRecord,
    request: &PredictionRelaySourceRequest,
    maximum: u32,
) -> anyhow::Result<PredictionSourceObservation> {
    let rpc = try_create_rpc_client(&member.config).await?;
    rpc.verify_pinned_primary_network(expected_network).await?;
    verify_prediction_checkpoint(&rpc, &request.pre_broadcast_masterchain_checkpoint).await?;
    let info = rpc.get_address_information(account).await?;
    verify_prediction_source_code(&info, &request.profile.source_agent_account_code_hash)?;
    let head_hash: [u8; 32] = info
        .last_transaction_id
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("source account head hash is not 32 bytes"))?;
    let boundary_hash = if request.pre_broadcast_source_cursor.last_logical_time == 0 {
        [0; 32]
    } else {
        parse_sha256_digest(&request.pre_broadcast_source_cursor.last_transaction_hash)?
    };
    let mut walk = SourceHistoryWalk::new(
        info.last_transaction_id.lt,
        head_hash,
        request.pre_broadcast_source_cursor.last_logical_time,
        boundary_hash,
    )?;

    while !walk.reached_boundary {
        let remaining = maximum - walk.inspected;
        let limit = remaining.saturating_add(1).min(SOURCE_HISTORY_PAGE_SIZE).max(1);
        let cursor_hash = base64::engine::general_purpose::STANDARD.encode(walk.expected_hash);
        let page = rpc.get_transactions(account, walk.expected_lt, &cursor_hash, limit).await?;
        anyhow::ensure!(
            !page.transactions.is_empty(),
            "Prediction source history ended before its durable cursor"
        );
        for raw in page.transactions {
            let step = parse_prediction_source_history_step(account, record, request, raw)?;
            anyhow::ensure!(
                walk.inspected < maximum || step.transaction_lt == walk.boundary_lt,
                "Prediction source history capacity was exhausted before its durable cursor"
            );
            walk.consume(step)?;
            if walk.reached_boundary {
                break;
            }
        }
    }
    let candidate = walk.found.context(
        "exact submitted Prediction message is not yet present after the durable cursor",
    )?;
    let provider = contracts::contract_provider!(rpc.clone());
    let finalized = AgentAccountContract::get_data(provider.as_ref(), account).await?;
    let finalized_deployment_id = hex::encode(finalized.deployment_id);
    anyhow::ensure!(
        finalized_deployment_id == record.claim.deployment_id
            && (finalized.controller_epoch, finalized.seqno)
                > (record.claim.controller_epoch, record.claim.seqno),
        "observer Agent Account state has not consumed the exact Prediction sequence"
    );
    let master = rpc.get_masterchain_info().await?;
    anyhow::ensure!(
        master.last.seqno >= request.pre_broadcast_masterchain_checkpoint.sequence_number,
        "observer masterchain head predates the Prediction checkpoint"
    );
    let observed_masterchain = block_identity_from_rpc(&master.last, master.last.seqno)?;
    let candidate_digest = economic_payment_observation_digest(
        SOURCE_RECEIPT_DIGEST_DOMAIN,
        &recursively_sorted_json(serde_json::json!({
            "observer_id": member.locator_identity_digest,
            "operator_provenance": member.operator_provenance,
            "observed_masterchain": observed_masterchain,
            "finalized_deployment_id": finalized_deployment_id,
            "finalized_controller_epoch": finalized.controller_epoch,
            "finalized_seqno": finalized.seqno,
            "candidate": candidate,
        })),
    )?;
    Ok(PredictionSourceObservation {
        candidate,
        receipt: PredictionSourceObserverReceipt {
            observer_id: member.locator_identity_digest.clone(),
            operator_provenance: member.operator_provenance.clone(),
            observed_masterchain,
            finalized_deployment_id,
            finalized_controller_epoch: finalized.controller_epoch,
            finalized_seqno: finalized.seqno,
            candidate_digest,
        },
    })
}

fn parse_prediction_source_history_step(
    account: &MsgAddressInt,
    record: &ControllerActionRecord,
    request: &PredictionRelaySourceRequest,
    raw: chain_rpc_client::v2::data_models::RawTransaction,
) -> anyhow::Result<ParsedHistoryStep> {
    anyhow::ensure!(!raw.data.is_empty(), "source transaction omitted its BOC");
    let transaction_boc = base64::engine::general_purpose::STANDARD
        .decode(&raw.data)
        .context("decode source transaction BOC")?;
    let root = read_single_root_boc(&transaction_boc).context("parse source transaction BOC")?;
    anyhow::ensure!(
        write_boc(&root)? == transaction_boc,
        "source transaction BOC is not canonical"
    );
    let transaction =
        Transaction::construct_from_cell(root.clone()).context("decode source transaction")?;
    let block = raw.block_id.context("source transaction has no block identity")?;
    let transaction_hash = *root.hash(0).as_slice();
    let wrapper_hash = base64::engine::general_purpose::STANDARD
        .decode(&raw.hash)
        .context("decode source transaction wrapper hash")?;
    anyhow::ensure!(
        wrapper_hash.as_slice() == transaction_hash
            && raw.lt == transaction.logical_time()
            && raw.utime == transaction.now()
            && transaction.account_id() == account.address()
            && block.workchain == account.workchain_id(),
        "source transaction wrapper contradicts its hash-bound BOC"
    );
    let in_cell = transaction.in_msg_cell().context("source transaction has no inbound message")?;
    let candidate = if format!("tvm-cell-sha256:{}", hex::encode(in_cell.hash(0)))
        == request.submitted_external_message_hash
    {
        Some(prediction_source_candidate(
            account,
            record,
            block,
            &transaction,
            &transaction_boc,
            transaction_hash,
            in_cell,
        )?)
    } else {
        None
    };
    let previous_hash = *transaction.prev_trans_hash().as_slice();
    Ok(ParsedHistoryStep {
        transaction_lt: transaction.logical_time(),
        transaction_hash,
        previous_lt: transaction.prev_trans_lt(),
        previous_hash,
        candidate,
    })
}

fn prediction_source_candidate(
    account: &MsgAddressInt,
    record: &ControllerActionRecord,
    block: chain_rpc_client::v2::data_models::BlockIdExt,
    transaction: &Transaction,
    transaction_boc: &[u8],
    transaction_hash: [u8; 32],
    inbound_cell: Cell,
) -> anyhow::Result<PredictionSourceCandidate> {
    let inbound = Message::construct_from_cell(inbound_cell)?;
    anyhow::ensure!(
        inbound.is_inbound_external() && inbound.dst().as_ref() == Some(account),
        "exact submitted Prediction message is not an external inbound to its source"
    );
    let description = transaction.read_description()?;
    let ordinary = match description {
        TransactionDescr::Ordinary(value) => value,
        _ => anyhow::bail!("Prediction Agent Account source transaction is not ordinary"),
    };
    anyhow::ensure!(
        !ordinary.aborted
            && ordinary.compute_ph.is_success().is_some()
            && ordinary.action.as_ref().is_some_and(|phase| phase.success),
        "Prediction Agent Account source transaction did not execute successfully"
    );
    let mut outputs = Vec::new();
    transaction.iterate_out_msgs(|message| {
        outputs.push(message);
        Ok(true)
    })?;
    anyhow::ensure!(
        outputs.len() == transaction.msg_count() as usize && outputs.len() <= 1,
        "Prediction source transaction has an unexpected outbound set"
    );
    let outbound_messages = outputs
        .iter()
        .map(|message| prediction_observed_checked_call(account, record, message))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let block_identity = block_identity_from_rpc(&block, 0)?;
    Ok(PredictionSourceCandidate {
        transaction_hash: format!("sha256:{}", hex::encode(transaction_hash)),
        transaction_boc_base64: base64::engine::general_purpose::STANDARD.encode(transaction_boc),
        block_workchain: block_identity.workchain_id,
        block_shard: block_identity.shard,
        block_seqno: block_identity.sequence_number,
        block_root_hash: block_identity.root_hash,
        block_file_hash: block_identity.file_hash,
        next_source_cursor: PredictionAccountCursor {
            account_address: account.to_string(),
            last_logical_time: transaction.logical_time(),
            last_transaction_hash: format!("sha256:{}", hex::encode(transaction_hash)),
        },
        outbound_messages,
    })
}

fn prediction_observed_checked_call(
    source: &MsgAddressInt,
    record: &ControllerActionRecord,
    message: &Message,
) -> anyhow::Result<PredictionObservedMessage> {
    let header = match message.header() {
        CommonMsgInfo::IntMsgInfo(value) => value,
        _ => anyhow::bail!("Prediction source output is not internal"),
    };
    let body =
        message.body().cloned().context("Prediction source output has no body")?.into_cell()?;
    let body_boc = write_boc(&body)?;
    let body_hash = format!("tvm-cell-sha256:{}", hex::encode(body.hash(0)));
    let amount =
        header.value.coins.as_u64().context("Prediction source output value exceeds u64")?;
    let extra_flags =
        header.extra_flags.as_u64().context("Prediction source output extra_flags exceed u64")?;
    anyhow::ensure!(
        header.ihr_disabled
            && header.bounce
            && !header.bounced
            && header.src_ref() == Some(source)
            && header.dst.to_string() == record.claim.target
            && amount == record.claim.value_atomic
            && header.value.other.is_empty()
            && extra_flags == 3
            && message.state_init().is_none()
            && record.claim.state_init_hash.is_none()
            && record.claim.body_hash.as_deref() == Some(body_hash.as_str()),
        "Prediction source output differs from the custody-authorized checked call"
    );
    let message_cell = message.serialize()?;
    let message_boc = write_boc(&message_cell)?;
    Ok(PredictionObservedMessage {
        message_hash: format!("tvm-cell-sha256:{}", hex::encode(message_cell.hash(0))),
        exact_message_boc_base64: base64::engine::general_purpose::STANDARD.encode(message_boc),
        source_address: source.to_string(),
        destination_address: header.dst.to_string(),
        value_nanotos: amount,
        body_boc_base64: base64::engine::general_purpose::STANDARD.encode(body_boc),
        body_hash,
        state_init_boc_base64: String::new(),
        state_init_hash: String::new(),
        bounce: header.bounce,
        bounced: header.bounced,
        extra_flags,
    })
}

async fn verify_prediction_checkpoint(
    rpc: &chain_rpc_client::v2::client_json_rpc::ClientJsonRpc,
    expected: &PredictionBlockIdentity,
) -> anyhow::Result<()> {
    let actual = rpc
        .lookup_block(expected.workchain_id, &expected.shard.to_string(), expected.sequence_number)
        .await?;
    let actual = block_identity_from_rpc(&actual, expected.sequence_number)?;
    anyhow::ensure!(
        actual.workchain_id == expected.workchain_id
            && actual.shard == expected.shard
            && actual.sequence_number == expected.sequence_number
            && actual.root_hash == expected.root_hash
            && actual.file_hash == expected.file_hash,
        "RPC member is not on the durable Prediction checkpoint fork"
    );
    Ok(())
}

fn verify_prediction_source_code(
    info: &chain_rpc_client::v2::data_models::GetAddressInformationRes,
    expected: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        info.state == AccountState::Active && info.extra_currencies.is_empty(),
        "Prediction source account is not an active native-TOS account"
    );
    let code = info.code.as_ref().context("Prediction source account has no code")?;
    let root = read_single_root_boc(code).context("parse Prediction source account code")?;
    anyhow::ensure!(
        format!("tvm-cell-sha256:{}", hex::encode(root.hash(0))) == expected,
        "Prediction source account code differs from the frozen relay profile"
    );
    Ok(())
}

fn block_identity_from_rpc(
    block: &chain_rpc_client::v2::data_models::BlockIdExt,
    masterchain_sequence_number: u32,
) -> anyhow::Result<PredictionBlockIdentity> {
    anyhow::ensure!(
        block.seqno != 0 && block.root_hash.len() == 32 && block.file_hash.len() == 32,
        "RPC block identity is incomplete"
    );
    Ok(PredictionBlockIdentity {
        workchain_id: block.workchain,
        shard: block.shard,
        sequence_number: block.seqno,
        root_hash: format!("sha256:{}", hex::encode(&block.root_hash)),
        file_hash: format!("sha256:{}", hex::encode(&block.file_hash)),
        masterchain_sequence_number,
    })
}

fn prediction_network_domain_digest(network: &RelayNetworkDomainPin) -> anyhow::Result<String> {
    let value = serde_json::json!({
        "network_id": network.network_id,
        "global_id": network.global_id,
        "zero_state_root_hash": network.zero_state_root_hash,
        "zero_state_file_hash": network.zero_state_file_hash,
        "workchain_id": network.workchain_id,
    });
    let mut canonical = Vec::new();
    encode_protocol_json_cbor(&value, &mut canonical, 0)?;
    protocol_cbor_digest(NETWORK_DOMAIN_DIGEST_DOMAIN, &canonical)
}

fn validate_cell_digest(name: &str, value: &str) -> anyhow::Result<()> {
    let hex = value
        .strip_prefix("tvm-cell-sha256:")
        .with_context(|| format!("{name} is not a TVM cell digest"))?;
    anyhow::ensure!(
        hex.len() == 64
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{name} is not canonical"
    );
    Ok(())
}

fn parse_sha256_digest(value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.strip_prefix("sha256:").context("digest has no sha256 prefix")?;
    let bytes = hex::decode(value).context("decode sha256 digest")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("sha256 digest is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(index: u32) -> [u8; 32] {
        Sha256::digest(index.to_be_bytes()).into()
    }

    #[test]
    fn source_walk_crosses_more_than_ten_thousand_transactions() {
        let newest = 20_100u32;
        let boundary = 10_099u32;
        let mut walk = SourceHistoryWalk::new(
            u64::from(newest),
            test_hash(newest),
            u64::from(boundary),
            test_hash(boundary),
        )
        .unwrap();
        for index in (boundary..=newest).rev() {
            let candidate = (index == newest).then(|| PredictionSourceCandidate {
                transaction_hash: format!("sha256:{}", hex::encode(test_hash(index))),
                transaction_boc_base64: "boc".into(),
                block_workchain: 0,
                block_shard: 1,
                block_seqno: 1,
                block_root_hash: format!("sha256:{}", "1".repeat(64)),
                block_file_hash: format!("sha256:{}", "2".repeat(64)),
                next_source_cursor: PredictionAccountCursor {
                    account_address: "0:source".into(),
                    last_logical_time: u64::from(index),
                    last_transaction_hash: format!("sha256:{}", hex::encode(test_hash(index))),
                },
                outbound_messages: Vec::new(),
            });
            let previous = index.saturating_sub(1);
            walk.consume(ParsedHistoryStep {
                transaction_lt: u64::from(index),
                transaction_hash: test_hash(index),
                previous_lt: u64::from(previous),
                previous_hash: test_hash(previous),
                candidate,
            })
            .unwrap();
        }
        assert!(walk.reached_boundary);
        assert_eq!(walk.inspected, 10_001);
        assert!(walk.found.is_some());
    }

    #[test]
    fn source_walk_rejects_forked_boundary_and_duplicate_inclusion() {
        let mut fork = SourceHistoryWalk::new(2, test_hash(2), 1, test_hash(1)).unwrap();
        fork.consume(ParsedHistoryStep {
            transaction_lt: 2,
            transaction_hash: test_hash(2),
            previous_lt: 1,
            previous_hash: test_hash(9),
            candidate: None,
        })
        .unwrap();
        assert!(
            fork.consume(ParsedHistoryStep {
                transaction_lt: 1,
                transaction_hash: test_hash(9),
                previous_lt: 0,
                previous_hash: [0; 32],
                candidate: None,
            })
            .is_err()
        );

        let candidate = PredictionSourceCandidate {
            transaction_hash: format!("sha256:{}", "1".repeat(64)),
            transaction_boc_base64: "boc".into(),
            block_workchain: 0,
            block_shard: 1,
            block_seqno: 1,
            block_root_hash: format!("sha256:{}", "2".repeat(64)),
            block_file_hash: format!("sha256:{}", "3".repeat(64)),
            next_source_cursor: PredictionAccountCursor {
                account_address: "0:source".into(),
                last_logical_time: 3,
                last_transaction_hash: format!("sha256:{}", "1".repeat(64)),
            },
            outbound_messages: Vec::new(),
        };
        let mut duplicate = SourceHistoryWalk::new(3, test_hash(3), 1, test_hash(1)).unwrap();
        duplicate
            .consume(ParsedHistoryStep {
                transaction_lt: 3,
                transaction_hash: test_hash(3),
                previous_lt: 2,
                previous_hash: test_hash(2),
                candidate: Some(candidate.clone()),
            })
            .unwrap();
        assert!(
            duplicate
                .consume(ParsedHistoryStep {
                    transaction_lt: 2,
                    transaction_hash: test_hash(2),
                    previous_lt: 1,
                    previous_hash: test_hash(1),
                    candidate: Some(candidate),
                })
                .is_err()
        );
    }

    #[test]
    fn source_receipt_digest_matches_openfox_golden() {
        let value = recursively_sorted_json(serde_json::json!({
            "z": "last",
            "a": 7u64,
            "nested": {"b": true, "a": "x"},
        }));
        assert_eq!(
            economic_payment_observation_digest(SOURCE_RECEIPT_DIGEST_DOMAIN, &value).unwrap(),
            "sha256:82c45f946d85935641b722a83c69932efecd7c28e797157011e5aee8f6fc9a13"
        );
    }
}
