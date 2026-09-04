/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use super::capability_registry_cmd::CapabilityRegistryCmd;
use super::dispute_cmd::DisputeCmd;
use super::output_format::OutputFormat;
use super::proof_attestation_cmd::ProofAttestationCmd;
use super::service_actor_cmd::ServiceActorCmd;
use super::utils::{
    DEPLOY_TIMEOUT, SEND_TIMEOUT, calculate_wallet_address, get_wallet_config, load_config_vault,
    load_config_vault_rpc_client, load_config_vault_rpc_client_fd, make_wallet, save_config,
    try_create_rpc_client, wait_for_deploy, wait_for_seqno_change, wallet_info,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    BuilderData, Cell, Coins, ConfigParamEnum, Deserializable, IBitstring, Message, MsgAddressInt,
    Serializable, Transaction, TransactionDescr, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::client_json_rpc::{
    canonicalize_chain_rpc_endpoint, validate_exact_boc_before_broadcast,
};
use chain_rpc_client::v2::data_models::{
    AccountState, ExactBocSubmissionResult, ExactBocSubmissionStatus, RelayNetworkDomainPin,
};
use clap::ValueEnum;
use colored::Colorize;
use common::{
    WalletVersion,
    app_config::{
        AgentRuntimeBinding, AgentTaskConfig, AgentWalletConfig, AgentWalletPolicy, AppConfig,
        KeyConfig, WalletConfig,
    },
    chain_utils::{display_tos, tos_to_nanotos},
    time_format,
};
use contracts::{
    AgentAccountContract, AgentAccountCustodyJournal, AgentAccountData, AgentAccountInit,
    AgentAccountPolicyUpdate, ControllerActionClaim, ControllerActionResolutionEvidence,
    ControllerActionStatus, EconomicActionAuthorization, EconomicEffectAuthorization,
    TaskEscrowContract, TaskEscrowData, TaskEscrowInit, Wallet, agent_account_task_body_hash,
    controller_resolution_evidence_digest,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use futures_util::{StreamExt, stream};
use rand::RngCore;
use secrets_vault::types::{
    algorithm::Algorithm, secret::Secret, secret_id::SecretId, secret_spec::SecretSpec,
};
use secrets_vault::vault::SecretVault;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

mod dual_absence;
use dual_absence::{
    AgentAccountEconomicPaymentRelayTransactionComponentAbsenceCmd,
    AgentAccountEconomicPaymentRelayTransactionComponentAbsenceProofVerifyCmd,
    AgentAccountEconomicPaymentSponsorshipComponentAbsenceCmd,
    AgentAccountEconomicPaymentSponsorshipComponentAbsenceProofVerifyCmd,
    AgentAccountEconomicPaymentSponsorshipDualAbsenceCapabilityCmd,
    AgentAccountEconomicPaymentSponsorshipDualAbsenceCmd,
    AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd,
};

const AGENT_WALLET_FUND_GAS: u64 = 1_000_000; // 0.001 TOS
const AGENT_ACCOUNT_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const AGENT_ACCOUNT_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS
const TASK_SEND_FINALIZED_SCHEMA: &str = "tos.agent-account.task-send-finalized.v1";

/// Top-level `tosctl agent` command.
#[derive(clap::Args, Clone)]
#[command(about = "AI agent wallet operations")]
pub struct AgentCmd {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the configuration file",
        default_value = "tosctl-config.json",
        env = "CONFIG_PATH",
        global = true
    )]
    config: String,

    #[command(subcommand)]
    action: AgentAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentAction {
    /// Agent wallet operations
    Wallet(AgentWalletCmd),
    /// Native Agent Account contract operations
    Account(AgentAccountCmd),
    /// Native Task Escrow contract operations
    Task(AgentTaskCmd),
    /// Capability Registry operations
    Registry(CapabilityRegistryCmd),
    /// Service Actor operations
    Service(ServiceActorCmd),
    /// Dispute case operations
    Dispute(DisputeCmd),
    /// Proof Attestation (ed25519 signature adapter) operations
    Attestation(ProofAttestationCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "AI Agent Task Escrow operations")]
pub struct AgentTaskCmd {
    #[command(subcommand)]
    action: AgentTaskAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentTaskAction {
    /// Report the versioned, machine-readable Task Escrow CLI contract
    Capabilities(AgentTaskCapabilitiesCmd),
    /// Deploy and fund a Task Escrow actor
    Create(AgentTaskCreateCmd),
    /// List locally tracked Task Escrow records
    Ls(AgentTaskLsCmd),
    /// Show Task Escrow state by address or local record name
    Show(AgentTaskShowCmd),
    /// Send a Task Escrow lifecycle message
    Send(AgentTaskSendCmd),
    /// Build deterministic Task Escrow StateInit
    BuildState(AgentTaskBuildStateCmd),
    /// Encode a Task Escrow lifecycle message
    Encode(AgentTaskEncodeCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Report the Task Escrow CLI capability contract")]
pub struct AgentTaskCapabilitiesCmd {
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a Task Escrow lifecycle message")]
pub struct AgentTaskSendCmd {
    #[arg(long, value_enum)]
    operation: AgentTaskOperation,
    #[arg(long, conflicts_with = "name", help = "Task Escrow address")]
    address: Option<String>,
    #[arg(long, help = "Local task record name from `agent task ls`")]
    name: Option<String>,
    #[arg(
        long,
        conflicts_with = "via_agent_account",
        help = "Signing wallet name or master_wallet"
    )]
    from: Option<String>,
    #[arg(
        long,
        conflicts_with = "from",
        help = "Agent Wallet profile whose deployed Agent Account sends the action"
    )]
    via_agent_account: Option<String>,
    #[arg(
        long,
        requires = "via_agent_account",
        help = "Controller action expiry; defaults to now + 300s"
    )]
    valid_until: Option<u32>,
    #[arg(
        long,
        requires = "via_agent_account",
        help = "Stable 64-lowercase-hex idempotency ID for the controller action"
    )]
    controller_action_id: Option<String>,
    #[arg(
        long = "quorum-config",
        requires = "via_agent_account",
        num_args = 2..,
        help = "Additional absolute single-endpoint configs used to resolve the exact Agent Account transaction"
    )]
    quorum_configs: Vec<String>,
    #[arg(
        long,
        requires = "via_agent_account",
        default_value_t = 1000,
        help = "Maximum source-account transactions inspected per RPC during exact-action resolution"
    )]
    max_transactions: u32,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    result_hash: Option<String>,
    #[arg(long)]
    evidence_hash: Option<String>,
    #[arg(long, help = "Dispute metadata/evidence hash for dispute operation")]
    dispute_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "payout_nanotos",
        help = "Payout in TOS for settle or resolve; message value uses --amount"
    )]
    payout: Option<f64>,
    #[arg(long, conflicts_with = "payout", help = "Exact payout in nanoTOS for settle or resolve")]
    payout_nanotos: Option<u64>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "64-byte ed25519 signature over the settle/resolve domain hash, for settle or resolve on a task deployed with --attestor-pubkey"
    )]
    attestation_signature: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestation_signature",
        help = "Sign the contract-bound settle/resolve domain hash with this vault key instead of passing --attestation-signature directly"
    )]
    signer_vault_key: Option<String>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "New 32-byte ed25519 public key for rotate-attestor-key (creator-only)"
    )]
    new_attestor_pubkey: Option<String>,
    #[arg(
        long,
        conflicts_with = "amount_nanotos",
        help = "Message value in TOS; defaults to 0.01"
    )]
    amount: Option<f64>,
    #[arg(long, conflicts_with = "amount", help = "Exact message value in nanoTOS")]
    amount_nanotos: Option<u64>,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Task Escrow state by address or local record name")]
pub struct AgentTaskShowCmd {
    #[arg(long, conflicts_with = "name", help = "Task Escrow address")]
    address: Option<String>,
    #[arg(long, help = "Local task record name from `agent task ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked Task Escrow records")]
pub struct AgentTaskLsCmd {
    #[arg(long, help = "Read current status and permission hash from each Task Escrow")]
    on_chain: bool,
    #[arg(long, value_enum, requires = "on_chain", help = "Filter by on-chain lifecycle status")]
    status: Option<AgentTaskStatusFilter>,
    #[arg(long, help = "Filter by creator address")]
    creator: Option<String>,
    #[arg(long, conflicts_with = "unassigned", help = "Filter by assigned agent address")]
    agent: Option<String>,
    #[arg(long, conflicts_with = "agent", help = "Show only tasks without an assigned agent")]
    unassigned: bool,
    #[arg(long, help = "Show tasks with deadline strictly before this Unix timestamp")]
    deadline_before: Option<u64>,
    #[arg(long, help = "Show tasks with deadline strictly after this Unix timestamp")]
    deadline_after: Option<u64>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy and fund a Task Escrow actor")]
pub struct AgentTaskCreateCmd {
    #[arg(long, help = "Local task record name; defaults to task-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Creator address; must match the funding wallet")]
    creator: String,
    #[arg(long)]
    agent: Option<String>,
    #[arg(long, help = "Optional verifier allowed to settle the task")]
    verifier: Option<String>,
    #[arg(
        long,
        conflicts_with = "permission_hash",
        help = "Optional account-permission ID linked to this task"
    )]
    permission_id: Option<String>,
    #[arg(
        long,
        conflicts_with = "permission_id",
        help = "Exact 32-byte permission hash in hex; intended for protocol-driven deployment"
    )]
    permission_hash: Option<String>,
    #[arg(long, conflicts_with = "budget_nanotos", required_unless_present = "budget_nanotos")]
    budget: Option<f64>,
    #[arg(long, conflicts_with = "budget", required_unless_present = "budget")]
    budget_nanotos: Option<u64>,
    #[arg(long)]
    deadline: u64,
    #[arg(long, default_value_t = 86_400, help = "Result review window in seconds")]
    review_period: u32,
    #[arg(long)]
    policy_hash: String,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "Optional 32-byte ed25519 public key; when set, settle also requires a signature over result_hash"
    )]
    attestor_pubkey: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestor_pubkey",
        help = "Derive --attestor-pubkey from a vault key instead of passing it directly"
    )]
    signer_vault_key: Option<String>,
    #[arg(long, help = "Funding wallet name or master_wallet")]
    from: String,
    #[arg(
        long,
        conflicts_with = "amount_nanotos",
        help = "Funding amount in TOS; defaults to 0.2"
    )]
    amount: Option<f64>,
    #[arg(long, conflicts_with = "amount", help = "Exact funding amount in nanoTOS")]
    amount_nanotos: Option<u64>,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(long)]
    yes: bool,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum AgentTaskOperation {
    Accept,
    Claim,
    Reject,
    Result,
    Dispute,
    Resolve,
    Settle,
    Cancel,
    Timeout,
    RotateAttestorKey,
    RevokeAttestor,
}

impl AgentTaskOperation {
    fn accepts_resolved_status(&self, status: u8) -> anyhow::Result<bool> {
        match self {
            Self::Accept | Self::Claim => Ok(status == 1),
            Self::Result => Ok(status == 2),
            Self::Settle | Self::Resolve => Ok(status == 3),
            Self::Cancel => Ok(status == 4),
            Self::Timeout => Ok(matches!(status, 3 | 5)),
            Self::Reject => Ok(status == 6),
            Self::Dispute => Ok(status == 7),
            _ => {
                anyhow::bail!("this Task operation is not supported through Agent Account custody")
            }
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Claim => "claim",
            Self::Reject => "reject",
            Self::Result => "result",
            Self::Dispute => "dispute",
            Self::Resolve => "resolve",
            Self::Settle => "settle",
            Self::Cancel => "cancel",
            Self::Timeout => "timeout",
            Self::RotateAttestorKey => "rotate-attestor-key",
            Self::RevokeAttestor => "revoke-attestor",
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
enum AgentTaskStatusFilter {
    Open,
    Accepted,
    ResultSubmitted,
    Settled,
    Cancelled,
    Expired,
    Rejected,
    Disputed,
}

impl AgentTaskStatusFilter {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::ResultSubmitted => "result_submitted",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Encode a Task Escrow lifecycle message")]
pub struct AgentTaskEncodeCmd {
    #[arg(long, value_enum)]
    operation: AgentTaskOperation,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "Result metadata hash for result operation")]
    result_hash: Option<String>,
    #[arg(long, help = "Evidence hash for result operation")]
    evidence_hash: Option<String>,
    #[arg(long, help = "Dispute metadata/evidence hash for dispute operation")]
    dispute_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "payout_nanotos",
        help = "Payout in TOS for settle or resolve operation"
    )]
    payout: Option<f64>,
    #[arg(
        long,
        conflicts_with = "payout",
        help = "Exact payout in nanoTOS for settle or resolve operation"
    )]
    payout_nanotos: Option<u64>,
    #[arg(
        long,
        help = "64-byte ed25519 signature over the settle/resolve domain hash, for settle or resolve on a task deployed with --attestor-pubkey"
    )]
    attestation_signature: Option<String>,
    #[arg(long, help = "New 32-byte ed25519 public key for rotate-attestor-key (creator-only)")]
    new_attestor_pubkey: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Build deterministic Task Escrow StateInit")]
pub struct AgentTaskBuildStateCmd {
    #[arg(long, help = "Task creator address")]
    creator: String,
    #[arg(long, help = "Optional assigned Agent address")]
    agent: Option<String>,
    #[arg(long, help = "Optional verifier allowed to settle the task")]
    verifier: Option<String>,
    #[arg(
        long,
        conflicts_with = "permission_hash",
        help = "Optional account-permission ID linked to this task"
    )]
    permission_id: Option<String>,
    #[arg(long, conflicts_with = "permission_id", help = "Exact 32-byte permission hash in hex")]
    permission_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "budget_nanotos",
        required_unless_present = "budget_nanotos",
        help = "Escrow budget in TOS"
    )]
    budget: Option<f64>,
    #[arg(
        long,
        conflicts_with = "budget",
        required_unless_present = "budget",
        help = "Exact escrow budget in nanoTOS"
    )]
    budget_nanotos: Option<u64>,
    #[arg(long, help = "Unix deadline")]
    deadline: u64,
    #[arg(long, default_value_t = 86_400, help = "Result review window in seconds")]
    review_period: u32,
    #[arg(long, help = "32-byte settlement policy hash")]
    policy_hash: String,
    #[arg(
        long,
        help = "Optional 32-byte ed25519 public key; when set, settle also requires a signature over result_hash"
    )]
    attestor_pubkey: Option<String>,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Native Agent Account contract operations")]
pub struct AgentAccountCmd {
    #[command(subcommand)]
    action: AgentAccountAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentAccountAction {
    /// Build Agent Account StateInit from a local Agent Wallet profile
    BuildState(AgentAccountBuildStateCmd),
    /// Deploy an Agent Account from a local Agent Wallet profile
    Deploy(AgentAccountDeployCmd),
    /// Show an Agent Account by its chain address
    Show(AgentAccountShowCmd),
    /// Show Agent Account contract template metadata
    ShowTemplate(AgentAccountShowTemplateCmd),
    /// Compare a local Agent Wallet profile with its Agent Account chain state
    Status(AgentAccountStatusCmd),
    /// Apply the local profile policy to a deployed Agent Account
    UpdatePolicy(AgentAccountUpdatePolicyCmd),
    /// Apply the local controller key to a deployed Agent Account
    RotateController(AgentAccountRotateControllerCmd),
    /// Send a controller-signed transfer from a deployed Agent Account
    TaskSend(AgentAccountTaskSendCmd),
    /// Resolve one already-broadcast task-send from exact transaction evidence
    TaskSendResolve(AgentAccountTaskSendResolveCmd),
    /// Prepare one owner-authorized, bodyless native TOS transfer without broadcasting it
    NativePrepare(AgentAccountNativePrepareCmd),
    /// Resolve one exact native transfer from a strict majority of independent RPC views
    NativeResolve(AgentAccountNativeResolveCmd),
    /// Prepare an Agreement-bound, writer-fenced native payment without broadcasting it
    EconomicPaymentPrepare(AgentAccountEconomicPaymentPrepareCmd),
    /// Broadcast the exact previously prepared Agreement payment BOC
    EconomicPaymentBroadcast(AgentAccountEconomicPaymentBroadcastCmd),
    /// Freeze and describe one owner-private RPC corroboration capability snapshot
    EconomicPaymentCorroborationProfile(AgentAccountEconomicPaymentCorroborationProfileCmd),
    /// Resolve an ordinary Agreement payment using the existing finalized-payment path
    EconomicPaymentResolve(AgentAccountEconomicPaymentResolveCmd),
    /// Corroborate a sponsorship payment without claiming validator finality
    EconomicPaymentCorroborate(AgentAccountEconomicPaymentCorroborateCmd),
    /// Resolve an owner-selected RPC-corroborated terminal predicate without claiming validator finality
    #[command(name = "economic-payment-sponsorship-corroborated-terminal")]
    EconomicPaymentSponsorshipFinality(AgentAccountEconomicPaymentSponsorshipFinalityCmd),
    /// Independently re-query and verify a sponsorship proof bundle without custody access
    EconomicPaymentSponsorshipProofVerify(AgentAccountEconomicPaymentSponsorshipProofVerifyCmd),
    /// Prove exact sponsorship and client-transaction non-inclusion from one frozen RPC snapshot
    EconomicPaymentSponsorshipDualAbsence(AgentAccountEconomicPaymentSponsorshipDualAbsenceCmd),
    /// Prove only the exact sponsorship component absent (query plus custody terminalization)
    EconomicPaymentSponsorshipComponentAbsence(
        AgentAccountEconomicPaymentSponsorshipComponentAbsenceCmd,
    ),
    /// Independently re-query an exact sponsorship-component absence bundle
    EconomicPaymentSponsorshipComponentAbsenceProofVerify(
        AgentAccountEconomicPaymentSponsorshipComponentAbsenceProofVerifyCmd,
    ),
    /// Prove only the exact relayed client transaction absent (query-only)
    EconomicPaymentRelayTransactionComponentAbsence(
        AgentAccountEconomicPaymentRelayTransactionComponentAbsenceCmd,
    ),
    /// Independently re-query an exact relayed-client-transaction absence bundle
    EconomicPaymentRelayTransactionComponentAbsenceProofVerify(
        AgentAccountEconomicPaymentRelayTransactionComponentAbsenceProofVerifyCmd,
    ),
    /// Independently re-query a Provider dual-absence bundle from a client-owned frozen snapshot
    EconomicPaymentSponsorshipDualAbsenceProofVerify(
        AgentAccountEconomicPaymentSponsorshipDualAbsenceProofVerifyCmd,
    ),
    /// Preflight the exact lower-assurance dual-absence capability tuple
    EconomicPaymentSponsorshipDualAbsenceCapability(
        AgentAccountEconomicPaymentSponsorshipDualAbsenceCapabilityCmd,
    ),
    /// Prepare an owner-authorized Agreement contract effect with an exact body
    EconomicEffectPrepare(AgentAccountEconomicEffectPrepareCmd),
    /// Broadcast the exact previously prepared Agreement contract effect
    EconomicEffectBroadcast(AgentAccountEconomicEffectBroadcastCmd),
    /// Prepare one owner-authorized cancellation for an existing controller action
    CancelPrepare(AgentAccountCancelPrepareCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Build Agent Account StateInit from a local Agent Wallet profile")]
pub struct AgentAccountBuildStateCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,

    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Agent Account workchain")]
    workchain: i32,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy an Agent Account from a local Agent Wallet profile")]
pub struct AgentAccountDeployCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,

    #[arg(long = "from", help = "Funding wallet name from config, or master_wallet")]
    from: String,

    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Agent Account workchain")]
    workchain: i32,

    #[arg(long = "amount", default_value_t = 0.2, help = "Initial Agent Account balance, in TOS")]
    amount: f64,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,

    #[arg(
        long = "new-generation",
        help = "Replace a previously deployed inactive Agent Account with a fresh deployment ID/address"
    )]
    new_generation: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show an Agent Account by its chain address")]
pub struct AgentAccountShowCmd {
    #[arg(short, long, help = "Agent Account address")]
    address: String,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Compare a local Agent Wallet profile with its Agent Account chain state")]
pub struct AgentAccountStatusCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,

    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Agent Account workchain")]
    workchain: i32,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,

    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Apply the local profile policy to a deployed Agent Account")]
pub struct AgentAccountUpdatePolicyCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,

    #[arg(
        long = "amount",
        default_value_t = 0.05,
        help = "Value carried by the owner message, in TOS"
    )]
    amount: f64,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Apply the local controller key to a deployed Agent Account")]
pub struct AgentAccountRotateControllerCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,

    #[arg(
        long = "amount",
        default_value_t = 0.05,
        help = "Value carried by the owner message, in TOS"
    )]
    amount: f64,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a controller-signed transfer from an Agent Account")]
pub struct AgentAccountTaskSendCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,
    #[arg(long, help = "Destination address")]
    target: String,
    #[arg(long, help = "Transfer amount in TOS")]
    value: f64,
    #[arg(long, help = "Body BOC as base64; defaults to an empty cell")]
    body_boc: Option<String>,
    #[arg(long, help = "Unix timestamp after which the request is invalid")]
    valid_until: u32,
    #[arg(long, help = "Stable 64-lowercase-hex idempotency ID")]
    action_id: String,
    #[arg(long, help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Resolve an exact body-bearing Agent Account task-send using three distinct RPC process views; never signs or broadcasts"
)]
pub struct AgentAccountTaskSendResolveCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Stable 64-lowercase-hex task-send action ID")]
    action_id: String,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Two additional absolute single-endpoint configs; with --config these form three distinct RPC process views"
    )]
    quorum_configs: Vec<String>,
    #[arg(
        long,
        default_value_t = 1000,
        help = "Maximum source-account transactions inspected per RPC process view"
    )]
    max_transactions: u32,
    #[arg(long, requires = "config_fd")]
    journal_directory: Option<String>,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Prepare an exact Agent Account native-send BOC; never broadcasts")]
pub struct AgentAccountNativePrepareCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long)]
    target: String,
    #[arg(long, help = "Exact native TOS amount in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long)]
    fee_reserve_nanotos: u64,
    #[arg(long)]
    valid_until: u32,
    #[arg(long)]
    action_id: String,
    #[arg(long)]
    request_digest: String,
    #[arg(long)]
    response_digest: String,
    #[arg(long)]
    owner_authorization_digest: String,
    #[arg(long)]
    unsigned_transfer_digest: String,
    #[arg(long)]
    yes: bool,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Resolve an exact native Agent Account transfer using at least three independent RPC configs"
)]
pub struct AgentAccountNativeResolveCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Stable 64-lowercase-hex native action ID")]
    action_id: String,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Additional absolute single-endpoint configs; with --config these form the strict-majority domain"
    )]
    quorum_configs: Vec<String>,
    #[arg(
        long,
        default_value_t = 1000,
        help = "Maximum source-account transactions inspected per RPC"
    )]
    max_transactions: u32,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Prepare an exact Agreement-bound native payment BOC; never broadcasts")]
pub struct AgentAccountEconomicPaymentPrepareCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long)]
    target: String,
    #[arg(long, help = "Exact native TOS amount in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long)]
    fee_reserve_nanotos: u64,
    #[arg(long)]
    valid_until: u32,
    #[arg(
        long = "authorization-file",
        help = "Absolute path to the bounded EconomicActionAuthorization JSON"
    )]
    authorization_file: String,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Broadcast an exact custody-journaled Agreement payment")]
pub struct AgentAccountEconomicPaymentBroadcastCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable economic action ID")]
    stable_action_id: String,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Prepare an exact Agreement-bound task-body effect; never broadcasts")]
pub struct AgentAccountEconomicEffectPrepareCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long)]
    target: String,
    #[arg(long, help = "Native TOS attached to the contract call, in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long)]
    fee_reserve_nanotos: u64,
    #[arg(long)]
    valid_until: u32,
    #[arg(long, help = "Exact task body BOC as canonical base64")]
    body_boc: String,
    #[arg(long = "authorization-file", help = "Absolute path to CustodyEffectAuthorization JSON")]
    authorization_file: String,
    #[arg(long)]
    yes: bool,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
    #[arg(long, requires = "config_fd")]
    journal_directory: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Broadcast an exact custody-journaled Agreement contract effect")]
pub struct AgentAccountEconomicEffectBroadcastCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long)]
    stable_action_id: String,
    #[arg(long)]
    yes: bool,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
    #[arg(long, requires = "config_fd")]
    journal_directory: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Resolve an Agreement payment using at least three independent RPC configs")]
pub struct AgentAccountEconomicPaymentResolveCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable economic action ID")]
    stable_action_id: String,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Additional tosctl config; together with --config at least three distinct RPC endpoints are required"
    )]
    quorum_configs: Vec<String>,
    #[arg(long, default_value_t = 1000, help = "Maximum account transactions inspected per RPC")]
    max_transactions: u32,
}

#[derive(clap::Args, Clone)]
#[command(about = "Corroborate a sponsorship payment without claiming validator finality")]
pub struct AgentAccountEconomicPaymentCorroborateCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable economic action ID")]
    stable_action_id: String,
    #[arg(
        long = "corroboration-snapshot",
        help = "Absolute owner-private snapshot manifest produced before quote authorization"
    )]
    corroboration_snapshot: String,
    #[arg(long, help = "Exact owner-private snapshot identity frozen for this action")]
    corroboration_snapshot_identity: String,
    #[arg(long, help = "Exact signed sponsorship release profile digest")]
    sponsorship_release_profile_digest: String,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Resolve an exact owner-selected RPC-corroborated sponsorship terminal predicate (never validator finality; no signing or broadcast)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipFinalityCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Canonical sha256 stable sponsorship action ID")]
    stable_action_id: String,
    #[arg(
        long = "agreement-payment-request-cbor",
        help = "Absolute owner-private exact canonical AgreementPaymentRequestV3 CBOR"
    )]
    agreement_payment_request_cbor: String,
    #[arg(
        long = "finality-profile-cbor",
        help = "Absolute owner-private exact canonical selected FinalityProfile CBOR"
    )]
    finality_profile_cbor: String,
    #[arg(
        long = "corroboration-snapshot",
        help = "Absolute owner-private snapshot manifest frozen before quote authorization"
    )]
    corroboration_snapshot: String,
    #[arg(long, help = "Exact owner-private snapshot identity frozen for this action")]
    corroboration_snapshot_identity: String,
    #[arg(long, help = "Exact signed sponsorship release profile digest")]
    sponsorship_release_profile_digest: String,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Independently re-query an exact sponsorship proof bundle (query-only; no wallet, custody, signing, broadcast, or journal access)"
)]
pub struct AgentAccountEconomicPaymentSponsorshipProofVerifyCmd {
    #[arg(
        long = "proof-bundle-cbor",
        help = "Absolute owner-private canonical sponsorship proof-bundle CBOR"
    )]
    proof_bundle_cbor: String,
    #[arg(
        long = "agreement-payment-request-cbor",
        help = "Absolute owner-private exact canonical AgreementPaymentRequestV3 CBOR"
    )]
    agreement_payment_request_cbor: String,
    #[arg(
        long = "finality-profile-cbor",
        help = "Absolute owner-private exact canonical selected FinalityProfile CBOR"
    )]
    finality_profile_cbor: String,
    #[arg(long = "corroboration-snapshot", help = "Absolute client-owned RPC snapshot manifest")]
    corroboration_snapshot: String,
    #[arg(long, help = "Exact client-owned snapshot identity")]
    corroboration_snapshot_identity: String,
    #[arg(long, help = "Exact client-owned sponsorship release profile digest")]
    sponsorship_release_profile_digest: String,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Freeze and describe an owner-private RPC corroboration capability (no chain write)"
)]
pub struct AgentAccountEconomicPaymentCorroborationProfileCmd {
    #[arg(long)]
    network_id: String,
    #[arg(long)]
    global_id: i32,
    #[arg(long)]
    zero_state_root_hash: String,
    #[arg(long)]
    zero_state_file_hash: String,
    #[arg(long)]
    workchain_id: i32,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Additional single-endpoint tosctl config; at least three distinct endpoints and owner-pinned operator_provenance digests are required"
    )]
    quorum_configs: Vec<String>,
    #[arg(long, default_value_t = 1000, help = "Maximum account transactions inspected per RPC")]
    max_transactions: u32,
    #[arg(
        long = "snapshot-directory",
        help = "Existing absolute owner-private directory that will retain exact config snapshots"
    )]
    snapshot_directory: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Prepare an exact same-seqno Agent Account cancellation; never broadcasts")]
pub struct AgentAccountCancelPrepareCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Primary controller action's stable idempotency ID")]
    action_id: String,
    #[arg(long)]
    owner_authorization_digest: String,
    #[arg(long)]
    valid_until: u32,
    #[arg(long)]
    yes: bool,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Agent Account contract template metadata")]
pub struct AgentAccountShowTemplateCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Manage AI agent wallets")]
pub struct AgentWalletCmd {
    #[command(subcommand)]
    action: AgentWalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentWalletAction {
    /// Create a local Agent Wallet profile
    Create(AgentWalletCreateCmd),
    /// List local Agent Wallet profiles
    Ls(AgentWalletLsCmd),
    /// Show a local Agent Wallet profile
    Show(AgentWalletShowCmd),
    /// Print only the machine-readable policy
    Policy(AgentWalletPolicyCmd),
    /// Update Agent Wallet policy and metadata
    UpdatePolicy(AgentWalletUpdatePolicyCmd),
    /// Bind an Agent Wallet to an off-chain runtime
    BindRuntime(AgentWalletBindRuntimeCmd),
    /// Rotate the controller key used by the agent runtime
    RotateController(AgentWalletRotateControllerCmd),
    /// Export the runtime-facing manifest
    ExportRuntime(AgentWalletExportRuntimeCmd),
    /// Fund an Agent Wallet from an existing configured wallet
    Fund(AgentWalletFundCmd),
    /// Show Agent Wallet chain status
    Status(AgentWalletStatusCmd),
    /// Activate the underlying Agent Wallet contract
    Activate(AgentWalletActivateCmd),
    /// Remove a local Agent Wallet profile
    Rm(AgentWalletRmCmd),
    /// Send an owner-authorized transfer from the underlying Agent Wallet
    Send(AgentWalletSendCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Send an owner-authorized transfer from the underlying Agent Wallet")]
pub struct AgentWalletSendCmd {
    #[arg(short = 'n', long = "name", help = "Agent Wallet profile name")]
    name: String,
    #[arg(long, help = "Destination address")]
    to: String,
    #[arg(long, help = "Amount in TOS (e.g. 1.5)")]
    amount: f64,
    #[arg(long, help = "Optional message/comment")]
    message: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a local Agent Wallet profile")]
pub struct AgentWalletCreateCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(
        short = 'v',
        long = "version",
        default_value = "V5R1",
        help = "Underlying wallet version"
    )]
    version: String,

    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Workchain ID")]
    workchain: i32,

    #[arg(short = 'i', long = "subwallet-id", default_value = "4242", help = "Subwallet ID")]
    subwallet_id: u32,

    #[arg(
        long = "max-per-tx",
        default_value = "1.0",
        help = "Max controller spend per action, in TOS"
    )]
    max_per_tx: f64,

    #[arg(
        long = "daily-limit",
        default_value = "10.0",
        help = "Max controller spend per day, in TOS"
    )]
    daily_limit: f64,

    #[arg(
        long = "approval-above",
        help = "Require owner approval above this per-action amount, in TOS"
    )]
    approval_above: Option<f64>,

    #[arg(long = "service", help = "Allowed service actor address or label")]
    allowed_service_actors: Vec<String>,

    #[arg(long = "task-category", help = "Allowed task category")]
    allowed_task_categories: Vec<String>,

    #[arg(long = "capability", help = "Capability label advertised by the agent")]
    capabilities: Vec<String>,

    #[arg(long = "metadata-hash", help = "Optional agent metadata hash")]
    metadata_hash: Option<String>,

    #[arg(long = "service-endpoint-hash", help = "Optional service endpoint descriptor hash")]
    service_endpoint_hash: Option<String>,

    #[arg(long = "default-task-timeout", default_value_t = 3600)]
    default_task_timeout_secs: u64,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List local Agent Wallet profiles")]
pub struct AgentWalletLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a local Agent Wallet profile")]
pub struct AgentWalletShowCmd {
    #[arg(short = 'n', long = "name")]
    name: String,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Print an Agent Wallet policy")]
pub struct AgentWalletPolicyCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Update Agent Wallet policy and metadata")]
pub struct AgentWalletUpdatePolicyCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "max-per-tx", help = "Max controller spend per action, in TOS")]
    max_per_tx: Option<f64>,

    #[arg(long = "daily-limit", help = "Max controller spend per day, in TOS")]
    daily_limit: Option<f64>,

    #[arg(long = "approval-above", help = "Require owner approval above this amount, in TOS")]
    approval_above: Option<f64>,

    #[arg(long = "clear-approval-above", help = "Remove the owner-approval threshold")]
    clear_approval_above: bool,

    #[arg(long = "service", help = "Replace allowed service actors with this repeated list")]
    allowed_service_actors: Vec<String>,

    #[arg(long = "clear-services", help = "Clear allowed service actors")]
    clear_services: bool,

    #[arg(
        long = "task-category",
        help = "Replace allowed task categories with this repeated list"
    )]
    allowed_task_categories: Vec<String>,

    #[arg(long = "clear-task-categories", help = "Clear allowed task categories")]
    clear_task_categories: bool,

    #[arg(long = "capability", help = "Replace capability labels with this repeated list")]
    capabilities: Vec<String>,

    #[arg(long = "clear-capabilities", help = "Clear capability labels")]
    clear_capabilities: bool,

    #[arg(long = "metadata-hash", help = "Set agent metadata hash")]
    metadata_hash: Option<String>,

    #[arg(long = "clear-metadata-hash", help = "Clear agent metadata hash")]
    clear_metadata_hash: bool,

    #[arg(long = "service-endpoint-hash", help = "Set service endpoint descriptor hash")]
    service_endpoint_hash: Option<String>,

    #[arg(long = "clear-service-endpoint-hash", help = "Clear service endpoint descriptor hash")]
    clear_service_endpoint_hash: bool,

    #[arg(long = "default-task-timeout", help = "Default task timeout, in seconds")]
    default_task_timeout_secs: Option<u64>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Bind an Agent Wallet to an off-chain runtime")]
pub struct AgentWalletBindRuntimeCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "runner-id", help = "Stable agent runtime identifier")]
    runner_id: String,

    #[arg(long = "endpoint", help = "Runtime endpoint or local descriptor URI")]
    endpoint: String,

    #[arg(long = "attestation-hash", help = "Optional runtime attestation hash")]
    attestation_hash: Option<String>,

    #[arg(
        long = "economic-authority-id",
        requires_all = ["economic_authority_public_key", "economic_custody_journal_directory"]
    )]
    economic_authority_id: Option<String>,

    #[arg(
        long = "economic-authority-public-key",
        requires = "economic_authority_id",
        help = "Pinned 32-byte Ed25519 public key in lowercase hex"
    )]
    economic_authority_public_key: Option<String>,

    #[arg(
        long = "economic-custody-journal-directory",
        requires = "economic_authority_id",
        help = "Existing private absolute directory pinned as the economic custody high-water domain"
    )]
    economic_custody_journal_directory: Option<String>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Rotate the controller key used by the agent runtime")]
pub struct AgentWalletRotateControllerCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "key-name", help = "Optional vault key name for the new controller")]
    key_name: Option<String>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Export the runtime-facing Agent Wallet manifest")]
pub struct AgentWalletExportRuntimeCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Fund an Agent Wallet from an existing configured wallet")]
pub struct AgentWalletFundCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "from", help = "Funding wallet name from config, or master_wallet")]
    from: String,

    #[arg(long = "amount", help = "Amount to transfer, in TOS")]
    amount: f64,

    #[arg(long = "message", help = "Optional transfer comment")]
    message: Option<String>,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Agent Wallet chain status")]
pub struct AgentWalletStatusCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Activate the underlying Agent Wallet contract")]
pub struct AgentWalletActivateCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a local Agent Wallet profile")]
pub struct AgentWalletRmCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "delete-keys", help = "Also delete owner and controller vault keys")]
    delete_keys: bool,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(serde::Serialize)]
struct AgentWalletView {
    name: String,
    address: String,
    agent_account_address: Option<String>,
    agent_account_deployment_id: Option<String>,
    version: WalletVersion,
    workchain: i32,
    subwallet_id: u32,
    owner_key: String,
    controller_key: String,
    policy: AgentWalletPolicy,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
    capabilities: Vec<String>,
    runtime: Option<AgentRuntimeBinding>,
    created_at: Option<u64>,
}

#[derive(serde::Serialize)]
struct AgentRuntimeManifest {
    name: String,
    address: String,
    agent_account_address: Option<String>,
    agent_account_deployment_id: Option<String>,
    controller_key: String,
    policy: AgentWalletPolicy,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
    capabilities: Vec<String>,
    runtime: Option<AgentRuntimeBinding>,
}

#[derive(serde::Serialize)]
struct AgentWalletFundView {
    agent_wallet: String,
    from: String,
    from_address: String,
    to_address: String,
    amount: String,
    message: Option<String>,
    status: String,
}

#[derive(serde::Serialize)]
struct AgentWalletStatusView {
    name: String,
    address: String,
    balance: String,
    state: String,
    wallet_type: Option<String>,
    seqno: Option<u32>,
    controller_key: String,
    runtime: Option<AgentRuntimeBinding>,
}

#[derive(serde::Serialize)]
struct AgentAccountStateView {
    wallet: String,
    address: String,
    workchain: i32,
    owner: String,
    controller_key: String,
    controller_pubkey: String,
    deployment_id: String,
    max_per_tx: u64,
    daily_limit: u64,
    default_task_timeout_secs: u64,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
    state_init_boc: String,
    code_hash: String,
    data_hash: String,
}

#[derive(serde::Serialize)]
struct AgentAccountDeployView {
    wallet: String,
    address: String,
    owner: String,
    deployment_id: String,
    payer: String,
    payer_address: String,
    amount: String,
    code_hash: String,
    data_hash: String,
    status: String,
}

#[derive(serde::Serialize)]
struct AgentAccountActionView {
    wallet: String,
    address: String,
    owner: String,
    action: String,
    query_id: u64,
    amount: String,
    status: String,
}

#[derive(serde::Serialize)]
struct AgentAccountChainView {
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet: Option<String>,
    address: String,
    state: String,
    balance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seqno: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_per_tx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spend_day: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spent_today: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_task_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_endpoint_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matches_profile: Option<bool>,
}

#[derive(serde::Serialize)]
struct AgentAccountTemplateView {
    contract: &'static str,
    source: &'static str,
    tlb: &'static str,
    update_policy_opcode: String,
    rotate_controller_opcode: String,
    task_send_opcode: String,
    native_send_opcode: String,
    cancel_seqno_opcode: String,
    get_methods: Vec<&'static str>,
    code_hash: String,
    code_boc: String,
}

impl AgentCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AgentAction::Wallet(cmd) => cmd.run(&self.config).await,
            AgentAction::Account(cmd) => cmd.run(&self.config).await,
            AgentAction::Task(cmd) => cmd.run(&self.config).await,
            AgentAction::Registry(cmd) => cmd.run(&self.config).await,
            AgentAction::Service(cmd) => cmd.run(&self.config).await,
            AgentAction::Dispute(cmd) => cmd.run(&self.config).await,
            AgentAction::Attestation(cmd) => cmd.run(&self.config).await,
        }
    }
}

impl AgentAccountCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AgentAccountAction::BuildState(cmd) => cmd.run(config_path).await,
            AgentAccountAction::Deploy(cmd) => cmd.run(config_path).await,
            AgentAccountAction::Show(cmd) => cmd.run(config_path).await,
            AgentAccountAction::ShowTemplate(cmd) => cmd.run().await,
            AgentAccountAction::Status(cmd) => cmd.run(config_path).await,
            AgentAccountAction::UpdatePolicy(cmd) => cmd.run(config_path).await,
            AgentAccountAction::RotateController(cmd) => cmd.run(config_path).await,
            AgentAccountAction::TaskSend(cmd) => cmd.run(config_path).await,
            AgentAccountAction::TaskSendResolve(cmd) => cmd.run(config_path).await,
            AgentAccountAction::NativePrepare(cmd) => cmd.run(config_path).await,
            AgentAccountAction::NativeResolve(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicPaymentPrepare(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicPaymentBroadcast(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicPaymentCorroborationProfile(cmd) => {
                cmd.run(config_path).await
            }
            AgentAccountAction::EconomicPaymentResolve(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicPaymentCorroborate(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicPaymentSponsorshipFinality(cmd) => {
                cmd.run(config_path).await
            }
            AgentAccountAction::EconomicPaymentSponsorshipProofVerify(cmd) => cmd.run().await,
            AgentAccountAction::EconomicPaymentSponsorshipDualAbsence(cmd) => cmd.run().await,
            AgentAccountAction::EconomicPaymentSponsorshipComponentAbsence(cmd) => cmd.run().await,
            AgentAccountAction::EconomicPaymentSponsorshipComponentAbsenceProofVerify(cmd) => {
                cmd.run().await
            }
            AgentAccountAction::EconomicPaymentRelayTransactionComponentAbsence(cmd) => {
                cmd.run().await
            }
            AgentAccountAction::EconomicPaymentRelayTransactionComponentAbsenceProofVerify(cmd) => {
                cmd.run().await
            }
            AgentAccountAction::EconomicPaymentSponsorshipDualAbsenceProofVerify(cmd) => {
                cmd.run().await
            }
            AgentAccountAction::EconomicPaymentSponsorshipDualAbsenceCapability(cmd) => {
                cmd.run().await
            }
            AgentAccountAction::EconomicEffectPrepare(cmd) => cmd.run(config_path).await,
            AgentAccountAction::EconomicEffectBroadcast(cmd) => cmd.run(config_path).await,
            AgentAccountAction::CancelPrepare(cmd) => cmd.run(config_path).await,
        }
    }
}

impl AgentTaskCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AgentTaskAction::Capabilities(cmd) => cmd.run(),
            AgentTaskAction::Create(cmd) => cmd.run(config_path).await,
            AgentTaskAction::Ls(cmd) => cmd.run(config_path).await,
            AgentTaskAction::Show(cmd) => cmd.run(config_path).await,
            AgentTaskAction::Send(cmd) => cmd.run(config_path).await,
            AgentTaskAction::BuildState(cmd) => cmd.run(),
            AgentTaskAction::Encode(cmd) => cmd.run(),
        }
    }
}

#[derive(serde::Serialize)]
struct AgentTaskCapabilitiesView {
    schema_version: &'static str,
    action_encoding: &'static str,
    commands: [&'static str; 3],
    create_flags: [&'static str; 14],
    send_flags: [&'static str; 10],
    send_operations: [&'static str; 9],
}

impl AgentTaskCapabilitiesCmd {
    fn run(&self) -> anyhow::Result<()> {
        if self.format != OutputFormat::Json {
            anyhow::bail!("Task Escrow capabilities support only JSON output");
        }
        let view = AgentTaskCapabilitiesView {
            schema_version: "tosctl.task-escrow-cli.v1",
            action_encoding: "tos.task-escrow.action.v1",
            commands: ["agent task build-state", "agent task create", "agent task send"],
            create_flags: [
                "--name",
                "--creator",
                "--agent",
                "--verifier",
                "--budget-nanotos",
                "--deadline",
                "--review-period",
                "--policy-hash",
                "--permission-hash",
                "--from",
                "--amount-nanotos",
                "--workchain",
                "--yes",
                "--format",
            ],
            send_flags: [
                "--operation",
                "--address",
                "--from",
                "--query-id",
                "--amount-nanotos",
                "--yes",
                "--result-hash",
                "--evidence-hash",
                "--dispute-hash",
                "--payout-nanotos",
            ],
            send_operations: [
                "accept", "reject", "result", "dispute", "resolve", "settle", "cancel", "timeout",
                "claim",
            ],
        };
        println!("{}", serde_json::to_string_pretty(&view)?);
        Ok(())
    }
}

/// Resolve the escrow address from an explicit `--address` or a stored `--name` record.
fn resolve_task_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .agent_tasks
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!("Task record '{}' not found; see `agent task ls`", name)
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid Task Escrow address")
}

fn validate_controller_task_action(
    operation: &AgentTaskOperation,
    task: &TaskEscrowData,
    agent_account: &MsgAddressInt,
    permission_hash: [u8; 32],
    context: &ControllerTaskActionContext<'_>,
) -> anyhow::Result<()> {
    if task.permission_hash != permission_hash {
        anyhow::bail!("local permission ID does not match the Task Escrow on-chain hash");
    }
    match operation {
        AgentTaskOperation::Accept | AgentTaskOperation::Reject => {
            require_task_status(task, 0, "open")?;
            if task.assigned_agent.as_ref() != Some(agent_account) {
                anyhow::bail!("Task Escrow is not assigned to the selected Agent Account");
            }
        }
        AgentTaskOperation::Claim => {
            require_task_status(task, 0, "open")?;
            if task.assigned_agent.is_some() {
                anyhow::bail!("Task Escrow is already assigned and cannot be claimed");
            }
        }
        AgentTaskOperation::Result => {
            require_task_status(task, 1, "accepted")?;
            if task.assigned_agent.as_ref() != Some(agent_account) {
                anyhow::bail!("Task Escrow is not assigned to the selected Agent Account");
            }
        }
        AgentTaskOperation::Settle => {
            require_task_status(task, 2, "result_submitted")?;
            if &task.creator != agent_account && task.verifier.as_ref() != Some(agent_account) {
                anyhow::bail!(
                    "Task Escrow settlement requires its creator or designated verifier Agent Account"
                );
            }
            if context.now > task.review_deadline {
                anyhow::bail!("Task Escrow review deadline has passed");
            }
            validate_controller_task_payout(task, context)?;
            validate_controller_task_attestation(operation, task, context)?;
        }
        AgentTaskOperation::Cancel => {
            require_task_status(task, 0, "open")?;
            if &task.creator != agent_account {
                anyhow::bail!("Task Escrow cancellation requires its creator Agent Account");
            }
        }
        AgentTaskOperation::Timeout => match task.status {
            0 | 1 if context.now < task.deadline => {
                anyhow::bail!("Task Escrow task deadline has not passed")
            }
            2 if context.now < task.review_deadline => {
                anyhow::bail!("Task Escrow review deadline has not passed")
            }
            0..=2 => {}
            _ => anyhow::bail!(
                "Task Escrow must be open, accepted or result_submitted for timeout (current status: {})",
                task_status_name(task.status)
            ),
        },
        AgentTaskOperation::Dispute => {
            require_task_status(task, 2, "result_submitted")?;
            if &task.creator != agent_account {
                anyhow::bail!("Task Escrow dispute requires its creator Agent Account");
            }
            if task.verifier.is_none() {
                anyhow::bail!("Task Escrow dispute requires a designated verifier");
            }
            if context.now > task.review_deadline {
                anyhow::bail!("Task Escrow review deadline has passed");
            }
            let dispute_hash =
                context.dispute_hash.context("controller Task dispute requires --dispute-hash")?;
            if dispute_hash == [0; 32] {
                anyhow::bail!("Task Escrow dispute hash must not be zero");
            }
        }
        AgentTaskOperation::Resolve => {
            require_task_status(task, 7, "disputed")?;
            if task.verifier.as_ref() != Some(agent_account) {
                anyhow::bail!(
                    "Task Escrow resolution requires its designated verifier Agent Account"
                );
            }
            validate_controller_task_payout(task, context)?;
            validate_controller_task_attestation(operation, task, context)?;
        }
        AgentTaskOperation::RotateAttestorKey | AgentTaskOperation::RevokeAttestor => {
            anyhow::bail!("this Task operation is not supported through Agent Account custody")
        }
    }
    Ok(())
}

struct ControllerTaskActionContext<'a> {
    task_address: &'a MsgAddressInt,
    now: u64,
    payout: Option<u64>,
    dispute_hash: Option<[u8; 32]>,
    attestation_signature: Option<&'a [u8; 64]>,
    available_balance: u64,
}

fn require_task_status(
    task: &TaskEscrowData,
    expected_status: u8,
    expected_name: &str,
) -> anyhow::Result<()> {
    if task.status != expected_status {
        anyhow::bail!(
            "Task Escrow must be {} for this controller action (current status: {})",
            expected_name,
            task_status_name(task.status)
        );
    }
    Ok(())
}

fn validate_controller_task_payout(
    task: &TaskEscrowData,
    context: &ControllerTaskActionContext<'_>,
) -> anyhow::Result<()> {
    let payout = context.payout.context("controller Task action requires an exact payout")?;
    if payout > task.budget {
        anyhow::bail!("Task Escrow payout exceeds its remaining budget");
    }
    if payout > context.available_balance {
        anyhow::bail!("Task Escrow payout exceeds its available balance");
    }
    Ok(())
}

fn validate_controller_task_attestation(
    operation: &AgentTaskOperation,
    task: &TaskEscrowData,
    context: &ControllerTaskActionContext<'_>,
) -> anyhow::Result<()> {
    let Some(attestor_pubkey) = task.attestor_pubkey else {
        if context.attestation_signature.is_some() {
            anyhow::bail!("Task Escrow has no attestor but an attestation signature was provided");
        }
        return Ok(());
    };
    let signature =
        context.attestation_signature.context("Task Escrow requires an attestation signature")?;
    let domain_hash = match operation {
        AgentTaskOperation::Settle => contracts::settle_domain_hash(
            context.task_address,
            &task.result_hash,
            context.payout.context("settle requires payout")?,
        )?,
        AgentTaskOperation::Resolve => contracts::resolve_domain_hash(
            context.task_address,
            &task.result_hash,
            &task.dispute_hash,
            context.payout.context("resolve requires payout")?,
        )?,
        _ => anyhow::bail!("attestation validation is only defined for settle and resolve"),
    };
    let key = VerifyingKey::from_bytes(&attestor_pubkey)
        .context("Task Escrow attestor public key is invalid")?;
    key.verify_strict(&domain_hash, &Ed25519Signature::from_bytes(signature))
        .context("Task Escrow attestation signature does not match its on-chain domain")
}

impl AgentTaskSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let amount_nanotos =
            resolve_nanotos("amount", self.amount, self.amount_nanotos, Some(0.01))?;
        let mut payout_nanotos = None;
        let mut dispute_hash = None;
        let mut attestation_signature = None;
        let mut body: Option<Cell> = match self.operation {
            AgentTaskOperation::Accept => Some(TaskEscrowContract::accept(self.query_id)?),
            AgentTaskOperation::Claim => Some(TaskEscrowContract::claim(self.query_id)?),
            AgentTaskOperation::Reject => Some(TaskEscrowContract::reject(self.query_id)?),
            AgentTaskOperation::Result => Some(TaskEscrowContract::result(
                self.query_id,
                parse_required_hash("result-hash", &self.result_hash)?,
                parse_required_hash("evidence-hash", &self.evidence_hash)?,
            )?),
            AgentTaskOperation::Dispute => {
                let hash = parse_required_hash("dispute-hash", &self.dispute_hash)?;
                dispute_hash = Some(hash);
                Some(TaskEscrowContract::dispute(self.query_id, hash)?)
            }
            AgentTaskOperation::Resolve => {
                let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
                payout_nanotos = Some(payout);
                let signature =
                    parse_optional_signature("attestation-signature", &self.attestation_signature)?;
                attestation_signature = signature;
                match signature {
                    Some(signature) => {
                        Some(TaskEscrowContract::resolve_signed(self.query_id, payout, &signature)?)
                    }
                    // Resolved once chain state (result_hash, dispute_hash) and the vault
                    // are available, below.
                    None if self.signer_vault_key.is_some() => None,
                    None => Some(TaskEscrowContract::resolve(self.query_id, payout)?),
                }
            }
            AgentTaskOperation::Settle => {
                let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
                payout_nanotos = Some(payout);
                let signature =
                    parse_optional_signature("attestation-signature", &self.attestation_signature)?;
                attestation_signature = signature;
                match signature {
                    Some(signature) => {
                        Some(TaskEscrowContract::settle_signed(self.query_id, payout, &signature)?)
                    }
                    // Resolved once chain state (result_hash) and the vault are available, below.
                    None if self.signer_vault_key.is_some() => None,
                    None => Some(TaskEscrowContract::settle(self.query_id, payout)?),
                }
            }
            AgentTaskOperation::Cancel => Some(TaskEscrowContract::cancel(self.query_id)?),
            AgentTaskOperation::Timeout => Some(TaskEscrowContract::timeout(self.query_id)?),
            AgentTaskOperation::RotateAttestorKey => {
                match parse_optional_hash("new-attestor-pubkey", &self.new_attestor_pubkey)? {
                    Some(pubkey) => {
                        Some(TaskEscrowContract::rotate_attestor_key(self.query_id, pubkey)?)
                    }
                    // Resolved once the vault is available, below.
                    None if self.signer_vault_key.is_some() => None,
                    None => anyhow::bail!(
                        "provide --new-attestor-pubkey or --signer-vault-key for rotate-attestor-key"
                    ),
                }
            }
            AgentTaskOperation::RevokeAttestor => {
                Some(TaskEscrowContract::revoke_attestor(self.query_id)?)
            }
        };
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_task_address(&config, &self.address, &self.name)?;
        if body.is_none() {
            let vault_key = self
                .signer_vault_key
                .as_deref()
                .context("deferred Task body requires --signer-vault-key")?;
            match self.operation {
                AgentTaskOperation::Settle => {
                    let payout = payout_nanotos.context("settle requires payout")?;
                    let provider = contracts::contract_provider!(rpc_client.clone());
                    let stack = provider
                        .get_method(destination.to_string(), "get_task_data", vec![])
                        .await?;
                    let chain_task = TaskEscrowContract::decode_data(&stack)?;
                    let domain_hash = contracts::settle_domain_hash(
                        &destination,
                        &chain_task.result_hash,
                        payout,
                    )?;
                    let signature =
                        sign_hash_with_vault_key(vault_key, &domain_hash, vault.clone()).await?;
                    attestation_signature = Some(signature);
                    body =
                        Some(TaskEscrowContract::settle_signed(self.query_id, payout, &signature)?);
                }
                AgentTaskOperation::Resolve => {
                    let payout = payout_nanotos.context("resolve requires payout")?;
                    let provider = contracts::contract_provider!(rpc_client.clone());
                    let stack = provider
                        .get_method(destination.to_string(), "get_task_data", vec![])
                        .await?;
                    let chain_task = TaskEscrowContract::decode_data(&stack)?;
                    let domain_hash = contracts::resolve_domain_hash(
                        &destination,
                        &chain_task.result_hash,
                        &chain_task.dispute_hash,
                        payout,
                    )?;
                    let signature =
                        sign_hash_with_vault_key(vault_key, &domain_hash, vault.clone()).await?;
                    attestation_signature = Some(signature);
                    body = Some(TaskEscrowContract::resolve_signed(
                        self.query_id,
                        payout,
                        &signature,
                    )?);
                }
                AgentTaskOperation::RotateAttestorKey => {
                    let pubkey =
                        resolve_attestor_pubkey(&None, &Some(vault_key.to_owned()), vault.clone())
                            .await?
                            .context("vault key did not resolve to an attestor public key")?;
                    body = Some(TaskEscrowContract::rotate_attestor_key(self.query_id, pubkey)?);
                }
                _ => anyhow::bail!("Task operation unexpectedly deferred body resolution"),
            }
        }
        let body = body.context("Task body was not resolved")?;
        if let Some(agent_wallet) = &self.via_agent_account {
            if self.quorum_configs.len() < 2 {
                anyhow::bail!(
                    "--via-agent-account requires at least two --quorum-config values before any Task side effect"
                );
            }
            let record = config
                .agent_tasks
                .values()
                .find(|task| task.address == destination.to_string())
                .ok_or_else(|| {
                    anyhow::anyhow!("controller task actions require a locally tracked task record")
                })?;
            let account = config
                .agent_wallets
                .get(agent_wallet)
                .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", agent_wallet))?
                .agent_account_address
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Agent wallet '{}' has no deployed Agent Account address; deploy it first",
                        agent_wallet
                    )
                })?
                .parse::<MsgAddressInt>()
                .context("Invalid persisted Agent Account address")?;
            let action_id = self.controller_action_id.as_deref().context(
                "--controller-action-id is required for crash-safe Agent Account actions",
            )?;
            let journal = open_controller_journal(path)?;
            if let Ok(existing) = journal.action_by_idempotency_key(action_id) {
                let retry_body_hash = agent_account_task_body_hash(&body);
                if existing.claim.target != destination.to_string()
                    || existing.claim.value_atomic != amount_nanotos
                    || existing.claim.body_hash.as_deref() != Some(retry_body_hash.as_str())
                {
                    anyhow::bail!("controller action id was reused for different Task semantics");
                }
                if existing.status == ControllerActionStatus::Broadcasting {
                    return resolve_agent_account_task_action(
                        config_path,
                        agent_wallet,
                        action_id,
                        &self.operation,
                        &destination,
                        &self.quorum_configs,
                        self.max_transactions,
                    )
                    .await;
                }
            }
            let provider = contracts::contract_provider!(rpc_client.clone());
            let stack =
                provider.get_method(destination.to_string(), "get_task_data", vec![]).await?;
            let chain_task = TaskEscrowContract::decode_data(&stack)?;
            let validation_now = if matches!(
                self.operation,
                AgentTaskOperation::Settle
                    | AgentTaskOperation::Timeout
                    | AgentTaskOperation::Dispute
            ) {
                let master = rpc_client.get_masterchain_info().await?;
                let header = rpc_client
                    .get_block_header(
                        master.last.workchain,
                        &master.last.shard.to_string(),
                        master.last.seqno,
                    )
                    .await?;
                if header.gen_utime == 0 {
                    anyhow::bail!("latest masterchain block has no generation time");
                }
                u64::from(header.gen_utime)
            } else {
                0
            };
            let available_balance = if matches!(
                self.operation,
                AgentTaskOperation::Settle | AgentTaskOperation::Resolve
            ) {
                provider
                    .balance(&destination)
                    .await?
                    .checked_add(amount_nanotos)
                    .context("Task Escrow balance plus attached value overflowed")?
            } else {
                u64::MAX
            };
            let validation_context = ControllerTaskActionContext {
                task_address: &destination,
                now: validation_now,
                payout: payout_nanotos,
                dispute_hash,
                attestation_signature: attestation_signature.as_ref(),
                available_balance,
            };
            validate_controller_task_action(
                &self.operation,
                &chain_task,
                &account,
                permission_id_hash(record.permission_id.as_deref()),
                &validation_context,
            )?;
            let body_boc = base64::engine::general_purpose::STANDARD.encode(write_boc(&body)?);
            AgentAccountTaskSendCmd {
                wallet: agent_wallet.clone(),
                target: destination.to_string(),
                value: nanotos_to_tos_f64(amount_nanotos)?,
                body_boc: Some(body_boc),
                valid_until: self.valid_until.unwrap_or_else(|| time_format::now() as u32 + 300),
                action_id: action_id.to_owned(),
                yes: self.yes,
            }
            .run(config_path)
            .await?;
            return resolve_agent_account_task_action(
                config_path,
                agent_wallet,
                action_id,
                &self.operation,
                &destination,
                &self.quorum_configs,
                self.max_transactions,
            )
            .await;
        }
        let from = self.from.as_deref().ok_or_else(|| {
            anyhow::anyhow!("provide exactly one of --from or --via-agent-account")
        })?;
        let wallet_config =
            get_wallet_config(from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }
        if owner_info.balance < amount_nanotos.saturating_add(AGENT_ACCOUNT_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Task Escrow message?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), wallet_config, owner_secret, from).await?;
        send_wallet_message(
            &wallet,
            rpc_client,
            destination.clone(),
            amount_nanotos,
            body,
            true,
            owner_info.seqno,
            &owner_address,
        )
        .await?;
        println!(
            "{} Task Escrow {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination
        );
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct AgentTaskDataView {
    address: String,
    creator: String,
    assigned_agent: Option<String>,
    verifier: Option<String>,
    permission_id: Option<String>,
    permission_hash: String,
    budget: String,
    deadline: u64,
    review_period: u32,
    review_deadline: u64,
    status: String,
    result_hash: String,
    evidence_hash: String,
    dispute_hash: String,
    settlement_policy_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_pubkey: Option<String>,
}

impl AgentTaskShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_task_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack = provider.get_method(address.to_string(), "get_task_data", vec![]).await?;
        let data = TaskEscrowContract::decode_data(&stack)?;
        let permission_id = config
            .agent_tasks
            .values()
            .find(|task| task.address == address.to_string())
            .and_then(|task| task.permission_id.clone());
        let view = AgentTaskDataView {
            address: address.to_string(),
            creator: data.creator.to_string(),
            assigned_agent: data.assigned_agent.map(|value| value.to_string()),
            verifier: data.verifier.map(|value| value.to_string()),
            permission_id,
            permission_hash: hex::encode(data.permission_hash),
            budget: display_tos(data.budget),
            deadline: data.deadline,
            review_period: data.review_period,
            review_deadline: data.review_deadline,
            status: task_status_name(data.status).to_string(),
            result_hash: hex::encode(data.result_hash),
            evidence_hash: hex::encode(data.evidence_hash),
            dispute_hash: hex::encode(data.dispute_hash),
            settlement_policy_hash: hex::encode(data.settlement_policy_hash),
            attestor_pubkey: data.attestor_pubkey.map(hex::encode),
        };
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Task Escrow: {}", view.address);
            println!("Creator: {}", view.creator);
            println!("Assigned Agent: {}", view.assigned_agent.as_deref().unwrap_or("none"));
            println!("Verifier: {}", view.verifier.as_deref().unwrap_or("none"));
            println!("Permission ID: {}", view.permission_id.as_deref().unwrap_or("none"));
            println!("Budget: {} TOS", view.budget);
            println!("Deadline: {}", view.deadline);
            println!("Review period: {}s", view.review_period);
            println!("Review deadline: {}", view.review_deadline);
            println!("Status: {}", view.status);
            println!("Attestor pubkey: {}", view.attestor_pubkey.as_deref().unwrap_or("none"));
        }
        Ok(())
    }
}

impl AgentTaskCreateCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let amount_nanotos =
            resolve_nanotos("amount", self.amount, self.amount_nanotos, Some(0.2))?;
        let budget_nanotos = resolve_nanotos("budget", self.budget, self.budget_nanotos, None)?;
        let creator = self.creator.parse::<MsgAddressInt>().context("invalid creator address")?;
        let agent =
            self.agent.as_deref().map(str::parse).transpose().context("invalid agent address")?;
        let verifier = self
            .verifier
            .as_deref()
            .map(str::parse)
            .transpose()
            .context("invalid verifier address")?;
        let policy_hash =
            parse_optional_hash("policy-hash", &Some(self.policy_hash.clone()))?.unwrap();
        if let Some(permission_id) = &self.permission_id {
            validate_non_empty("permission-id", permission_id)?;
        }
        let permission_hash = match parse_optional_hash("permission-hash", &self.permission_hash)? {
            Some(value) => value,
            None => permission_id_hash(self.permission_id.as_deref()),
        };
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let attestor_pubkey =
            resolve_attestor_pubkey(&self.attestor_pubkey, &self.signer_vault_key, vault.clone())
                .await?;
        let init = TaskEscrowInit {
            creator: creator.clone(),
            assigned_agent: agent,
            verifier,
            budget: budget_nanotos,
            deadline: self.deadline,
            review_period: self.review_period,
            settlement_policy_hash: policy_hash,
            permission_hash,
            attestor_pubkey,
        };
        let address = TaskEscrowContract::calculate_address(self.workchain, &init)?;
        let state_init = TaskEscrowContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("task-{}", &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.agent_tasks.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "Task record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .agent_tasks
            .iter()
            .find(|(name, task)| *name != &record_name && task.address == address.to_string())
        {
            anyhow::bail!(
                "Task Escrow address {} is already tracked as '{}'",
                address,
                existing_name
            );
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != creator {
            anyhow::bail!("creator address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        if payer_info.balance < amount_nanotos.saturating_add(AGENT_ACCOUNT_DEPLOY_GAS) {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Task Escrow deployment?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), payer_cfg, payer_secret, &self.from).await?;
        let body = BuilderData::new().into_cell()?;
        send_wallet_message_with_state_init(
            &wallet,
            rpc_client,
            address.clone(),
            amount_nanotos,
            body,
            payer_info.seqno,
            &payer_address,
            state_init,
        )
        .await?;
        config.agent_tasks.insert(
            record_name.clone(),
            AgentTaskConfig {
                address: address.to_string(),
                creator: creator.to_string(),
                assigned_agent: init.assigned_agent.as_ref().map(|agent| agent.to_string()),
                verifier: init.verifier.as_ref().map(|verifier| verifier.to_string()),
                permission_id: self.permission_id.clone(),
                budget: init.budget,
                deadline: init.deadline,
                review_period: init.review_period,
                policy_hash: hex::encode(policy_hash),
                attestor_pubkey: init.attestor_pubkey.map(hex::encode),
                created_at: Some(time_format::now()),
            },
        );
        save_config(&config, path)?;
        if self.format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({
                    "name": record_name,
                    "address": address.to_string(),
                    "status": "submitted",
                    "creator": creator.to_string(),
                    "permission_id": self.permission_id,
                    "permission_hash": hex::encode(permission_hash),
                })
            );
        } else {
            println!(
                "{} Task Escrow '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct AgentTaskRecordView {
    name: String,
    address: String,
    creator: String,
    assigned_agent: Option<String>,
    verifier: Option<String>,
    permission_id: Option<String>,
    budget: String,
    deadline: u64,
    review_period: u32,
    policy_hash: String,
    created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_assigned_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_permission_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_error: Option<String>,
}

impl AgentTaskLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let creator_filter = self
            .creator
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .context("creator filter must be a valid native address")?;
        let agent_filter = self
            .agent
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .context("agent filter must be a valid native address")?;
        if matches!((self.deadline_after, self.deadline_before), (Some(after), Some(before)) if after >= before)
        {
            anyhow::bail!("deadline-after must be less than deadline-before");
        }
        let mut records: Vec<AgentTaskRecordView> = config
            .agent_tasks
            .iter()
            .filter(|(_, task)| {
                creator_filter.as_ref().is_none_or(|creator| {
                    task.creator.parse::<MsgAddressInt>().ok().as_ref() == Some(creator)
                })
            })
            .filter(|(_, task)| self.deadline_before.is_none_or(|value| task.deadline < value))
            .filter(|(_, task)| self.deadline_after.is_none_or(|value| task.deadline > value))
            .map(|(name, task)| AgentTaskRecordView {
                name: name.clone(),
                address: task.address.clone(),
                creator: task.creator.clone(),
                assigned_agent: task.assigned_agent.clone(),
                verifier: task.verifier.clone(),
                permission_id: task.permission_id.clone(),
                budget: display_tos(task.budget),
                deadline: task.deadline,
                review_period: task.review_period,
                policy_hash: task.policy_hash.clone(),
                created_at: task.created_at,
                chain_status: None,
                chain_assigned_agent: None,
                chain_permission_hash: None,
                chain_error: None,
            })
            .collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        if self.on_chain {
            let rpc_client = try_create_rpc_client(&config).await?;
            let provider = contracts::contract_provider!(rpc_client);
            let queries = records
                .iter()
                .enumerate()
                .map(|(index, record)| (index, record.address.clone()))
                .collect::<Vec<_>>();
            let results = stream::iter(queries.into_iter().map(|(index, raw_address)| {
                let provider = provider.clone();
                async move {
                    let result = async {
                        let address = raw_address
                            .parse::<MsgAddressInt>()
                            .context("invalid persisted Task Escrow address")?;
                        let stack = provider
                            .get_method(address.to_string(), "get_task_data", vec![])
                            .await?;
                        TaskEscrowContract::decode_data(&stack)
                    }
                    .await;
                    (index, result)
                }
            }))
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
            for (index, result) in results {
                let record = &mut records[index];
                match result {
                    Ok(data) => {
                        record.chain_status = Some(task_status_name(data.status).to_string());
                        record.chain_assigned_agent =
                            data.assigned_agent.map(|address| address.to_string());
                        record.chain_permission_hash = Some(hex::encode(data.permission_hash));
                    }
                    Err(error) => {
                        record.chain_error = Some(chain_query_failure_diagnostic(&error));
                    }
                }
            }
        }
        records.retain(|record| {
            self.status
                .as_ref()
                .is_none_or(|status| record.chain_status.as_deref() == Some(status.as_str()))
        });
        records.retain(|record| {
            let assigned = if self.on_chain {
                record.chain_assigned_agent.as_deref()
            } else {
                record.assigned_agent.as_deref()
            };
            if self.unassigned {
                return assigned.is_none() && (!self.on_chain || record.chain_status.is_some());
            }
            agent_filter.as_ref().is_none_or(|agent| {
                assigned.and_then(|value| value.parse::<MsgAddressInt>().ok()).as_ref()
                    == Some(agent)
            })
        });
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No Task Escrow records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:    {}\n  Creator:    {}\n  Agent:      {}\n  Verifier:   {}\n  Permission: {}\n  Budget:     {} TOS\n  Deadline:   {}",
                record.name.bold(),
                record.address,
                record.creator,
                record.assigned_agent.as_deref().unwrap_or("open"),
                record.verifier.as_deref().unwrap_or("none"),
                record.permission_id.as_deref().unwrap_or("none"),
                record.budget,
                record.deadline,
            );
            println!("  Review:     {}s", record.review_period);
            if let Some(status) = &record.chain_status {
                println!("  Chain status: {}", status);
            }
            if let Some(agent) = &record.chain_assigned_agent {
                println!("  Chain agent:  {}", agent);
            }
            if let Some(error) = &record.chain_error {
                println!("  Chain error:  {}", error);
            }
        }
        Ok(())
    }
}

impl AgentTaskEncodeCmd {
    fn run(&self) -> anyhow::Result<()> {
        let body = match self.operation {
            AgentTaskOperation::Accept => TaskEscrowContract::accept(self.query_id)?,
            AgentTaskOperation::Claim => TaskEscrowContract::claim(self.query_id)?,
            AgentTaskOperation::Reject => TaskEscrowContract::reject(self.query_id)?,
            AgentTaskOperation::Result => {
                let result_hash = parse_required_hash("result-hash", &self.result_hash)?;
                let evidence_hash = parse_required_hash("evidence-hash", &self.evidence_hash)?;
                TaskEscrowContract::result(self.query_id, result_hash, evidence_hash)?
            }
            AgentTaskOperation::Dispute => TaskEscrowContract::dispute(
                self.query_id,
                parse_required_hash("dispute-hash", &self.dispute_hash)?,
            )?,
            AgentTaskOperation::Resolve => {
                let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
                match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
                    Some(signature) => {
                        TaskEscrowContract::resolve_signed(self.query_id, payout, &signature)?
                    }
                    None => TaskEscrowContract::resolve(self.query_id, payout)?,
                }
            }
            AgentTaskOperation::Settle => {
                let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
                match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
                    Some(signature) => {
                        TaskEscrowContract::settle_signed(self.query_id, payout, &signature)?
                    }
                    None => TaskEscrowContract::settle(self.query_id, payout)?,
                }
            }
            AgentTaskOperation::Cancel => TaskEscrowContract::cancel(self.query_id)?,
            AgentTaskOperation::Timeout => TaskEscrowContract::timeout(self.query_id)?,
            AgentTaskOperation::RotateAttestorKey => TaskEscrowContract::rotate_attestor_key(
                self.query_id,
                parse_required_hash("new-attestor-pubkey", &self.new_attestor_pubkey)?,
            )?,
            AgentTaskOperation::RevokeAttestor => {
                TaskEscrowContract::revoke_attestor(self.query_id)?
            }
        };
        println!("{}", base64::engine::general_purpose::STANDARD.encode(write_boc(&body)?));
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct AgentTaskStateView {
    creator: String,
    assigned_agent: Option<String>,
    verifier: Option<String>,
    permission_id: Option<String>,
    permission_hash: String,
    budget: String,
    budget_nanotos: u64,
    deadline: u64,
    review_period: u32,
    workchain: i32,
    address: String,
    policy_hash: String,
    state_init_boc: String,
    code_hash: String,
    data_hash: String,
}

impl AgentTaskBuildStateCmd {
    fn run(&self) -> anyhow::Result<()> {
        let creator = MsgAddressInt::from_str(&self.creator)
            .with_context(|| "creator must be a valid native address")?;
        let assigned_agent = self
            .agent
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .with_context(|| "agent must be a valid native address")?;
        let verifier = self
            .verifier
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .with_context(|| "verifier must be a valid native address")?;
        let policy_hash = parse_optional_hash("policy-hash", &Some(self.policy_hash.clone()))?
            .expect("policy hash is required");
        if let Some(permission_id) = &self.permission_id {
            validate_non_empty("permission-id", permission_id)?;
        }
        let permission_hash = match parse_optional_hash("permission-hash", &self.permission_hash)? {
            Some(value) => value,
            None => permission_id_hash(self.permission_id.as_deref()),
        };
        let budget_nanotos = resolve_nanotos("budget", self.budget, self.budget_nanotos, None)?;
        let attestor_pubkey = parse_optional_hash("attestor-pubkey", &self.attestor_pubkey)?;
        let init = TaskEscrowInit {
            creator: creator.clone(),
            assigned_agent: assigned_agent.clone(),
            verifier: verifier.clone(),
            budget: budget_nanotos,
            deadline: self.deadline,
            review_period: self.review_period,
            settlement_policy_hash: policy_hash,
            permission_hash,
            attestor_pubkey,
        };
        let state_init = TaskEscrowContract::build_state_init(&init)?;
        let address = TaskEscrowContract::calculate_address(self.workchain, &init)?;
        let state_cell = state_init.write_to_new_cell()?.into_cell()?;
        let code_hash = hex::encode(TaskEscrowContract::code()?.hash(0));
        let data_hash = hex::encode(TaskEscrowContract::build_data(&init)?.hash(0));
        let view = AgentTaskStateView {
            creator: creator.to_string(),
            assigned_agent: assigned_agent.map(|value| value.to_string()),
            verifier: verifier.map(|value| value.to_string()),
            permission_id: self.permission_id.clone(),
            permission_hash: hex::encode(permission_hash),
            budget: display_tos(init.budget),
            budget_nanotos: init.budget,
            deadline: init.deadline,
            review_period: init.review_period,
            workchain: self.workchain,
            address: address.to_string(),
            policy_hash: hex::encode(policy_hash),
            state_init_boc: base64::engine::general_purpose::STANDARD
                .encode(write_boc(&state_cell)?),
            code_hash,
            data_hash,
        };
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Task Escrow address: {}", view.address);
            println!("Creator: {}", view.creator);
            println!("Assigned Agent: {}", view.assigned_agent.as_deref().unwrap_or("none"));
            println!("Verifier: {}", view.verifier.as_deref().unwrap_or("none"));
            println!("Permission ID: {}", view.permission_id.as_deref().unwrap_or("none"));
            println!("Permission hash: {}", view.permission_hash);
            println!("Budget: {} TOS", view.budget);
            println!("Deadline: {}", view.deadline);
            println!("StateInit BOC: {}", view.state_init_boc);
        }
        Ok(())
    }
}

impl AgentAccountBuildStateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?
            .clone();

        let (init, owner_address) =
            build_agent_account_init(&self.wallet, &agent_wallet, vault).await?;
        if agent_wallet.agent_account_deployment_id.is_none() {
            config
                .agent_wallets
                .get_mut(&self.wallet)
                .context("Agent wallet disappeared while persisting deployment ID")?
                .agent_account_deployment_id = Some(hex::encode(init.deployment_id));
            save_config(&config, path)?;
        }
        let state_init = AgentAccountContract::build_state_init(&init)?;
        let address = AgentAccountContract::calculate_address(self.workchain, &init)?;
        let state_cell = state_init.write_to_new_cell()?.into_cell()?;
        let data_cell = AgentAccountContract::build_data(&init)?;
        let code_cell = AgentAccountContract::code()?;
        let state_init_boc =
            base64::engine::general_purpose::STANDARD.encode(write_boc(&state_cell)?);

        let view = AgentAccountStateView {
            wallet: self.wallet.clone(),
            address: address.to_string(),
            workchain: self.workchain,
            owner: owner_address,
            controller_key: describe_key(&agent_wallet.controller_key),
            controller_pubkey: hex::encode(init.controller_pubkey),
            deployment_id: hex::encode(init.deployment_id),
            max_per_tx: init.max_per_tx,
            daily_limit: init.daily_limit,
            default_task_timeout_secs: init.default_task_timeout_secs,
            metadata_hash: agent_wallet.metadata_hash.clone(),
            service_endpoint_hash: agent_wallet.service_endpoint_hash.clone(),
            state_init_boc,
            code_hash: hex::encode(code_cell.hash(0)),
            data_hash: hex::encode(data_cell.hash(0)),
        };

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{}", "Agent Account StateInit".bold());
        println!("  Wallet profile:       {}", view.wallet);
        println!("  Address:              {}", view.address);
        println!("  Owner:                {}", view.owner);
        println!("  Controller key:       {}", view.controller_key);
        println!("  Controller pubkey:    {}", view.controller_pubkey);
        println!("  Deployment ID:        {}", view.deployment_id);
        println!("  Max per action:       {} TOS", display_tos(view.max_per_tx));
        println!("  Daily limit:          {} TOS", display_tos(view.daily_limit));
        println!("  Default task timeout: {}s", view.default_task_timeout_secs);
        println!("  Code hash:            {}", view.code_hash);
        println!("  Data hash:            {}", view.data_hash);
        println!("  StateInit BOC:        {}", view.state_init_boc);
        Ok(())
    }
}

impl AgentAccountDeployCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        if self.amount == 0.0 {
            anyhow::bail!("amount must be greater than zero");
        }

        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let mut agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?
            .clone();

        let mut retired_generation = None;
        if self.new_generation {
            let old_address = agent_wallet
                .agent_account_address
                .as_ref()
                .context("--new-generation requires a previously deployed Agent Account")?
                .parse::<MsgAddressInt>()?;
            let old_info = rpc_client.get_address_information(&old_address).await?;
            match old_info.state {
                AccountState::Active => anyhow::bail!(
                    "refusing to replace active Agent Account {}; retire or recover it first",
                    old_address
                ),
                AccountState::Frozen => anyhow::bail!(
                    "refusing to replace frozen Agent Account {}; it can still be unfrozen with its old StateInit",
                    old_address
                ),
                AccountState::Uninitialized => {}
            }
            let old_deployment_id = agent_wallet
                .agent_account_deployment_id
                .clone()
                .context("--new-generation requires the previous deployment ID")?;
            let mut deployment_id = [0u8; 32];
            while deployment_id == [0u8; 32] {
                rand::rngs::OsRng.fill_bytes(&mut deployment_id);
            }
            retired_generation = Some((old_address.to_string(), old_deployment_id));
            agent_wallet.agent_account_deployment_id = Some(hex::encode(deployment_id));
            agent_wallet.agent_account_address = None;
        }

        let (init, _owner_address) =
            build_agent_account_init(&self.wallet, &agent_wallet, vault.clone()).await?;
        let owner = init.owner.clone();
        let state_init = AgentAccountContract::build_state_init(&init)?;
        let address = AgentAccountContract::calculate_address(self.workchain, &init)?;
        let address_info = rpc_client.get_address_information(&address).await?;
        if address_info.state == AccountState::Active {
            if self.new_generation {
                anyhow::bail!("fresh deployment ID unexpectedly resolves to an active account");
            }
            let deployed_code = address_info.code.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Agent Account '{}' has no deployed code", self.wallet)
            })?;
            if read_single_root_boc(deployed_code)?.hash(0) != AgentAccountContract::code()?.hash(0)
            {
                anyhow::bail!(
                    "Active account at {} does not match the supported Agent Account template",
                    address
                );
            }
            let provider = contracts::contract_provider!(rpc_client);
            let deployed = AgentAccountContract::get_data(provider.as_ref(), &address).await?;
            if !agent_account_data_matches(&deployed, &init) {
                anyhow::bail!(
                    "Active Agent Account at {} does not match local profile '{}'",
                    address,
                    self.wallet
                );
            }
            config
                .agent_wallets
                .get_mut(&self.wallet)
                .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?
                .agent_account_address = Some(address.to_string());
            save_config(&config, path)?;
            if self.format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "wallet": self.wallet,
                        "address": address.to_string(),
                        "status": "already_deployed"
                    }))?
                );
            } else {
                println!(
                    "{} Agent Account '{}' already deployed at {}; address saved to profile",
                    "OK".green().bold(),
                    self.wallet,
                    address
                );
            }
            return Ok(());
        }
        if address_info.state == AccountState::Frozen {
            anyhow::bail!("Agent Account '{}' ({}) is frozen", self.wallet, address);
        }
        if agent_wallet.agent_account_address.is_some() {
            anyhow::bail!(
                "Agent Account generation at {} is no longer active; use --new-generation to deploy a fresh deployment ID/address",
                address
            );
        }

        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }
        if payer_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        let amount_nanotos = tos_to_nanotos(self.amount);
        if !(1..=payer_info.balance.saturating_sub(AGENT_ACCOUNT_DEPLOY_GAS))
            .contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                self.amount,
                display_tos(payer_info.balance)
            );
        }

        if self.format != OutputFormat::Json {
            println!(
                "\n{}\n  Profile:  {}\n  Owner:    {}\n  From:     {} ({})\n  Account:  {}\n  Amount:   {:.9} TOS\n",
                "Agent Account deployment summary:".cyan().bold(),
                self.wallet,
                owner,
                self.from,
                payer_address,
                address,
                self.amount,
            );
        }
        if !self.yes && !confirm("Confirm Agent Account deployment?")? {
            println!("{}", "Agent Account deployment cancelled".yellow());
            return Ok(());
        }

        let wallet = make_wallet(rpc_client.clone(), payer_cfg, payer_secret, &self.from)
            .await
            .context("create Agent Account funding wallet")?;
        let msg = wallet
            .build_message(
                address.clone(),
                amount_nanotos,
                Cell::default(),
                false,
                payer_info.seqno,
                None,
                Some(state_init),
            )
            .await?;
        if let Some((old_address, old_deployment_id)) = retired_generation {
            let old_address_parsed = old_address.parse::<MsgAddressInt>()?;
            let old_info = rpc_client.get_address_information(&old_address_parsed).await?;
            if old_info.state != AccountState::Uninitialized {
                anyhow::bail!(
                    "previous Agent Account {} changed state before replacement; refusing new generation",
                    old_address
                );
            }
            let global_id = match rpc_client.get_config_param(19).await? {
                ConfigParamEnum::ConfigParam19(value) => value as i32,
                _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
            };
            open_controller_journal(path)?.retire_generation(
                &old_address,
                global_id,
                &old_deployment_id,
                time_format::now(),
            )?;
            let profile = config
                .agent_wallets
                .get_mut(&self.wallet)
                .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
            profile.agent_account_deployment_id = Some(hex::encode(init.deployment_id));
            profile.agent_account_address = None;
            save_config(&config, path)?;
        }
        rpc_client.send_boc(&write_boc(&msg)?).await?;
        wait_for_deploy(
            rpc_client,
            &address,
            &common::task_cancellation::CancellationCtx::default(),
            self.format != OutputFormat::Json,
            DEPLOY_TIMEOUT,
        )
        .await?;

        let code_cell = AgentAccountContract::code()?;
        let data_cell = AgentAccountContract::build_data(&init)?;
        let result = AgentAccountDeployView {
            wallet: self.wallet.clone(),
            address: address.to_string(),
            owner: owner.to_string(),
            deployment_id: hex::encode(init.deployment_id),
            payer: self.from.clone(),
            payer_address: payer_address.to_string(),
            amount: display_tos(amount_nanotos),
            code_hash: hex::encode(code_cell.hash(0)),
            data_hash: hex::encode(data_cell.hash(0)),
            status: "deployed".to_string(),
        };
        let deployed_profile = config
            .agent_wallets
            .get_mut(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        deployed_profile.agent_account_address = Some(address.to_string());
        deployed_profile.agent_account_deployment_id = Some(hex::encode(init.deployment_id));
        save_config(&config, path)?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{} Agent Account '{}' deployed at {}",
                "OK".green().bold(),
                self.wallet,
                result.address
            );
        }
        Ok(())
    }
}

impl AgentAccountShowCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let address = self
            .address
            .parse::<MsgAddressInt>()
            .with_context(|| format!("Invalid Agent Account address '{}'", self.address))?;
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let view = load_agent_account_chain_view(rpc_client, &address, None, None).await?;
        print_agent_account_chain_view(&view, self.format.clone())
    }
}

impl AgentAccountStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let (init, _) = build_agent_account_init(&self.wallet, agent_wallet, vault).await?;
        let address = if let Some(address) = &agent_wallet.agent_account_address {
            address.parse::<MsgAddressInt>().context("Invalid persisted Agent Account address")?
        } else {
            AgentAccountContract::calculate_address(self.workchain, &init)?
        };
        let view = load_agent_account_chain_view(
            rpc_client,
            &address,
            Some(self.wallet.clone()),
            Some(&init),
        )
        .await?;
        print_agent_account_chain_view(&view, self.format.clone())
    }
}

impl AgentAccountUpdatePolicyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        run_agent_account_owner_action(
            config_path,
            &self.wallet,
            self.amount,
            self.yes,
            self.format.clone(),
            "update-policy",
            |query_id, init| {
                AgentAccountContract::build_update_policy_message(
                    query_id,
                    &AgentAccountPolicyUpdate {
                        max_per_tx: init.max_per_tx,
                        daily_limit: init.daily_limit,
                        default_task_timeout_secs: init.default_task_timeout_secs,
                        metadata_hash: init.metadata_hash,
                        service_endpoint_hash: init.service_endpoint_hash,
                    },
                )
            },
            |data, init| {
                data.max_per_tx == init.max_per_tx
                    && data.daily_limit == init.daily_limit
                    && data.default_task_timeout_secs == init.default_task_timeout_secs
                    && data.metadata_hash == init.metadata_hash
                    && data.service_endpoint_hash == init.service_endpoint_hash
            },
        )
        .await
    }
}

impl AgentAccountRotateControllerCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        run_agent_account_owner_action(
            config_path,
            &self.wallet,
            self.amount,
            self.yes,
            self.format.clone(),
            "rotate-controller",
            |query_id, init| {
                AgentAccountContract::build_rotate_controller_message(
                    query_id,
                    init.controller_pubkey,
                )
            },
            |data, init| data.controller_pubkey == init.controller_pubkey,
        )
        .await
    }
}

impl AgentAccountTaskSendCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.action_id.len() != 64
            || !self
                .action_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("action_id must be exactly 64 lowercase hexadecimal characters");
        }
        validate_tos_amount("value", self.value)?;
        if self.value == 0.0 {
            anyhow::bail!("value must be greater than zero");
        }
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent Account is not deployed for this wallet"))?
            .parse::<MsgAddressInt>()?;
        let target = self.target.parse::<MsgAddressInt>().context("invalid target address")?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let value = tos_to_nanotos(self.value);
        if value > data.max_per_tx {
            anyhow::bail!(
                "value {} exceeds Agent Account max_per_tx {}",
                display_tos(value),
                display_tos(data.max_per_tx)
            );
        }
        let now = time_format::now() as u32;
        if self.valid_until <= now {
            anyhow::bail!("valid_until must be a future Unix timestamp");
        }
        if u128::from(self.valid_until)
            > u128::from(now) + u128::from(data.default_task_timeout_secs)
        {
            anyhow::bail!("valid_until exceeds the Agent Account default_task_timeout");
        }
        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("controller secret has no public key"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        if controller_pubkey != data.controller_pubkey {
            anyhow::bail!("configured controller key does not match the deployed Agent Account");
        }
        let body = match &self.body_boc {
            Some(encoded) => {
                read_single_root_boc(base64::engine::general_purpose::STANDARD.decode(encoded)?)?
            }
            None => Cell::default(),
        };
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let master = rpc_client.get_masterchain_info().await?;
        let zero_state = master.init.context("primary RPC omitted the zero-state identity")?;
        let network_domain = RelayNetworkDomainPin {
            network_id: format!("tos:global-id:{global_id}"),
            global_id,
            zero_state_root_hash: format!("sha256:{}", hex::encode(&zero_state.root_hash)),
            zero_state_file_hash: format!("sha256:{}", hex::encode(&zero_state.file_hash)),
            workchain_id: account.workchain_id(),
        };
        let action_body_hash = *body.repr_hash().as_array();
        let action_body_identity = agent_account_task_body_hash(&body);
        let payload = AgentAccountContract::build_task_send_payload(
            global_id,
            data.controller_epoch,
            data.seqno,
            self.valid_until,
            &target,
            value,
            body,
        )?;
        let hash_to_sign =
            AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
        if !self.yes
            && !confirm(&format!(
                "Authorize controller action {} from {} to {} for {}, seqno {}, valid_until {}?",
                self.action_id,
                account,
                target,
                display_tos(value),
                data.seqno,
                self.valid_until
            ))?
        {
            return Ok(());
        }

        let mut identity = Sha256::new();
        identity.update(b"tos.agent-account.controller-action.v1\0");
        let account_text = account.to_string();
        let target_text = target.to_string();
        for part in [self.action_id.as_bytes(), account_text.as_bytes(), target_text.as_bytes()] {
            identity.update((part.len() as u64).to_be_bytes());
            identity.update(part);
        }
        for part in [
            global_id.to_be_bytes().as_slice(),
            value.to_be_bytes().as_slice(),
            self.valid_until.to_be_bytes().as_slice(),
            action_body_hash.as_slice(),
        ] {
            identity.update((part.len() as u64).to_be_bytes());
            identity.update(part);
        }
        let claim = ControllerActionClaim {
            account: account.to_string(),
            network_global_id: global_id,
            network_domain: Some(network_domain),
            deployment_id: hex::encode(data.deployment_id),
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            target: target.to_string(),
            value_atomic: value,
            body_hash: Some(action_body_identity),
            action_kind: "agent-task-send".to_owned(),
            idempotency_key: self.action_id.clone(),
            action_identity: format!("sha256:{}", hex::encode(identity.finalize())),
            valid_until: self.valid_until,
        };
        let journal = open_controller_journal(Path::new(config_path))?;
        journal.reconcile_finalized_state(
            &claim.account,
            claim.network_global_id,
            &claim.deployment_id,
            data.controller_epoch,
            data.seqno,
            time_format::now(),
        )?;
        let (record, _) = journal.claim_primary(claim.clone(), time_format::now())?;
        if record.status == ControllerActionStatus::Resolved {
            anyhow::bail!(
                "controller action {} sequence was consumed without a confirmed task dispatch; verify the target transaction/task state",
                self.action_id,
            );
        }
        if record.status == ControllerActionStatus::Broadcasting {
            anyhow::bail!(
                "controller action broadcast is ambiguous; resolve finalized seqno before retrying"
            );
        }
        let boc = if let Some(encoded) = record.exact_signed_boc_base64 {
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let signature = keypair.sign(&hash_to_sign).await?;
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
            journal.attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                &digest,
                time_format::now(),
            )?;
            boc
        };
        validate_exact_boc_before_broadcast(&boc)?;
        journal.begin_broadcast(&claim, time_format::now())?;
        rpc_client.send_boc(&boc).await?;
        println!("{} controller task action sent from {}", "OK".green().bold(), account);
        Ok(())
    }
}

fn validate_tvm_cell_digest(name: &str, value: &str) -> anyhow::Result<()> {
    let digest = value
        .strip_prefix("tvm-cell-sha256:")
        .with_context(|| format!("{name} has the wrong domain"))?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("{name} is not a canonical TVM cell digest");
    }
    Ok(())
}

fn validate_task_send_resolution_claim(
    record: &contracts::ControllerActionRecord,
    account: &MsgAddressInt,
) -> anyhow::Result<RelayNetworkDomainPin> {
    validate_controller_action_id(&record.claim.idempotency_key)?;
    if record.claim.action_kind != "agent-task-send"
        || record.claim.account != account.to_string()
        || record.claim.value_atomic == 0
    {
        anyhow::bail!("task-send action ID belongs to a different custody effect");
    }
    if record.claim.deployment_id.len() != 64
        || !record
            .claim
            .deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("task-send custody deployment ID is not canonical");
    }
    let body_hash = record
        .claim
        .body_hash
        .as_deref()
        .context("task-send custody claim has no exact body hash")?;
    validate_tvm_cell_digest("task-send custody body hash", body_hash)?;
    record.claim.target.parse::<MsgAddressInt>().context("task-send custody target is invalid")?;
    let signed_digest = record
        .exact_signed_boc_digest
        .as_deref()
        .context("task-send custody record has no exact signed BOC digest")?;
    validate_sha256_digest("exact_signed_boc_digest", signed_digest)?;
    let network = record
        .claim
        .network_domain
        .clone()
        .context("task-send custody claim has no complete network domain")?;
    if network.global_id != record.claim.network_global_id
        || network.workchain_id != account.workchain_id()
    {
        anyhow::bail!("task-send custody network domain conflicts with its claim");
    }
    validate_sha256_digest("zero_state_root_hash", &network.zero_state_root_hash)?;
    validate_sha256_digest("zero_state_file_hash", &network.zero_state_file_hash)?;
    Ok(network)
}

fn validate_unresolved_task_send_boc(
    record: &contracts::ControllerActionRecord,
) -> anyhow::Result<String> {
    // `action_by_idempotency_key` loads the journal through its fail-closed
    // document validator. That validator semantically decodes this exact BOC
    // and binds opcode/global ID/epoch/seqno/expiry/target/value/body to the
    // claim. Recheck canonical bytes and digest here before using its message
    // cell hash as the finalized transaction's exact inbound identity.
    let encoded = record
        .exact_signed_boc_base64
        .as_deref()
        .context("unresolved task-send custody record has no exact signed BOC")?;
    let boc = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode unresolved task-send signed BOC")?;
    validate_exact_boc_before_broadcast(&boc)
        .context("unresolved task-send signed BOC failed the exact-BOC gate")?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
    if record.exact_signed_boc_digest.as_deref() != Some(digest.as_str()) {
        anyhow::bail!("unresolved task-send signed BOC digest does not match custody");
    }
    let root = read_single_root_boc(&boc)?;
    Ok(format!("tvm-cell-sha256:{}", hex::encode(root.hash(0))))
}

fn validate_task_send_resolution_evidence(
    record: &contracts::ControllerActionRecord,
    resolution: &ControllerActionResolutionEvidence,
) -> anyhow::Result<()> {
    if resolution.evidence_kind != TASK_SEND_FINALIZED_SCHEMA
        || resolution.evidence_digest
            != controller_resolution_evidence_digest(
                TASK_SEND_FINALIZED_SCHEMA,
                &resolution.evidence,
            )?
    {
        anyhow::bail!("resolved task-send has invalid exact-winner evidence identity");
    }
    let evidence = &resolution.evidence;
    let expected_network = serde_json::to_value(
        record
            .claim
            .network_domain
            .as_ref()
            .context("resolved task-send claim lost its network domain")?,
    )?;
    let quorum = evidence
        .get("quorum")
        .and_then(serde_json::Value::as_object)
        .context("resolved task-send evidence has no quorum")?;
    let transaction: FinalizedTaskSendObservation = serde_json::from_value(
        evidence
            .get("transaction")
            .cloned()
            .context("resolved task-send evidence has no transaction")?,
    )
    .context("resolved task-send transaction evidence is malformed")?;
    let observations: Vec<FinalizedTaskSendObservation> = serde_json::from_value(
        evidence
            .get("observations")
            .cloned()
            .context("resolved task-send evidence has no observations")?,
    )
    .context("resolved task-send process-view observations are malformed")?;
    let finalized_controller_epoch = evidence
        .get("finalized_controller_epoch")
        .and_then(serde_json::Value::as_u64)
        .context("resolved task-send evidence has no finalized controller epoch")?;
    let finalized_seqno = u32::try_from(
        evidence
            .get("finalized_seqno")
            .and_then(serde_json::Value::as_u64)
            .context("resolved task-send evidence has no finalized seqno")?,
    )
    .context("resolved task-send finalized seqno exceeds uint32")?;
    let controller_state_advanced = finalized_controller_epoch > record.claim.controller_epoch
        || (finalized_controller_epoch == record.claim.controller_epoch
            && finalized_seqno > record.claim.seqno);
    let distinct_endpoints =
        observations.iter().map(|item| &item.transaction.endpoint).collect::<BTreeSet<_>>();
    let distinct_locators = observations
        .iter()
        .map(|item| &item.transaction.locator_identity_digest)
        .collect::<BTreeSet<_>>();
    let exact_observations =
        observations.iter().all(|item| item.quorum_key() == transaction.quorum_key());
    validate_sha256_digest(
        "task-send transaction hash",
        &transaction.transaction.transaction_hash,
    )?;
    validate_sha256_digest(
        "task-send transaction BOC digest",
        &transaction.transaction.transaction_boc_digest,
    )?;
    validate_tvm_cell_digest(
        "task-send outbound message hash",
        &transaction.outbound_message_cell_hash,
    )?;
    validate_tvm_cell_digest("task-send outbound body hash", &transaction.outbound_body_hash)?;
    validate_sha256_digest("task-send block root hash", &transaction.transaction.block_root_hash)?;
    validate_sha256_digest("task-send block file hash", &transaction.transaction.block_file_hash)?;
    for observation in &observations {
        validate_sha256_digest(
            "task-send RPC locator identity",
            &observation.transaction.locator_identity_digest,
        )?;
    }
    validate_tvm_cell_digest(
        "task-send submitted message hash",
        evidence
            .get("submitted_message_cell_hash")
            .and_then(serde_json::Value::as_str)
            .context("resolved task-send has no submitted message hash")?,
    )?;
    if evidence.get("schema").and_then(serde_json::Value::as_str)
        != Some(TASK_SEND_FINALIZED_SCHEMA)
        || evidence.get("action_id").and_then(serde_json::Value::as_str)
            != Some(record.claim.idempotency_key.as_str())
        || evidence.get("source_account").and_then(serde_json::Value::as_str)
            != Some(record.claim.account.as_str())
        || evidence.get("deployment_id").and_then(serde_json::Value::as_str)
            != Some(record.claim.deployment_id.as_str())
        || evidence.get("controller_epoch").and_then(serde_json::Value::as_u64)
            != Some(record.claim.controller_epoch)
        || evidence.get("seqno").and_then(serde_json::Value::as_u64)
            != Some(u64::from(record.claim.seqno))
        || !controller_state_advanced
        || evidence.get("destination").and_then(serde_json::Value::as_str)
            != Some(record.claim.target.as_str())
        || evidence.get("amount_nanotos").and_then(serde_json::Value::as_u64)
            != Some(record.claim.value_atomic)
        || evidence.get("body_hash").and_then(serde_json::Value::as_str)
            != record.claim.body_hash.as_deref()
        || evidence.get("exact_signed_boc_digest").and_then(serde_json::Value::as_str)
            != record.exact_signed_boc_digest.as_deref()
        || evidence.get("network_domain") != Some(&expected_network)
        || evidence.get("state").and_then(serde_json::Value::as_str) != Some("resolved")
        || evidence.get("independent_operator_domains_proven").and_then(serde_json::Value::as_bool)
            != Some(false)
        || evidence.get("process_view_scope").and_then(serde_json::Value::as_str)
            != Some(
                "distinct RPC process views; no independent-operator or Byzantine-finality claim",
            )
        || evidence.get("block_reference_scope").and_then(serde_json::Value::as_str)
            != Some(
                "RPC-asserted transaction and block identifiers; no inclusion proof was verified",
            )
        || quorum.get("members").and_then(serde_json::Value::as_u64) != Some(3)
        || quorum.get("threshold").and_then(serde_json::Value::as_u64) != Some(2)
        || quorum.get("agreeing").and_then(serde_json::Value::as_u64)
            != Some(observations.len() as u64)
        || !(2..=3).contains(&observations.len())
        || distinct_endpoints.len() != observations.len()
        || distinct_locators.len() != observations.len()
        || observations.iter().any(|item| item.transaction.endpoint.is_empty())
        || !exact_observations
        || !observations.contains(&transaction)
        || transaction.finalized_controller_epoch != finalized_controller_epoch
        || transaction.finalized_seqno != finalized_seqno
        || observations.iter().any(|item| {
            item.finalized_controller_epoch != finalized_controller_epoch
                || item.finalized_seqno != finalized_seqno
        })
        || Some(transaction.outbound_body_hash.as_str()) != record.claim.body_hash.as_deref()
    {
        anyhow::bail!("resolved task-send exact-winner evidence conflicts with its custody claim");
    }
    Ok(())
}

type TaskSendResolutionVote = FinalizedTaskSendObservation;

fn record_task_send_resolution_vote(
    votes: &mut BTreeMap<String, Vec<TaskSendResolutionVote>>,
    observation: FinalizedEconomicPaymentMatch,
    finalized: anyhow::Result<AgentAccountData>,
    record: &contracts::ControllerActionRecord,
) {
    let Ok(finalized) = finalized else {
        return;
    };
    let controller_state_advanced = finalized.controller_epoch > record.claim.controller_epoch
        || (finalized.controller_epoch == record.claim.controller_epoch
            && finalized.seqno > record.claim.seqno);
    if hex::encode(finalized.deployment_id) != record.claim.deployment_id
        || !controller_state_advanced
    {
        return;
    }
    let Some(outbound_body_hash) = observation.outbound_body_hash else {
        return;
    };
    let vote = FinalizedTaskSendObservation {
        transaction: observation.observation,
        outbound_message_cell_hash: observation.outbound_message_cell_hash,
        outbound_body_hash,
        finalized_controller_epoch: finalized.controller_epoch,
        finalized_seqno: finalized.seqno,
    };
    votes.entry(vote.quorum_key()).or_default().push(vote);
}

impl AgentAccountTaskSendResolveCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        if self.quorum_configs.len() != 2
            || self.max_transactions == 0
            || self.max_transactions > 10_000
        {
            anyhow::bail!(
                "task-send resolution requires exactly two additional RPC configs and a bounded transaction history"
            );
        }
        let primary_path = Path::new(config_path);
        if !primary_path.is_absolute() {
            anyhow::bail!("primary config must be absolute for task-send resolution");
        }
        let primary = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => {
                let (config, _vault, _rpc) = load_config_vault_rpc_client_fd(fd, format).await?;
                config
            }
            (None, None) => {
                let primary_bytes =
                    fs::read(primary_path).context("read primary task-send RPC config")?;
                AppConfig::load_bytes(
                    &primary_bytes,
                    config_format_from_path(primary_path)?,
                    "primary task-send RPC config",
                )?
            }
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = primary
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let journal = if self.journal_directory.is_some() {
            let runtime = agent_wallet
                .runtime
                .as_ref()
                .context("Agent Wallet has no owner-pinned runtime authority")?;
            open_economic_controller_journal(
                primary_path,
                self.journal_directory.as_deref(),
                runtime.economic_custody_journal_directory.as_deref(),
            )?
        } else {
            open_controller_journal(primary_path)?
        };
        let record = journal.action_by_idempotency_key(&self.action_id)?;
        let expected_network = validate_task_send_resolution_claim(&record, &account)?;

        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved task-send has no replayable exact-winner evidence")?;
            validate_task_send_resolution_evidence(&record, resolution)?;
            println!("{}", resolution.evidence);
            return Ok(());
        }
        if record.status != ControllerActionStatus::Broadcasting {
            anyhow::bail!("only an ambiguously broadcast exact task-send may be resolved");
        }
        let submitted_message_cell_hash = validate_unresolved_task_send_boc(&record)?;

        let mut configurations = vec![primary];
        for value in &self.quorum_configs {
            let path = Path::new(value);
            if !path.is_absolute() {
                anyhow::bail!("every task-send quorum config must be absolute");
            }
            let bytes = fs::read(path).context("read task-send quorum config")?;
            configurations.push(AppConfig::load_bytes(
                &bytes,
                config_format_from_path(path)?,
                "task-send quorum config",
            )?);
        }
        let mut endpoints = BTreeSet::new();
        let mut members = Vec::with_capacity(3);
        for config in configurations {
            let configured = config.chain_rpc.endpoints();
            if configured.len() != 1 {
                anyhow::bail!("every task-send quorum config must name exactly one RPC endpoint");
            }
            let (endpoint, display_origin) = canonicalize_chain_rpc_endpoint(&configured[0])?;
            // Distinctness is judged on the origin, matching how the evidence
            // records and re-validates endpoints: two configs naming the same
            // origin with different paths are one RPC process, and letting
            // them pass here would only fail later with a confusing
            // evidence-conflict error after a quorum was already found.
            if !endpoints.insert(display_origin.clone()) {
                anyhow::bail!("task-send quorum RPC endpoints must be distinct");
            }
            members.push((
                config,
                endpoint.clone(),
                display_origin,
                rpc_locator_identity_digest(&endpoint)?,
            ));
        }
        let threshold = 2;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut failures: Vec<String> = Vec::new();
        loop {
            let mut votes: BTreeMap<String, Vec<TaskSendResolutionVote>> = BTreeMap::new();
            for (config, _endpoint, display_origin, locator_identity_digest) in &members {
                let observation = observe_finalized_economic_payment(
                    config,
                    display_origin.clone(),
                    locator_identity_digest.clone(),
                    &expected_network,
                    &account,
                    &record,
                    self.max_transactions,
                )
                .await;
                let observation = match observation {
                    Ok(observation) => observation,
                    Err(error) => {
                        failures.push(rpc_failure_diagnostic(display_origin, &error));
                        continue;
                    }
                };
                let finalized: anyhow::Result<AgentAccountData> = async {
                    let rpc = try_create_rpc_client(config).await?;
                    let provider = contracts::contract_provider!(rpc);
                    AgentAccountContract::get_data(provider.as_ref(), &account).await
                }
                .await;
                if let Err(error) = &finalized {
                    // A member that found the transaction but cannot answer the
                    // account-state query would otherwise time the resolution
                    // out with no diagnostic at all, hiding the difference
                    // between "no finalized transaction" and "state
                    // unavailable".
                    failures.push(format!(
                        "{}: {}",
                        display_origin,
                        chain_query_failure_diagnostic(error)
                    ));
                }
                record_task_send_resolution_vote(&mut votes, observation, finalized, &record);
            }
            if let Some(winner) = votes.values().find(|group| group.len() >= threshold) {
                let finalized_controller_epoch = winner[0].finalized_controller_epoch;
                let finalized_seqno = winner[0].finalized_seqno;
                let output = serde_json::json!({
                    "schema": TASK_SEND_FINALIZED_SCHEMA,
                    "wallet": self.wallet,
                    "action_id": self.action_id,
                    "source_account": record.claim.account,
                    "deployment_id": record.claim.deployment_id,
                    "controller_epoch": record.claim.controller_epoch,
                    "seqno": record.claim.seqno,
                    "finalized_controller_epoch": finalized_controller_epoch,
                    "finalized_seqno": finalized_seqno,
                    "destination": record.claim.target,
                    "amount_nanotos": record.claim.value_atomic,
                    "body_hash": record.claim.body_hash,
                    "exact_signed_boc_digest": record.exact_signed_boc_digest,
                    "submitted_message_cell_hash": submitted_message_cell_hash,
                    "network_domain": expected_network,
                    "quorum": {"members": 3, "threshold": threshold, "agreeing": winner.len()},
                    "process_view_scope": "distinct RPC process views; no independent-operator or Byzantine-finality claim",
                    "block_reference_scope": "RPC-asserted transaction and block identifiers; no inclusion proof was verified",
                    "independent_operator_domains_proven": false,
                    "transaction": &winner[0],
                    "observations": winner,
                    "state": "resolved"
                });
                let resolution = ControllerActionResolutionEvidence {
                    evidence_kind: TASK_SEND_FINALIZED_SCHEMA.to_owned(),
                    evidence_digest: controller_resolution_evidence_digest(
                        TASK_SEND_FINALIZED_SCHEMA,
                        &output,
                    )?,
                    evidence: output.clone(),
                };
                validate_task_send_resolution_evidence(&record, &resolution)?;
                let exact_signed_boc_digest = record
                    .exact_signed_boc_digest
                    .as_deref()
                    .context("task-send custody record lost its exact signed BOC digest")?;
                let resolved = match journal.resolve_exact_winner(
                    &record.claim,
                    exact_signed_boc_digest,
                    finalized_controller_epoch,
                    finalized_seqno,
                    resolution,
                    time_format::now(),
                ) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        let replay = journal.action_by_idempotency_key(&self.action_id)?;
                        if replay.status != ControllerActionStatus::Resolved {
                            return Err(error);
                        }
                        let stored = replay.exact_winner_resolution.as_ref().context(
                            "concurrently resolved task-send lost exact-winner evidence",
                        )?;
                        validate_task_send_resolution_evidence(&replay, stored)?;
                        println!("{}", stored.evidence);
                        return Ok(());
                    }
                };
                let stored = resolved
                    .exact_winner_resolution
                    .as_ref()
                    .context("resolved task-send lost its exact-winner evidence")?;
                validate_task_send_resolution_evidence(&resolved, stored)?;
                println!("{}", stored.evidence);
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let detail = if failures.is_empty() {
                    String::new()
                } else {
                    let mut sorted: Vec<_> = failures.iter().cloned().collect();
                    sorted.sort();
                    sorted.dedup();
                    format!(" (member failures: {})", sorted.join("; "))
                };
                anyhow::bail!(
                    "task-send could not obtain a strict-majority exact transaction resolution{detail}"
                );
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}

impl AgentAccountNativePrepareCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        for (name, value) in [
            ("request_digest", &self.request_digest),
            ("response_digest", &self.response_digest),
            ("owner_authorization_digest", &self.owner_authorization_digest),
            ("unsigned_transfer_digest", &self.unsigned_transfer_digest),
        ] {
            validate_sha256_digest(name, value)?;
        }
        if self.amount_nanotos == 0 {
            anyhow::bail!("amount_nanotos must be greater than zero");
        }
        let now = time_format::now() as u32;
        if self.valid_until <= now {
            anyhow::bail!("valid_until must be a future Unix timestamp");
        }

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent Account is not deployed for this wallet"))?
            .parse::<MsgAddressInt>()?;
        let target = self.target.parse::<MsgAddressInt>().context("invalid target address")?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if u128::from(self.valid_until)
            > u128::from(now) + u128::from(data.default_task_timeout_secs)
        {
            anyhow::bail!("valid_until exceeds the Agent Account default_task_timeout");
        }
        if self.amount_nanotos > data.max_per_tx {
            anyhow::bail!("Gift amount exceeds Agent Account max_per_tx");
        }
        if data.spent_today.saturating_add(self.amount_nanotos) > data.daily_limit {
            anyhow::bail!("Gift amount exceeds Agent Account remaining daily limit");
        }
        let account_info = rpc_client.get_address_information(&account).await?;
        if account_info.state != AccountState::Active
            || account_info.balance < self.amount_nanotos.saturating_add(self.fee_reserve_nanotos)
        {
            anyhow::bail!("Agent Account is inactive or lacks Gift principal plus fee reserve");
        }
        let deployed_code =
            account_info.code.as_ref().context("Agent Account has no deployed code")?;
        if read_single_root_boc(deployed_code)?.hash(0) != AgentAccountContract::code()?.hash(0) {
            anyhow::bail!("Agent Account code does not match the supported final interface");
        }
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let master = rpc_client.get_masterchain_info().await?;
        let zero_state = master.init.context("primary RPC omitted the zero-state identity")?;
        let network_domain = RelayNetworkDomainPin {
            network_id: format!("tos:global-id:{global_id}"),
            global_id,
            zero_state_root_hash: format!("sha256:{}", hex::encode(&zero_state.root_hash)),
            zero_state_file_hash: format!("sha256:{}", hex::encode(&zero_state.file_hash)),
            workchain_id: account.workchain_id(),
        };
        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .context("controller secret has no public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        if controller_pubkey != data.controller_pubkey {
            anyhow::bail!("configured controller key does not match the Agent Account");
        }

        let mut identity = Sha256::new();
        identity.update(b"tos.agent-account.native-action.v1\0");
        for value in [
            self.action_id.as_bytes(),
            account.to_string().as_bytes(),
            target.to_string().as_bytes(),
            self.request_digest.as_bytes(),
            self.response_digest.as_bytes(),
            self.owner_authorization_digest.as_bytes(),
            self.unsigned_transfer_digest.as_bytes(),
            global_id.to_be_bytes().as_slice(),
            self.amount_nanotos.to_be_bytes().as_slice(),
            self.fee_reserve_nanotos.to_be_bytes().as_slice(),
            self.valid_until.to_be_bytes().as_slice(),
        ] {
            identity.update((value.len() as u64).to_be_bytes());
            identity.update(value);
        }
        let claim = ControllerActionClaim {
            account: account.to_string(),
            network_global_id: global_id,
            network_domain: Some(network_domain),
            deployment_id: hex::encode(data.deployment_id),
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            target: target.to_string(),
            value_atomic: self.amount_nanotos,
            body_hash: None,
            action_kind: "agent-native-send".to_owned(),
            idempotency_key: self.action_id.clone(),
            action_identity: format!("sha256:{}", hex::encode(identity.finalize())),
            valid_until: self.valid_until,
        };
        if !self.yes
            && !confirm(&format!(
                "Authorize native Gift {} from {} to {} for {} nanoTOS, seqno {}, valid_until {}?",
                self.action_id, account, target, self.amount_nanotos, data.seqno, self.valid_until
            ))?
        {
            anyhow::bail!("owner declined Gift authorization");
        }
        let journal = open_controller_journal(path)?;
        journal.reconcile_finalized_state(
            &claim.account,
            claim.network_global_id,
            &claim.deployment_id,
            data.controller_epoch,
            data.seqno,
            time_format::now(),
        )?;
        let (record, _) = journal.claim_primary(claim.clone(), time_format::now())?;
        if record.status == ControllerActionStatus::Resolved {
            anyhow::bail!(
                "controller action sequence was consumed; verify the target transaction before treating the Gift as paid"
            );
        }
        let boc = if let Some(encoded) = record.exact_signed_boc_base64 {
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let payload = AgentAccountContract::build_native_send_payload(
                global_id,
                data.controller_epoch,
                data.seqno,
                self.valid_until,
                &target,
                self.amount_nanotos,
            )?;
            let hash =
                AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
            let signature: [u8; 64] = keypair
                .sign(&hash)
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
            journal.attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                &digest,
                time_format::now(),
            )?;
            boc
        };
        // Once the exact signed BOC leaves custody through stdout, any holder
        // can submit it. Persist the ambiguity before releasing those bytes so
        // a crash or a remote recipient broadcast cannot leave a merely
        // `signed` journal record behind an advanced on-chain seqno.
        journal.begin_broadcast(&claim, time_format::now())?;
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.prepared-action.v1",
                "action_id": self.action_id,
                "action": "agent-native-send",
                "account": account.to_string(),
                "deployment_id": format!("sha256:{}", hex::encode(data.deployment_id)),
                "controller_epoch": data.controller_epoch,
                "seqno": data.seqno,
                "network_global_id": global_id,
                "valid_until": self.valid_until,
                "exact_signed_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
                "exact_signed_boc_digest": format!("sha256:{}", hex::encode(Sha256::digest(&boc))),
            })
        );
        Ok(())
    }
}

impl AgentAccountNativeResolveCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        if self.quorum_configs.len() < 2
            || self.max_transactions == 0
            || self.max_transactions > 10_000
        {
            anyhow::bail!(
                "native action resolution requires two additional RPC configs and a bounded transaction history"
            );
        }
        let primary_path = Path::new(config_path);
        if !primary_path.is_absolute() {
            anyhow::bail!("primary config must be an absolute path for native action resolution");
        }
        let (primary, primary_rpc) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => {
                let (config, _vault, rpc) = load_config_vault_rpc_client_fd(fd, format).await?;
                (config, rpc)
            }
            (None, None) => {
                let primary_bytes = fs::read(primary_path).context("read primary RPC config")?;
                let config = AppConfig::load_bytes(
                    &primary_bytes,
                    config_format_from_path(primary_path)?,
                    "primary RPC config",
                )?;
                let rpc = try_create_rpc_client(&config).await?;
                (config, rpc)
            }
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = primary
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let journal = open_controller_journal(primary_path)?;
        let record = journal.action_by_idempotency_key(&self.action_id)?;
        if record.claim.action_kind != "agent-native-send"
            || record.claim.account != account.to_string()
        {
            anyhow::bail!("native action ID belongs to a different custody effect");
        }
        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved native action has no replayable exact-winner evidence")?;
            println!("{}", resolution.evidence);
            return Ok(());
        }
        if record.status != ControllerActionStatus::Signed
            && record.status != ControllerActionStatus::Broadcasting
        {
            anyhow::bail!("native action has no exact signed BOC that can be resolved");
        }

        let primary_master = primary_rpc.get_masterchain_info().await?;
        let primary_zero_state =
            primary_master.init.context("primary RPC omitted the zero-state identity")?;
        let primary_global_id = match primary_rpc.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let expected_network =
            record.claim.network_domain.clone().unwrap_or(RelayNetworkDomainPin {
                network_id: format!("tos:global-id:{primary_global_id}"),
                global_id: primary_global_id,
                zero_state_root_hash: format!(
                    "sha256:{}",
                    hex::encode(&primary_zero_state.root_hash)
                ),
                zero_state_file_hash: format!(
                    "sha256:{}",
                    hex::encode(&primary_zero_state.file_hash)
                ),
                workchain_id: account.workchain_id(),
            });

        let mut paths = vec![primary_path.to_path_buf()];
        paths.extend(self.quorum_configs.iter().map(PathBuf::from));
        let mut endpoints = BTreeSet::new();
        let mut members = Vec::with_capacity(paths.len());
        for path in paths {
            if !path.is_absolute() {
                anyhow::bail!("every native-action quorum config must be absolute");
            }
            let bytes = fs::read(&path).context("read native-action quorum config")?;
            let config = AppConfig::load_bytes(
                &bytes,
                config_format_from_path(&path)?,
                "native-action quorum config",
            )?;
            let configured = config.chain_rpc.endpoints();
            if configured.len() != 1 {
                anyhow::bail!(
                    "every native-action quorum config must name exactly one RPC endpoint"
                );
            }
            let (endpoint, display_origin) = canonicalize_chain_rpc_endpoint(&configured[0])?;
            if !endpoints.insert(endpoint.clone()) {
                anyhow::bail!("native-action quorum RPC endpoints must be distinct");
            }
            members.push((
                config,
                endpoint.clone(),
                display_origin,
                rpc_locator_identity_digest(&endpoint)?,
            ));
        }
        let threshold = members.len() / 2 + 1;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            let mut votes: BTreeMap<String, Vec<FinalizedEconomicPaymentObservation>> =
                BTreeMap::new();
            for (config, _endpoint, display_origin, locator_identity_digest) in &members {
                if let Ok(observation) = observe_finalized_economic_payment(
                    config,
                    display_origin.clone(),
                    locator_identity_digest.clone(),
                    &expected_network,
                    &account,
                    &record,
                    self.max_transactions,
                )
                .await
                {
                    let observation = observation.observation;
                    votes.entry(observation.quorum_key()).or_default().push(observation);
                }
            }
            if let Some(winner) = votes.values().find(|group| group.len() >= threshold) {
                let provider = contracts::contract_provider!(primary_rpc.clone());
                let finalized = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
                if (finalized.controller_epoch, finalized.seqno)
                    <= (record.claim.controller_epoch, record.claim.seqno)
                {
                    anyhow::bail!(
                        "finalized Agent Account state has not consumed the native action sequence"
                    );
                }
                let output = serde_json::json!({
                    "schema": "tos.agent-account.native-action-finalized.v1",
                    "wallet": self.wallet,
                    "action_id": self.action_id,
                    "source_account": account.to_string(),
                    "destination": record.claim.target,
                    "amount_nanotos": record.claim.value_atomic,
                    "exact_signed_boc_digest": record.exact_signed_boc_digest.clone(),
                    "network_domain": expected_network,
                    "quorum": {"members": members.len(), "threshold": threshold, "agreeing": winner.len()},
                    "transaction": winner[0],
                    "state": "finalized"
                });
                let evidence_kind = "tos.agent-account.native-action-finalized.v1";
                let resolution = ControllerActionResolutionEvidence {
                    evidence_kind: evidence_kind.to_owned(),
                    evidence_digest: controller_resolution_evidence_digest(evidence_kind, &output)?,
                    evidence: output.clone(),
                };
                let exact_signed_boc_digest = record
                    .exact_signed_boc_digest
                    .as_deref()
                    .context("native custody record has no exact signed BOC digest")?;
                if record.status == ControllerActionStatus::Signed {
                    journal.begin_broadcast(&record.claim, time_format::now())?;
                }
                journal.resolve_exact_winner(
                    &record.claim,
                    exact_signed_boc_digest,
                    finalized.controller_epoch,
                    finalized.seqno,
                    resolution,
                    time_format::now(),
                )?;
                println!("{}", output);
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "native action could not obtain a strict-majority exact transaction resolution"
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

impl AgentAccountEconomicPaymentPrepareCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.amount_nanotos == 0 {
            anyhow::bail!("amount_nanotos must be greater than zero");
        }
        let now = time_format::now();
        if self.valid_until <= now as u32 {
            anyhow::bail!("valid_until must be a future Unix timestamp");
        }
        let authorization_path = Path::new(&self.authorization_file);
        if !authorization_path.is_absolute() {
            anyhow::bail!("authorization-file must be absolute");
        }
        let authorization_bytes = open_private_snapshot_file(authorization_path)
            .context("open economic authorization exactly once")?;
        if authorization_bytes.is_empty() || authorization_bytes.len() > 64 << 10 {
            anyhow::bail!("economic authorization must be a bounded regular file");
        }
        let authorization: EconomicActionAuthorization =
            serde_json::from_slice(&authorization_bytes)
                .context("decode EconomicActionAuthorization")?;

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let expected_authority_id = runtime
            .economic_authority_id
            .as_deref()
            .context("runtime has no economic_authority_id")?;
        let expected_key_text = runtime
            .economic_authority_public_key_hex
            .as_deref()
            .context("runtime has no economic_authority_public_key")?;
        let expected_key: [u8; 32] = hex::decode(expected_key_text)
            .context("decode pinned economic authority key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("pinned economic authority key must be 32 bytes"))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let target =
            self.target.parse::<MsgAddressInt>().context("invalid payment target address")?;
        if authorization.authority_id != expected_authority_id
            || authorization.source_account != account.to_string()
            || authorization.destination != target.to_string()
            || authorization.amount_atomic != self.amount_nanotos
            || authorization.expires_at_unix < u64::from(self.valid_until)
        {
            anyhow::bail!(
                "command payment tuple differs from the owner-pinned economic authorization"
            );
        }
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if u128::from(self.valid_until)
            > u128::from(now) + u128::from(data.default_task_timeout_secs)
        {
            anyhow::bail!("valid_until exceeds the Agent Account default_task_timeout");
        }
        if self.amount_nanotos > data.max_per_tx
            || data.spent_today.saturating_add(self.amount_nanotos) > data.daily_limit
        {
            anyhow::bail!("Agreement payment exceeds Agent Account policy limits");
        }
        let account_info = rpc_client.get_address_information(&account).await?;
        if account_info.state != AccountState::Active
            || account_info.balance < self.amount_nanotos.saturating_add(self.fee_reserve_nanotos)
        {
            anyhow::bail!("Agent Account is inactive or lacks payment principal plus fee reserve");
        }
        let deployed_code =
            account_info.code.as_ref().context("Agent Account has no deployed code")?;
        if read_single_root_boc(deployed_code)?.hash(0) != AgentAccountContract::code()?.hash(0) {
            anyhow::bail!("Agent Account code does not match the supported final interface");
        }
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        if authorization.network_global_id != global_id {
            anyhow::bail!("economic authorization targets another TOS network");
        }
        let network_domain = authorization
            .network_domain
            .as_ref()
            .context("economic authorization has no full network-domain pin")?;
        if network_domain.network_id != authorization.network_id
            || network_domain.global_id != authorization.network_global_id
        {
            anyhow::bail!("economic authorization network fields conflict");
        }
        rpc_client.verify_pinned_primary_network(network_domain).await?;
        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .context("controller secret has no public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        if controller_pubkey != data.controller_pubkey {
            anyhow::bail!("configured controller key does not match the Agent Account");
        }
        let stable_hex = authorization
            .stable_action_id
            .strip_prefix("sha256:")
            .context("economic stable action ID is not canonical")?
            .to_owned();
        validate_controller_action_id(&stable_hex)?;
        let sponsorship_commitment =
            if authorization.sponsorship_finality_profile_cbor_digest.is_some() {
                Some(AgentAccountContract::build_sponsorship_payment_commitment(
                    authorization.agreement_payment_request_digest.as_deref().context(
                        "sponsorship authorization has no AgreementPaymentRequest digest",
                    )?,
                    &authorization.stable_action_id,
                )?)
            } else {
                None
            };
        let sponsorship_body_hash = sponsorship_commitment
            .as_ref()
            .map(|body| format!("tvm-cell-sha256:{}", hex::encode(body.hash(0))));
        let claim = ControllerActionClaim {
            account: account.to_string(),
            network_global_id: global_id,
            network_domain: Some(
                authorization
                    .network_domain
                    .clone()
                    .context("economic authorization has no full network-domain pin")?,
            ),
            deployment_id: hex::encode(data.deployment_id),
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            target: target.to_string(),
            value_atomic: self.amount_nanotos,
            body_hash: sponsorship_body_hash.clone(),
            action_kind: if sponsorship_commitment.is_some() {
                "agent-task-send".to_owned()
            } else {
                "agent-native-send".to_owned()
            },
            idempotency_key: stable_hex,
            action_identity: authorization.stable_action_id.clone(),
            valid_until: self.valid_until,
        };
        if !self.yes
            && !confirm(&format!(
                "Authorize Agreement payment {} from {} to {} for {} nanoTOS?",
                authorization.stable_action_id, account, target, self.amount_nanotos
            ))?
        {
            anyhow::bail!("owner declined Agreement payment authorization");
        }
        let journal = open_economic_controller_journal(
            path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        journal.reconcile_finalized_state(
            &claim.account,
            claim.network_global_id,
            &claim.deployment_id,
            data.controller_epoch,
            data.seqno,
            now,
        )?;
        let (record, _) = journal.claim_economic_payment(
            claim.clone(),
            authorization.clone(),
            expected_authority_id,
            expected_key,
            now,
        )?;
        if record.status == ControllerActionStatus::Resolved {
            anyhow::bail!(
                "economic action sequence was consumed; resolve finalized evidence before any retry"
            );
        }
        let boc = if let Some(encoded) = record.exact_signed_boc_base64 {
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let payload = if let Some(commitment) = sponsorship_commitment.clone() {
                AgentAccountContract::build_task_send_payload(
                    global_id,
                    data.controller_epoch,
                    data.seqno,
                    self.valid_until,
                    &target,
                    self.amount_nanotos,
                    commitment,
                )?
            } else {
                AgentAccountContract::build_native_send_payload(
                    global_id,
                    data.controller_epoch,
                    data.seqno,
                    self.valid_until,
                    &target,
                    self.amount_nanotos,
                )?
            };
            let hash =
                AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
            let signature: [u8; 64] = keypair
                .sign(&hash)
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
            journal.attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                &digest,
                now,
            )?;
            boc
        };
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.agreement-payment-prepared.v1",
                "stable_action_id": authorization.stable_action_id,
                "agreement_body_digest": authorization.agreement_body_digest,
                "obligation_instance_id": authorization.obligation_instance_id,
                "account": account.to_string(), "target": target.to_string(), "amount_nanotos": self.amount_nanotos,
                "controller_epoch": data.controller_epoch, "seqno": data.seqno,
                "network_global_id": global_id, "network_domain": authorization.network_domain,
                "valid_until": self.valid_until,
                "action_kind": claim.action_kind,
                "sponsorship_commitment_body_hash": sponsorship_body_hash,
                "exact_signed_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
                "exact_signed_boc_digest": format!("sha256:{}", hex::encode(Sha256::digest(&boc))),
            })
        );
        Ok(())
    }
}

impl AgentAccountEconomicEffectPrepareCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.amount_nanotos == 0 || self.body_boc.is_empty() || self.body_boc.len() > 128 << 10 {
            anyhow::bail!("economic effect amount and body must be bounded and non-empty");
        }
        let body_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.body_boc)
            .context("decode economic effect body")?;
        let body =
            read_single_root_boc(body_bytes.clone()).context("parse economic effect body")?;
        if write_boc(&body)? != body_bytes {
            anyhow::bail!("economic effect body is not canonical BOC");
        }
        let body_hash = format!("tvm-cell-sha256:{}", hex::encode(body.hash(0)));
        let now = time_format::now();
        if self.valid_until <= now as u32 {
            anyhow::bail!("valid_until must be a future Unix timestamp");
        }
        let authorization_path = Path::new(&self.authorization_file);
        if !authorization_path.is_absolute() {
            anyhow::bail!("authorization-file must be absolute");
        }
        let metadata = fs::symlink_metadata(authorization_path)
            .context("inspect economic effect authorization file")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > 64 << 10
        {
            anyhow::bail!("economic effect authorization must be a bounded regular file");
        }
        let authorization: EconomicEffectAuthorization =
            serde_json::from_slice(&fs::read(authorization_path)?)
                .context("decode CustodyEffectAuthorization")?;

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let expected_authority_id = runtime
            .economic_authority_id
            .as_deref()
            .context("runtime has no economic_authority_id")?;
        let expected_key: [u8; 32] = hex::decode(
            runtime
                .economic_authority_public_key_hex
                .as_deref()
                .context("runtime has no economic_authority_public_key")?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned economic authority key must be 32 bytes"))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let target =
            self.target.parse::<MsgAddressInt>().context("invalid economic effect target")?;
        if authorization.authority_id != expected_authority_id
            || authorization.source_account != account.to_string()
            || authorization.destination != target.to_string()
            || authorization.amount_nanotos != self.amount_nanotos
            || authorization.body_hash != body_hash
            || authorization.expires_at_unix < u64::from(self.valid_until)
        {
            anyhow::bail!("command effect differs from the owner-pinned authorization");
        }
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if u128::from(self.valid_until)
            > u128::from(now) + u128::from(data.default_task_timeout_secs)
        {
            anyhow::bail!("valid_until exceeds the Agent Account default_task_timeout");
        }
        if self.amount_nanotos > data.max_per_tx
            || data.spent_today.saturating_add(self.amount_nanotos) > data.daily_limit
        {
            anyhow::bail!("Agreement effect exceeds Agent Account policy limits");
        }
        let account_info = rpc_client.get_address_information(&account).await?;
        if account_info.state != AccountState::Active
            || account_info.balance < self.amount_nanotos.saturating_add(self.fee_reserve_nanotos)
        {
            anyhow::bail!("Agent Account is inactive or lacks effect value plus fee reserve");
        }
        let deployed_code =
            account_info.code.as_ref().context("Agent Account has no deployed code")?;
        if read_single_root_boc(deployed_code)?.hash(0) != AgentAccountContract::code()?.hash(0) {
            anyhow::bail!("Agent Account code does not match the supported final interface");
        }
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        if authorization.network_global_id != global_id {
            anyhow::bail!("economic effect targets another TOS network");
        }
        let network_domain = authorization
            .network_domain
            .as_ref()
            .context("economic effect has no full network-domain pin")?;
        if network_domain.network_id != authorization.network_id
            || network_domain.global_id != authorization.network_global_id
        {
            anyhow::bail!("economic effect network fields conflict");
        }
        rpc_client.verify_pinned_primary_network(network_domain).await?;
        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .context("controller secret has no public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        if controller_pubkey != data.controller_pubkey {
            anyhow::bail!("configured controller key does not match the Agent Account");
        }
        let stable_hex = authorization
            .stable_action_id
            .strip_prefix("sha256:")
            .context("economic effect action ID is not canonical")?
            .to_owned();
        validate_controller_action_id(&stable_hex)?;
        let claim = ControllerActionClaim {
            account: account.to_string(),
            network_global_id: global_id,
            network_domain: Some(
                authorization
                    .network_domain
                    .clone()
                    .context("economic effect has no full network-domain pin")?,
            ),
            deployment_id: hex::encode(data.deployment_id),
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            target: target.to_string(),
            value_atomic: self.amount_nanotos,
            body_hash: Some(body_hash.clone()),
            action_kind: "agent-task-send".to_owned(),
            idempotency_key: stable_hex,
            action_identity: authorization.stable_action_id.clone(),
            valid_until: self.valid_until,
        };
        if !self.yes
            && !confirm(&format!(
                "Authorize Agreement effect {} ({}) from {} to {}?",
                authorization.stable_action_id, authorization.action_kind, account, target
            ))?
        {
            anyhow::bail!("owner declined Agreement effect authorization");
        }
        let journal = open_economic_controller_journal(
            path,
            self.journal_directory.as_deref(),
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        journal.reconcile_finalized_state(
            &claim.account,
            claim.network_global_id,
            &claim.deployment_id,
            data.controller_epoch,
            data.seqno,
            now,
        )?;
        let (record, _) = journal.claim_economic_effect(
            claim.clone(),
            authorization.clone(),
            expected_authority_id,
            expected_key,
            now,
        )?;
        if record.status == ControllerActionStatus::Resolved {
            anyhow::bail!("economic effect sequence was consumed; resolve before retry");
        }
        let boc = if let Some(encoded) = record.exact_signed_boc_base64 {
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let payload = AgentAccountContract::build_task_send_payload(
                record.claim.network_global_id,
                record.claim.controller_epoch,
                record.claim.seqno,
                record.claim.valid_until,
                &target,
                record.claim.value_atomic,
                body,
            )?;
            let hash =
                AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
            let signature: [u8; 64] = keypair
                .sign(&hash)
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
            journal.attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                &digest,
                now,
            )?;
            boc
        };
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.economic-effect-prepared.v1",
                "stable_action_id": authorization.stable_action_id,
                "action_kind": authorization.action_kind,
                "agreement_body_digest": authorization.agreement_body_digest,
                "obligation_id": authorization.obligation_id,
                "account": record.claim.account, "target": record.claim.target,
                "amount_nanotos": record.claim.value_atomic,
                "body_hash": record.claim.body_hash, "controller_epoch": record.claim.controller_epoch,
                "deployment_id": record.claim.deployment_id,
                "seqno": record.claim.seqno, "network_global_id": record.claim.network_global_id,
                "network_domain": record.claim.network_domain,
                "valid_until": record.claim.valid_until,
                "exact_signed_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
                "exact_signed_boc_digest": format!("sha256:{}", hex::encode(Sha256::digest(&boc))),
            })
        );
        Ok(())
    }
}

impl AgentAccountEconomicPaymentBroadcastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        let idempotency = self.stable_action_id[7..].to_owned();
        let path = Path::new(config_path);
        let (config, _vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let expected_authority_id = runtime
            .economic_authority_id
            .as_deref()
            .context("runtime has no economic_authority_id")?;
        let expected_key = runtime
            .economic_authority_public_key_hex
            .as_deref()
            .context("runtime has no economic_authority_public_key")?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let journal = open_economic_controller_journal(
            path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        journal.reconcile_finalized_state(
            &account.to_string(),
            global_id,
            &hex::encode(data.deployment_id),
            data.controller_epoch,
            data.seqno,
            time_format::now(),
        )?;
        let record = journal
            .find_primary(
                &account.to_string(),
                global_id,
                &hex::encode(data.deployment_id),
                data.controller_epoch,
                &idempotency,
            )?
            .context("prepared Agreement payment was not found")?;
        let authorization = record
            .economic_authorization
            .as_ref()
            .context("custody record is not an economic payment")?;
        if authorization.stable_action_id != self.stable_action_id
            || authorization.authority_id != expected_authority_id
            || authorization.public_key != format!("ed25519:{expected_key}")
        {
            anyhow::bail!("prepared payment differs from the currently owner-pinned authority");
        }
        let encoded =
            record.exact_signed_boc_base64.as_ref().context("Agreement payment is not signed")?;
        let boc = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
        if record.exact_signed_boc_digest.as_deref() != Some(digest.as_str()) {
            anyhow::bail!("custody BOC digest is inconsistent");
        }
        if !self.yes
            && !confirm(&format!("Broadcast exact Agreement payment {}?", self.stable_action_id))?
        {
            anyhow::bail!("owner declined Agreement payment broadcast");
        }
        let network_domain = record
            .claim
            .network_domain
            .as_ref()
            .context("custody payment has no full network-domain pin")?;
        validate_exact_boc_before_broadcast(&boc)?;
        rpc_client.verify_pinned_primary_network(network_domain).await?;
        // This command is the custody-backed crash-recovery seam.  It may
        // advance Signed -> Broadcasting or resume Broadcasting, but in both
        // cases it submits only the exact bytes and account sequence already
        // frozen in the journal.  It never prepares, signs, or allocates a
        // replacement transaction.
        journal.begin_or_resume_exact_broadcast(&record.claim, time_format::now())?;
        let submission = rpc_client.submit_exact_boc_pinned(&boc, network_domain).await?;
        if submission.status == ExactBocSubmissionStatus::Accepted {
            println!(
                "{}",
                serde_json::json!({
                    "schema": "tosctl.agent-account.agreement-payment-broadcast.v1",
                    "stable_action_id": self.stable_action_id,
                    "account": account.to_string(),
                    "exact_signed_boc_digest": digest,
                    "state": "broadcasting"
                })
            );
            return Ok(());
        }
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.agreement-payment-broadcast.v2",
                "stable_action_id": self.stable_action_id,
                "account": account.to_string(),
                "exact_signed_boc_digest": digest,
                "state": "broadcasting",
                "submission": &submission,
            })
        );
        require_exact_submission_accepted(&submission, "Agreement payment")
    }
}

impl AgentAccountEconomicEffectBroadcastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        let idempotency = self.stable_action_id[7..].to_owned();
        let path = Path::new(config_path);
        let (config, _vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let expected_authority_id = runtime
            .economic_authority_id
            .as_deref()
            .context("runtime has no economic_authority_id")?;
        let expected_key = runtime
            .economic_authority_public_key_hex
            .as_deref()
            .context("runtime has no economic_authority_public_key")?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let journal = open_economic_controller_journal(
            path,
            self.journal_directory.as_deref(),
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        journal.reconcile_finalized_state(
            &account.to_string(),
            global_id,
            &hex::encode(data.deployment_id),
            data.controller_epoch,
            data.seqno,
            time_format::now(),
        )?;
        let record = journal
            .find_primary(
                &account.to_string(),
                global_id,
                &hex::encode(data.deployment_id),
                data.controller_epoch,
                &idempotency,
            )?
            .context("prepared Agreement effect was not found")?;
        let authorization = record
            .economic_effect_authorization
            .as_ref()
            .context("custody record is not an economic effect")?;
        if authorization.stable_action_id != self.stable_action_id
            || authorization.authority_id != expected_authority_id
            || authorization.public_key != format!("ed25519:{expected_key}")
        {
            anyhow::bail!("prepared effect differs from the currently owner-pinned authority");
        }
        let encoded =
            record.exact_signed_boc_base64.as_ref().context("Agreement effect is not signed")?;
        let boc = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
        if record.exact_signed_boc_digest.as_deref() != Some(digest.as_str()) {
            anyhow::bail!("custody effect BOC digest is inconsistent");
        }
        if !self.yes
            && !confirm(&format!("Broadcast exact Agreement effect {}?", self.stable_action_id))?
        {
            anyhow::bail!("owner declined Agreement effect broadcast");
        }
        let network_domain = record
            .claim
            .network_domain
            .as_ref()
            .context("custody effect has no full network-domain pin")?;
        validate_exact_boc_before_broadcast(&boc)?;
        rpc_client.verify_pinned_primary_network(network_domain).await?;
        journal.begin_broadcast(&record.claim, time_format::now())?;
        let submission = rpc_client.submit_exact_boc_pinned(&boc, network_domain).await?;
        if submission.status == ExactBocSubmissionStatus::Accepted {
            println!(
                "{}",
                serde_json::json!({
                    "schema": "tosctl.agent-account.economic-effect-broadcast.v1",
                    "stable_action_id": self.stable_action_id,
                    "action_kind": authorization.action_kind,
                    "account": account.to_string(),
                    "exact_signed_boc_digest": digest,
                    "state": "broadcasting"
                })
            );
            return Ok(());
        }
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.economic-effect-broadcast.v2",
                "stable_action_id": self.stable_action_id,
                "action_kind": authorization.action_kind,
                "account": account.to_string(),
                "exact_signed_boc_digest": digest,
                "state": "broadcasting",
                "submission": &submission,
            })
        );
        require_exact_submission_accepted(&submission, "Agreement effect")
    }
}

fn require_exact_submission_accepted(
    submission: &ExactBocSubmissionResult,
    action: &str,
) -> anyhow::Result<()> {
    match submission.status {
        ExactBocSubmissionStatus::Accepted => Ok(()),
        ExactBocSubmissionStatus::Rejected => anyhow::bail!(
            "{} {} was rejected by {}",
            action,
            submission.cell_hash,
            submission.endpoint
        ),
        ExactBocSubmissionStatus::Unknown => anyhow::bail!(
            "{} {} outcome is unknown at {}; resolve it before any retry",
            action,
            submission.cell_hash,
            submission.endpoint
        ),
    }
}

// This is the original ordinary Agreement-payment resolver evidence shape.
// It deliberately remains separate from sponsorship RPC corroboration: the
// latter is nonterminal and must never change the established finalized-v1
// command contract consumed by existing callers.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct FinalizedEconomicPaymentObservation {
    endpoint: String,
    locator_identity_digest: String,
    transaction_hash: String,
    transaction_lt: u64,
    transaction_utime: u32,
    transaction_boc_digest: String,
    block_workchain: i32,
    block_shard: i64,
    block_seqno: u32,
    block_root_hash: String,
    block_file_hash: String,
    observed_masterchain_seqno: u32,
}

impl FinalizedEconomicPaymentObservation {
    fn quorum_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.transaction_hash,
            self.transaction_lt,
            self.transaction_utime,
            self.transaction_boc_digest,
            self.block_workchain,
            self.block_shard,
            self.block_seqno,
            self.block_root_hash,
            self.block_file_hash
        )
    }
}

#[derive(Clone, Debug)]
struct FinalizedEconomicPaymentMatch {
    observation: FinalizedEconomicPaymentObservation,
    outbound_message_cell_hash: String,
    outbound_body_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct FinalizedTaskSendObservation {
    #[serde(flatten)]
    transaction: FinalizedEconomicPaymentObservation,
    outbound_message_cell_hash: String,
    outbound_body_hash: String,
    finalized_controller_epoch: u64,
    finalized_seqno: u32,
}

impl FinalizedTaskSendObservation {
    fn quorum_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.transaction.quorum_key(),
            self.outbound_message_cell_hash,
            self.outbound_body_hash,
            self.finalized_controller_epoch,
            self.finalized_seqno,
        )
    }
}

fn finalized_output_matches_claim(
    message: &Message,
    target: &MsgAddressInt,
    expected_value: &chain_block::CurrencyCollection,
    expected_body_hash: Option<&str>,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    if message.dst().as_ref() != Some(target) || message.value() != Some(expected_value) {
        return Ok(None);
    }
    let body_hash = message
        .body()
        .cloned()
        .map(|body| {
            body.into_cell()
                .context("construct finalized output body cell")
                .map(|body| agent_account_task_body_hash(&body))
        })
        .transpose()?;
    if expected_body_hash.is_some_and(|expected| body_hash.as_deref() != Some(expected)) {
        return Ok(None);
    }
    let message_hash = format!("tvm-cell-sha256:{}", hex::encode(message.serialize()?.hash(0)));
    Ok(Some((message_hash, body_hash)))
}

fn select_exact_finalized_output(
    messages: &[Message],
    target: &MsgAddressInt,
    expected_value: &chain_block::CurrencyCollection,
    expected_body_hash: Option<&str>,
) -> anyhow::Result<(String, Option<String>)> {
    let mut target_value_candidates = 0usize;
    let mut exact = Vec::new();
    for message in messages {
        if message.dst().as_ref() == Some(target) && message.value() == Some(expected_value) {
            target_value_candidates += 1;
            if let Some(identity) =
                finalized_output_matches_claim(message, target, expected_value, expected_body_hash)?
            {
                exact.push(identity);
            }
        }
    }
    if target_value_candidates != 1 || exact.len() != 1 {
        anyhow::bail!(
            "finalized submitted transaction does not contain exactly one authorized target/value/body output"
        );
    }
    exact.pop().context("authorized finalized output identity is absent")
}

async fn observe_finalized_economic_payment(
    config: &AppConfig,
    endpoint: String,
    locator_identity_digest: String,
    expected_network: &RelayNetworkDomainPin,
    account: &MsgAddressInt,
    record: &contracts::ControllerActionRecord,
    max_transactions: u32,
) -> anyhow::Result<FinalizedEconomicPaymentMatch> {
    let rpc_client = try_create_rpc_client(config).await?;
    rpc_client.verify_pinned_primary_network(expected_network).await?;
    let encoded = record
        .exact_signed_boc_base64
        .as_ref()
        .context("custody record no longer contains the submitted payment BOC")?;
    let submitted_boc = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let submitted_root = read_single_root_boc(&submitted_boc)?;
    let submitted_message_hash = submitted_root.hash(0);
    let target = record.claim.target.parse::<MsgAddressInt>()?;
    let expected_value = chain_block::CurrencyCollection::with_coins(record.claim.value_atomic);

    let info = rpc_client.get_address_information(account).await?;
    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let bounded_max = max_transactions.clamp(1, 10_000);

    while cursor_lt != 0 && inspected < bounded_max {
        let page_limit = (bounded_max - inspected).min(100);
        let page =
            rpc_client.get_transactions(account, cursor_lt, &cursor_hash, page_limit).await?;
        if page.transactions.is_empty() {
            break;
        }
        let mut next_cursor = None;
        for raw in page.transactions {
            inspected = inspected.saturating_add(1);
            next_cursor = Some((raw.lt, raw.hash.clone()));
            if raw.data.is_empty() {
                continue;
            }
            let transaction_boc = base64::engine::general_purpose::STANDARD
                .decode(&raw.data)
                .context("decode finalized transaction BOC")?;
            let transaction_root = read_single_root_boc(&transaction_boc)
                .context("parse finalized transaction BOC")?;
            let transaction = Transaction::construct_from_cell(transaction_root.clone())
                .context("decode finalized transaction")?;
            let transaction_utime = exact_transaction_utime(transaction.now(), raw.utime)?;
            let Some(in_cell) = transaction.in_msg_cell() else {
                continue;
            };
            if in_cell.hash(0) != submitted_message_hash {
                continue;
            }
            let mut outputs = Vec::new();
            transaction.iterate_out_msgs(|message| {
                outputs.push(message);
                Ok(true)
            })?;
            let (outbound_message_cell_hash, outbound_body_hash) = select_exact_finalized_output(
                &outputs,
                &target,
                &expected_value,
                record.claim.body_hash.as_deref(),
            )?;
            let block = raw.block_id.context("finalized transaction has no block identity")?;
            let master = rpc_client.get_masterchain_info().await?;
            return Ok(FinalizedEconomicPaymentMatch {
                outbound_message_cell_hash,
                outbound_body_hash,
                observation: FinalizedEconomicPaymentObservation {
                    endpoint,
                    locator_identity_digest,
                    transaction_hash: format!("sha256:{}", hex::encode(transaction_root.hash(0))),
                    transaction_lt: transaction.logical_time(),
                    transaction_utime,
                    transaction_boc_digest: format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(&transaction_boc))
                    ),
                    block_workchain: block.workchain,
                    block_shard: block.shard,
                    block_seqno: block.seqno,
                    block_root_hash: format!("sha256:{}", hex::encode(block.root_hash)),
                    block_file_hash: format!("sha256:{}", hex::encode(block.file_hash)),
                    observed_masterchain_seqno: master.last.seqno,
                },
            });
        }
        let Some((next_lt, next_hash)) = next_cursor else {
            break;
        };
        if next_lt == cursor_lt && next_hash == cursor_hash {
            break;
        }
        cursor_lt = next_lt;
        cursor_hash = next_hash;
    }
    anyhow::bail!(
        "submitted Agreement payment was not found in the bounded finalized account history"
    )
}

async fn resolve_agent_account_task_action(
    config_path: &str,
    wallet: &str,
    action_id: &str,
    operation: &AgentTaskOperation,
    task_address: &MsgAddressInt,
    quorum_configs: &[String],
    max_transactions: u32,
) -> anyhow::Result<()> {
    if quorum_configs.len() < 2 || max_transactions == 0 || max_transactions > 10_000 {
        anyhow::bail!(
            "Agent Account Task resolution requires two additional RPC configs and a bounded transaction history"
        );
    }
    let primary_path = Path::new(config_path);
    if !primary_path.is_absolute() {
        anyhow::bail!("primary config must be an absolute path for Task resolution");
    }
    let journal = open_controller_journal(primary_path)?;
    let record = journal.action_by_idempotency_key(action_id)?;
    if record.claim.action_kind != "agent-task-send"
        || record.claim.target != task_address.to_string()
        || record.status != ControllerActionStatus::Broadcasting
    {
        anyhow::bail!("Task action is not one unresolved exact broadcast");
    }
    let account = record.claim.account.parse::<MsgAddressInt>()?;
    let primary_bytes = fs::read(primary_path).context("read primary RPC config")?;
    let primary = AppConfig::load_bytes(
        &primary_bytes,
        config_format_from_path(primary_path)?,
        "primary RPC config",
    )?;
    let primary_rpc = try_create_rpc_client(&primary).await?;
    let primary_master = primary_rpc.get_masterchain_info().await?;
    let primary_zero_state =
        primary_master.init.context("primary RPC omitted the zero-state identity")?;
    let primary_global_id = match primary_rpc.get_config_param(19).await? {
        ConfigParamEnum::ConfigParam19(value) => value as i32,
        _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
    };
    let expected_network = record.claim.network_domain.clone().unwrap_or(RelayNetworkDomainPin {
        network_id: format!("tos:global-id:{primary_global_id}"),
        global_id: primary_global_id,
        zero_state_root_hash: format!("sha256:{}", hex::encode(&primary_zero_state.root_hash)),
        zero_state_file_hash: format!("sha256:{}", hex::encode(&primary_zero_state.file_hash)),
        workchain_id: account.workchain_id(),
    });

    let mut paths = vec![primary_path.to_path_buf()];
    paths.extend(quorum_configs.iter().map(PathBuf::from));
    let mut endpoints = BTreeSet::new();
    let mut members = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.is_absolute() {
            anyhow::bail!("every Task quorum config must be absolute");
        }
        let bytes = fs::read(&path).context("read Task quorum config")?;
        let config =
            AppConfig::load_bytes(&bytes, config_format_from_path(&path)?, "Task quorum config")?;
        let configured = config.chain_rpc.endpoints();
        if configured.len() != 1 {
            anyhow::bail!("every Task quorum config must name exactly one RPC endpoint");
        }
        let (endpoint, display_origin) = canonicalize_chain_rpc_endpoint(&configured[0])?;
        if !endpoints.insert(endpoint.clone()) {
            anyhow::bail!("Task quorum RPC endpoints must be distinct");
        }
        members.push((
            config,
            endpoint.clone(),
            display_origin,
            rpc_locator_identity_digest(&endpoint)?,
        ));
    }
    let threshold = members.len() / 2 + 1;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    type TaskActionResolutionVote =
        (FinalizedEconomicPaymentObservation, u64, u32, u8, [u8; 32], [u8; 32]);
    loop {
        let mut votes: BTreeMap<String, Vec<TaskActionResolutionVote>> = BTreeMap::new();
        for (config, _endpoint, display_origin, locator_identity_digest) in &members {
            let observation = observe_finalized_economic_payment(
                config,
                display_origin.clone(),
                locator_identity_digest.clone(),
                &expected_network,
                &account,
                &record,
                max_transactions,
            )
            .await;
            let Ok(observation) = observation else { continue };
            let observation = observation.observation;
            let rpc = try_create_rpc_client(config).await?;
            let provider = contracts::contract_provider!(rpc.clone());
            let task = TaskEscrowContract::decode_data(
                &provider.get_method(task_address.to_string(), "get_task_data", vec![]).await?,
            )?;
            let agent = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
            if !operation.accepts_resolved_status(task.status)?
                || (agent.controller_epoch, agent.seqno)
                    <= (record.claim.controller_epoch, record.claim.seqno)
            {
                continue;
            }
            let key = format!(
                "{}:{}:{}:{}:{}:{}",
                observation.quorum_key(),
                task.status,
                hex::encode(task.result_hash),
                hex::encode(task.evidence_hash),
                agent.controller_epoch,
                agent.seqno
            );
            votes.entry(key).or_default().push((
                observation,
                agent.controller_epoch,
                agent.seqno,
                task.status,
                task.result_hash,
                task.evidence_hash,
            ));
        }
        if let Some(winner) = votes.values().find(|group| group.len() >= threshold) {
            let (observation, controller_epoch, seqno, task_status, result_hash, evidence_hash) =
                &winner[0];
            let output = serde_json::json!({
                "schema": "tos.agent-account.task-action-finalized.v1",
                "wallet": wallet,
                "action_id": action_id,
                "operation": operation.as_str(),
                "source_account": account.to_string(),
                "task_address": task_address.to_string(),
                "task_status": task_status_name(*task_status),
                "task_result_hash": format!("sha256:{}", hex::encode(result_hash)),
                "task_evidence_hash": format!("sha256:{}", hex::encode(evidence_hash)),
                "network_domain": expected_network,
                "quorum": {"members": members.len(), "threshold": threshold, "agreeing": winner.len()},
                "transaction": observation,
            });
            let evidence_kind = "tos.agent-account.task-action-finalized.v1";
            let resolution = ControllerActionResolutionEvidence {
                evidence_kind: evidence_kind.to_owned(),
                evidence_digest: controller_resolution_evidence_digest(evidence_kind, &output)?,
                evidence: output,
            };
            let boc_digest = record
                .exact_signed_boc_digest
                .as_deref()
                .context("Task custody record has no exact signed BOC digest")?;
            journal.resolve_exact_winner(
                &record.claim,
                boc_digest,
                *controller_epoch,
                *seqno,
                resolution,
                time_format::now(),
            )?;
            println!(
                "{} exact controller Task action resolved by {}/{} RPC observations",
                "OK".green().bold(),
                winner.len(),
                members.len()
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Task action could not obtain a strict-majority exact transaction resolution"
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

impl AgentAccountEconomicPaymentResolveCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        if self.max_transactions == 0 || self.max_transactions > 10_000 {
            anyhow::bail!("max_transactions must be between 1 and 10000");
        }
        let primary_path = Path::new(config_path);
        let primary = AppConfig::load(primary_path)?;
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
        let journal = open_economic_controller_journal(
            primary_path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let record = journal
            .find_economic_payment_by_stable_action(&self.stable_action_id)?
            .context("prepared Agreement payment was not found")?;
        let authorization = record
            .economic_authorization
            .as_ref()
            .context("custody record is not an economic payment")?;
        if authorization.stable_action_id != self.stable_action_id {
            anyhow::bail!("custody action identity mismatch");
        }
        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved legacy payment has no replayable exact-winner evidence")?;
            if resolution.evidence_kind != ECONOMIC_PAYMENT_FINALIZED_SCHEMA {
                anyhow::bail!("payment was resolved under a different evidence profile");
            }
            println!("{}", resolution.evidence);
            return Ok(());
        }
        if record.status != ControllerActionStatus::Broadcasting {
            anyhow::bail!("only an ambiguously broadcast Agreement payment may be resolved");
        }
        let primary_rpc = try_create_rpc_client(&primary).await?;
        let provider = contracts::contract_provider!(primary_rpc.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let global_id = match primary_rpc.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        if global_id != record.claim.network_global_id
            || hex::encode(data.deployment_id) != record.claim.deployment_id
        {
            anyhow::bail!("current Agent Account generation differs from the custody payment");
        }
        let expected_network = record
            .claim
            .network_domain
            .as_ref()
            .context("custody payment has no full network-domain pin")?;

        let mut configs = Vec::with_capacity(self.quorum_configs.len() + 1);
        configs.push(primary_path.to_path_buf());
        for value in &self.quorum_configs {
            let path = Path::new(value);
            if !path.is_absolute() {
                anyhow::bail!("every quorum-config must be an absolute path");
            }
            configs.push(path.to_path_buf());
        }
        if configs.len() < 3 {
            anyhow::bail!("at least three RPC configurations are required");
        }

        let mut endpoints = BTreeMap::new();
        let mut loaded = Vec::with_capacity(configs.len());
        for path in configs {
            let bytes = fs::read(&path).context("read RPC quorum config")?;
            let config = AppConfig::load_bytes(
                &bytes,
                config_format_from_path(&path)?,
                "RPC quorum config",
            )?;
            let configured = config.chain_rpc.endpoints();
            if configured.len() != 1 {
                anyhow::bail!("every quorum config must name exactly one RPC endpoint");
            }
            let (endpoint, display_origin) = canonicalize_chain_rpc_endpoint(&configured[0])?;
            if endpoints.insert(endpoint.clone(), path.clone()).is_some() {
                anyhow::bail!("quorum RPC endpoints must be distinct");
            }
            let locator_identity_digest = rpc_locator_identity_digest(&endpoint)?;
            loaded.push((config, endpoint, display_origin, locator_identity_digest));
        }

        let mut observations = Vec::with_capacity(loaded.len());
        let mut failures = Vec::new();
        for (config, endpoint, display_origin, locator_identity_digest) in &loaded {
            match observe_finalized_economic_payment(
                config,
                display_origin.clone(),
                locator_identity_digest.clone(),
                expected_network,
                &account,
                &record,
                self.max_transactions,
            )
            .await
            {
                Ok(observation) => observations.push(observation.observation),
                Err(error) => failures.push(rpc_failure_diagnostic(endpoint, &error)),
            }
        }
        let threshold = loaded.len() / 2 + 1;
        let mut votes: BTreeMap<String, Vec<&FinalizedEconomicPaymentObservation>> =
            BTreeMap::new();
        for observation in &observations {
            votes.entry(observation.quorum_key()).or_default().push(observation);
        }
        let winner = votes
            .values()
            .max_by_key(|group| group.len())
            .filter(|group| group.len() >= threshold)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no strict majority agreed on the finalized payment transaction; observation_count={}; failures={}",
                    observations.len(),
                    serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
                )
            })?;
        let evidence = winner[0];

        let finalized = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if (finalized.controller_epoch, finalized.seqno)
            <= (record.claim.controller_epoch, record.claim.seqno)
        {
            anyhow::bail!(
                "primary finalized Agent Account state has not consumed the payment seqno"
            );
        }
        let output = serde_json::json!({
            "schema": ECONOMIC_PAYMENT_FINALIZED_SCHEMA,
            "stable_action_id": self.stable_action_id,
            "agreement_body_digest": authorization.agreement_body_digest,
            "obligation_instance_id": authorization.obligation_instance_id,
            "source_account": account.to_string(),
            "destination": record.claim.target,
            "amount_nanotos": record.claim.value_atomic,
            "network_global_id": global_id,
            "quorum": {"members": loaded.len(), "threshold": threshold, "agreeing": winner.len()},
            "evidence": evidence,
            "observations": observations,
            "failures": failures,
            "state": "finalized"
        });
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: ECONOMIC_PAYMENT_FINALIZED_SCHEMA.to_owned(),
            evidence_digest: controller_resolution_evidence_digest(
                ECONOMIC_PAYMENT_FINALIZED_SCHEMA,
                &output,
            )?,
            evidence: output,
        };
        let exact_signed_boc_digest = record
            .exact_signed_boc_digest
            .as_deref()
            .context("custody payment has no exact signed BOC digest")?;
        let resolved = journal.resolve_exact_winner(
            &record.claim,
            exact_signed_boc_digest,
            finalized.controller_epoch,
            finalized.seqno,
            resolution,
            time_format::now(),
        )?;
        println!(
            "{}",
            resolved
                .exact_winner_resolution
                .context("resolved payment lost exact-winner evidence")?
                .evidence
        );
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicPaymentObservation {
    endpoint: String,
    locator_identity_digest: String,
    operator_provenance: String,
    transaction_hash: String,
    transaction_lt: u64,
    transaction_utime: u32,
    transaction_boc_digest: String,
    source_outbound_message_hash: String,
    destination_credit_reference: String,
    destination_transaction_hash: String,
    destination_transaction_lt: u64,
    destination_transaction_utime: u32,
    destination_transaction_boc_digest: String,
    destination_block_workchain: i32,
    destination_block_shard: i64,
    destination_block_seqno: u32,
    destination_block_root_hash: String,
    destination_block_file_hash: String,
    destination_credit_atomic: String,
    destination_credit_first: bool,
    destination_transaction_aborted: bool,
    destination_bounce_present: bool,
    destination_credit_observed_exact: bool,
    block_workchain: i32,
    block_shard: i64,
    block_seqno: u32,
    block_root_hash: String,
    block_file_hash: String,
    network_global_id: i32,
    zero_state_workchain: i32,
    zero_state_shard: i64,
    zero_state_seqno: u32,
    zero_state_root_hash: String,
    zero_state_file_hash: String,
    observed_masterchain_workchain: i32,
    observed_masterchain_shard: i64,
    observed_masterchain_seqno: u32,
    observed_masterchain_root_hash: String,
    observed_masterchain_file_hash: String,
    observed_masterchain_gen_utime: u32,
    finality_proven: bool,
}

const ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI: &str = "agreement-payment-rpc-corroboration.v1";
const RPC_LOCATOR_IDENTITY_DOMAIN: &[u8] = b"tosctl.agreement-payment-rpc-locator-identity.v1\0";
const ECONOMIC_PAYMENT_FINALIZED_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-finalized.v1";
const ECONOMIC_PAYMENT_CORROBORATION_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-rpc-corroboration.v2";
const ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-corroborated-terminal.v1";
const ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA: &str =
    "tosctl.agent-account.agreement-payment-sponsorship-proof-verification.v1";
const AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN: &str = "tos.agreement-payment-request.v1";
const NETWORK_DOMAIN_DIGEST_DOMAIN: &str = "tos.agent-relay-network-domain.v1";
const SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN: &str =
    "tos.agent-relay-sponsorship-proof-bundle.v1";
const SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI: &str =
    "tos.sponsorship.client-corroborated-terminal.v1";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorshipAgreementAmount {
    asset_namespace: String,
    asset_identifier: String,
    amount_atomic: String,
    unit: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorshipAgreementPaymentRequestV3 {
    schema_version: u16,
    owner_id: String,
    agent_id: String,
    agreement_body_digest: String,
    agreement_obligation_id: String,
    obligation_instance_id: String,
    payer_agent_id: String,
    payee_agent_id: String,
    network_id: String,
    network_domain_digest: String,
    amount: SponsorshipAgreementAmount,
    /// Protocol JSON encodes []byte as canonical base64 text before CBOR.
    destination: String,
    settlement_adapter_uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    semantic_action_kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    adapter_profile_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    external_system_id: String,
    stable_action_id: String,
    expires_at_unix: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SponsorshipFinalityProfile {
    profile_uri: String,
    profile_digest: String,
    terminal_evidence_class: String,
    minimum_confirmation_depth: u32,
    minimum_observers: u16,
    minimum_operator_domains: u16,
    reorg_window_seconds: u32,
    maximum_resolution_seconds: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorshipFinalityProofBundleV1 {
    schema: String,
    agreement_payment_request: SponsorshipAgreementPaymentRequestV3,
    agreement_payment_request_digest: String,
    sponsorship_stable_action_id: String,
    sponsorship_exact_request_digest: String,
    provider_sponsor_source_account: String,
    provider_sponsor_source_sequence: u32,
    provider_sponsor_valid_until_unix: u64,
    destination_source_account: String,
    signed_top_up_transaction_digest: String,
    signed_top_up_transaction_cell_hash: String,
    signed_top_up_transaction_boc: String,
    sponsorship_payment_commitment_cell_hash: String,
    network_digest: String,
    network_domain: RelayNetworkDomainPin,
    finality_profile: SponsorshipFinalityProfile,
    finality_profile_cbor_digest: String,
    sponsorship_release_profile_uri: String,
    sponsorship_release_profile_digest: String,
    sponsorship_release_profile: serde_json::Value,
    corroboration_snapshot_identity: String,
    confirmation_depth: u32,
    terminal_evidence_class: String,
    validator_authenticated_portable_proof: bool,
    quorum: serde_json::Value,
    observation_digests: Vec<String>,
    observations: Vec<EconomicPaymentObservation>,
    failures: Vec<String>,
    finalized_checkpoint_id: String,
    finalized_checkpoint_sequence: u32,
    finalized_checkpoint_unix: u32,
}

fn encode_cbor_head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Encode the protocol JSON data model using RFC 8949 Core Deterministic
/// CBOR. Floating point values, byte strings, tags and indefinite values are
/// outside the released service-protocol codec.
fn encode_protocol_json_cbor(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
    depth: usize,
) -> anyhow::Result<()> {
    if depth > 16 {
        anyhow::bail!("protocol CBOR exceeds the nesting bound");
    }
    match value {
        serde_json::Value::Null => output.push(0xf6),
        serde_json::Value::Bool(false) => output.push(0xf4),
        serde_json::Value::Bool(true) => output.push(0xf5),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                encode_cbor_head(0, value, output);
            } else if let Some(value) = number.as_i64() {
                let encoded = u64::try_from(-1i128 - i128::from(value))?;
                encode_cbor_head(1, encoded, output);
            } else {
                anyhow::bail!("floating-point protocol values are forbidden");
            }
        }
        serde_json::Value::String(value) => {
            if value.len() > 256 << 10 {
                anyhow::bail!("protocol string exceeds the byte bound");
            }
            encode_cbor_head(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            if values.len() > 4096 {
                anyhow::bail!("protocol array exceeds the item bound");
            }
            encode_cbor_head(4, values.len() as u64, output);
            for value in values {
                encode_protocol_json_cbor(value, output, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            if values.len() > 4096 {
                anyhow::bail!("protocol object exceeds the item bound");
            }
            let mut entries = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut encoded_key = Vec::new();
                encode_protocol_json_cbor(
                    &serde_json::Value::String(key.clone()),
                    &mut encoded_key,
                    depth + 1,
                )?;
                entries.push((encoded_key, value));
            }
            // RFC 8949 Core Deterministic Encoding sorts by the bytewise
            // lexical order of each already-deterministically encoded key.
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            encode_cbor_head(5, entries.len() as u64, output);
            for (key, value) in entries {
                output.extend_from_slice(&key);
                encode_protocol_json_cbor(value, output, depth + 1)?;
            }
        }
    }
    if output.len() > 1 << 20 {
        anyhow::bail!("canonical protocol CBOR exceeds the byte bound");
    }
    Ok(())
}

fn cbor_value_to_protocol_json(value: ciborium::Value) -> anyhow::Result<serde_json::Value> {
    match value {
        ciborium::Value::Integer(value) => {
            let value = i128::from(value);
            if value >= 0 {
                Ok(serde_json::Value::Number(serde_json::Number::from(u64::try_from(value)?)))
            } else {
                Ok(serde_json::Value::Number(serde_json::Number::from(i64::try_from(value)?)))
            }
        }
        ciborium::Value::Text(value) => Ok(serde_json::Value::String(value)),
        ciborium::Value::Bool(value) => Ok(serde_json::Value::Bool(value)),
        ciborium::Value::Null => Ok(serde_json::Value::Null),
        ciborium::Value::Array(values) => values
            .into_iter()
            .map(cbor_value_to_protocol_json)
            .collect::<anyhow::Result<Vec<_>>>()
            .map(serde_json::Value::Array),
        ciborium::Value::Map(values) => {
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                let ciborium::Value::Text(key) = key else {
                    anyhow::bail!("protocol CBOR map keys must be text strings");
                };
                if output.insert(key.clone(), cbor_value_to_protocol_json(value)?).is_some() {
                    anyhow::bail!("protocol CBOR contains duplicate map key {key:?}");
                }
            }
            Ok(serde_json::Value::Object(output))
        }
        ciborium::Value::Bytes(_) => {
            anyhow::bail!("protocol CBOR byte strings are outside the JSON data model")
        }
        ciborium::Value::Float(_) => anyhow::bail!("floating-point protocol CBOR is forbidden"),
        ciborium::Value::Tag(_, _) => anyhow::bail!("tagged protocol CBOR is forbidden"),
        _ => anyhow::bail!("unsupported protocol CBOR value"),
    }
}

fn decode_exact_protocol_cbor(path: &Path) -> anyhow::Result<(Vec<u8>, serde_json::Value)> {
    let bytes = open_private_snapshot_file(path)?;
    if bytes.is_empty() || bytes.len() > 1 << 20 {
        anyhow::bail!("canonical protocol CBOR has invalid size");
    }
    let mut cursor = Cursor::new(bytes.as_slice());
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
    Ok((bytes, value))
}

fn protocol_cbor_digest(domain: &str, canonical: &[u8]) -> anyhow::Result<String> {
    if domain.is_empty() || domain.len() > u16::MAX as usize || canonical.is_empty() {
        anyhow::bail!("protocol digest input is invalid");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"TOS-PROTOCOL-CBOR\0");
    hasher.update((domain.len() as u16).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(canonical);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn exact_protocol_action_request_digest(canonical: &[u8]) -> anyhow::Result<String> {
    if canonical.is_empty() || canonical.len() > 1 << 20 {
        anyhow::bail!("canonical action request has invalid size");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"tos.action-request.v1\0");
    hasher.update(u32::try_from(canonical.len())?.to_be_bytes());
    hasher.update(canonical);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn bounded_protocol_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn relay_network_domain_digest(network: &RelayNetworkDomainPin) -> anyhow::Result<String> {
    let value = serde_json::to_value(network)?;
    let mut canonical = Vec::new();
    encode_protocol_json_cbor(&value, &mut canonical, 0)?;
    protocol_cbor_digest(NETWORK_DOMAIN_DIGEST_DOMAIN, &canonical)
}

fn validate_sponsorship_finality_profile(
    profile: &SponsorshipFinalityProfile,
    available_members: usize,
) -> anyhow::Result<()> {
    if profile.profile_uri != SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI
        || profile.terminal_evidence_class != "client_corroborated"
        || validate_sha256_digest("finality_profile.profile_digest", &profile.profile_digest)
            .is_err()
        || profile.minimum_confirmation_depth == 0
        || profile.minimum_observers == 0
        || profile.minimum_operator_domains == 0
        || profile.minimum_operator_domains > profile.minimum_observers
        || profile.maximum_resolution_seconds == 0
        || profile.maximum_resolution_seconds > 24 * 60 * 60
        || profile.reorg_window_seconds > profile.maximum_resolution_seconds
        || usize::from(profile.minimum_observers) > available_members
        || usize::from(profile.minimum_operator_domains) > available_members
    {
        anyhow::bail!("selected sponsorship terminal predicate is invalid or unsupported");
    }
    if profile.minimum_confirmation_depth > 1 {
        anyhow::bail!(
            "selected sponsorship terminal predicate requires confirmation depth greater than this adapter can corroborate"
        );
    }
    Ok(())
}

fn validate_sponsorship_payment_request(
    request: &SponsorshipAgreementPaymentRequestV3,
    request_digest: &str,
    exact_request_digest: &str,
    network: &RelayNetworkDomainPin,
    record: &contracts::ControllerActionRecord,
    authorization: &EconomicActionAuthorization,
) -> anyhow::Result<()> {
    let sponsorship_commitment = AgentAccountContract::build_sponsorship_payment_commitment(
        request_digest,
        &request.stable_action_id,
    )?;
    let sponsorship_commitment_cell_hash =
        format!("tvm-cell-sha256:{}", hex::encode(sponsorship_commitment.hash(0)));
    let destination = base64::engine::general_purpose::STANDARD
        .decode(&request.destination)
        .context("decode AgreementPaymentRequestV3 destination")?;
    if base64::engine::general_purpose::STANDARD.encode(&destination) != request.destination {
        anyhow::bail!("AgreementPaymentRequestV3 destination is not canonical base64");
    }
    let destination = String::from_utf8(destination)
        .context("AgreementPaymentRequestV3 destination is not a UTF-8 TOS address")?;
    let amount = request
        .amount
        .amount_atomic
        .parse::<u64>()
        .context("AgreementPaymentRequestV3 amount does not fit native TOS")?;
    if amount.to_string() != request.amount.amount_atomic {
        anyhow::bail!("AgreementPaymentRequestV3 amount is not canonical atomic notation");
    }
    let network_digest = relay_network_domain_digest(network)?;
    if request.schema_version != 3
        || request.semantic_action_kind != ""
        || request.adapter_profile_digest != ""
        || request.external_system_id != ""
        || request.settlement_adapter_uri != "tos.payment.direct.v1"
        || !bounded_protocol_identifier(&request.owner_id, 256)
        || !bounded_protocol_identifier(&request.agent_id, 256)
        || !bounded_protocol_identifier(&request.agreement_obligation_id, 128)
        || !bounded_protocol_identifier(&request.payer_agent_id, 256)
        || !bounded_protocol_identifier(&request.payee_agent_id, 256)
        || !bounded_protocol_identifier(&request.network_id, 128)
        || !bounded_protocol_identifier(&request.amount.asset_namespace, 128)
        || !bounded_protocol_identifier(&request.amount.asset_identifier, 256)
        || !bounded_protocol_identifier(&request.amount.unit, 128)
        || request.amount.unit != "nanotos"
        || request.amount.asset_namespace != "tos.native"
        || request.amount.asset_identifier != network.network_id
        || amount == 0
        || request_digest
            != authorization
                .agreement_payment_request_digest
                .as_deref()
                .context("custody payment lacks schema-v3 AgreementPaymentRequest digest")?
        || exact_request_digest != authorization.exact_request_digest
        || request.stable_action_id != authorization.stable_action_id
        || request.stable_action_id != record.claim.action_identity
        || request.owner_id != authorization.owner_id
        || request.agent_id != authorization.agent_id
        || request.payer_agent_id != authorization.agent_id
        || request.agreement_body_digest != authorization.agreement_body_digest
        || request.obligation_instance_id != authorization.obligation_instance_id
        || request.network_id != authorization.network_id
        || request.network_domain_digest != network_digest
        || destination != record.claim.target
        || destination != authorization.destination
        || amount != record.claim.value_atomic
        || amount != authorization.amount_atomic
        || request.expires_at_unix != u64::from(record.claim.valid_until)
        || request.expires_at_unix != authorization.expires_at_unix
        || authorization.schema_version != 3
        || authorization.network_domain.as_ref() != Some(network)
        || authorization.source_account != record.claim.account
        || record.claim.action_kind != "agent-task-send"
        || record.claim.body_hash.as_deref() != Some(sponsorship_commitment_cell_hash.as_str())
    {
        anyhow::bail!(
            "AgreementPaymentRequestV3 conflicts with the exact custody authorization or transaction"
        );
    }
    Ok(())
}

fn validate_sponsorship_custody_evidence_context(
    authorization: &EconomicActionAuthorization,
    finality_profile_cbor_digest: &str,
    release_profile_digest: &str,
    snapshot_identity: &str,
) -> anyhow::Result<()> {
    if authorization.sponsorship_finality_profile_cbor_digest.as_deref()
        != Some(finality_profile_cbor_digest)
        || authorization.sponsorship_release_profile_digest.as_deref()
            != Some(release_profile_digest)
        || authorization.sponsorship_corroboration_snapshot_identity.as_deref()
            != Some(snapshot_identity)
    {
        anyhow::bail!(
            "custody authorization does not bind the exact sponsorship terminal predicate and frozen observation capability"
        );
    }
    Ok(())
}

fn validate_replayed_sponsorship_finality(
    evidence: &serde_json::Value,
    stable_action_id: &str,
    payment_request_digest: &str,
    finality_profile: &SponsorshipFinalityProfile,
    finality_profile_value: &serde_json::Value,
    finality_profile_cbor_digest: &str,
    snapshot_identity: &str,
    release_profile_digest: &str,
) -> anyhow::Result<()> {
    let nested = evidence
        .get("sponsorship_transaction_evidence")
        .and_then(serde_json::Value::as_object)
        .context("stored sponsorship corroborated terminal has no nested transaction evidence")?;
    if evidence.get("schema").and_then(serde_json::Value::as_str)
        != Some(ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA)
        || evidence.get("stable_action_id").and_then(serde_json::Value::as_str)
            != Some(stable_action_id)
        || json_object_string(nested, "sponsorship_stable_action_id") != Some(stable_action_id)
        || json_object_string(nested, "agreement_payment_request_digest")
            != Some(payment_request_digest)
        || json_object_string(nested, "sponsorship_terminal_profile_digest")
            != Some(finality_profile.profile_digest.as_str())
        || evidence.get("finality_profile_uri").and_then(serde_json::Value::as_str)
            != Some(finality_profile.profile_uri.as_str())
        || evidence.get("finality_profile") != Some(finality_profile_value)
        || evidence.get("finality_profile_cbor_digest").and_then(serde_json::Value::as_str)
            != Some(finality_profile_cbor_digest)
        || evidence.get("corroboration_snapshot_identity").and_then(serde_json::Value::as_str)
            != Some(snapshot_identity)
        || evidence.get("sponsorship_release_profile_digest").and_then(serde_json::Value::as_str)
            != Some(release_profile_digest)
        || evidence.get("state").and_then(serde_json::Value::as_str)
            != Some("corroborated_terminal")
        || evidence.get("custody_state").and_then(serde_json::Value::as_str) != Some("resolved")
    {
        anyhow::bail!(
            "stored sponsorship corroborated terminal conflicts with the exact supplied context"
        );
    }
    Ok(())
}

fn json_object_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    object.get(key).and_then(serde_json::Value::as_str)
}

#[derive(Clone)]
struct LoadedEconomicPaymentCorroborationMember {
    config: AppConfig,
    canonical_path: PathBuf,
    content_digest: String,
    endpoint: String,
    display_origin: String,
    locator_identity_digest: String,
    operator_provenance: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicPaymentCorroborationSnapshotMember {
    config_path: String,
    config_content_digest: String,
    endpoint: String,
    locator_identity_digest: String,
    operator_provenance: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicPaymentCorroborationSnapshot {
    schema: String,
    snapshot_identity: String,
    snapshot_nonce: String,
    evidence_profile_uri: String,
    evidence_profile_digest: String,
    network_domain: RelayNetworkDomainPin,
    maximum_history_transactions: u32,
    evidence_profile: serde_json::Value,
    members: Vec<EconomicPaymentCorroborationSnapshotMember>,
}

impl EconomicPaymentObservation {
    fn quorum_key(&self) -> String {
        serde_json::json!({
            "source_transaction_hash": self.transaction_hash,
            "source_transaction_lt": self.transaction_lt,
            "source_transaction_utime": self.transaction_utime,
            "source_transaction_boc_digest": self.transaction_boc_digest,
            "source_outbound_message_hash": self.source_outbound_message_hash,
            "source_block": [self.block_workchain, self.block_shard, i64::from(self.block_seqno)],
            "source_block_root_hash": self.block_root_hash,
            "source_block_file_hash": self.block_file_hash,
            "destination_credit_reference": self.destination_credit_reference,
            "destination_transaction_hash": self.destination_transaction_hash,
            "destination_transaction_lt": self.destination_transaction_lt,
            "destination_transaction_utime": self.destination_transaction_utime,
            "destination_transaction_boc_digest": self.destination_transaction_boc_digest,
            "destination_block": [self.destination_block_workchain, self.destination_block_shard, i64::from(self.destination_block_seqno)],
            "destination_block_root_hash": self.destination_block_root_hash,
            "destination_block_file_hash": self.destination_block_file_hash,
            "destination_credit_atomic": self.destination_credit_atomic,
            "destination_credit_first": self.destination_credit_first,
            "destination_transaction_aborted": self.destination_transaction_aborted,
            "destination_bounce_present": self.destination_bounce_present,
            "destination_credit_observed_exact": self.destination_credit_observed_exact,
            "network_global_id": self.network_global_id,
            "zero_state": [self.zero_state_workchain, self.zero_state_shard, i64::from(self.zero_state_seqno)],
            "zero_state_root_hash": self.zero_state_root_hash,
            "zero_state_file_hash": self.zero_state_file_hash,
            "masterchain": [self.observed_masterchain_workchain, self.observed_masterchain_shard, i64::from(self.observed_masterchain_seqno)],
            "masterchain_root_hash": self.observed_masterchain_root_hash,
            "masterchain_file_hash": self.observed_masterchain_file_hash,
            "masterchain_gen_utime": self.observed_masterchain_gen_utime,
        })
        .to_string()
    }
}

fn exact_transaction_utime(transaction_utime: u32, rpc_wrapper_utime: u32) -> anyhow::Result<u32> {
    if transaction_utime == 0 {
        anyhow::bail!("observed transaction BOC has no hash-bound generation time");
    }
    if rpc_wrapper_utime != transaction_utime {
        anyhow::bail!(
            "RPC transaction wrapper time differs from the hash-bound transaction BOC time"
        );
    }
    Ok(transaction_utime)
}

fn sponsorship_rpc_not_found(failure: &str) -> bool {
    failure.contains("rpc_failure_category=not_found")
        || failure.contains(
            "submitted Agreement payment was not found in the bounded RPC account history",
        )
        || failure.contains(
            "submitted Agreement payment was not found in the bounded finalized account history",
        )
        || failure.contains(
            "authorized destination credit was not found in the bounded RPC account history",
        )
}

fn sponsorship_rpc_temporarily_unavailable(failure: &str) -> bool {
    failure.contains("rpc_failure_category=temporarily_unavailable")
        || failure.contains("RPC temporarily unavailable:")
        || failure.contains("rpc_error_category=timeout")
        || failure.contains("rpc_error_category=transport_unavailable")
}

fn rpc_failure_category(error: &anyhow::Error) -> &'static str {
    let rendered = format!("{error:#}");
    if sponsorship_rpc_not_found(&rendered) {
        "not_found"
    } else if sponsorship_rpc_temporarily_unavailable(&rendered) {
        "temporarily_unavailable"
    } else {
        "invalid_or_conflicting_response"
    }
}

fn rpc_display_origin(endpoint: &str) -> String {
    const MAX_DISPLAY_ORIGIN_BYTES: usize = 256;
    let Ok((_, origin)) = canonicalize_chain_rpc_endpoint(endpoint) else {
        return "<invalid-rpc-origin>".to_owned();
    };
    if origin.len() > MAX_DISPLAY_ORIGIN_BYTES {
        "<rpc-origin-too-long>".to_owned()
    } else {
        origin
    }
}

fn rpc_failure_diagnostic(endpoint: &str, error: &anyhow::Error) -> String {
    format!(
        "{}: rpc_failure_category={}",
        rpc_display_origin(endpoint),
        rpc_failure_category(error)
    )
}

fn chain_query_failure_diagnostic(error: &anyhow::Error) -> String {
    format!("chain_query_failure_category={}", rpc_failure_category(error))
}

#[derive(Clone, Debug)]
struct DestinationCreditObservation {
    message_hash: String,
    transaction_hash: String,
    transaction_lt: u64,
    transaction_utime: u32,
    transaction_boc_digest: String,
    block_workchain: i32,
    block_shard: i64,
    block_seqno: u32,
    block_root_hash: String,
    block_file_hash: String,
    credit_atomic: String,
    credit_first: bool,
    transaction_aborted: bool,
    bounce_present: bool,
}

fn validate_destination_credit_semantics(
    ordinary: &chain_block::TransactionDescrOrdinary,
    expected_value: &chain_block::CurrencyCollection,
) -> anyhow::Result<()> {
    let credit =
        ordinary.credit_ph.as_ref().context("destination transaction has no credit phase")?;
    // For a non-bounce message, credit-first is the economic terminal fact.
    // Destination contract compute may abort on an unknown optional body, but
    // it cannot roll back the already applied exact credit and no bounce phase
    // returns that value to the sponsor.
    if !ordinary.credit_first || ordinary.bounce.is_some() || credit.credit != *expected_value {
        anyhow::bail!(
            "destination transaction did not finalize an exact credit-first non-bounced credit"
        );
    }
    Ok(())
}

async fn observe_exact_destination_credit(
    rpc_client: &chain_rpc_client::v2::client_json_rpc::ClientJsonRpc,
    source: &MsgAddressInt,
    target: &MsgAddressInt,
    outbound_message: &Cell,
    expected_value: &chain_block::CurrencyCollection,
    max_transactions: u32,
) -> anyhow::Result<DestinationCreditObservation> {
    let outbound_message_hash =
        format!("tvm-cell-sha256:{}", hex::encode(outbound_message.hash(0)));
    let info = rpc_client
        .get_address_information(target)
        .await
        .context("RPC temporarily unavailable: query destination account")?;
    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let bounded_max = max_transactions.clamp(1, 10_000);
    while cursor_lt != 0 && inspected < bounded_max {
        let page_limit = (bounded_max - inspected).min(100);
        let page = rpc_client
            .get_transactions(target, cursor_lt, &cursor_hash, page_limit)
            .await
            .context("RPC temporarily unavailable: query destination transaction history")?;
        if page.transactions.is_empty() {
            break;
        }
        let mut next_cursor = None;
        for raw in page.transactions {
            inspected = inspected.saturating_add(1);
            next_cursor = Some((raw.lt, raw.hash.clone()));
            if raw.data.is_empty() {
                continue;
            }
            let transaction_boc = base64::engine::general_purpose::STANDARD
                .decode(&raw.data)
                .context("decode destination transaction BOC")?;
            let transaction_root = read_single_root_boc(&transaction_boc)
                .context("parse destination transaction BOC")?;
            let transaction = Transaction::construct_from_cell(transaction_root.clone())
                .context("decode destination transaction")?;
            let Some(in_cell) = transaction.in_msg_cell() else {
                continue;
            };
            if in_cell.hash(0) != outbound_message.hash(0) {
                continue;
            }
            let transaction_utime = exact_transaction_utime(transaction.now(), raw.utime)?;
            let inbound = Message::construct_from_cell(in_cell)
                .context("decode exact destination inbound message")?;
            if !inbound.is_internal()
                || inbound.is_bounced()
                || inbound.src().as_ref() != Some(source)
                || inbound.dst().as_ref() != Some(target)
                || inbound.value() != Some(expected_value)
            {
                anyhow::bail!(
                    "destination transaction inbound message conflicts with the exact source outbound transfer"
                );
            }
            let description = transaction.read_description()?;
            let TransactionDescr::Ordinary(ordinary) = description else {
                anyhow::bail!("destination credit is not an ordinary transaction");
            };
            validate_destination_credit_semantics(&ordinary, expected_value)?;
            let credit = ordinary.credit_ph.as_ref().expect("validated credit phase");
            let block = raw.block_id.context("destination transaction has no block identity")?;
            return Ok(DestinationCreditObservation {
                message_hash: outbound_message_hash,
                transaction_hash: format!("sha256:{}", hex::encode(transaction_root.hash(0))),
                transaction_lt: transaction.logical_time(),
                transaction_utime,
                transaction_boc_digest: canonical_file_digest(&transaction_boc),
                block_workchain: block.workchain,
                block_shard: block.shard,
                block_seqno: block.seqno,
                block_root_hash: format!("sha256:{}", hex::encode(block.root_hash)),
                block_file_hash: format!("sha256:{}", hex::encode(block.file_hash)),
                credit_atomic: credit.credit.coins.as_u128().to_string(),
                credit_first: ordinary.credit_first,
                transaction_aborted: ordinary.aborted,
                bounce_present: ordinary.bounce.is_some(),
            });
        }
        let Some((next_lt, next_hash)) = next_cursor else {
            break;
        };
        if next_lt == cursor_lt && next_hash == cursor_hash {
            break;
        }
        cursor_lt = next_lt;
        cursor_hash = next_hash;
    }
    anyhow::bail!("authorized destination credit was not found in the bounded RPC account history")
}

fn sponsorship_checkpoint_is_mature(
    observation: &EconomicPaymentObservation,
    profile: &SponsorshipFinalityProfile,
    observed_at_unix: u64,
) -> anyhow::Result<bool> {
    if observation.observed_masterchain_seqno == 0
        || observation.observed_masterchain_gen_utime == 0
        || u64::from(observation.observed_masterchain_gen_utime)
            > observed_at_unix.saturating_add(5 * 60)
    {
        anyhow::bail!("sponsorship checkpoint time is invalid or outside the permitted host skew");
    }
    let economic_effect_utime =
        observation.transaction_utime.max(observation.destination_transaction_utime);
    Ok(u64::from(observation.observed_masterchain_gen_utime)
        >= u64::from(economic_effect_utime).saturating_add(u64::from(profile.reorg_window_seconds)))
}

fn sponsorship_chain_effect_key(observation: &EconomicPaymentObservation) -> String {
    serde_json::json!({
        "source_transaction_hash": observation.transaction_hash,
        "source_transaction_lt": observation.transaction_lt,
        "source_transaction_utime": observation.transaction_utime,
        "source_transaction_boc_digest": observation.transaction_boc_digest,
        "source_outbound_message_hash": observation.source_outbound_message_hash,
        "source_block": [observation.block_workchain, observation.block_shard, i64::from(observation.block_seqno)],
        "source_block_root_hash": observation.block_root_hash,
        "source_block_file_hash": observation.block_file_hash,
        "destination_credit_reference": observation.destination_credit_reference,
        "destination_transaction_hash": observation.destination_transaction_hash,
        "destination_transaction_lt": observation.destination_transaction_lt,
        "destination_transaction_utime": observation.destination_transaction_utime,
        "destination_transaction_boc_digest": observation.destination_transaction_boc_digest,
        "destination_block": [observation.destination_block_workchain, observation.destination_block_shard, i64::from(observation.destination_block_seqno)],
        "destination_block_root_hash": observation.destination_block_root_hash,
        "destination_block_file_hash": observation.destination_block_file_hash,
        "destination_credit_atomic": observation.destination_credit_atomic,
        "destination_credit_first": observation.destination_credit_first,
        "destination_transaction_aborted": observation.destination_transaction_aborted,
        "destination_bounce_present": observation.destination_bounce_present,
        "destination_credit_observed_exact": observation.destination_credit_observed_exact,
        "network_global_id": observation.network_global_id,
        "zero_state": [observation.zero_state_workchain, observation.zero_state_shard, i64::from(observation.zero_state_seqno)],
        "zero_state_root_hash": observation.zero_state_root_hash,
        "zero_state_file_hash": observation.zero_state_file_hash,
    })
    .to_string()
}

#[derive(Clone, Debug)]
struct ParsedControllerAuthorization {
    controller_epoch: u64,
    signature: [u8; 64],
    hash_to_sign: [u8; 32],
}

fn verify_parsed_controller_authorization(
    authorization: &ParsedControllerAuthorization,
    controller_public_key: &[u8; 32],
) -> anyhow::Result<()> {
    let key = VerifyingKey::from_bytes(controller_public_key)
        .context("Agent Account controller public key is invalid")?;
    let signature = Ed25519Signature::from_slice(&authorization.signature)
        .context("Agent Account controller signature is not 64 bytes")?;
    key.verify_strict(&authorization.hash_to_sign, &signature)
        .context("Agent Account controller signature is invalid")
}

fn verify_current_controller_authorization(
    authorization: &ParsedControllerAuthorization,
    current_controller_epoch: u64,
    current_controller_public_key: &[u8; 32],
) -> anyhow::Result<()> {
    if current_controller_epoch < authorization.controller_epoch {
        anyhow::bail!(
            "current Agent Account controller epoch rolled behind the signed sponsorship action"
        );
    }
    if current_controller_epoch > authorization.controller_epoch {
        anyhow::bail!(
            "cannot verify the signed sponsorship action after controller rotation: V1 has no bound historical controller-authority proof"
        );
    }
    verify_parsed_controller_authorization(authorization, current_controller_public_key)
}

#[allow(clippy::too_many_arguments)]
fn validate_exact_sponsorship_top_up_boc(
    bytes: &[u8],
    encoded: &str,
    expected_digest: &str,
    expected_cell_hash: &str,
    source: &MsgAddressInt,
    network_global_id: i32,
    source_sequence: u32,
    valid_until: u32,
    target: &MsgAddressInt,
    value_atomic: u64,
    agreement_payment_request_digest: &str,
    stable_action_id: &str,
) -> anyhow::Result<ParsedControllerAuthorization> {
    if base64::engine::general_purpose::STANDARD.encode(bytes) != encoded {
        anyhow::bail!("signed top-up transaction uses non-canonical base64");
    }
    validate_exact_boc_before_broadcast(bytes)
        .context("signed top-up transaction failed the shared exact-BOC gate")?;
    let digest = canonical_file_digest(bytes);
    let root = read_single_root_boc(bytes)?;
    if write_boc(&root)? != bytes {
        anyhow::bail!("signed top-up transaction BOC is not canonically serialized");
    }
    let cell_hash = format!("tvm-cell-sha256:{}", hex::encode(root.hash(0)));
    if digest != expected_digest || cell_hash != expected_cell_hash {
        anyhow::bail!("signed top-up transaction bytes conflict with their exact digests");
    }
    let message = Message::construct_from_cell(root)
        .context("parse signed top-up external Agent Account message")?;
    let header = message
        .ext_in_header()
        .context("signed top-up transaction is not an external inbound message")?;
    if &header.dst != source {
        anyhow::bail!("signed top-up transaction destination is not the provider source account");
    }
    let mut body = message.body().cloned().context("signed top-up transaction has no body")?;
    let signature: [u8; 64] = body
        .get_next_bytes(64)
        .context("signed top-up transaction has a truncated signature")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signed top-up transaction signature must be 64 bytes"))?;
    if signature.iter().all(|byte| *byte == 0) {
        anyhow::bail!("signed top-up transaction has an invalid zero signature");
    }
    let payload = body.clone().into_cell()?;
    let opcode = body.get_next_u32()?;
    let message_global_id = body.get_next_i32()?;
    let controller_epoch = body.get_next_u64()?;
    let message_sequence = body.get_next_u32()?;
    let message_valid_until = body.get_next_u32()?;
    let message_target = MsgAddressInt::construct_from(&mut body)
        .context("signed top-up transaction has an invalid target")?;
    let message_value = Coins::construct_from(&mut body)
        .context("signed top-up transaction has an invalid value")?
        .as_u128();
    if opcode != contracts::agent_account::AGENT_TASK_SEND_OPCODE
        || message_global_id != network_global_id
        || message_sequence != source_sequence
        || message_valid_until != valid_until
        || &message_target != target
        || message_value != u128::from(value_atomic)
        || body.remaining_bits() != 0
        || body.remaining_references() != 1
    {
        anyhow::bail!(
            "signed top-up transaction does not exactly encode the claimed network, sequence, expiry, destination, and amount"
        );
    }
    let commitment = body.checked_drain_reference()?;
    let expected_commitment = AgentAccountContract::build_sponsorship_payment_commitment(
        agreement_payment_request_digest,
        stable_action_id,
    )?;
    if commitment.hash(0) != expected_commitment.hash(0)
        || write_boc(&commitment)? != write_boc(&expected_commitment)?
        || body.remaining_references() != 0
    {
        anyhow::bail!(
            "signed top-up transaction does not commit the exact AgreementPaymentRequest and stable action"
        );
    }
    let hash_to_sign =
        AgentAccountContract::controller_hash_to_sign(source, network_global_id, &payload)?;
    Ok(ParsedControllerAuthorization { controller_epoch, signature, hash_to_sign })
}

async fn verify_sponsorship_controller_authorization_quorum(
    loaded: &[LoadedEconomicPaymentCorroborationMember],
    network: &RelayNetworkDomainPin,
    source: &MsgAddressInt,
    authorization: &ParsedControllerAuthorization,
    threshold: usize,
    minimum_operator_domains: usize,
) -> anyhow::Result<()> {
    let mut votes: BTreeMap<(u64, [u8; 32]), BTreeSet<String>> = BTreeMap::new();
    let mut failures = Vec::new();
    for member in loaded {
        let result = async {
            let rpc_client = try_create_rpc_client(&member.config).await?;
            rpc_client.verify_pinned_primary_network(network).await?;
            let provider = contracts::contract_provider!(rpc_client);
            AgentAccountContract::get_data(provider.as_ref(), source).await
        }
        .await;
        match result {
            Ok(data) => {
                votes
                    .entry((data.controller_epoch, data.controller_pubkey))
                    .or_default()
                    .insert(member.operator_provenance.clone());
            }
            Err(error) => failures.push(rpc_failure_diagnostic(&member.endpoint, &error)),
        }
    }
    let ((controller_epoch, controller_public_key), operators) = votes
        .into_iter()
        .max_by_key(|(_, operators)| operators.len())
        .context("RPC snapshot produced no Agent Account controller-authority observation")?;
    if operators.len() < threshold || operators.len() < minimum_operator_domains {
        anyhow::bail!(
            "RPC snapshot has no strict controller-authority quorum; agreeing={}; threshold={threshold}; minimum_operator_domains={minimum_operator_domains}; failures={}",
            operators.len(),
            serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    verify_current_controller_authorization(authorization, controller_epoch, &controller_public_key)
}

fn economic_payment_observation_digest<T: serde::Serialize>(
    domain: &[u8],
    value: &T,
) -> anyhow::Result<String> {
    let encoded = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

async fn corroborate_economic_payment(
    config: &AppConfig,
    endpoint: String,
    locator_identity_digest: String,
    operator_provenance: String,
    expected_network: &RelayNetworkDomainPin,
    account: &MsgAddressInt,
    record: &contracts::ControllerActionRecord,
    max_transactions: u32,
) -> anyhow::Result<EconomicPaymentObservation> {
    let encoded = record
        .exact_signed_boc_base64
        .as_ref()
        .context("custody record no longer contains the submitted payment BOC")?;
    let submitted_boc = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let submitted_root = read_single_root_boc(&submitted_boc)?;
    let target = record.claim.target.parse::<MsgAddressInt>()?;
    corroborate_economic_payment_expected(
        config,
        endpoint,
        locator_identity_digest,
        operator_provenance,
        expected_network,
        account,
        &format!("tvm-cell-sha256:{}", hex::encode(submitted_root.hash(0))),
        &target,
        record.claim.value_atomic,
        max_transactions,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn corroborate_economic_payment_expected(
    config: &AppConfig,
    endpoint: String,
    locator_identity_digest: String,
    operator_provenance: String,
    expected_network: &RelayNetworkDomainPin,
    account: &MsgAddressInt,
    submitted_message_cell_hash: &str,
    target: &MsgAddressInt,
    expected_value_atomic: u64,
    max_transactions: u32,
) -> anyhow::Result<EconomicPaymentObservation> {
    let rpc_client = try_create_rpc_client(config).await?;
    // Corroborating operators may report observations, but none may choose the
    // network on which those observations are interpreted. Every member must
    // independently match the full owner-signed custody pin first.
    rpc_client.verify_pinned_primary_network(expected_network).await?;
    let expected_value = chain_block::CurrencyCollection::with_coins(expected_value_atomic);
    let network_global_id = match rpc_client
        .get_config_param(19)
        .await
        .context("RPC temporarily unavailable: query network global ID")?
    {
        ConfigParamEnum::ConfigParam19(value) => value as i32,
        _ => anyhow::bail!("RPC config parameter 19 is not a global ID"),
    };

    let info = rpc_client
        .get_address_information(account)
        .await
        .context("RPC temporarily unavailable: query provider source account")?;
    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let bounded_max = max_transactions.clamp(1, 10_000);

    while cursor_lt != 0 && inspected < bounded_max {
        let page_limit = (bounded_max - inspected).min(100);
        let page = rpc_client
            .get_transactions(account, cursor_lt, &cursor_hash, page_limit)
            .await
            .context("RPC temporarily unavailable: query provider transaction history")?;
        if page.transactions.is_empty() {
            break;
        }
        let mut next_cursor = None;
        for raw in page.transactions {
            inspected = inspected.saturating_add(1);
            next_cursor = Some((raw.lt, raw.hash.clone()));
            if raw.data.is_empty() {
                continue;
            }
            let transaction_boc = base64::engine::general_purpose::STANDARD
                .decode(&raw.data)
                .context("decode observed transaction BOC")?;
            let transaction_root =
                read_single_root_boc(&transaction_boc).context("parse observed transaction BOC")?;
            let transaction = Transaction::construct_from_cell(transaction_root.clone())
                .context("decode observed transaction")?;
            let transaction_utime = exact_transaction_utime(transaction.now(), raw.utime)?;
            let Some(in_cell) = transaction.in_msg_cell() else {
                continue;
            };
            if format!("tvm-cell-sha256:{}", hex::encode(in_cell.hash(0)))
                != submitted_message_cell_hash
            {
                continue;
            }
            let mut exact_outputs = 0u32;
            let mut exact_outbound_message = None;
            transaction.iterate_out_msgs(|message| {
                if message.dst().as_ref() == Some(target)
                    && message.value() == Some(&expected_value)
                {
                    exact_outputs = exact_outputs.saturating_add(1);
                    exact_outbound_message = Some(message.serialize()?);
                }
                Ok(true)
            })?;
            if exact_outputs != 1 {
                anyhow::bail!(
                    "observed submitted transaction does not contain exactly one authorized output"
                );
            }
            let block = raw.block_id.context("observed transaction has no block identity")?;
            let exact_outbound_message = exact_outbound_message
                .context("authorized destination output has no exact message cell")?;
            let destination_credit = observe_exact_destination_credit(
                rpc_client.as_ref(),
                account,
                target,
                &exact_outbound_message,
                &expected_value,
                max_transactions,
            )
            .await?;
            let master = rpc_client
                .get_masterchain_info()
                .await
                .context("RPC temporarily unavailable: query masterchain head")?;
            let zero_state = master
                .init
                .as_ref()
                .context("getMasterchainInfo omitted the zero-state BlockIdExt")?;
            let master_header = rpc_client
                .get_block_header(
                    master.last.workchain,
                    &master.last.shard.to_string(),
                    master.last.seqno,
                )
                .await
                .context("RPC temporarily unavailable: query masterchain header")?;
            if master_header.gen_utime == 0 {
                anyhow::bail!("observed masterchain header has no generation time");
            }
            return Ok(EconomicPaymentObservation {
                endpoint,
                locator_identity_digest,
                operator_provenance,
                transaction_hash: format!("sha256:{}", hex::encode(transaction_root.hash(0))),
                transaction_lt: transaction.logical_time(),
                transaction_utime,
                transaction_boc_digest: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(&transaction_boc))
                ),
                source_outbound_message_hash: destination_credit.message_hash,
                destination_credit_reference: destination_credit.transaction_hash.clone(),
                destination_transaction_hash: destination_credit.transaction_hash,
                destination_transaction_lt: destination_credit.transaction_lt,
                destination_transaction_utime: destination_credit.transaction_utime,
                destination_transaction_boc_digest: destination_credit.transaction_boc_digest,
                destination_block_workchain: destination_credit.block_workchain,
                destination_block_shard: destination_credit.block_shard,
                destination_block_seqno: destination_credit.block_seqno,
                destination_block_root_hash: destination_credit.block_root_hash,
                destination_block_file_hash: destination_credit.block_file_hash,
                destination_credit_atomic: destination_credit.credit_atomic,
                destination_credit_first: destination_credit.credit_first,
                destination_transaction_aborted: destination_credit.transaction_aborted,
                destination_bounce_present: destination_credit.bounce_present,
                destination_credit_observed_exact: true,
                block_workchain: block.workchain,
                block_shard: block.shard,
                block_seqno: block.seqno,
                block_root_hash: format!("sha256:{}", hex::encode(block.root_hash)),
                block_file_hash: format!("sha256:{}", hex::encode(block.file_hash)),
                network_global_id,
                zero_state_workchain: zero_state.workchain,
                zero_state_shard: zero_state.shard,
                zero_state_seqno: zero_state.seqno,
                zero_state_root_hash: format!("sha256:{}", hex::encode(&zero_state.root_hash)),
                zero_state_file_hash: format!("sha256:{}", hex::encode(&zero_state.file_hash)),
                observed_masterchain_workchain: master.last.workchain,
                observed_masterchain_shard: master.last.shard,
                observed_masterchain_seqno: master.last.seqno,
                observed_masterchain_root_hash: format!(
                    "sha256:{}",
                    hex::encode(&master.last.root_hash)
                ),
                observed_masterchain_file_hash: format!(
                    "sha256:{}",
                    hex::encode(&master.last.file_hash)
                ),
                observed_masterchain_gen_utime: master_header.gen_utime,
                // RPC agreement is corroboration, not a shard/masterchain
                // inclusion proof with validator signatures.
                finality_proven: false,
            });
        }
        let Some((next_lt, next_hash)) = next_cursor else {
            break;
        };
        if next_lt == cursor_lt && next_hash == cursor_hash {
            break;
        }
        cursor_lt = next_lt;
        cursor_hash = next_hash;
    }
    anyhow::bail!("submitted Agreement payment was not found in the bounded RPC account history")
}

fn canonical_file_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Stable, credential-independent identity for one exact RPC locator.
///
/// Formula:
/// SHA-256(domain || uint64be(len(canonical_locator_utf8)) ||
///         canonical_locator_utf8)
///
/// The canonical locator includes its path but never an API key. Public
/// evidence carries this digest and the origin-only `endpoint`; the full
/// locator remains solely in the owner-private frozen config bytes.
fn rpc_locator_identity_digest(locator: &str) -> anyhow::Result<String> {
    let (canonical, _) = canonicalize_chain_rpc_endpoint(locator)?;
    let bytes = canonical.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(RPC_LOCATOR_IDENTITY_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_release_profile_rpc_locator(value: &str) -> anyhow::Result<(String, String)> {
    let (canonical, display_origin) = canonicalize_chain_rpc_endpoint(value)?;
    if value != canonical {
        anyhow::bail!("release-profile RPC locator must already use its canonical byte form");
    }
    let path = canonical
        .strip_prefix(&display_origin)
        .context("canonical RPC locator does not begin with its display origin")?;
    if value.contains('\\')
        || path.contains("//")
        || path.split('/').any(|segment| segment == "." || segment == "..")
    {
        anyhow::bail!("release-profile RPC locator path contains a forbidden alias");
    }
    Ok((canonical, display_origin))
}

fn corroboration_snapshot_handle(snapshot_identity: &str) -> anyhow::Result<String> {
    validate_sha256_digest("corroboration_snapshot_identity", snapshot_identity)?;
    Ok(format!("corroboration-{}/manifest.json", &snapshot_identity[7..]))
}

fn validate_snapshot_nonce(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("corroboration snapshot nonce must be 32 bytes of lowercase hex");
    }
    Ok(())
}

fn validate_snapshot_member_basename(value: &str) -> anyhow::Result<&str> {
    if value.is_empty()
        || value.len() > 128
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        anyhow::bail!("corroboration snapshot member path must be one relative basename");
    }
    let path = Path::new(value);
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
        || path.file_name().and_then(|name| name.to_str()) != Some(value)
    {
        anyhow::bail!("corroboration snapshot member path must be one relative basename");
    }
    Ok(value)
}

fn recursively_sorted_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(recursively_sorted_json).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted = values.into_iter().collect::<BTreeMap<_, _>>();
            let mut object = serde_json::Map::new();
            for (key, value) in sorted {
                object.insert(key, recursively_sorted_json(value));
            }
            serde_json::Value::Object(object)
        }
        scalar => scalar,
    }
}

fn config_format_from_path(path: &Path) -> anyhow::Result<&str> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("json") => Ok("json"),
        Some("yaml" | "yml") => Ok("yaml"),
        _ => anyhow::bail!("frozen RPC config must use a JSON or YAML extension"),
    }
}

fn economic_payment_corroboration_profile(
    network: &RelayNetworkDomainPin,
    members: &[LoadedEconomicPaymentCorroborationMember],
    maximum_history_transactions: u32,
) -> anyhow::Result<(serde_json::Value, String, usize)> {
    if members.len() < 3
        || maximum_history_transactions == 0
        || maximum_history_transactions > 10_000
    {
        anyhow::bail!("RPC corroboration profile is incomplete");
    }
    if members.iter().map(|member| member.display_origin.as_str()).collect::<BTreeSet<_>>().len()
        != members.len()
    {
        anyhow::bail!("RPC corroboration profile repeats a public display origin");
    }
    let threshold = members.len() / 2 + 1;
    let mut descriptor_members = members
        .iter()
        .map(|member| {
            (
                member.display_origin.clone(),
                member.locator_identity_digest.clone(),
                member.operator_provenance.clone(),
            )
        })
        .collect::<Vec<_>>();
    descriptor_members.sort();
    let descriptor = recursively_sorted_json(serde_json::json!({
        "profile_uri": ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI,
        "network_domain": network,
        "members": descriptor_members.iter().map(|(display_origin, locator_identity_digest, operator)| serde_json::json!({
            // `endpoint` is retained for the released cross-language shape,
            // but its public value is deliberately origin-only. The exact
            // capability path remains solely in the owner-private config,
            // and is committed without credential/config disclosure.
            "endpoint": display_origin,
            "locator_identity_digest": locator_identity_digest,
            "operator_provenance": operator,
        })).collect::<Vec<_>>(),
        "threshold": threshold,
        "maximum_history_transactions": maximum_history_transactions,
        "strict_majority": true,
        "exact_submitted_message": true,
        "exact_destination_credit": true,
        "validator_finality_proven": false,
    }));
    let digest = economic_payment_observation_digest(
        b"tosctl.agreement-payment-rpc-corroboration-profile.v1\0",
        &descriptor,
    )?;
    Ok((descriptor, digest, threshold))
}

fn load_economic_payment_corroboration_members(
    primary_path: &Path,
    quorum_configs: &[String],
) -> anyhow::Result<Vec<LoadedEconomicPaymentCorroborationMember>> {
    let mut paths = Vec::with_capacity(quorum_configs.len() + 1);
    paths.push(fs::canonicalize(primary_path).context("resolve primary RPC config")?);
    for value in quorum_configs {
        let path = Path::new(value);
        if !path.is_absolute() {
            anyhow::bail!("every quorum-config must be an absolute path");
        }
        paths.push(fs::canonicalize(path).context("resolve quorum RPC config")?);
    }
    if paths.len() < 3 {
        anyhow::bail!("at least three RPC configurations are required");
    }
    let mut endpoints = BTreeMap::new();
    let mut display_origins = BTreeMap::new();
    let mut operators = BTreeMap::new();
    let mut loaded = Vec::with_capacity(paths.len());
    for (index, path) in paths.into_iter().enumerate() {
        let bytes = fs::read(&path).context("read RPC config snapshot source")?;
        let config = AppConfig::load_bytes(
            &bytes,
            config_format_from_path(&path)?,
            "RPC config snapshot source",
        )?;
        if config.chain_rpc.urls.len() != 1 {
            anyhow::bail!("RPC config snapshot member {index} must name exactly one endpoint");
        }
        let configured_locator = config.chain_rpc.urls[0].url();
        let (endpoint, display_origin) = validate_release_profile_rpc_locator(configured_locator)?;
        let locator_identity_digest = rpc_locator_identity_digest(&endpoint)?;
        if endpoints.insert(endpoint.clone(), path.clone()).is_some() {
            anyhow::bail!("quorum RPC endpoints must be distinct");
        }
        if display_origins.insert(display_origin.clone(), path.clone()).is_some() {
            anyhow::bail!("quorum RPC display origins must be distinct");
        }
        let operator_provenance = config
            .chain_rpc
            .operator_provenance
            .clone()
            .context("every quorum config must owner-pin operator_provenance")?;
        validate_sha256_digest("operator_provenance", &operator_provenance)?;
        if operators.insert(operator_provenance.clone(), path.clone()).is_some() {
            anyhow::bail!("quorum RPC operators must have distinct owner-pinned provenance");
        }
        loaded.push(LoadedEconomicPaymentCorroborationMember {
            config,
            canonical_path: path,
            content_digest: canonical_file_digest(&bytes),
            endpoint,
            display_origin,
            locator_identity_digest,
            operator_provenance,
        });
    }
    Ok(loaded)
}

async fn verify_economic_payment_corroboration_network(
    members: &[LoadedEconomicPaymentCorroborationMember],
    network: &RelayNetworkDomainPin,
) -> anyhow::Result<()> {
    for member in members {
        let result = async {
            let client = try_create_rpc_client(&member.config).await?;
            client.verify_pinned_primary_network(network).await
        }
        .await;
        if let Err(error) = result {
            anyhow::bail!(
                "frozen RPC member {} failed network verification; rpc_failure_category={}",
                member.display_origin,
                rpc_failure_category(&error)
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_owner_private_agent_storage() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn require_owner_private_agent_storage() -> anyhow::Result<()> {
    anyhow::bail!(
        "owner-private Agent custody and corroboration storage is not implemented on this platform"
    )
}

fn open_private_snapshot_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    require_owner_private_agent_storage()?;
    if !path.is_absolute() {
        anyhow::bail!("corroboration snapshot path must be absolute");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).context("open corroboration snapshot file")?;
    let metadata = file.metadata().context("inspect corroboration snapshot file")?;
    if !metadata.is_file() || metadata.len() > 4 << 20 {
        anyhow::bail!("corroboration snapshot must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!(
                "corroboration snapshot file must be owner-private with exactly one hard link"
            );
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).context("read corroboration snapshot file")?;
    Ok(bytes)
}

fn write_private_snapshot_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    require_owner_private_agent_storage()?;
    if let Ok(existing) = open_private_snapshot_file(path) {
        if existing == bytes {
            return Ok(());
        }
        anyhow::bail!("existing corroboration snapshot file has different bytes");
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_snapshot_directory(parent: &Path, name: &str) -> anyhow::Result<PathBuf> {
    require_owner_private_agent_storage()?;
    let parent = canonical_private_journal_directory(
        parent.to_str().context("snapshot directory path is not UTF-8")?,
    )?;
    let directory = parent.join(name);
    match fs::symlink_metadata(&directory) {
        Ok(_) => canonical_private_journal_directory(
            directory.to_str().context("snapshot path is not UTF-8")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&directory)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(&directory)?;
            canonical_private_journal_directory(
                directory.to_str().context("snapshot path is not UTF-8")?,
            )
        }
        Err(error) => Err(error.into()),
    }
}

fn freeze_economic_payment_corroboration_snapshot(
    snapshot_parent: &Path,
    network: RelayNetworkDomainPin,
    members: &[LoadedEconomicPaymentCorroborationMember],
    maximum_history_transactions: u32,
    evidence_profile: serde_json::Value,
    evidence_profile_digest: String,
) -> anyhow::Result<(PathBuf, EconomicPaymentCorroborationSnapshot)> {
    let mut snapshot_nonce_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut snapshot_nonce_bytes);
    let snapshot_nonce = hex::encode(snapshot_nonce_bytes);
    let snapshot_identity = economic_payment_observation_digest(
        b"tosctl.agreement-payment-rpc-corroboration-snapshot.v1\0",
        &serde_json::json!({
            "evidence_profile_digest": evidence_profile_digest,
            "config_content_digests": members.iter().map(|member| member.content_digest.clone()).collect::<Vec<_>>(),
            "snapshot_nonce": snapshot_nonce.clone(),
        }),
    )?;
    let directory = create_private_snapshot_directory(
        snapshot_parent,
        &format!("corroboration-{}", &snapshot_identity[7..]),
    )?;
    let mut frozen = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let extension = config_format_from_path(&member.canonical_path)?;
        let destination = directory.join(format!("member-{index:03}.{extension}"));
        let bytes = fs::read(&member.canonical_path)?;
        if canonical_file_digest(&bytes) != member.content_digest {
            anyhow::bail!("RPC config changed while its snapshot was being frozen");
        }
        write_private_snapshot_file(&destination, &bytes)?;
        frozen.push(EconomicPaymentCorroborationSnapshotMember {
            config_path: destination
                .file_name()
                .and_then(|name| name.to_str())
                .context("frozen RPC member basename is not UTF-8")?
                .to_owned(),
            config_content_digest: member.content_digest.clone(),
            endpoint: member.display_origin.clone(),
            locator_identity_digest: member.locator_identity_digest.clone(),
            operator_provenance: member.operator_provenance.clone(),
        });
    }
    let snapshot = EconomicPaymentCorroborationSnapshot {
        schema: "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1".to_owned(),
        snapshot_identity,
        snapshot_nonce,
        evidence_profile_uri: ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI.to_owned(),
        evidence_profile_digest,
        network_domain: network,
        maximum_history_transactions,
        evidence_profile,
        members: frozen,
    };
    let manifest = directory.join("manifest.json");
    write_private_snapshot_file(&manifest, &serde_json::to_vec_pretty(&snapshot)?)?;
    Ok((fs::canonicalize(manifest)?, snapshot))
}

fn load_economic_payment_corroboration_snapshot(
    manifest_path: &Path,
    expected_profile_digest: &str,
    expected_snapshot_identity: &str,
) -> anyhow::Result<(
    EconomicPaymentCorroborationSnapshot,
    Vec<LoadedEconomicPaymentCorroborationMember>,
    usize,
)> {
    validate_sha256_digest("sponsorship_release_profile_digest", expected_profile_digest)?;
    validate_sha256_digest("corroboration_snapshot_identity", expected_snapshot_identity)?;
    // Inspect and read the caller-supplied path before canonicalization so a
    // symlink cannot be hidden by resolving it first.
    let manifest_bytes = open_private_snapshot_file(manifest_path)?;
    let manifest_path =
        fs::canonicalize(manifest_path).context("resolve corroboration snapshot")?;
    let directory =
        manifest_path.parent().context("corroboration snapshot has no parent directory")?;
    canonical_private_journal_directory(
        directory.to_str().context("snapshot directory path is not UTF-8")?,
    )?;
    let snapshot: EconomicPaymentCorroborationSnapshot = serde_json::from_slice(&manifest_bytes)?;
    if snapshot.schema != "tosctl.agent-account.agreement-payment-rpc-corroboration-snapshot.v1"
        || snapshot.evidence_profile_uri != ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI
        || snapshot.evidence_profile_digest != expected_profile_digest
        || snapshot.snapshot_identity != expected_snapshot_identity
        || snapshot.members.len() < 3
    {
        anyhow::bail!("corroboration snapshot conflicts with the signed release profile");
    }
    validate_sha256_digest("snapshot_identity", &snapshot.snapshot_identity)?;
    validate_snapshot_nonce(&snapshot.snapshot_nonce)?;
    let expected_handle = corroboration_snapshot_handle(&snapshot.snapshot_identity)?;
    let expected_directory_name = expected_handle
        .split('/')
        .next()
        .context("corroboration snapshot handle has no directory")?;
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json")
        || directory.file_name().and_then(|name| name.to_str()) != Some(expected_directory_name)
    {
        anyhow::bail!("corroboration snapshot path conflicts with its opaque handle");
    }
    let mut loaded = Vec::with_capacity(snapshot.members.len());
    let mut canonical_paths = BTreeMap::new();
    let mut endpoints = BTreeMap::new();
    let mut display_origins = BTreeMap::new();
    let mut operators = BTreeMap::new();
    for frozen in &snapshot.members {
        validate_sha256_digest("config_content_digest", &frozen.config_content_digest)?;
        validate_sha256_digest("locator_identity_digest", &frozen.locator_identity_digest)?;
        validate_sha256_digest("operator_provenance", &frozen.operator_provenance)?;
        let basename = validate_snapshot_member_basename(&frozen.config_path)?;
        let supplied_path = directory.join(basename);
        // Hash and parse one no-follow read. AppConfig::load(path) here would
        // permit config replacement between the digest check and use.
        let bytes = open_private_snapshot_file(&supplied_path)?;
        let path = fs::canonicalize(&supplied_path)?;
        if !path.starts_with(directory) {
            anyhow::bail!("corroboration snapshot member escapes its private directory");
        }
        if canonical_paths.insert(path.clone(), ()).is_some() {
            anyhow::bail!("corroboration snapshot repeats a member path");
        }
        if canonical_file_digest(&bytes) != frozen.config_content_digest {
            anyhow::bail!("corroboration snapshot member bytes changed");
        }
        let config =
            AppConfig::load_bytes(&bytes, config_format_from_path(&path)?, "frozen RPC member")?;
        if config.chain_rpc.urls.len() != 1 {
            anyhow::bail!("corroboration snapshot member no longer has one endpoint");
        }
        let configured_locator = config.chain_rpc.urls[0].url();
        let (endpoint, display_origin) = validate_release_profile_rpc_locator(configured_locator)?;
        let locator_identity_digest = rpc_locator_identity_digest(&endpoint)?;
        let operator = config
            .chain_rpc
            .operator_provenance
            .clone()
            .context("snapshot member has no operator provenance")?;
        if display_origin != frozen.endpoint
            || locator_identity_digest != frozen.locator_identity_digest
            || operator != frozen.operator_provenance
        {
            anyhow::bail!("corroboration snapshot member conflicts with its manifest");
        }
        if endpoints.insert(endpoint.clone(), ()).is_some() {
            anyhow::bail!("corroboration snapshot repeats an RPC endpoint");
        }
        if display_origins.insert(display_origin.clone(), ()).is_some() {
            anyhow::bail!("corroboration snapshot repeats an RPC display origin");
        }
        if operators.insert(operator.clone(), ()).is_some() {
            anyhow::bail!("corroboration snapshot repeats an operator provenance");
        }
        loaded.push(LoadedEconomicPaymentCorroborationMember {
            config,
            canonical_path: path,
            content_digest: frozen.config_content_digest.clone(),
            endpoint,
            display_origin,
            locator_identity_digest,
            operator_provenance: operator,
        });
    }
    let (descriptor, digest, threshold) = economic_payment_corroboration_profile(
        &snapshot.network_domain,
        &loaded,
        snapshot.maximum_history_transactions,
    )?;
    if descriptor != snapshot.evidence_profile || digest != snapshot.evidence_profile_digest {
        anyhow::bail!("corroboration snapshot profile cannot be reproduced");
    }
    let expected_snapshot_identity = economic_payment_observation_digest(
        b"tosctl.agreement-payment-rpc-corroboration-snapshot.v1\0",
        &serde_json::json!({
            "evidence_profile_digest": snapshot.evidence_profile_digest,
            "config_content_digests": snapshot.members.iter().map(|member| member.config_content_digest.clone()).collect::<Vec<_>>(),
            "snapshot_nonce": snapshot.snapshot_nonce.clone(),
        }),
    )?;
    if snapshot.snapshot_identity != expected_snapshot_identity {
        anyhow::bail!("corroboration snapshot identity cannot be reproduced");
    }
    Ok((snapshot, loaded, threshold))
}

impl AgentAccountEconomicPaymentCorroborationProfileCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let network = RelayNetworkDomainPin {
            network_id: self.network_id.clone(),
            global_id: self.global_id,
            zero_state_root_hash: self.zero_state_root_hash.clone(),
            zero_state_file_hash: self.zero_state_file_hash.clone(),
            workchain_id: self.workchain_id,
        };
        if self.max_transactions == 0 || self.max_transactions > 10_000 {
            anyhow::bail!("max_transactions must be between 1 and 10000");
        }
        let members = load_economic_payment_corroboration_members(
            Path::new(config_path),
            &self.quorum_configs,
        )?;
        verify_economic_payment_corroboration_network(&members, &network).await?;
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, self.max_transactions)?;
        let (_manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            Path::new(&self.snapshot_directory),
            network,
            &members,
            self.max_transactions,
            descriptor,
            digest,
        )?;
        let snapshot_handle = corroboration_snapshot_handle(&snapshot.snapshot_identity)?;
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.agreement-payment-rpc-corroboration-capability.v1",
                "evidence_class": "observed_unproven",
                "evidence_profile_uri": snapshot.evidence_profile_uri,
                "evidence_profile_digest": snapshot.evidence_profile_digest,
                "evidence_profile": snapshot.evidence_profile,
                "corroboration_snapshot_handle": snapshot_handle,
                "corroboration_snapshot_identity": snapshot.snapshot_identity,
                "network_domain": snapshot.network_domain,
                "maximum_history_transactions": snapshot.maximum_history_transactions,
                "member_count": snapshot.members.len(),
                "side_effect": false,
            })
        );
        Ok(())
    }
}

impl AgentAccountEconomicPaymentCorroborateCmd {
    pub async fn run(&self, _config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        let idempotency = self.stable_action_id[7..].to_owned();
        let (snapshot, loaded, threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        let snapshot_handle = corroboration_snapshot_handle(&snapshot.snapshot_identity)?;
        let primary = &loaded[0].config;
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
        verify_economic_payment_corroboration_network(&loaded, &snapshot.network_domain).await?;
        let primary_rpc = try_create_rpc_client(&loaded[0].config).await?;
        let provider = contracts::contract_provider!(primary_rpc.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let global_id = match primary_rpc.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let journal = open_economic_controller_journal(
            &loaded[0].canonical_path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let record = journal
            .find_primary(
                &account.to_string(),
                global_id,
                &hex::encode(data.deployment_id),
                data.controller_epoch,
                &idempotency,
            )?
            .context("prepared Agreement payment was not found")?;
        let authorization = record
            .economic_authorization
            .as_ref()
            .context("custody record is not an economic payment")?;
        if authorization.stable_action_id != self.stable_action_id {
            anyhow::bail!("custody action identity mismatch");
        }
        if record.status != ControllerActionStatus::Broadcasting {
            anyhow::bail!("only an ambiguously broadcast Agreement payment may be resolved");
        }
        let expected_network = record
            .claim
            .network_domain
            .as_ref()
            .context("custody payment has no full network-domain pin")?;
        if expected_network != &snapshot.network_domain {
            anyhow::bail!("custody payment network differs from the frozen corroboration snapshot");
        }

        let mut observations = Vec::with_capacity(loaded.len());
        let mut failures = Vec::new();
        for member in &loaded {
            match corroborate_economic_payment(
                &member.config,
                member.display_origin.clone(),
                member.locator_identity_digest.clone(),
                member.operator_provenance.clone(),
                expected_network,
                &account,
                &record,
                snapshot.maximum_history_transactions,
            )
            .await
            {
                Ok(observation) => observations.push(observation),
                Err(error) => failures.push(rpc_failure_diagnostic(&member.endpoint, &error)),
            }
        }
        let mut votes: BTreeMap<String, Vec<&EconomicPaymentObservation>> = BTreeMap::new();
        for observation in &observations {
            votes.entry(observation.quorum_key()).or_default().push(observation);
        }
        let winner = votes
            .values()
            .max_by_key(|group| group.len())
            .filter(|group| group.len() >= threshold)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no strict majority corroborated the payment transaction and full block/network identity; observation_count={}; failures={}",
                    observations.len(),
                    serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
                )
            })?;
        let evidence = winner[0];
        let payment_request_digest = authorization
            .agreement_payment_request_digest
            .as_ref()
            .context("custody payment lacks schema-v3 agreement_payment_request_digest")?;
        let sponsorship_commitment = AgentAccountContract::build_sponsorship_payment_commitment(
            payment_request_digest,
            &self.stable_action_id,
        )?;
        let sponsorship_payment_commitment_cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(sponsorship_commitment.hash(0)));
        if record.claim.action_kind != "agent-task-send"
            || record.claim.body_hash.as_deref()
                != Some(sponsorship_payment_commitment_cell_hash.as_str())
        {
            anyhow::bail!(
                "custody sponsorship does not bind the exact AgreementPaymentRequest commitment"
            );
        }
        let exact_signed_boc_digest = record
            .exact_signed_boc_digest
            .as_ref()
            .context("custody payment lacks exact signed BOC digest")?;
        let exact_signed_boc = base64::engine::general_purpose::STANDARD.decode(
            record
                .exact_signed_boc_base64
                .as_ref()
                .context("custody payment lacks exact signed BOC")?,
        )?;
        let recomputed_boc_digest =
            format!("sha256:{}", hex::encode(Sha256::digest(&exact_signed_boc)));
        if &recomputed_boc_digest != exact_signed_boc_digest {
            anyhow::bail!("custody payment exact signed BOC digest is inconsistent");
        }
        let signed_top_up_cell = read_single_root_boc(&exact_signed_boc)?;
        let signed_top_up_cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(signed_top_up_cell.hash(0)));
        let mut observation_digests = winner
            .iter()
            .map(|observation| {
                economic_payment_observation_digest(
                    b"tosctl.agreement-payment-rpc-observation.v1\0",
                    *observation,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        observation_digests.sort();
        observation_digests.dedup();
        if observation_digests.len() < threshold {
            anyhow::bail!("corroboration observations do not have a unique digest quorum");
        }
        let evidence_profile_descriptor = snapshot.evidence_profile.clone();
        let evidence_profile_digest = snapshot.evidence_profile_digest.clone();
        let observed_checkpoint_id = format!(
            "masterchain:{}:{}:{}:{}:{}",
            evidence.observed_masterchain_workchain,
            evidence.observed_masterchain_shard,
            evidence.observed_masterchain_seqno,
            evidence.observed_masterchain_root_hash,
            evidence.observed_masterchain_file_hash,
        );

        let observed_account = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if observed_account.controller_epoch != record.claim.controller_epoch
            || observed_account.seqno <= record.claim.seqno
        {
            anyhow::bail!("primary RPC Agent Account view has not consumed the payment seqno");
        }
        println!(
            "{}",
            serde_json::json!({
                "schema": ECONOMIC_PAYMENT_CORROBORATION_SCHEMA,
                "stable_action_id": self.stable_action_id,
                "sponsorship_stable_action_id": self.stable_action_id,
                "sponsorship_exact_request_digest": authorization.exact_request_digest,
                "agreement_payment_request_digest": payment_request_digest,
                "agreement_body_digest": authorization.agreement_body_digest,
                "obligation_instance_id": authorization.obligation_instance_id,
                "provider_sponsor_source_account": account.to_string(),
                "provider_sponsor_source_sequence": record.claim.seqno,
                "provider_sponsor_valid_until_unix": record.claim.valid_until,
                "signed_top_up_transaction_digest": exact_signed_boc_digest,
                "signed_top_up_transaction_cell_hash": signed_top_up_cell_hash,
                "sponsorship_payment_commitment_cell_hash": sponsorship_payment_commitment_cell_hash,
                "destination_source_account": record.claim.target,
                "destination": record.claim.target,
                "amount_nanotos": record.claim.value_atomic,
                "network_global_id": global_id,
                "network_domain": expected_network,
                "submitted_transaction_hash": evidence.transaction_hash,
                "source_execution_reference": evidence.transaction_hash,
                "destination_credit_references": [evidence.destination_credit_reference.clone()],
                "evidence_profile_uri": ECONOMIC_PAYMENT_CORROBORATION_PROFILE_URI,
                "evidence_profile_digest": evidence_profile_digest,
                "evidence_profile": evidence_profile_descriptor,
                "corroboration_snapshot_handle": snapshot_handle,
                "corroboration_snapshot_identity": snapshot.snapshot_identity,
                "observed_checkpoint_id": observed_checkpoint_id,
                "observed_checkpoint_sequence": evidence.observed_masterchain_seqno,
                "observed_checkpoint_unix": evidence.observed_masterchain_gen_utime,
                "observation_digests": observation_digests,
                "observed_at_unix": time_format::now(),
                "quorum": {"members": loaded.len(), "threshold": threshold, "agreeing": winner.len()},
                "evidence": evidence,
                "observations": observations,
                "failures": failures,
                "finality": "unproven",
                "state": "observed_unproven",
                "custody_state": "broadcasting",
                "missing_proof": "validator-authenticated shard inclusion plus masterchain finality proof"
            })
        );
        Ok(())
    }
}

impl AgentAccountEconomicPaymentSponsorshipFinalityCmd {
    pub async fn run(&self, _config_path: &str) -> anyhow::Result<()> {
        validate_sha256_digest("stable_action_id", &self.stable_action_id)?;
        validate_sha256_digest(
            "corroboration_snapshot_identity",
            &self.corroboration_snapshot_identity,
        )?;
        validate_sha256_digest(
            "sponsorship_release_profile_digest",
            &self.sponsorship_release_profile_digest,
        )?;

        let (payment_cbor, payment_value) =
            decode_exact_protocol_cbor(Path::new(&self.agreement_payment_request_cbor))?;
        let payment: SponsorshipAgreementPaymentRequestV3 =
            serde_json::from_value(payment_value.clone())
                .context("decode exact AgreementPaymentRequestV3")?;
        let payment_request_digest =
            protocol_cbor_digest(AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN, &payment_cbor)?;
        let payment_exact_request_digest = exact_protocol_action_request_digest(&payment_cbor)?;

        let (finality_profile_cbor, finality_profile_value) =
            decode_exact_protocol_cbor(Path::new(&self.finality_profile_cbor))?;
        let finality_profile: SponsorshipFinalityProfile =
            serde_json::from_value(finality_profile_value.clone())
                .context("decode exact selected sponsorship FinalityProfile")?;
        let finality_profile_cbor_digest = canonical_file_digest(&finality_profile_cbor);

        let (snapshot, loaded, threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        let snapshot_handle = corroboration_snapshot_handle(&snapshot.snapshot_identity)?;
        let primary = &loaded[0].config;
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
        let journal = open_economic_controller_journal(
            &loaded[0].canonical_path,
            None,
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let record = journal
            .find_economic_payment_by_stable_action(&self.stable_action_id)?
            .context("prepared sponsorship Agreement payment was not found")?;
        let authorization = record
            .economic_authorization
            .as_ref()
            .context("custody record is not an economic payment")?;
        let expected_network = record
            .claim
            .network_domain
            .as_ref()
            .context("custody sponsorship payment has no full network-domain pin")?;
        validate_sponsorship_payment_request(
            &payment,
            &payment_request_digest,
            &payment_exact_request_digest,
            expected_network,
            &record,
            authorization,
        )?;
        validate_sponsorship_custody_evidence_context(
            authorization,
            &finality_profile_cbor_digest,
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        let sponsorship_payment_commitment_cell_hash = record
            .claim
            .body_hash
            .clone()
            .context("custody sponsorship has no PaymentRequest commitment body")?;

        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved sponsorship payment has no replayable exact-winner evidence")?;
            if resolution.evidence_kind != ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA {
                anyhow::bail!(
                    "sponsorship payment was resolved under a different evidence profile"
                );
            }
            validate_replayed_sponsorship_finality(
                &resolution.evidence,
                &self.stable_action_id,
                &payment_request_digest,
                &finality_profile,
                &finality_profile_value,
                &finality_profile_cbor_digest,
                &self.corroboration_snapshot_identity,
                &self.sponsorship_release_profile_digest,
            )?;
            println!("{}", resolution.evidence);
            return Ok(());
        }
        if record.status != ControllerActionStatus::Broadcasting {
            anyhow::bail!("only an ambiguously broadcast sponsorship payment may be resolved");
        }

        if expected_network != &snapshot.network_domain {
            anyhow::bail!("custody payment network differs from the frozen corroboration snapshot");
        }
        validate_sponsorship_finality_profile(&finality_profile, loaded.len())?;
        verify_economic_payment_corroboration_network(&loaded, &snapshot.network_domain).await?;

        let primary_rpc = try_create_rpc_client(&loaded[0].config).await?;
        let provider = contracts::contract_provider!(primary_rpc.clone());
        let current = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        let global_id = match primary_rpc.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        if global_id != record.claim.network_global_id
            || hex::encode(current.deployment_id) != record.claim.deployment_id
        {
            anyhow::bail!("current Agent Account generation differs from the custody sponsorship");
        }

        let mut observations = Vec::with_capacity(loaded.len());
        let mut failures = Vec::new();
        for member in &loaded {
            match corroborate_economic_payment(
                &member.config,
                member.display_origin.clone(),
                member.locator_identity_digest.clone(),
                member.operator_provenance.clone(),
                expected_network,
                &account,
                &record,
                snapshot.maximum_history_transactions,
            )
            .await
            {
                Ok(observation) => observations.push(observation),
                Err(error) => failures.push(rpc_failure_diagnostic(&member.endpoint, &error)),
            }
        }
        observations.sort_by(|left, right| {
            left.operator_provenance
                .cmp(&right.operator_provenance)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        failures.sort();
        let mut votes: BTreeMap<String, Vec<&EconomicPaymentObservation>> = BTreeMap::new();
        for observation in &observations {
            votes.entry(observation.quorum_key()).or_default().push(observation);
        }
        let winner =
            votes.values().max_by_key(|group| group.len()).filter(|group| group.len() >= threshold);
        let Some(winner) = winner else {
            if observations.is_empty()
                && !failures.is_empty()
                && failures.iter().all(|failure| sponsorship_rpc_not_found(failure))
            {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
                        "state": "unknown",
                        "category": "not_found",
                        "reason": "exact submitted sponsorship transaction is not yet visible in bounded RPC history",
                        "stable_action_id": self.stable_action_id,
                        "agreement_payment_request_digest": payment_request_digest,
                        "sponsorship_exact_request_digest": payment_exact_request_digest,
                        "custody_state": "broadcasting",
                        "chain_side_effect": false,
                        "custody_side_effect": false,
                    })
                );
                return Ok(());
            }
            if votes.len() <= 1
                && observations.len() < threshold
                && failures.iter().any(|failure| sponsorship_rpc_temporarily_unavailable(failure))
                && failures.iter().all(|failure| {
                    sponsorship_rpc_not_found(failure)
                        || sponsorship_rpc_temporarily_unavailable(failure)
                })
            {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
                        "state": "unknown",
                        "category": "temporarily_unavailable",
                        "reason": "the frozen RPC quorum is temporarily insufficient for an exact terminal observation",
                        "stable_action_id": self.stable_action_id,
                        "agreement_payment_request_digest": payment_request_digest,
                        "sponsorship_exact_request_digest": payment_exact_request_digest,
                        "custody_state": "broadcasting",
                        "chain_side_effect": false,
                        "custody_side_effect": false,
                    })
                );
                return Ok(());
            }
            anyhow::bail!(
                "no strict majority corroborated the sponsorship transaction and full block/network identity; observation_count={}; failures={}",
                observations.len(),
                serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
            );
        };
        if winner.len() < usize::from(finality_profile.minimum_observers) {
            anyhow::bail!("corroborated sponsorship has fewer observers than the selected profile");
        }
        let winner_operators = winner
            .iter()
            .map(|observation| observation.operator_provenance.clone())
            .collect::<BTreeSet<_>>();
        if winner_operators.len() < usize::from(finality_profile.minimum_operator_domains) {
            anyhow::bail!(
                "corroborated sponsorship has fewer operator domains than the selected profile"
            );
        }
        let evidence = (*winner[0]).clone();
        let observed_at_unix = time_format::now();
        if !sponsorship_checkpoint_is_mature(&evidence, &finality_profile, observed_at_unix)? {
            println!(
                "{}",
                serde_json::json!({
                    "schema": ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
                    "state": "unknown",
                    "category": "not_mature",
                    "reason": "quorum checkpoint has not crossed the selected chain-time reorg window",
                    "stable_action_id": self.stable_action_id,
                    "agreement_payment_request_digest": payment_request_digest,
                    "sponsorship_exact_request_digest": payment_exact_request_digest,
                    "custody_state": "broadcasting",
                    "chain_side_effect": false,
                    "custody_side_effect": false,
                })
            );
            return Ok(());
        }

        let finalized = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if hex::encode(finalized.deployment_id) != record.claim.deployment_id
            || (finalized.controller_epoch, finalized.seqno)
                <= (record.claim.controller_epoch, record.claim.seqno)
        {
            anyhow::bail!("finalized Agent Account state has not consumed the sponsorship seqno");
        }

        let exact_signed_boc_digest = record
            .exact_signed_boc_digest
            .as_ref()
            .context("custody sponsorship lacks exact signed BOC digest")?;
        let exact_signed_boc = base64::engine::general_purpose::STANDARD.decode(
            record
                .exact_signed_boc_base64
                .as_ref()
                .context("custody sponsorship lacks exact signed BOC")?,
        )?;
        let recomputed_boc_digest =
            format!("sha256:{}", hex::encode(Sha256::digest(&exact_signed_boc)));
        if &recomputed_boc_digest != exact_signed_boc_digest {
            anyhow::bail!("custody sponsorship exact signed BOC digest is inconsistent");
        }
        let signed_top_up_cell = read_single_root_boc(&exact_signed_boc)?;
        let signed_top_up_cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(signed_top_up_cell.hash(0)));
        let mut observation_digests = winner
            .iter()
            .map(|observation| {
                economic_payment_observation_digest(
                    b"tosctl.agreement-payment-rpc-observation.v1\0",
                    *observation,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        observation_digests.sort();
        observation_digests.dedup();
        if observation_digests.len() != winner.len() {
            anyhow::bail!("corroborated sponsorship repeats an observation digest");
        }

        let finalized_checkpoint_id = format!(
            "masterchain:{}:{}:{}:{}:{}",
            evidence.observed_masterchain_workchain,
            evidence.observed_masterchain_shard,
            evidence.observed_masterchain_seqno,
            evidence.observed_masterchain_root_hash,
            evidence.observed_masterchain_file_hash,
        );
        let network_digest = relay_network_domain_digest(expected_network)?;
        let destination_credit_references = vec![evidence.destination_credit_reference.clone()];
        let proof_bundle = recursively_sorted_json(serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-sponsorship-proof-bundle.v1",
            "agreement_payment_request": payment_value,
            "agreement_payment_request_digest": payment_request_digest,
            "sponsorship_stable_action_id": self.stable_action_id,
            "sponsorship_exact_request_digest": payment_exact_request_digest,
            "provider_sponsor_source_account": account.to_string(),
            "provider_sponsor_source_sequence": record.claim.seqno,
            "provider_sponsor_valid_until_unix": payment.expires_at_unix,
            "destination_source_account": record.claim.target,
            "signed_top_up_transaction_digest": exact_signed_boc_digest,
            "signed_top_up_transaction_cell_hash": signed_top_up_cell_hash,
            "signed_top_up_transaction_boc": base64::engine::general_purpose::STANDARD.encode(&exact_signed_boc),
            "sponsorship_payment_commitment_cell_hash": sponsorship_payment_commitment_cell_hash,
            "network_digest": network_digest,
            "network_domain": expected_network,
            "finality_profile": finality_profile_value,
            "finality_profile_cbor_digest": finality_profile_cbor_digest,
            "sponsorship_release_profile_uri": snapshot.evidence_profile_uri,
            "sponsorship_release_profile_digest": snapshot.evidence_profile_digest,
            "sponsorship_release_profile": snapshot.evidence_profile,
            "corroboration_snapshot_identity": snapshot.snapshot_identity,
            "confirmation_depth": 1,
            "terminal_evidence_class": "client_corroborated",
            "validator_authenticated_portable_proof": false,
            "quorum": {"members": loaded.len(), "threshold": threshold, "agreeing": winner.len()},
            "observation_digests": observation_digests,
            "observations": observations,
            "failures": failures,
            "finalized_checkpoint_id": finalized_checkpoint_id,
            "finalized_checkpoint_sequence": evidence.observed_masterchain_seqno,
            "finalized_checkpoint_unix": evidence.observed_masterchain_gen_utime,
        }));
        let mut proof_bundle_cbor = Vec::new();
        encode_protocol_json_cbor(&proof_bundle, &mut proof_bundle_cbor, 0)?;
        if proof_bundle_cbor.len() > 128 << 10 {
            anyhow::bail!("sponsorship corroboration proof bundle exceeds the protocol byte bound");
        }
        let proof_bundle_digest =
            protocol_cbor_digest(SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN, &proof_bundle_cbor)?;
        let proof_bundle_cbor_base64 =
            base64::engine::general_purpose::STANDARD.encode(&proof_bundle_cbor);
        let amount = serde_json::json!({
            "asset": {
                "asset_namespace": payment.amount.asset_namespace,
                "asset_identifier": payment.amount.asset_identifier,
                "unit": payment.amount.unit,
            },
            "amount_atomic": payment.amount.amount_atomic,
        });
        let sponsorship_transaction_evidence = serde_json::json!({
            "schema_version": 1,
            "network_digest": network_digest,
            "agreement_payment_request": payment_value,
            "agreement_payment_request_digest": payment_request_digest,
            "sponsorship_stable_action_id": self.stable_action_id,
            "sponsorship_exact_request_digest": payment_exact_request_digest,
            "provider_sponsor_source_account": account.to_string(),
            "provider_sponsor_source_sequence": record.claim.seqno,
            "provider_sponsor_valid_until_unix": payment.expires_at_unix,
            "signed_top_up_transaction_digest": exact_signed_boc_digest,
            "signed_top_up_transaction_cell_hash": signed_top_up_cell_hash,
            "sponsorship_payment_commitment_cell_hash": sponsorship_payment_commitment_cell_hash,
            "destination_source_account": record.claim.target,
            "amount": amount,
            "submitted_transaction_hash": evidence.transaction_hash,
            "source_execution_reference": evidence.transaction_hash,
            "destination_credit_references": destination_credit_references,
            "finalized_checkpoint_id": finalized_checkpoint_id,
            "finalized_checkpoint_sequence": evidence.observed_masterchain_seqno,
            "finalized_checkpoint_unix": evidence.observed_masterchain_gen_utime,
            "confirmation_depth": 1,
            "terminal_evidence_class": "client_corroborated",
            "validator_authenticated_portable_proof": false,
            "sponsorship_terminal_profile_digest": finality_profile.profile_digest,
            "observation_digests": observation_digests,
            "proof_bundle_digest": proof_bundle_digest,
            "proof_bundle": proof_bundle_cbor_base64,
            "observed_at_unix": observed_at_unix,
        });
        let output = serde_json::json!({
            "schema": ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
            "stable_action_id": self.stable_action_id,
            "agreement_payment_request_digest": payment_request_digest,
            "sponsorship_exact_request_digest": payment_exact_request_digest,
            "network_domain": expected_network,
            "network_digest": network_digest,
            "finality_profile_uri": finality_profile.profile_uri,
            "finality_profile_digest": finality_profile.profile_digest,
            "finality_profile": finality_profile_value,
            "finality_profile_cbor_digest": finality_profile_cbor_digest,
            "sponsorship_release_profile_uri": snapshot.evidence_profile_uri,
            "sponsorship_release_profile_digest": snapshot.evidence_profile_digest,
            "sponsorship_release_profile": snapshot.evidence_profile,
            "corroboration_snapshot_handle": snapshot_handle,
            "corroboration_snapshot_identity": snapshot.snapshot_identity,
            "provider_snapshot_identity": snapshot.snapshot_identity,
            "operator_provenance": winner_operators,
            "proof_bundle_digest_algorithm": "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic",
            "proof_bundle_digest_domain": SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN,
            "proof_bundle_digest": proof_bundle_digest,
            "proof_bundle_cbor": proof_bundle_cbor_base64,
            "proof_bundle": proof_bundle,
            "sponsorship_payment_commitment_cell_hash": sponsorship_payment_commitment_cell_hash,
            "quorum": {"members": loaded.len(), "threshold": threshold, "agreeing": winner.len()},
            "evidence": evidence,
            "observations": observations,
            "failures": failures,
            "sponsorship_transaction_evidence": sponsorship_transaction_evidence,
            "observed_at_unix": observed_at_unix,
            "state": "corroborated_terminal",
            "custody_state": "resolved",
            "terminal_evidence_class": "client_corroborated",
            "assurance_scope": "owner-selected-rpc-corroborated-terminal",
            "validator_authenticated_portable_proof": false,
            "chain_side_effect": false,
            "custody_side_effect": true,
        });
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA.to_owned(),
            evidence_digest: controller_resolution_evidence_digest(
                ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
                &output,
            )?,
            evidence: output,
        };
        let resolved = journal.resolve_exact_winner(
            &record.claim,
            exact_signed_boc_digest,
            finalized.controller_epoch,
            finalized.seqno,
            resolution,
            observed_at_unix,
        )?;
        println!(
            "{}",
            resolved
                .exact_winner_resolution
                .context("resolved sponsorship lost exact-winner evidence")?
                .evidence
        );
        Ok(())
    }
}

impl AgentAccountEconomicPaymentSponsorshipProofVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        validate_sha256_digest(
            "corroboration_snapshot_identity",
            &self.corroboration_snapshot_identity,
        )?;
        validate_sha256_digest(
            "sponsorship_release_profile_digest",
            &self.sponsorship_release_profile_digest,
        )?;

        let (proof_bundle_cbor, proof_bundle_value) =
            decode_exact_protocol_cbor(Path::new(&self.proof_bundle_cbor))?;
        if proof_bundle_cbor.len() > 128 << 10 {
            anyhow::bail!("sponsorship proof bundle exceeds the protocol byte bound");
        }
        let proof_bundle: SponsorshipFinalityProofBundleV1 =
            serde_json::from_value(proof_bundle_value.clone())
                .context("decode exact sponsorship corroboration proof bundle")?;
        let proof_bundle_digest =
            protocol_cbor_digest(SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN, &proof_bundle_cbor)?;

        let (payment_cbor, payment_value) =
            decode_exact_protocol_cbor(Path::new(&self.agreement_payment_request_cbor))?;
        let payment: SponsorshipAgreementPaymentRequestV3 =
            serde_json::from_value(payment_value.clone())
                .context("decode exact AgreementPaymentRequestV3")?;
        let payment_request_digest =
            protocol_cbor_digest(AGREEMENT_PAYMENT_REQUEST_DIGEST_DOMAIN, &payment_cbor)?;
        let payment_exact_request_digest = exact_protocol_action_request_digest(&payment_cbor)?;

        let (finality_profile_cbor, finality_profile_value) =
            decode_exact_protocol_cbor(Path::new(&self.finality_profile_cbor))?;
        let finality_profile: SponsorshipFinalityProfile =
            serde_json::from_value(finality_profile_value.clone())
                .context("decode exact selected sponsorship FinalityProfile")?;
        let finality_profile_cbor_digest = canonical_file_digest(&finality_profile_cbor);

        let (snapshot, loaded, threshold) = load_economic_payment_corroboration_snapshot(
            Path::new(&self.corroboration_snapshot),
            &self.sponsorship_release_profile_digest,
            &self.corroboration_snapshot_identity,
        )?;
        validate_sponsorship_finality_profile(&finality_profile, loaded.len())?;
        verify_economic_payment_corroboration_network(&loaded, &snapshot.network_domain).await?;

        let destination_bytes = base64::engine::general_purpose::STANDARD
            .decode(&payment.destination)
            .context("decode AgreementPaymentRequestV3 destination")?;
        if base64::engine::general_purpose::STANDARD.encode(&destination_bytes)
            != payment.destination
        {
            anyhow::bail!("AgreementPaymentRequestV3 destination is not canonical base64");
        }
        let destination_text = String::from_utf8(destination_bytes)
            .context("AgreementPaymentRequestV3 destination is not a UTF-8 TOS address")?;
        let destination = destination_text.parse::<MsgAddressInt>()?;
        let source = proof_bundle.provider_sponsor_source_account.parse::<MsgAddressInt>()?;
        let amount_atomic = payment
            .amount
            .amount_atomic
            .parse::<u64>()
            .context("AgreementPaymentRequestV3 amount does not fit native TOS")?;
        if amount_atomic.to_string() != payment.amount.amount_atomic {
            anyhow::bail!("AgreementPaymentRequestV3 amount is not canonical atomic notation");
        }
        let network_digest = relay_network_domain_digest(&snapshot.network_domain)?;
        let expected_commitment = AgentAccountContract::build_sponsorship_payment_commitment(
            &payment_request_digest,
            &payment.stable_action_id,
        )?;
        let expected_commitment_cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(expected_commitment.hash(0)));
        validate_sha256_digest(
            "provider_corroboration_snapshot_identity",
            &proof_bundle.corroboration_snapshot_identity,
        )?;
        let payment_from_bundle = serde_json::to_value(&proof_bundle.agreement_payment_request)?;
        let profile_from_bundle = serde_json::to_value(&proof_bundle.finality_profile)?;
        if proof_bundle.schema
            != "tosctl.agent-account.agreement-payment-sponsorship-proof-bundle.v1"
            || payment_from_bundle != payment_value
            || profile_from_bundle != finality_profile_value
            || proof_bundle.agreement_payment_request_digest != payment_request_digest
            || proof_bundle.sponsorship_stable_action_id != payment.stable_action_id
            || proof_bundle.sponsorship_exact_request_digest != payment_exact_request_digest
            || proof_bundle.provider_sponsor_valid_until_unix != payment.expires_at_unix
            || proof_bundle.destination_source_account != destination_text
            || proof_bundle.network_domain != snapshot.network_domain
            || proof_bundle.network_digest != network_digest
            || proof_bundle.finality_profile_cbor_digest != finality_profile_cbor_digest
            || proof_bundle.sponsorship_payment_commitment_cell_hash
                != expected_commitment_cell_hash
            || proof_bundle.sponsorship_release_profile_uri != snapshot.evidence_profile_uri
            || proof_bundle.sponsorship_release_profile_digest != snapshot.evidence_profile_digest
            || proof_bundle.sponsorship_release_profile != snapshot.evidence_profile
            || proof_bundle.confirmation_depth != 1
            || proof_bundle.terminal_evidence_class != "client_corroborated"
            || proof_bundle.validator_authenticated_portable_proof
            || payment.schema_version != 3
            || payment.settlement_adapter_uri != "tos.payment.direct.v1"
            || !payment.semantic_action_kind.is_empty()
            || !payment.adapter_profile_digest.is_empty()
            || !payment.external_system_id.is_empty()
            || payment.network_id != snapshot.network_domain.network_id
            || payment.network_domain_digest != network_digest
            || payment.amount.asset_namespace != "tos.native"
            || payment.amount.asset_identifier != snapshot.network_domain.network_id
            || payment.amount.unit != "nanotos"
            || amount_atomic == 0
        {
            anyhow::bail!(
                "sponsorship proof bundle conflicts with the client-owned payment, finality profile, or RPC snapshot"
            );
        }
        validate_sha256_digest("sponsorship_stable_action_id", &payment.stable_action_id)?;
        validate_sha256_digest(
            "signed_top_up_transaction_digest",
            &proof_bundle.signed_top_up_transaction_digest,
        )?;
        let signed_boc = base64::engine::general_purpose::STANDARD
            .decode(&proof_bundle.signed_top_up_transaction_boc)
            .context("decode exact signed top-up transaction BOC")?;
        if signed_boc.is_empty() || signed_boc.len() > 64 << 10 {
            anyhow::bail!("signed top-up transaction BOC has invalid size");
        }
        let valid_until = u32::try_from(payment.expires_at_unix)
            .context("AgreementPaymentRequestV3 expiry exceeds the TOS transaction field")?;
        let provider_sponsor_controller_authorization = validate_exact_sponsorship_top_up_boc(
            &signed_boc,
            &proof_bundle.signed_top_up_transaction_boc,
            &proof_bundle.signed_top_up_transaction_digest,
            &proof_bundle.signed_top_up_transaction_cell_hash,
            &source,
            snapshot.network_domain.global_id,
            proof_bundle.provider_sponsor_source_sequence,
            valid_until,
            &destination,
            amount_atomic,
            &payment_request_digest,
            &payment.stable_action_id,
        )?;
        // The exact successful chain effect is independently corroborated
        // below, but the portable verifier must not rely on RPC execution as
        // an implicit substitute for authenticating the signed bytes. Bind
        // them to the controller authority observed by the same frozen quorum.
        // A rotated epoch fails closed because V1 carries no historical key.
        verify_sponsorship_controller_authorization_quorum(
            &loaded,
            &snapshot.network_domain,
            &source,
            &provider_sponsor_controller_authorization,
            threshold,
            usize::from(finality_profile.minimum_operator_domains),
        )
        .await?;
        let provider_sponsor_controller_epoch =
            provider_sponsor_controller_authorization.controller_epoch;
        let signed_boc_digest = proof_bundle.signed_top_up_transaction_digest.clone();
        let signed_cell_hash = proof_bundle.signed_top_up_transaction_cell_hash.clone();

        if proof_bundle.observations.len() > loaded.len() || proof_bundle.observations.is_empty() {
            anyhow::bail!("proof bundle has an invalid observation count");
        }
        let allowed_members = loaded
            .iter()
            .map(|member| {
                (
                    member.display_origin.clone(),
                    member.locator_identity_digest.clone(),
                    member.operator_provenance.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let mut bundled_members = BTreeSet::new();
        for observation in &proof_bundle.observations {
            let member = (
                observation.endpoint.clone(),
                observation.locator_identity_digest.clone(),
                observation.operator_provenance.clone(),
            );
            if !allowed_members.contains(&member)
                || !bundled_members.insert(member)
                || observation.finality_proven
            {
                anyhow::bail!(
                    "proof bundle contains an unauthorized, duplicate, or overstated observation"
                );
            }
        }
        let mut bundled_votes: BTreeMap<String, Vec<&EconomicPaymentObservation>> = BTreeMap::new();
        for observation in &proof_bundle.observations {
            bundled_votes.entry(observation.quorum_key()).or_default().push(observation);
        }
        let bundled_winner = bundled_votes
            .values()
            .max_by_key(|group| group.len())
            .filter(|group| group.len() >= threshold)
            .context("proof bundle has no strict RPC quorum winner")?;
        let bundled_operators = bundled_winner
            .iter()
            .map(|observation| observation.operator_provenance.clone())
            .collect::<BTreeSet<_>>();
        if bundled_winner.len() < usize::from(finality_profile.minimum_observers)
            || bundled_operators.len() < usize::from(finality_profile.minimum_operator_domains)
            || proof_bundle.quorum
                != serde_json::json!({
                    "members": loaded.len(),
                    "threshold": threshold,
                    "agreeing": bundled_winner.len(),
                })
        {
            anyhow::bail!("proof bundle does not satisfy its client-selected quorum profile");
        }
        let mut bundled_observation_digests = bundled_winner
            .iter()
            .map(|observation| {
                economic_payment_observation_digest(
                    b"tosctl.agreement-payment-rpc-observation.v1\0",
                    *observation,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        bundled_observation_digests.sort();
        bundled_observation_digests.dedup();
        if bundled_observation_digests != proof_bundle.observation_digests
            || bundled_observation_digests.len() != bundled_winner.len()
        {
            anyhow::bail!("proof bundle observation digest set is not its exact quorum winner");
        }
        let bundled_evidence = bundled_winner[0];
        let bundled_checkpoint_id = format!(
            "masterchain:{}:{}:{}:{}:{}",
            bundled_evidence.observed_masterchain_workchain,
            bundled_evidence.observed_masterchain_shard,
            bundled_evidence.observed_masterchain_seqno,
            bundled_evidence.observed_masterchain_root_hash,
            bundled_evidence.observed_masterchain_file_hash,
        );
        if proof_bundle.finalized_checkpoint_id != bundled_checkpoint_id
            || proof_bundle.finalized_checkpoint_sequence
                != bundled_evidence.observed_masterchain_seqno
            || proof_bundle.finalized_checkpoint_unix
                != bundled_evidence.observed_masterchain_gen_utime
        {
            anyhow::bail!("proof bundle checkpoint conflicts with its exact quorum winner");
        }
        if !sponsorship_checkpoint_is_mature(
            bundled_evidence,
            &finality_profile,
            time_format::now(),
        )? {
            anyhow::bail!("proof bundle checkpoint never satisfied the selected reorg window");
        }

        let mut observations = Vec::with_capacity(loaded.len());
        let mut failures = Vec::new();
        for member in &loaded {
            match corroborate_economic_payment_expected(
                &member.config,
                member.display_origin.clone(),
                member.locator_identity_digest.clone(),
                member.operator_provenance.clone(),
                &snapshot.network_domain,
                &source,
                &signed_cell_hash,
                &destination,
                amount_atomic,
                snapshot.maximum_history_transactions,
            )
            .await
            {
                Ok(observation) => observations.push(observation),
                Err(error) => failures.push(rpc_failure_diagnostic(&member.endpoint, &error)),
            }
        }
        observations.sort_by(|left, right| {
            left.operator_provenance
                .cmp(&right.operator_provenance)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        failures.sort();
        let mut votes: BTreeMap<String, Vec<&EconomicPaymentObservation>> = BTreeMap::new();
        for observation in &observations {
            votes.entry(observation.quorum_key()).or_default().push(observation);
        }
        let winner =
            votes.values().max_by_key(|group| group.len()).filter(|group| group.len() >= threshold);
        let Some(winner) = winner else {
            if observations.is_empty()
                && !failures.is_empty()
                && failures.iter().all(|failure| sponsorship_rpc_not_found(failure))
            {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA,
                        "state": "unknown",
                        "category": "not_found",
                        "reason": "exact sponsorship transaction is not visible in the client-owned bounded RPC history",
                        "proof_bundle_digest": proof_bundle_digest,
                        "agreement_payment_request_digest": payment_request_digest,
                        "sponsorship_stable_action_id": payment.stable_action_id,
                        "sponsorship_exact_request_digest": payment_exact_request_digest,
                        "chain_side_effect": false,
                        "custody_side_effect": false,
                    })
                );
                return Ok(());
            }
            if votes.len() <= 1
                && observations.len() < threshold
                && failures.iter().any(|failure| sponsorship_rpc_temporarily_unavailable(failure))
                && failures.iter().all(|failure| {
                    sponsorship_rpc_not_found(failure)
                        || sponsorship_rpc_temporarily_unavailable(failure)
                })
            {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA,
                        "state": "unknown",
                        "category": "temporarily_unavailable",
                        "reason": "the client-owned RPC quorum is temporarily insufficient for exact verification",
                        "proof_bundle_digest": proof_bundle_digest,
                        "agreement_payment_request_digest": payment_request_digest,
                        "sponsorship_stable_action_id": payment.stable_action_id,
                        "sponsorship_exact_request_digest": payment_exact_request_digest,
                        "chain_side_effect": false,
                        "custody_side_effect": false,
                    })
                );
                return Ok(());
            }
            anyhow::bail!(
                "client RPC snapshot found no strict quorum for the exact sponsorship transaction; observation_count={}; failures={}",
                observations.len(),
                serde_json::to_string(&failures).unwrap_or_else(|_| "[]".to_owned())
            );
        };
        let fresh_operators = winner
            .iter()
            .map(|observation| observation.operator_provenance.clone())
            .collect::<BTreeSet<_>>();
        if winner.len() < usize::from(finality_profile.minimum_observers)
            || fresh_operators.len() < usize::from(finality_profile.minimum_operator_domains)
        {
            anyhow::bail!("fresh client observations do not satisfy the selected profile");
        }
        let evidence = (*winner[0]).clone();
        if sponsorship_chain_effect_key(&evidence) != sponsorship_chain_effect_key(bundled_evidence)
        {
            anyhow::bail!(
                "fresh client observations do not reproduce the proof bundle's exact chain effect"
            );
        }
        let verified_at_unix = time_format::now();
        if !sponsorship_checkpoint_is_mature(&evidence, &finality_profile, verified_at_unix)? {
            println!(
                "{}",
                serde_json::json!({
                    "schema": ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA,
                    "state": "unknown",
                    "category": "not_mature",
                    "reason": "client quorum checkpoint has not crossed the selected chain-time reorg window",
                    "proof_bundle_digest": proof_bundle_digest,
                    "agreement_payment_request_digest": payment_request_digest,
                    "sponsorship_stable_action_id": payment.stable_action_id,
                    "sponsorship_exact_request_digest": payment_exact_request_digest,
                    "chain_side_effect": false,
                    "custody_side_effect": false,
                })
            );
            return Ok(());
        }
        let mut observation_digests = winner
            .iter()
            .map(|observation| {
                economic_payment_observation_digest(
                    b"tosctl.agreement-payment-rpc-observation.v1\0",
                    *observation,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        observation_digests.sort();
        observation_digests.dedup();
        if observation_digests.len() != winner.len() {
            anyhow::bail!("fresh client observations repeat an observation digest");
        }
        println!(
            "{}",
            serde_json::json!({
                "schema": ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA,
                "proof_bundle_digest_algorithm": "TOS-PROTOCOL-CBOR/rfc8949-core-deterministic",
                "proof_bundle_digest_domain": SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN,
                "proof_bundle_digest": proof_bundle_digest,
                "agreement_payment_request_digest": payment_request_digest,
                "sponsorship_stable_action_id": payment.stable_action_id,
                "sponsorship_exact_request_digest": payment_exact_request_digest,
                "network_digest": network_digest,
                "finality_profile_digest": finality_profile.profile_digest,
                "finality_profile_cbor_digest": finality_profile_cbor_digest,
                "sponsorship_release_profile_uri": snapshot.evidence_profile_uri,
                "sponsorship_release_profile_digest": snapshot.evidence_profile_digest,
                "provider_snapshot_identity": proof_bundle.corroboration_snapshot_identity,
                "client_snapshot_identity": snapshot.snapshot_identity,
                "provider_sponsor_source_account": source.to_string(),
                "provider_sponsor_controller_epoch": provider_sponsor_controller_epoch,
                "provider_sponsor_source_sequence": proof_bundle.provider_sponsor_source_sequence,
                "provider_sponsor_valid_until_unix": proof_bundle.provider_sponsor_valid_until_unix,
                "signed_top_up_transaction_digest": signed_boc_digest,
                "signed_top_up_transaction_cell_hash": signed_cell_hash,
                "sponsorship_payment_commitment_cell_hash": expected_commitment_cell_hash,
                "destination_source_account": destination.to_string(),
                "amount_atomic": amount_atomic.to_string(),
                "confirmation_depth": 1,
                "terminal_evidence_class": "client_corroborated",
                "operator_provenance": fresh_operators,
                "quorum": {"members": loaded.len(), "threshold": threshold, "agreeing": winner.len()},
                "observation_digests": observation_digests,
                "evidence": evidence,
                "observations": observations,
                "failures": failures,
                "verified_at_unix": verified_at_unix,
                "state": "corroborated_terminal_verified",
                "assurance_scope": "client-owned-rpc-corroborated-terminal-verification",
                "validator_authenticated_portable_proof": false,
                "chain_side_effect": false,
                "custody_side_effect": false,
            })
        );
        Ok(())
    }
}

impl AgentAccountCancelPrepareCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        validate_sha256_digest("owner_authorization_digest", &self.owner_authorization_digest)?;
        let now = time_format::now() as u32;
        if self.valid_until <= now {
            anyhow::bail!("valid_until must be a future Unix timestamp");
        }
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        if u128::from(self.valid_until)
            > u128::from(now) + u128::from(data.default_task_timeout_secs)
        {
            anyhow::bail!("valid_until exceeds the Agent Account default_task_timeout");
        }
        let journal = open_controller_journal(path)?;
        let global_id = match rpc_client.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let deployment_id = hex::encode(data.deployment_id);
        journal.reconcile_finalized_state(
            &account.to_string(),
            global_id,
            &deployment_id,
            data.controller_epoch,
            data.seqno,
            time_format::now(),
        )?;
        let record = journal
            .find_primary(
                &account.to_string(),
                global_id,
                &deployment_id,
                data.controller_epoch,
                &self.action_id,
            )?
            .context("primary controller action not found")?;
        if record.status == ControllerActionStatus::Resolved || record.claim.seqno != data.seqno {
            anyhow::bail!("primary action is no longer cancellable at the finalized sequence");
        }
        if global_id != record.claim.network_global_id {
            anyhow::bail!("primary action network no longer matches the connected chain");
        }
        if !self.yes
            && !confirm(&format!(
                "Authorize cancellation of action {} on {} at seqno {}?",
                self.action_id, account, data.seqno
            ))?
        {
            anyhow::bail!("owner declined cancellation authorization");
        }
        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .context("controller secret has no public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        if controller_pubkey != data.controller_pubkey {
            anyhow::bail!("configured controller key does not match the Agent Account");
        }
        let cancellation_identity = {
            let mut digest = Sha256::new();
            digest.update(b"tos.agent-account.cancel-authorization.v1\0");
            digest.update(self.action_id.as_bytes());
            digest.update(self.owner_authorization_digest.as_bytes());
            digest.update(self.valid_until.to_be_bytes());
            format!("sha256:{}", hex::encode(digest.finalize()))
        };
        let boc = if let Some(encoded) = record.cancellation_boc_base64 {
            if record.cancellation_identity.as_deref() != Some(&cancellation_identity) {
                anyhow::bail!("changed cancellation conflicts with custody journal");
            }
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let payload = AgentAccountContract::build_cancel_seqno_payload(
                global_id,
                data.controller_epoch,
                data.seqno,
                self.valid_until,
            )?;
            let hash =
                AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
            let signature: [u8; 64] = keypair
                .sign(&hash)
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            journal.authorize_cancellation(
                &record.claim,
                &cancellation_identity,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                time_format::now(),
            )?;
            boc
        };
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.prepared-action.v1",
                "action_id": self.action_id,
                "action": "agent-cancel-seqno",
                "account": account.to_string(),
                "deployment_id": format!("sha256:{}", hex::encode(data.deployment_id)),
                "controller_epoch": data.controller_epoch,
                "seqno": data.seqno,
                "network_global_id": global_id,
                "valid_until": self.valid_until,
                "exact_signed_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
                "exact_signed_boc_digest": format!("sha256:{}", hex::encode(Sha256::digest(&boc))),
            })
        );
        Ok(())
    }
}

fn validate_controller_action_id(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("action_id must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_sha256_digest(name: &str, value: &str) -> anyhow::Result<()> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..].bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("{} must be a canonical sha256 digest", name);
    }
    Ok(())
}

fn open_controller_journal(config_path: &Path) -> anyhow::Result<AgentAccountCustodyJournal> {
    require_owner_private_agent_storage()?;
    let absolute =
        fs::canonicalize(config_path).context("resolve tosctl config path for custody journal")?;
    let directory = absolute
        .parent()
        .context("tosctl config path has no parent")?
        .join(".tosctl-agent-controller-journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => anyhow::bail!("Agent Account custody journal path is not a real directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&directory)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    AgentAccountCustodyJournal::open(directory)
}

fn open_economic_controller_journal(
    _config_path: &Path,
    explicit_directory: Option<&str>,
    pinned_directory: Option<&str>,
) -> anyhow::Result<AgentAccountCustodyJournal> {
    let pinned = pinned_directory
        .context("runtime has no owner-pinned economic_custody_journal_directory")?;
    let pinned = canonical_private_journal_directory(pinned)?;
    if let Some(explicit) = explicit_directory {
        let explicit = canonical_private_journal_directory(explicit)?;
        if explicit != pinned {
            anyhow::bail!("economic effect journal differs from owner-pinned runtime binding");
        }
    }
    AgentAccountCustodyJournal::open(pinned)
}

fn canonical_private_journal_directory(value: &str) -> anyhow::Result<PathBuf> {
    require_owner_private_agent_storage()?;
    let directory = Path::new(value);
    if !directory.is_absolute() {
        anyhow::bail!("economic effect journal directory must be absolute");
    }
    let metadata =
        fs::symlink_metadata(directory).context("inspect economic effect journal directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("economic effect journal path is not a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("economic effect journal directory must be owner-private");
        }
    }
    let canonical = fs::canonicalize(directory)?;
    if !canonical.is_absolute() {
        anyhow::bail!("economic effect journal canonical path is not absolute");
    }
    Ok(canonical)
}

async fn run_agent_account_owner_action(
    config_path: &str,
    wallet_name: &str,
    amount: f64,
    yes: bool,
    format: OutputFormat,
    action: &'static str,
    build_body: impl FnOnce(u64, &AgentAccountInit) -> anyhow::Result<Cell>,
    matches: impl Fn(&AgentAccountData, &AgentAccountInit) -> bool,
) -> anyhow::Result<()> {
    validate_tos_amount("amount", amount)?;
    if amount == 0.0 {
        anyhow::bail!("amount must be greater than zero");
    }

    let path = Path::new(config_path);
    let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
    let agent_wallet = config
        .agent_wallets
        .get(wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", wallet_name))?;
    let address = agent_wallet
        .agent_account_address
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Agent wallet '{}' has no deployed Agent Account address; deploy it first",
                wallet_name
            )
        })?
        .parse::<MsgAddressInt>()
        .context("Invalid persisted Agent Account address")?;
    let (init, _) = build_agent_account_init(wallet_name, agent_wallet, vault.clone()).await?;

    let account_info = rpc_client.get_address_information(&address).await?;
    if account_info.state != AccountState::Active {
        anyhow::bail!(
            "Agent Account '{}' ({}) is not active (state: {})",
            wallet_name,
            address,
            account_info.state
        );
    }
    let deployed_code = account_info
        .code
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Agent Account '{}' has no deployed code", wallet_name))?;
    let deployed_code_hash = read_single_root_boc(deployed_code)?.hash(0);
    if deployed_code_hash != AgentAccountContract::code()?.hash(0) {
        anyhow::bail!("Agent Account '{}' code does not match the supported template", wallet_name);
    }

    let provider = contracts::contract_provider!(rpc_client.clone());
    let current = AgentAccountContract::get_data(provider.as_ref(), &address).await?;
    let (owner_address, owner_info, owner_secret) =
        wallet_info(rpc_client.clone(), &agent_wallet.wallet, vault).await?;
    if owner_address != current.owner || owner_address != init.owner {
        anyhow::bail!("Agent Wallet '{}' is not the deployed Agent Account owner", wallet_name);
    }
    if owner_info.account_state != AccountState::Active {
        anyhow::bail!(
            "Agent Wallet '{}' ({}) is not active (state: {})",
            wallet_name,
            owner_address,
            owner_info.account_state
        );
    }

    let amount_nanotos = tos_to_nanotos(amount);
    if !(1..=owner_info.balance.saturating_sub(AGENT_ACCOUNT_ACTION_GAS)).contains(&amount_nanotos)
    {
        anyhow::bail!(
            "Wrong amount value {} TOS. Agent Wallet balance is {} TOS",
            amount,
            display_tos(owner_info.balance)
        );
    }
    let query_id = (time_format::now() << 32) | u64::from(owner_info.seqno.unwrap_or_default());
    let body = build_body(query_id, &init)?;

    if format != OutputFormat::Json {
        println!(
            "\n{}\n  Profile:  {}\n  Owner:    {}\n  Account:  {}\n  Amount:   {:.9} TOS\n  Query ID: {}\n",
            format!("Agent Account {} summary:", action).cyan().bold(),
            wallet_name,
            owner_address,
            address,
            amount,
            query_id,
        );
    }
    if !yes && !confirm(&format!("Confirm Agent Account {}?", action))? {
        println!("{}", "Agent Account action cancelled".yellow());
        return Ok(());
    }

    let wallet = make_wallet(rpc_client.clone(), &agent_wallet.wallet, owner_secret, wallet_name)
        .await
        .context("create Agent Account owner wallet")?;
    send_wallet_message(
        &wallet,
        rpc_client.clone(),
        address.clone(),
        amount_nanotos,
        body,
        true,
        owner_info.seqno,
        &owner_address,
    )
    .await?;
    wait_for_agent_account_match(rpc_client, &address, &init, matches).await?;

    let result = AgentAccountActionView {
        wallet: wallet_name.to_string(),
        address: address.to_string(),
        owner: owner_address.to_string(),
        action: action.to_string(),
        query_id,
        amount: display_tos(amount_nanotos),
        status: "applied".to_string(),
    };
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{} Agent Account {} applied at {}", "OK".green().bold(), action, address);
    }
    Ok(())
}

pub(crate) async fn send_wallet_message(
    wallet: &dyn Wallet,
    rpc_client: std::sync::Arc<chain_rpc_client::v2::client_json_rpc::ClientJsonRpc>,
    destination: MsgAddressInt,
    amount: u64,
    body: Cell,
    bounce: bool,
    seqno: Option<u32>,
    owner_address: &MsgAddressInt,
) -> anyhow::Result<()> {
    let msg = wallet.build_message(destination, amount, body, bounce, seqno, None, None).await?;
    rpc_client.send_boc(&write_boc(&msg)?).await?;
    wait_for_seqno_change(
        rpc_client,
        owner_address,
        seqno,
        &common::task_cancellation::CancellationCtx::default(),
        SEND_TIMEOUT,
    )
    .await
}

/// Build and sign a wallet message without broadcasting it. Returns the
/// serialized external-message BOC, suitable for
/// `wallet broadcast-prepared --message-boc <base64>`.
pub(crate) async fn build_wallet_message_boc(
    wallet: &dyn Wallet,
    destination: MsgAddressInt,
    amount: u64,
    body: Cell,
    bounce: bool,
    seqno: Option<u32>,
) -> anyhow::Result<Vec<u8>> {
    let msg = wallet.build_message(destination, amount, body, bounce, seqno, None, None).await?;
    Ok(write_boc(&msg)?)
}

pub(crate) async fn send_wallet_message_with_state_init(
    wallet: &dyn Wallet,
    rpc_client: std::sync::Arc<chain_rpc_client::v2::client_json_rpc::ClientJsonRpc>,
    destination: MsgAddressInt,
    amount: u64,
    body: Cell,
    seqno: Option<u32>,
    owner_address: &MsgAddressInt,
    state_init: chain_block::StateInit,
) -> anyhow::Result<()> {
    let msg = wallet
        .build_message(destination, amount, body, false, seqno, None, Some(state_init))
        .await?;
    rpc_client.send_boc(&write_boc(&msg)?).await?;
    wait_for_seqno_change(
        rpc_client,
        owner_address,
        seqno,
        &common::task_cancellation::CancellationCtx::default(),
        SEND_TIMEOUT,
    )
    .await
}

async fn wait_for_agent_account_match(
    rpc_client: std::sync::Arc<chain_rpc_client::v2::client_json_rpc::ClientJsonRpc>,
    address: &MsgAddressInt,
    expected: &AgentAccountInit,
    matches: impl Fn(&AgentAccountData, &AgentAccountInit) -> bool,
) -> anyhow::Result<()> {
    let provider = contracts::contract_provider!(rpc_client);
    tokio::time::timeout(SEND_TIMEOUT, async {
        loop {
            let data = AgentAccountContract::get_data(provider.as_ref(), address).await?;
            if matches(&data, expected) {
                return Ok(());
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timeout waiting for Agent Account state update"))?
}

async fn load_agent_account_chain_view(
    rpc_client: std::sync::Arc<chain_rpc_client::v2::client_json_rpc::ClientJsonRpc>,
    address: &MsgAddressInt,
    wallet: Option<String>,
    expected: Option<&AgentAccountInit>,
) -> anyhow::Result<AgentAccountChainView> {
    let info = rpc_client.get_address_information(address).await?;
    let active = info.state == AccountState::Active;
    let code_hash = info
        .code
        .as_ref()
        .map(|code| read_single_root_boc(code).map(|cell| hex::encode(cell.hash(0))))
        .transpose()?;
    let expected_code_hash = hex::encode(AgentAccountContract::code()?.hash(0));
    let template_matches = code_hash.as_ref().map(|hash| hash == &expected_code_hash);

    let data = if active {
        let provider = contracts::contract_provider!(rpc_client);
        Some(AgentAccountContract::get_data(provider.as_ref(), address).await?)
    } else {
        None
    };
    let matches_profile = expected.map(|expected| {
        template_matches == Some(true)
            && data.as_ref().is_some_and(|data| agent_account_data_matches(data, expected))
    });

    Ok(AgentAccountChainView {
        wallet,
        address: address.to_string(),
        state: info.state.to_string(),
        balance: display_tos(info.balance),
        code_hash,
        template_matches,
        owner: data.as_ref().map(|data| data.owner.to_string()),
        controller_pubkey: data.as_ref().map(|data| hex::encode(data.controller_pubkey)),
        deployment_id: data.as_ref().map(|data| hex::encode(data.deployment_id)),
        controller_epoch: data.as_ref().map(|data| data.controller_epoch),
        seqno: data.as_ref().map(|data| data.seqno),
        max_per_tx: data.as_ref().map(|data| data.max_per_tx),
        daily_limit: data.as_ref().map(|data| data.daily_limit),
        spend_day: data.as_ref().map(|data| data.spend_day),
        spent_today: data.as_ref().map(|data| data.spent_today),
        default_task_timeout_secs: data.as_ref().map(|data| data.default_task_timeout_secs),
        metadata_hash: data.as_ref().and_then(|data| data.metadata_hash.map(hex::encode)),
        service_endpoint_hash: data
            .as_ref()
            .and_then(|data| data.service_endpoint_hash.map(hex::encode)),
        matches_profile,
    })
}

fn agent_account_data_matches(data: &AgentAccountData, expected: &AgentAccountInit) -> bool {
    data.owner == expected.owner
        && data.controller_pubkey == expected.controller_pubkey
        && data.deployment_id == expected.deployment_id
        && data.max_per_tx == expected.max_per_tx
        && data.daily_limit == expected.daily_limit
        && data.default_task_timeout_secs == expected.default_task_timeout_secs
        && data.metadata_hash == expected.metadata_hash
        && data.service_endpoint_hash == expected.service_endpoint_hash
}

fn print_agent_account_chain_view(
    view: &AgentAccountChainView,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(view)?);
        return Ok(());
    }

    println!("{}", "Agent Account Chain State".bold());
    if let Some(wallet) = &view.wallet {
        println!("  Wallet profile:       {}", wallet);
    }
    println!("  Address:              {}", view.address);
    println!("  State:                {}", view.state);
    println!("  Balance:              {} TOS", view.balance);
    if let Some(code_hash) = &view.code_hash {
        println!("  Code hash:            {}", code_hash);
    }
    if let Some(matches) = view.template_matches {
        println!("  Template matches:     {}", matches);
    }
    if let Some(owner) = &view.owner {
        println!("  Owner:                {}", owner);
    }
    if let Some(controller) = &view.controller_pubkey {
        println!("  Controller pubkey:    {}", controller);
    }
    if let Some(deployment_id) = &view.deployment_id {
        println!("  Deployment ID:        {}", deployment_id);
    }
    if let Some(seqno) = view.seqno {
        println!("  Controller seqno:     {}", seqno);
    }
    if let Some(max_per_tx) = view.max_per_tx {
        println!("  Max per action:       {} TOS", display_tos(max_per_tx));
    }
    if let Some(daily_limit) = view.daily_limit {
        println!("  Daily limit:          {} TOS", display_tos(daily_limit));
    }
    if let Some(spent_today) = view.spent_today {
        println!("  Spent today:          {} TOS", display_tos(spent_today));
    }
    if let Some(spend_day) = view.spend_day {
        println!("  Spend day (UTC):      {}", spend_day);
    }
    if let Some(timeout) = view.default_task_timeout_secs {
        println!("  Default task timeout: {}s", timeout);
    }
    if let Some(metadata_hash) = &view.metadata_hash {
        println!("  Metadata hash:        {}", metadata_hash);
    }
    if let Some(endpoint_hash) = &view.service_endpoint_hash {
        println!("  Endpoint hash:        {}", endpoint_hash);
    }
    if let Some(matches) = view.matches_profile {
        println!("  Profile matches:      {}", matches);
    }
    Ok(())
}

impl AgentAccountShowTemplateCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let code = AgentAccountContract::code()?;
        let code_boc = base64::engine::general_purpose::STANDARD.encode(write_boc(&code)?);
        let view = AgentAccountTemplateView {
            contract: "agent-account",
            source: "crypto/smartcont/agent-account-code.fc",
            tlb: "crypto/smartcont/agent-account.tlb",
            update_policy_opcode: "0x41475001".to_string(),
            rotate_controller_opcode: "0x41475002".to_string(),
            task_send_opcode: "0x41475003".to_string(),
            native_send_opcode: "0x41475004".to_string(),
            cancel_seqno_opcode: "0x41475005".to_string(),
            get_methods: vec![
                "get_agent_account_data",
                "get_owner",
                "get_controller_pubkey",
                "get_agent_policy",
            ],
            code_hash: hex::encode(code.hash(0)),
            code_boc,
        };

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{}", "Agent Account Template".bold());
        println!("  Contract:                 {}", view.contract);
        println!("  Source:                   {}", view.source);
        println!("  TLB:                      {}", view.tlb);
        println!("  Update policy opcode:     {}", view.update_policy_opcode);
        println!("  Rotate controller opcode: {}", view.rotate_controller_opcode);
        println!("  Task send opcode:         {}", view.task_send_opcode);
        println!("  Native send opcode:       {}", view.native_send_opcode);
        println!("  Cancel seqno opcode:      {}", view.cancel_seqno_opcode);
        println!("  Get methods:              {}", view.get_methods.join(", "));
        println!("  Code hash:                {}", view.code_hash);
        Ok(())
    }
}

impl AgentWalletCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AgentWalletAction::Create(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Ls(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Show(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Policy(cmd) => cmd.run(config_path).await,
            AgentWalletAction::UpdatePolicy(cmd) => cmd.run(config_path).await,
            AgentWalletAction::BindRuntime(cmd) => cmd.run(config_path).await,
            AgentWalletAction::RotateController(cmd) => cmd.run(config_path).await,
            AgentWalletAction::ExportRuntime(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Fund(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Status(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Activate(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Rm(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Send(cmd) => cmd.run(config_path).await,
        }
    }
}

impl AgentWalletCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("Agent wallet name cannot be empty");
        }
        validate_tos_amount("max-per-tx", self.max_per_tx)?;
        validate_tos_amount("daily-limit", self.daily_limit)?;
        if self.daily_limit < self.max_per_tx {
            anyhow::bail!("daily-limit must be greater than or equal to max-per-tx");
        }
        if let Some(value) = self.approval_above {
            validate_tos_amount("approval-above", value)?;
        }

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;

        if config.agent_wallets.contains_key(&self.name) {
            anyhow::bail!("Agent wallet '{}' already exists in config", self.name);
        }

        let version = WalletVersion::from_str(&self.version).map_err(|_| {
            anyhow::anyhow!(
                "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                self.version
            )
        })?;

        let owner_secret_name = format!("agent-wallet-{}-owner", self.name);
        let controller_secret_name = format!("agent-wallet-{}-controller", self.name);
        let owner_secret_id = owner_secret_name.as_str().into();
        let controller_secret_id = controller_secret_name.as_str().into();
        let spec = SecretSpec::new(Algorithm::Ed25519).extractable(false);

        vault.generate_secret(&spec, &owner_secret_id).await?;
        vault.generate_secret(&spec, &controller_secret_id).await?;
        vault.flush().await?;

        let wallet = WalletConfig {
            key: KeyConfig::VaultKey { name: owner_secret_name.clone() },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        let policy = AgentWalletPolicy {
            max_per_tx: tos_to_nanotos(self.max_per_tx),
            daily_limit: tos_to_nanotos(self.daily_limit),
            allowed_service_actors: self.allowed_service_actors.clone(),
            allowed_task_categories: self.allowed_task_categories.clone(),
            require_owner_approval_above: self.approval_above.map(tos_to_nanotos),
            default_task_timeout_secs: self.default_task_timeout_secs,
        };

        let agent_wallet = AgentWalletConfig {
            wallet: wallet.clone(),
            agent_account_address: None,
            agent_account_deployment_id: None,
            controller_key: KeyConfig::VaultKey { name: controller_secret_name.clone() },
            policy,
            metadata_hash: self.metadata_hash.clone(),
            service_endpoint_hash: self.service_endpoint_hash.clone(),
            capabilities: self.capabilities.clone(),
            runtime: None,
            created_at: Some(time_format::now()),
        };

        config.agent_wallets.insert(self.name.clone(), agent_wallet.clone());
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault.clone()))
            .await
            .context("build agent wallet view")?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        print_view(&view, self.format.clone())?;
        println!("\n{} Agent wallet '{}' created", "OK".green().bold(), self.name);
        println!("  Owner key:      {} (in vault)", owner_secret_name);
        println!("  Controller key: {} (in vault)", controller_secret_name);
        println!(
            "  Next step:      fund the address, then bind an agent runtime to the controller key"
        );
        Ok(())
    }
}

impl AgentWalletBindRuntimeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_non_empty("runner-id", &self.runner_id)?;
        validate_non_empty("endpoint", &self.endpoint)?;
        if let Some(authority_id) = &self.economic_authority_id {
            validate_non_empty("economic-authority-id", authority_id)?;
        }
        if let Some(key) = &self.economic_authority_public_key {
            if key.len() != 64
                || !key.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                anyhow::bail!("economic-authority-public-key must be 32 lowercase-hex bytes");
            }
        }
        let economic_custody_journal_directory = self
            .economic_custody_journal_directory
            .as_deref()
            .map(canonical_private_journal_directory)
            .transpose()?
            .map(|value| value.to_string_lossy().into_owned());

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        agent_wallet.runtime = Some(AgentRuntimeBinding {
            runner_id: self.runner_id.clone(),
            endpoint: self.endpoint.clone(),
            attestation_hash: self.attestation_hash.clone(),
            economic_authority_id: self.economic_authority_id.clone(),
            economic_authority_public_key_hex: self.economic_authority_public_key.clone(),
            economic_custody_journal_directory,
            bound_at: Some(time_format::now()),
        });
        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{} Runtime bound for '{}'", "OK".green().bold(), self.name);
        print_view(&view, self.format.clone())
    }
}

impl AgentWalletRotateControllerCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;

        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        let new_key_name = match &self.key_name {
            Some(name) => {
                validate_non_empty("key-name", name)?;
                name.clone()
            }
            None => format!("agent-wallet-{}-controller-{}", self.name, time_format::now()),
        };
        let secret_id = new_key_name.as_str().into();
        let spec = SecretSpec::new(Algorithm::Ed25519).extractable(false);

        vault.generate_secret(&spec, &secret_id).await?;
        vault.flush().await?;

        agent_wallet.controller_key = KeyConfig::VaultKey { name: new_key_name.clone() };
        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{} Controller key rotated for '{}'", "OK".green().bold(), self.name);
        println!("  New controller key: {} (in vault)", new_key_name);
        Ok(())
    }
}

impl AgentWalletExportRuntimeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        let manifest = AgentRuntimeManifest {
            name: view.name,
            address: view.address,
            agent_account_address: view.agent_account_address,
            agent_account_deployment_id: view.agent_account_deployment_id,
            controller_key: view.controller_key,
            policy: view.policy,
            metadata_hash: view.metadata_hash,
            service_endpoint_hash: view.service_endpoint_hash,
            capabilities: view.capabilities,
            runtime: view.runtime,
        };
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        Ok(())
    }
}

impl AgentWalletFundCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        if self.amount == 0.0 {
            anyhow::bail!("amount must be greater than zero");
        }

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault.clone())).await?;
        let dest_addr = view
            .address
            .parse::<MsgAddressInt>()
            .context("Invalid Agent Wallet destination address")?;

        let from_wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (from_wallet_address, from_wallet_info, from_secret) =
            wallet_info(rpc_client.clone(), from_wallet_cfg, vault).await?;

        let amount_nanotos = tos_to_nanotos(self.amount);
        if !(1..=from_wallet_info.balance.saturating_sub(AGENT_WALLET_FUND_GAS))
            .contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                self.amount,
                display_tos(from_wallet_info.balance)
            );
        }
        if from_wallet_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }
        if from_wallet_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        println!(
            "\n{}\n  Agent:   {}\n  From:    {} ({})\n  To:      {}\n  Amount:  {:.9} TOS{}\n",
            "Agent Wallet funding summary:".cyan().bold(),
            self.name,
            self.from,
            from_wallet_address,
            dest_addr,
            self.amount,
            if let Some(msg) = &self.message {
                format!("\n  Comment: {}", msg)
            } else {
                String::new()
            },
        );

        if !self.yes && !confirm("Confirm funding transfer?")? {
            println!("{}", "Funding transfer cancelled".yellow());
            return Ok(());
        }

        let wallet = make_wallet(rpc_client.clone(), from_wallet_cfg, from_secret, &self.from)
            .await
            .context("create funding wallet")?;
        let body =
            if let Some(msg) = &self.message { build_comment_cell(msg)? } else { Cell::default() };
        let msg =
            wallet.build_message(dest_addr, amount_nanotos, body, false, None, None, None).await?;
        let msg_boc = write_boc(&msg)?;
        rpc_client.send_boc(&msg_boc).await?;
        wait_for_seqno_change(
            rpc_client.clone(),
            &from_wallet_address,
            from_wallet_info.seqno,
            &common::task_cancellation::CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await?;

        let result = AgentWalletFundView {
            agent_wallet: self.name.clone(),
            from: self.from.clone(),
            from_address: from_wallet_address.to_string(),
            to_address: view.address,
            amount: display_tos(amount_nanotos),
            message: self.message.clone(),
            status: "sent".to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

impl AgentWalletSendCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        // Signs with the Agent Wallet's owner key only. This is a direct,
        // owner-authorized transfer from the underlying wallet -- it does
        // not go through the Agent Account controller path, and is
        // therefore not constrained by the controller's max-per-tx or
        // daily-limit policy. Automated agent spending must continue
        // through `tosctl agent account task-send` or
        // `tosctl agent task send --via-agent-account`.
        let wallet_cfg = &agent_wallet.wallet;
        let (from_address, from_info, from_secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault).await?;

        let dest_addr = self.to.parse::<MsgAddressInt>().context("Invalid destination address")?;

        let amount_nanotos = tos_to_nanotos(self.amount);
        if !(1..=from_info.balance.saturating_sub(AGENT_WALLET_FUND_GAS)).contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Agent Wallet balance is {} TOS",
                self.amount,
                display_tos(from_info.balance)
            );
        }
        if from_info.account_state == AccountState::Frozen {
            anyhow::bail!("Agent wallet '{}' is frozen", self.name);
        }
        if from_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("Agent wallet '{}' is uninitialized", self.name);
        }

        println!(
            "\n{}\n  Agent:   {}\n  From:    {}\n  To:      {}\n  Amount:  {:.9} TOS{}\n",
            "Agent Wallet owner transfer summary:".cyan().bold(),
            self.name,
            from_address,
            dest_addr,
            self.amount,
            if let Some(msg) = &self.message {
                format!("\n  Comment: {}", msg)
            } else {
                String::new()
            },
        );

        if !self.yes && !confirm("Confirm owner transfer?")? {
            println!("{}", "Transfer cancelled".yellow());
            return Ok(());
        }

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, from_secret, &self.name)
            .await
            .context("create agent wallet signer")?;
        let body =
            if let Some(msg) = &self.message { build_comment_cell(msg)? } else { Cell::default() };
        let msg = wallet
            .build_message(dest_addr.clone(), amount_nanotos, body, false, None, None, None)
            .await?;
        let msg_boc = write_boc(&msg)?;
        rpc_client.send_boc(&msg_boc).await?;
        wait_for_seqno_change(
            rpc_client.clone(),
            &from_address,
            from_info.seqno,
            &common::task_cancellation::CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await?;

        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "agent_wallet": self.name,
                "from_address": from_address.to_string(),
                "to_address": dest_addr.to_string(),
                "amount": display_tos(amount_nanotos),
                "message": self.message,
                "status": "sent",
            }))?
        );
        Ok(())
    }
}

impl AgentWalletStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        let address =
            view.address.parse::<MsgAddressInt>().context("Invalid Agent Wallet address")?;
        let info = rpc_client
            .get_wallet_information(&address)
            .await
            .context("get Agent Wallet chain status")?;
        let status = AgentWalletStatusView {
            name: self.name.clone(),
            address: view.address,
            balance: display_tos(info.balance),
            state: info.account_state.to_string(),
            wallet_type: info.wallet_type.map(|t| t.to_string()),
            seqno: info.seqno,
            controller_key: view.controller_key,
            runtime: view.runtime,
        };

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&status)?);
            return Ok(());
        }

        println!("{}", status.name.bold());
        println!("  Address:     {}", status.address);
        println!("  Balance:     {} TOS", status.balance);
        println!("  State:       {}", status.state);
        println!("  Wallet type: {}", status.wallet_type.unwrap_or_else(|| "-".to_string()));
        println!(
            "  Seqno:       {}",
            status.seqno.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string())
        );
        println!("  Controller:  {}", status.controller_key);
        if let Some(runtime) = status.runtime {
            println!("  Runtime:     {} ({})", runtime.runner_id, runtime.endpoint);
        }
        Ok(())
    }
}

impl AgentWalletActivateCmd {
    const MIN_BALANCE: u64 = 100_000_000; // 0.1 TOS

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        let (address, info, secret) =
            wallet_info(rpc_client.clone(), &agent_wallet.wallet, vault).await?;
        if info.account_state == AccountState::Active {
            println!(
                "{} Agent Wallet '{}' ({}) already active",
                "OK".green().bold(),
                self.name,
                address
            );
            return Ok(());
        }
        if info.account_state == AccountState::Frozen {
            anyhow::bail!("Agent Wallet '{}' ({}) is frozen", self.name, address);
        }
        if info.balance < Self::MIN_BALANCE {
            anyhow::bail!(
                "Agent Wallet '{}' ({}) balance {} too low (min {})",
                self.name,
                address,
                display_tos(info.balance),
                display_tos(Self::MIN_BALANCE),
            );
        }

        println!("Deploying Agent Wallet '{}' ({})...", self.name, address);

        let wallet = make_wallet(rpc_client.clone(), &agent_wallet.wallet, secret, &self.name)
            .await
            .context("create Agent Wallet deployer")?;
        let msg = wallet.deploy_message(Self::MIN_BALANCE / 10, Cell::default()).await?;
        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;
        wait_for_deploy(
            rpc_client,
            &address,
            &common::task_cancellation::CancellationCtx::default(),
            true,
            DEPLOY_TIMEOUT,
        )
        .await?;

        println!("{} Agent Wallet '{}' ({}) activated", "OK".green().bold(), self.name, address);
        Ok(())
    }
}

impl AgentWalletRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        println!(
            "\n{}\n  Agent:       {}\n  Owner key:   {}\n  Controller:  {}\n  Delete keys: {}\n",
            "Remove Agent Wallet profile:".cyan().bold(),
            self.name,
            describe_key(&agent_wallet.wallet.key),
            describe_key(&agent_wallet.controller_key),
            if self.delete_keys { "yes" } else { "no" },
        );

        if !self.yes && !confirm("Confirm remove?")? {
            println!("{}", "Remove cancelled".yellow());
            return Ok(());
        }

        let agent_wallet = config
            .agent_wallets
            .remove(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        if self.delete_keys {
            delete_vault_key_if_present(&vault, &agent_wallet.wallet.key).await?;
            delete_vault_key_if_present(&vault, &agent_wallet.controller_key).await?;
            vault.flush().await?;
        }
        save_config(&config, path)?;

        println!("{} Agent Wallet '{}' removed", "OK".green().bold(), self.name);
        if !self.delete_keys {
            println!("  Vault keys were preserved");
        }
        Ok(())
    }
}

impl AgentWalletLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let mut views = Vec::new();
        for (name, agent_wallet) in &config.agent_wallets {
            views.push(build_view(name, agent_wallet, Some(vault.clone())).await?);
        }
        views.sort_by(|a, b| a.name.cmp(&b.name));

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&views)?);
            return Ok(());
        }

        if views.is_empty() {
            println!("{}", "No agent wallets configured".yellow());
            return Ok(());
        }
        for view in views {
            print_table_summary(&view);
        }
        Ok(())
    }
}

impl AgentWalletShowCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        print_view(&view, self.format.clone())
    }
}

impl AgentWalletPolicyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        println!("{}", serde_json::to_string_pretty(&agent_wallet.policy)?);
        Ok(())
    }
}

impl AgentWalletUpdatePolicyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.clear_approval_above && self.approval_above.is_some() {
            anyhow::bail!("Use either --approval-above or --clear-approval-above, not both");
        }
        if self.clear_services && !self.allowed_service_actors.is_empty() {
            anyhow::bail!("Use either --service or --clear-services, not both");
        }
        if self.clear_task_categories && !self.allowed_task_categories.is_empty() {
            anyhow::bail!("Use either --task-category or --clear-task-categories, not both");
        }
        if self.clear_capabilities && !self.capabilities.is_empty() {
            anyhow::bail!("Use either --capability or --clear-capabilities, not both");
        }
        if self.clear_metadata_hash && self.metadata_hash.is_some() {
            anyhow::bail!("Use either --metadata-hash or --clear-metadata-hash, not both");
        }
        if self.clear_service_endpoint_hash && self.service_endpoint_hash.is_some() {
            anyhow::bail!(
                "Use either --service-endpoint-hash or --clear-service-endpoint-hash, not both"
            );
        }
        if let Some(value) = self.max_per_tx {
            validate_tos_amount("max-per-tx", value)?;
        }
        if let Some(value) = self.daily_limit {
            validate_tos_amount("daily-limit", value)?;
        }
        if let Some(value) = self.approval_above {
            validate_tos_amount("approval-above", value)?;
        }

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        if let Some(value) = self.max_per_tx {
            agent_wallet.policy.max_per_tx = tos_to_nanotos(value);
        }
        if let Some(value) = self.daily_limit {
            agent_wallet.policy.daily_limit = tos_to_nanotos(value);
        }
        if agent_wallet.policy.daily_limit < agent_wallet.policy.max_per_tx {
            anyhow::bail!("daily-limit must be greater than or equal to max-per-tx");
        }
        if self.clear_approval_above {
            agent_wallet.policy.require_owner_approval_above = None;
        } else if let Some(value) = self.approval_above {
            agent_wallet.policy.require_owner_approval_above = Some(tos_to_nanotos(value));
        }
        if self.clear_services {
            agent_wallet.policy.allowed_service_actors.clear();
        } else if !self.allowed_service_actors.is_empty() {
            agent_wallet.policy.allowed_service_actors = self.allowed_service_actors.clone();
        }
        if self.clear_task_categories {
            agent_wallet.policy.allowed_task_categories.clear();
        } else if !self.allowed_task_categories.is_empty() {
            agent_wallet.policy.allowed_task_categories = self.allowed_task_categories.clone();
        }
        if self.clear_capabilities {
            agent_wallet.capabilities.clear();
        } else if !self.capabilities.is_empty() {
            agent_wallet.capabilities = self.capabilities.clone();
        }
        if self.clear_metadata_hash {
            agent_wallet.metadata_hash = None;
        } else if let Some(value) = &self.metadata_hash {
            agent_wallet.metadata_hash = Some(value.clone());
        }
        if self.clear_service_endpoint_hash {
            agent_wallet.service_endpoint_hash = None;
        } else if let Some(value) = &self.service_endpoint_hash {
            agent_wallet.service_endpoint_hash = Some(value.clone());
        }
        if let Some(value) = self.default_task_timeout_secs {
            agent_wallet.policy.default_task_timeout_secs = value;
        }

        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;
        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{} Agent Wallet policy updated", "OK".green().bold());
        print_view(&view, self.format.clone())
    }
}

pub(crate) fn validate_tos_amount(name: &str, value: f64) -> anyhow::Result<()> {
    if !value.is_finite() || value < 0.0 {
        anyhow::bail!("{name} must be a finite non-negative TOS amount");
    }
    Ok(())
}

fn validate_non_empty(name: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    Ok(())
}

async fn build_agent_account_init(
    wallet_name: &str,
    agent_wallet: &AgentWalletConfig,
    vault: std::sync::Arc<SecretVault>,
) -> anyhow::Result<(AgentAccountInit, String)> {
    let owner_view = build_view(wallet_name, agent_wallet, Some(vault.clone())).await?;
    let owner = owner_view
        .address
        .parse::<MsgAddressInt>()
        .context("Invalid Agent Wallet owner address")?;
    let controller_secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
    let controller_pubkey: [u8; 32] = public_key_from_secret(&controller_secret)
        .await?
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
    let deployment_id = if let Some(value) = &agent_wallet.agent_account_deployment_id {
        parse_optional_hash("agent-account-deployment-id", &Some(value.clone()))?
            .context("configured Agent Account deployment ID is missing")?
    } else {
        let mut generated = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut generated);
        generated
    };
    anyhow::ensure!(deployment_id != [0u8; 32], "Agent Account deployment ID must be nonzero");

    Ok((
        AgentAccountInit {
            owner,
            controller_pubkey,
            deployment_id,
            max_per_tx: agent_wallet.policy.max_per_tx,
            daily_limit: agent_wallet.policy.daily_limit,
            default_task_timeout_secs: agent_wallet.policy.default_task_timeout_secs,
            metadata_hash: parse_optional_hash("metadata-hash", &agent_wallet.metadata_hash)?,
            service_endpoint_hash: parse_optional_hash(
                "service-endpoint-hash",
                &agent_wallet.service_endpoint_hash,
            )?,
        },
        owner_view.address,
    ))
}

pub(crate) fn parse_optional_hash(
    name: &str,
    value: &Option<String>,
) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(trimmed).with_context(|| format!("{name} must be a 32-byte hex string"))?;
    let hash: [u8; 32] =
        bytes.try_into().map_err(|_| anyhow::anyhow!("{name} must be exactly 32 bytes"))?;
    Ok(Some(hash))
}

pub(crate) fn parse_required_hash(name: &str, value: &Option<String>) -> anyhow::Result<[u8; 32]> {
    parse_optional_hash(name, value)?.ok_or_else(|| anyhow::anyhow!("--{name} is required"))
}

pub(crate) async fn resolve_attestor_pubkey(
    attestor_pubkey: &Option<String>,
    signer_vault_key: &Option<String>,
    vault: std::sync::Arc<SecretVault>,
) -> anyhow::Result<Option<[u8; 32]>> {
    match (attestor_pubkey, signer_vault_key) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide at most one of --attestor-pubkey or --signer-vault-key")
        }
        (Some(hex), None) => parse_optional_hash("attestor-pubkey", &Some(hex.clone())),
        (None, Some(name)) => {
            let secret =
                KeyConfig::VaultKey { name: name.clone() }.read_secret(Some(vault)).await?;
            let keypair = secret.as_keypair()?;
            let raw = keypair
                .public_key()
                .await?
                .ok_or_else(|| anyhow::anyhow!("vault key '{}' has no public key", name))?;
            let pubkey: [u8; 32] =
                raw.try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
            Ok(Some(pubkey))
        }
        (None, None) => Ok(None),
    }
}

/// Sign a 32-byte hash directly with the named vault key, matching
/// CHKSIGNU's convention (the raw hash, not a re-hashed or prefixed encoding).
pub(crate) async fn sign_hash_with_vault_key(
    name: &str,
    hash: &[u8; 32],
    vault: std::sync::Arc<SecretVault>,
) -> anyhow::Result<[u8; 64]> {
    let secret = KeyConfig::VaultKey { name: name.to_owned() }.read_secret(Some(vault)).await?;
    let keypair = secret.as_keypair()?;
    let raw = keypair.sign(hash).await?;
    raw.try_into().map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))
}

pub(crate) fn parse_optional_signature(
    name: &str,
    value: &Option<String>,
) -> anyhow::Result<Option<[u8; 64]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(trimmed).with_context(|| format!("{name} must be a 64-byte hex string"))?;
    let signature: [u8; 64] =
        bytes.try_into().map_err(|_| anyhow::anyhow!("{name} must be exactly 64 bytes"))?;
    Ok(Some(signature))
}

fn resolve_nanotos(
    name: &str,
    value_tos: Option<f64>,
    value_nanotos: Option<u64>,
    default_tos: Option<f64>,
) -> anyhow::Result<u64> {
    if let Some(value) = value_nanotos {
        if value == 0 {
            anyhow::bail!("{name}-nanotos must be greater than zero");
        }
        return Ok(value);
    }
    let value = value_tos
        .or(default_tos)
        .ok_or_else(|| anyhow::anyhow!("provide exactly one of --{name} or --{name}-nanotos"))?;
    validate_tos_amount(name, value)?;
    let nanotos = tos_to_nanotos(value);
    if nanotos == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(nanotos)
}

// A successful zero-charge settlement or a dispute resolved entirely in the
// requester's favour has an exact provider payout of zero. TaskEscrow binds
// that value in the signed action and refunds the remaining budget; it is not
// the same as an omitted amount. Keep every funding/value path strictly
// positive while allowing only the explicit atomic payout form to be zero.
fn resolve_payout_nanotos(
    value_tos: Option<f64>,
    value_nanotos: Option<u64>,
) -> anyhow::Result<u64> {
    if value_tos.is_none() && value_nanotos == Some(0) {
        return Ok(0);
    }
    resolve_nanotos("payout", value_tos, value_nanotos, None)
}

fn nanotos_to_tos_f64(value: u64) -> anyhow::Result<f64> {
    // Controller forwarding still accepts TOS as f64. Refuse values that cannot
    // round-trip through IEEE-754 at nanoTOS precision instead of silently
    // changing an economic amount.
    const MAX_EXACT_NANOTOS: u64 = 9_007_199_254_740_991;
    if value > MAX_EXACT_NANOTOS {
        anyhow::bail!("nanoTOS value cannot be represented exactly by this command path");
    }
    Ok(value as f64 / 1_000_000_000.0)
}

fn permission_id_hash(permission_id: Option<&str>) -> [u8; 32] {
    permission_id.map(|id| Sha256::digest(id.as_bytes()).into()).unwrap_or([0; 32])
}

fn task_status_name(status: u8) -> &'static str {
    match status {
        0 => "open",
        1 => "accepted",
        2 => "result_submitted",
        3 => "settled",
        4 => "cancelled",
        5 => "expired",
        6 => "rejected",
        7 => "disputed",
        _ => "unknown",
    }
}

pub(crate) fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn build_comment_cell(text: &str) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_u32(0)?;
    builder.append_raw(text.as_bytes(), text.len() * 8)?;
    Ok(builder.into_cell()?)
}

async fn build_view(
    name: &str,
    agent_wallet: &AgentWalletConfig,
    vault: Option<std::sync::Arc<secrets_vault::vault::SecretVault>>,
) -> anyhow::Result<AgentWalletView> {
    let owner_key = describe_key(&agent_wallet.wallet.key);
    let controller_key = describe_key(&agent_wallet.controller_key);
    let address = match &agent_wallet.wallet.key {
        KeyConfig::VaultKey { .. } => {
            let vault = vault
                .ok_or_else(|| anyhow::anyhow!("vault is required for address calculation"))?;
            let secret = agent_wallet.wallet.key.read_secret(Some(vault)).await?;
            let pub_key = public_key_from_secret(&secret).await?;
            calculate_wallet_address(&agent_wallet.wallet, &pub_key)?.to_string()
        }
        _ => {
            let secret = agent_wallet.wallet.key.read_secret(vault).await?;
            let pub_key = public_key_from_secret(&secret).await?;
            calculate_wallet_address(&agent_wallet.wallet, &pub_key)?.to_string()
        }
    };

    Ok(AgentWalletView {
        name: name.to_string(),
        address,
        agent_account_address: agent_wallet.agent_account_address.clone(),
        agent_account_deployment_id: agent_wallet.agent_account_deployment_id.clone(),
        version: agent_wallet.wallet.version,
        workchain: agent_wallet.wallet.workchain,
        subwallet_id: agent_wallet.wallet.subwallet_id,
        owner_key,
        controller_key,
        policy: agent_wallet.policy.clone(),
        metadata_hash: agent_wallet.metadata_hash.clone(),
        service_endpoint_hash: agent_wallet.service_endpoint_hash.clone(),
        capabilities: agent_wallet.capabilities.clone(),
        runtime: agent_wallet.runtime.clone(),
        created_at: agent_wallet.created_at,
    })
}

async fn public_key_from_secret(secret: &Secret) -> anyhow::Result<Vec<u8>> {
    let keypair = secret.as_keypair()?;
    keypair.public_key().await?.ok_or_else(|| anyhow::anyhow!("secret has no public key"))
}

fn describe_key(key: &KeyConfig) -> String {
    match key {
        KeyConfig::VaultKey { name } => format!("vault:{name}"),
        KeyConfig::PublicKey { .. } => "public-key".to_string(),
        KeyConfig::PrivateKey { .. } => "private-key".to_string(),
        KeyConfig::KeyPair(_) => "inline-keypair".to_string(),
    }
}

async fn delete_vault_key_if_present(
    vault: &secrets_vault::vault::SecretVault,
    key: &KeyConfig,
) -> anyhow::Result<()> {
    if let KeyConfig::VaultKey { name } = key {
        let secret_id: SecretId = name.as_str().into();
        if vault.exists(&secret_id).await? {
            vault.delete(&secret_id).await?;
        }
    }
    Ok(())
}

fn print_view(view: &AgentWalletView, format: OutputFormat) -> anyhow::Result<()> {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(view)?);
        return Ok(());
    }
    print_table_summary(view);
    println!("  Max per action:       {} TOS", display_tos(view.policy.max_per_tx));
    println!("  Daily limit:          {} TOS", display_tos(view.policy.daily_limit));
    if let Some(value) = view.policy.require_owner_approval_above {
        println!("  Owner approval above: {} TOS", display_tos(value));
    }
    println!("  Default task timeout: {}s", view.policy.default_task_timeout_secs);
    if !view.policy.allowed_service_actors.is_empty() {
        println!("  Allowed services:     {}", view.policy.allowed_service_actors.join(", "));
    }
    if !view.policy.allowed_task_categories.is_empty() {
        println!("  Task categories:      {}", view.policy.allowed_task_categories.join(", "));
    }
    if !view.capabilities.is_empty() {
        println!("  Capabilities:         {}", view.capabilities.join(", "));
    }
    if let Some(runtime) = &view.runtime {
        println!("  Runtime runner:       {}", runtime.runner_id);
        println!("  Runtime endpoint:     {}", runtime.endpoint);
        if let Some(hash) = &runtime.attestation_hash {
            println!("  Runtime attestation:  {}", hash);
        }
    }
    Ok(())
}

fn print_table_summary(view: &AgentWalletView) {
    println!("{}", view.name.bold());
    println!("  Address:       {}", view.address);
    if let Some(address) = &view.agent_account_address {
        println!("  Agent Account: {}", address);
    }
    println!("  Version:       {}", view.version);
    println!("  Workchain:     {}", view.workchain);
    println!("  Subwallet ID:  {}", view.subwallet_id);
    println!("  Owner key:     {}", view.owner_key);
    println!("  Controller:    {}", view.controller_key);
}

#[cfg(test)]
mod tests {
    use super::{
        AgentAccountAction, AgentTaskOperation, ControllerTaskActionContext,
        ECONOMIC_PAYMENT_CORROBORATION_SCHEMA, ECONOMIC_PAYMENT_FINALIZED_SCHEMA,
        ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
        ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA, FinalizedEconomicPaymentMatch,
        FinalizedEconomicPaymentObservation, FinalizedTaskSendObservation,
        LoadedEconomicPaymentCorroborationMember, SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI,
        SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN, SponsorshipAgreementPaymentRequestV3,
        SponsorshipFinalityProfile, TASK_SEND_FINALIZED_SCHEMA, canonical_file_digest,
        canonicalize_chain_rpc_endpoint, chain_query_failure_diagnostic,
        corroboration_snapshot_handle, decode_exact_protocol_cbor,
        economic_payment_corroboration_profile, encode_protocol_json_cbor,
        exact_protocol_action_request_digest, exact_transaction_utime,
        finalized_output_matches_claim, freeze_economic_payment_corroboration_snapshot,
        load_economic_payment_corroboration_members, load_economic_payment_corroboration_snapshot,
        permission_id_hash, protocol_cbor_digest, record_task_send_resolution_vote,
        relay_network_domain_digest, resolve_nanotos, resolve_payout_nanotos,
        rpc_failure_diagnostic, rpc_locator_identity_digest, select_exact_finalized_output,
        sponsorship_rpc_not_found, sponsorship_rpc_temporarily_unavailable,
        validate_controller_task_action, validate_destination_credit_semantics,
        validate_exact_sponsorship_top_up_boc, validate_release_profile_rpc_locator,
        validate_sponsorship_custody_evidence_context, validate_sponsorship_finality_profile,
        validate_sponsorship_payment_request, validate_task_send_resolution_claim,
        validate_task_send_resolution_evidence, verify_current_controller_authorization,
        verify_parsed_controller_authorization, write_private_snapshot_file,
    };
    use base64::Engine;
    use chain_block::{
        BuilderData, CurrencyCollection, InternalMessageHeader, Message, MsgAddressInt, SliceData,
        TrCreditPhase, TransactionDescrOrdinary, read_single_root_boc, write_boc,
    };
    use chain_rpc_client::v2::data_models::RelayNetworkDomainPin;
    use common::app_config::AppConfig;
    use contracts::{
        AgentAccountContract, AgentAccountData, ControllerActionClaim, ControllerActionRecord,
        ControllerActionResolutionEvidence, ControllerActionStatus, EconomicActionAuthorization,
        TaskEscrowData, agent_account_task_body_hash, controller_resolution_evidence_digest,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(clap::Parser)]
    struct AccountActionParser {
        #[command(subcommand)]
        action: AgentAccountAction,
    }

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn create(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tosctl-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_network() -> RelayNetworkDomainPin {
        RelayNetworkDomainPin {
            network_id: "testnet".to_owned(),
            global_id: -239,
            zero_state_root_hash: format!("sha256:{}", "11".repeat(32)),
            zero_state_file_hash: format!("sha256:{}", "22".repeat(32)),
            workchain_id: 0,
        }
    }

    fn test_corroboration_member(
        directory: &Path,
        index: usize,
    ) -> LoadedEconomicPaymentCorroborationMember {
        let configured_endpoint = format!("http://127.0.0.1:{}", 3400 + index);
        test_corroboration_member_at(directory, index, &configured_endpoint)
    }

    fn test_corroboration_member_at(
        directory: &Path,
        index: usize,
        configured_endpoint: &str,
    ) -> LoadedEconomicPaymentCorroborationMember {
        let (endpoint, display_origin) =
            canonicalize_chain_rpc_endpoint(configured_endpoint).unwrap();
        let operator_provenance = format!("sha256:{:064x}", index + 1);
        let value = serde_json::json!({
            "nodes": {},
            "chain_rpc": {
                "urls": [configured_endpoint],
                "api_key": format!("private-key-{index}"),
                "operator_provenance": operator_provenance.clone(),
            },
            "http": {},
            "master_wallet": null,
            "log": null,
        });
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        let path = directory.join(format!("source-{index}.json"));
        write_private_snapshot_file(&path, &bytes).unwrap();
        let config = AppConfig::load_bytes(&bytes, "json", &path.display().to_string()).unwrap();
        LoadedEconomicPaymentCorroborationMember {
            config,
            canonical_path: fs::canonicalize(path).unwrap(),
            content_digest: canonical_file_digest(&bytes),
            locator_identity_digest: rpc_locator_identity_digest(&endpoint).unwrap(),
            endpoint,
            display_origin,
            operator_provenance,
        }
    }

    fn address(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
    }

    fn masterchain_address(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, -1, [byte; 32].into()).unwrap()
    }

    fn task_send_resolution_record() -> ControllerActionRecord {
        ControllerActionRecord {
            claim: ControllerActionClaim {
                account: address(2).to_string(),
                network_global_id: test_network().global_id,
                network_domain: Some(test_network()),
                deployment_id: "3".repeat(64),
                controller_epoch: 7,
                seqno: 11,
                target: masterchain_address(4).to_string(),
                value_atomic: 5_000_000_000,
                body_hash: Some(format!("tvm-cell-sha256:{}", "5".repeat(64))),
                action_kind: "agent-task-send".into(),
                idempotency_key: "6".repeat(64),
                action_identity: format!("sha256:{}", "7".repeat(64)),
                valid_until: 1_900_000_000,
            },
            status: ControllerActionStatus::Broadcasting,
            exact_signed_boc_base64: None,
            exact_signed_boc_digest: Some(format!("sha256:{}", "8".repeat(64))),
            cancellation_identity: None,
            cancellation_boc_base64: None,
            economic_authorization: None,
            economic_effect_authorization: None,
            exact_winner_resolution: None,
            created_at_unix: 1,
            updated_at_unix: 2,
        }
    }

    fn economic_payment_observation(index: u32) -> FinalizedEconomicPaymentObservation {
        FinalizedEconomicPaymentObservation {
            endpoint: format!("http://127.0.0.1:{}/", 23000 + index),
            locator_identity_digest: format!("sha256:{:064x}", index),
            transaction_hash: format!("sha256:{}", "a".repeat(64)),
            transaction_lt: 1234,
            transaction_utime: 1_800_000_000,
            transaction_boc_digest: format!("sha256:{}", "b".repeat(64)),
            block_workchain: 0,
            block_shard: i64::MIN,
            block_seqno: 77,
            block_root_hash: format!("sha256:{}", "d".repeat(64)),
            block_file_hash: format!("sha256:{}", "e".repeat(64)),
            observed_masterchain_seqno: 80 + index,
        }
    }

    fn task_send_match(
        record: &ControllerActionRecord,
        index: u32,
    ) -> FinalizedEconomicPaymentMatch {
        FinalizedEconomicPaymentMatch {
            observation: economic_payment_observation(index),
            outbound_message_cell_hash: format!("tvm-cell-sha256:{}", "c".repeat(64)),
            outbound_body_hash: record.claim.body_hash.clone(),
        }
    }

    fn task_send_observation(
        record: &ControllerActionRecord,
        index: u32,
        finalized_controller_epoch: u64,
        finalized_seqno: u32,
    ) -> FinalizedTaskSendObservation {
        FinalizedTaskSendObservation {
            transaction: economic_payment_observation(index),
            outbound_message_cell_hash: format!("tvm-cell-sha256:{}", "c".repeat(64)),
            outbound_body_hash: record.claim.body_hash.clone().unwrap(),
            finalized_controller_epoch,
            finalized_seqno,
        }
    }

    fn task_send_account_data(epoch: u64, seqno: u32) -> AgentAccountData {
        AgentAccountData {
            owner: address(1),
            controller_pubkey: [2; 32],
            deployment_id: [0x33; 32],
            controller_epoch: epoch,
            seqno,
            spend_day: 0,
            spent_today: 0,
            max_per_tx: 10_000_000_000,
            daily_limit: 100_000_000_000,
            default_task_timeout_secs: 600,
            metadata_hash: None,
            service_endpoint_hash: None,
        }
    }

    fn task_send_resolution_evidence(
        record: &ControllerActionRecord,
    ) -> ControllerActionResolutionEvidence {
        let first_observation = task_send_observation(record, 1, 7, 12);
        let second_observation = task_send_observation(record, 2, 7, 12);
        let evidence = serde_json::json!({
            "schema": TASK_SEND_FINALIZED_SCHEMA,
            "wallet": "campaign-agent-0",
            "action_id": record.claim.idempotency_key,
            "source_account": record.claim.account,
            "deployment_id": record.claim.deployment_id,
            "controller_epoch": record.claim.controller_epoch,
            "seqno": record.claim.seqno,
            "finalized_controller_epoch": record.claim.controller_epoch,
            "finalized_seqno": record.claim.seqno + 1,
            "destination": record.claim.target,
            "amount_nanotos": record.claim.value_atomic,
            "body_hash": record.claim.body_hash,
            "exact_signed_boc_digest": record.exact_signed_boc_digest,
            "submitted_message_cell_hash": format!("tvm-cell-sha256:{}", "9".repeat(64)),
            "network_domain": record.claim.network_domain,
            "quorum": {"members": 3, "threshold": 2, "agreeing": 2},
            "process_view_scope": "distinct RPC process views; no independent-operator or Byzantine-finality claim",
            "block_reference_scope": "RPC-asserted transaction and block identifiers; no inclusion proof was verified",
            "independent_operator_domains_proven": false,
            "transaction": first_observation.clone(),
            "observations": [first_observation, second_observation],
            "state": "resolved",
        });
        ControllerActionResolutionEvidence {
            evidence_kind: TASK_SEND_FINALIZED_SCHEMA.into(),
            evidence_digest: controller_resolution_evidence_digest(
                TASK_SEND_FINALIZED_SCHEMA,
                &evidence,
            )
            .unwrap(),
            evidence,
        }
    }

    fn controller_task(status: u8) -> TaskEscrowData {
        TaskEscrowData {
            creator: address(1),
            assigned_agent: Some(address(2)),
            verifier: None,
            budget: 1_000_000_000,
            deadline: u64::MAX,
            review_period: 3_600,
            review_deadline: 0,
            status,
            result_hash: [0; 32],
            evidence_hash: [0; 32],
            settlement_policy_hash: [3; 32],
            permission_hash: permission_id_hash(Some("bounded-task")),
            dispute_hash: [0; 32],
            attestor_pubkey: None,
        }
    }

    fn controller_task_context(task_address: &MsgAddressInt) -> ControllerTaskActionContext<'_> {
        ControllerTaskActionContext {
            task_address,
            now: 100,
            payout: Some(500_000_000),
            dispute_hash: Some([7; 32]),
            attestation_signature: None,
            available_balance: 1_000_000_000,
        }
    }

    #[test]
    fn permission_hash_has_stable_encoding() {
        assert_eq!(
            hex::encode(permission_id_hash(Some("e2e-agent:bounded-task:1"))),
            "873d4711315b76cfa2130ec78baabe70fa7d60e8f69f363f45ff6f03246a81ca"
        );
        assert_eq!(permission_id_hash(None), [0; 32]);
    }

    #[test]
    fn exact_nanotos_bypasses_float_conversion() {
        assert_eq!(resolve_nanotos("budget", None, Some(u64::MAX), None).unwrap(), u64::MAX);
        assert!(resolve_nanotos("budget", None, Some(0), None).is_err());
        assert_eq!(resolve_nanotos("amount", None, None, Some(0.2)).unwrap(), 200_000_000);
    }

    #[test]
    fn exact_zero_payout_is_valid_but_zero_funding_is_not() {
        assert_eq!(resolve_payout_nanotos(None, Some(0)).unwrap(), 0);
        assert!(resolve_payout_nanotos(Some(0.0), None).is_err());
        assert!(resolve_nanotos("amount", None, Some(0), None).is_err());
    }

    #[test]
    fn task_send_resolve_cli_is_resolution_only_and_uses_three_process_views() {
        use clap::Parser;

        let action_id = "a".repeat(64);
        let parsed = AccountActionParser::try_parse_from([
            "agent-account",
            "task-send-resolve",
            "--wallet=campaign-agent-0",
            &format!("--action-id={action_id}"),
            "--quorum-config",
            "/private/view-2.json",
            "/private/view-3.json",
            "--max-transactions=321",
        ])
        .unwrap();
        match parsed.action {
            AgentAccountAction::TaskSendResolve(command) => {
                assert_eq!(command.wallet, "campaign-agent-0");
                assert_eq!(command.action_id, action_id);
                assert_eq!(
                    command.quorum_configs,
                    ["/private/view-2.json", "/private/view-3.json"]
                );
                assert_eq!(command.max_transactions, 321);
                assert!(command.journal_directory.is_none());
                assert!(command.config_fd.is_none());
                assert!(command.config_format.is_none());
            }
            _ => panic!("task-send-resolve parsed as another command"),
        }

        let economic = AccountActionParser::try_parse_from([
            "agent-account",
            "task-send-resolve",
            "--wallet=campaign-agent-0",
            &format!("--action-id={action_id}"),
            "--quorum-config",
            "/private/view-2.json",
            "/private/view-3.json",
            "--journal-directory=/private/economic-custody",
            "--config-fd=3",
            "--config-format=json",
        ])
        .unwrap();
        match economic.action {
            AgentAccountAction::TaskSendResolve(command) => {
                assert_eq!(command.journal_directory.as_deref(), Some("/private/economic-custody"));
                assert_eq!(command.config_fd, Some(3));
                assert_eq!(command.config_format.as_deref(), Some("json"));
            }
            _ => panic!("economic task-send resolution parsed as another command"),
        }

        assert!(
            AccountActionParser::try_parse_from([
                "agent-account",
                "task-send-resolve",
                "--wallet=campaign-agent-0",
                &format!("--action-id={action_id}"),
                "--quorum-config",
                "/private/view-2.json",
            ])
            .is_err()
        );
        for forbidden in [
            format!("--target={}", masterchain_address(4)),
            "--body-boc=te6ccgEBAQEAAgAAAA==".to_owned(),
            "--yes".to_owned(),
        ] {
            assert!(
                AccountActionParser::try_parse_from([
                    "agent-account",
                    "task-send-resolve",
                    "--wallet=campaign-agent-0",
                    &format!("--action-id={action_id}"),
                    "--quorum-config",
                    "/private/view-2.json",
                    "/private/view-3.json",
                    &forbidden,
                ])
                .is_err(),
                "resolver unexpectedly accepted broadcast/signing option {forbidden}"
            );
        }
    }

    #[test]
    fn task_send_resolution_binds_masterchain_body_effect_and_replay_evidence() {
        let record = task_send_resolution_record();
        let domain = validate_task_send_resolution_claim(&record, &address(2)).unwrap();
        assert_eq!(domain, test_network());
        assert_eq!(record.claim.target, masterchain_address(4).to_string());

        let resolution = task_send_resolution_evidence(&record);
        validate_task_send_resolution_evidence(&record, &resolution).unwrap();
        let mut resolved = record.clone();
        resolved.status = ControllerActionStatus::Resolved;
        resolved.exact_winner_resolution = Some(resolution.clone());
        validate_task_send_resolution_evidence(
            &resolved,
            resolved.exact_winner_resolution.as_ref().unwrap(),
        )
        .unwrap();

        let mut wrong_body = resolution.clone();
        wrong_body.evidence["body_hash"] =
            serde_json::json!(format!("tvm-cell-sha256:{}", "f".repeat(64)));
        wrong_body.evidence_digest =
            controller_resolution_evidence_digest(TASK_SEND_FINALIZED_SCHEMA, &wrong_body.evidence)
                .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &wrong_body).is_err());

        // The declared scopes are part of the contract: evidence that drops
        // or rewrites the RPC-asserted block-reference disclaimer, or names a
        // different network domain, must be rejected.
        let mut wrong_scope = resolution.clone();
        wrong_scope.evidence["block_reference_scope"] =
            serde_json::json!("verified inclusion proof");
        wrong_scope.evidence_digest = controller_resolution_evidence_digest(
            TASK_SEND_FINALIZED_SCHEMA,
            &wrong_scope.evidence,
        )
        .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &wrong_scope).is_err());

        let mut wrong_network = resolution.clone();
        wrong_network.evidence["network_domain"]["global_id"] = serde_json::json!(-999);
        wrong_network.evidence_digest = controller_resolution_evidence_digest(
            TASK_SEND_FINALIZED_SCHEMA,
            &wrong_network.evidence,
        )
        .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &wrong_network).is_err());

        let mut wrong_observation = resolution.clone();
        wrong_observation.evidence["observations"][1]["outbound_body_hash"] =
            serde_json::json!(format!("tvm-cell-sha256:{}", "f".repeat(64)));
        wrong_observation.evidence_digest = controller_resolution_evidence_digest(
            TASK_SEND_FINALIZED_SCHEMA,
            &wrong_observation.evidence,
        )
        .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &wrong_observation).is_err());

        let mut duplicate_view = resolution.clone();
        duplicate_view.evidence["observations"][1]["endpoint"] =
            duplicate_view.evidence["observations"][0]["endpoint"].clone();
        duplicate_view.evidence_digest = controller_resolution_evidence_digest(
            TASK_SEND_FINALIZED_SCHEMA,
            &duplicate_view.evidence,
        )
        .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &duplicate_view).is_err());

        let mut forged_state_view = resolution.clone();
        forged_state_view.evidence["observations"][1]["finalized_seqno"] = serde_json::json!(13);
        forged_state_view.evidence_digest = controller_resolution_evidence_digest(
            TASK_SEND_FINALIZED_SCHEMA,
            &forged_state_view.evidence,
        )
        .unwrap();
        assert!(validate_task_send_resolution_evidence(&record, &forged_state_view).is_err());

        let mut rotation = resolution.clone();
        rotation.evidence["finalized_controller_epoch"] = serde_json::json!(8);
        rotation.evidence["finalized_seqno"] = serde_json::json!(0);
        rotation.evidence["transaction"]["finalized_controller_epoch"] = serde_json::json!(8);
        rotation.evidence["transaction"]["finalized_seqno"] = serde_json::json!(0);
        for observation in rotation.evidence["observations"].as_array_mut().unwrap() {
            observation["finalized_controller_epoch"] = serde_json::json!(8);
            observation["finalized_seqno"] = serde_json::json!(0);
        }
        rotation.evidence_digest =
            controller_resolution_evidence_digest(TASK_SEND_FINALIZED_SCHEMA, &rotation.evidence)
                .unwrap();
        validate_task_send_resolution_evidence(&record, &rotation).unwrap();

        let mut wrong_action = record.clone();
        wrong_action.claim.action_kind = "agent-native-send".into();
        assert!(validate_task_send_resolution_claim(&wrong_action, &address(2)).is_err());
        assert!(validate_task_send_resolution_claim(&record, &address(3)).is_err());
    }

    #[test]
    fn finalized_task_send_output_rejects_same_target_and_value_with_wrong_body() {
        let source = address(2);
        let target = masterchain_address(4);
        let value = CurrencyCollection::with_coins(5_000_000_000);
        let body = BuilderData::with_raw(vec![0xab], 8).unwrap().into_cell().unwrap();
        let message = Message::with_int_header_and_body(
            InternalMessageHeader::with_addresses(source, target.clone(), value.clone()),
            SliceData::load_cell(body.clone()).unwrap(),
        );
        let expected_body_hash = agent_account_task_body_hash(&body);

        assert!(
            finalized_output_matches_claim(&message, &target, &value, Some(&expected_body_hash),)
                .unwrap()
                .is_some()
        );
        assert!(
            finalized_output_matches_claim(
                &message,
                &target,
                &value,
                Some(&format!("tvm-cell-sha256:{}", "f".repeat(64))),
            )
            .unwrap()
            .is_none()
        );
        assert!(finalized_output_matches_claim(&message, &target, &value, None).unwrap().is_some());

        let wrong_body = BuilderData::with_raw(vec![0xcd], 8).unwrap().into_cell().unwrap();
        let duplicate = Message::with_int_header_and_body(
            InternalMessageHeader::with_addresses(address(2), target.clone(), value.clone()),
            SliceData::load_cell(wrong_body).unwrap(),
        );
        assert!(
            select_exact_finalized_output(
                &[message.clone(), duplicate],
                &target,
                &value,
                Some(&expected_body_hash),
            )
            .is_err()
        );

        let absent_body = Message::with_int_header(InternalMessageHeader::with_addresses(
            address(2),
            target.clone(),
            value.clone(),
        ));
        assert!(
            finalized_output_matches_claim(
                &absent_body,
                &target,
                &value,
                Some(&expected_body_hash),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            select_exact_finalized_output(
                &[absent_body],
                &target,
                &value,
                Some(&expected_body_hash),
            )
            .is_err()
        );
    }

    #[test]
    fn task_send_quorum_tolerates_one_state_error_and_accepts_controller_rotation() {
        let record = task_send_resolution_record();
        let mut votes = BTreeMap::new();
        record_task_send_resolution_vote(
            &mut votes,
            task_send_match(&record, 1),
            Err(anyhow::anyhow!("one RPC process view timed out")),
            &record,
        );
        record_task_send_resolution_vote(
            &mut votes,
            task_send_match(&record, 2),
            Ok(task_send_account_data(7, 12)),
            &record,
        );
        record_task_send_resolution_vote(
            &mut votes,
            task_send_match(&record, 3),
            Ok(task_send_account_data(7, 12)),
            &record,
        );
        assert_eq!(votes.values().next().unwrap().len(), 2);

        let mut rotated = BTreeMap::new();
        record_task_send_resolution_vote(
            &mut rotated,
            task_send_match(&record, 1),
            Ok(task_send_account_data(8, 0)),
            &record,
        );
        assert_eq!(rotated.values().next().unwrap()[0].finalized_controller_epoch, 8);
        assert_eq!(rotated.values().next().unwrap()[0].finalized_seqno, 0);
    }

    #[test]
    fn legacy_finalized_payment_observation_json_shape_is_unchanged() {
        let encoded = serde_json::to_string(&economic_payment_observation(1)).unwrap();
        let expected = format!(
            concat!(
                "{{\"endpoint\":\"http://127.0.0.1:23001/\",",
                "\"locator_identity_digest\":\"sha256:{locator}\",",
                "\"transaction_hash\":\"sha256:{transaction}\",",
                "\"transaction_lt\":1234,\"transaction_utime\":1800000000,",
                "\"transaction_boc_digest\":\"sha256:{boc}\",",
                "\"block_workchain\":0,\"block_shard\":-9223372036854775808,",
                "\"block_seqno\":77,\"block_root_hash\":\"sha256:{root}\",",
                "\"block_file_hash\":\"sha256:{file}\",",
                "\"observed_masterchain_seqno\":81}}"
            ),
            locator = format!("{:064x}", 1),
            transaction = "a".repeat(64),
            boc = "b".repeat(64),
            root = "d".repeat(64),
            file = "e".repeat(64),
        );
        assert_eq!(encoded, expected);
        assert!(!encoded.contains("outbound_body_hash"));
        assert!(!encoded.contains("finalized_controller_epoch"));
    }

    #[test]
    fn ordinary_resolve_and_sponsorship_corroborate_keep_distinct_cli_contracts() {
        use clap::Parser;

        let action_id = format!("sha256:{}", "aa".repeat(32));
        let ordinary = AccountActionParser::try_parse_from([
            "agent-account",
            "economic-payment-resolve",
            "--wallet",
            "provider",
            "--stable-action-id",
            &action_id,
            "--quorum-config",
            "/operator-b.json",
            "/operator-c.json",
            "--max-transactions",
            "321",
        ])
        .unwrap();
        match ordinary.action {
            AgentAccountAction::EconomicPaymentResolve(command) => {
                assert_eq!(command.quorum_configs.len(), 2);
                assert_eq!(command.max_transactions, 321);
            }
            _ => panic!("legacy economic-payment-resolve parsed as another command"),
        }
        assert_eq!(
            ECONOMIC_PAYMENT_FINALIZED_SCHEMA,
            "tosctl.agent-account.agreement-payment-finalized.v1"
        );

        let corroborate = AccountActionParser::try_parse_from([
            "agent-account",
            "economic-payment-corroborate",
            "--wallet",
            "provider",
            "--stable-action-id",
            &action_id,
            "--corroboration-snapshot",
            "/private/action/manifest.json",
            "--corroboration-snapshot-identity",
            &format!("sha256:{}", "cc".repeat(32)),
            "--sponsorship-release-profile-digest",
            &format!("sha256:{}", "bb".repeat(32)),
        ])
        .unwrap();
        match corroborate.action {
            AgentAccountAction::EconomicPaymentCorroborate(command) => {
                assert_eq!(command.corroboration_snapshot, "/private/action/manifest.json");
                assert_eq!(
                    command.corroboration_snapshot_identity,
                    format!("sha256:{}", "cc".repeat(32))
                );
                assert_eq!(
                    command.sponsorship_release_profile_digest,
                    format!("sha256:{}", "bb".repeat(32))
                );
            }
            _ => panic!("economic-payment-corroborate parsed as another command"),
        }
        assert_eq!(
            ECONOMIC_PAYMENT_CORROBORATION_SCHEMA,
            "tosctl.agent-account.agreement-payment-rpc-corroboration.v2"
        );

        let finality = AccountActionParser::try_parse_from([
            "agent-account",
            "economic-payment-sponsorship-corroborated-terminal",
            "--wallet",
            "provider",
            "--stable-action-id",
            &action_id,
            "--agreement-payment-request-cbor",
            "/private/action/payment.cbor",
            "--finality-profile-cbor",
            "/private/action/finality.cbor",
            "--corroboration-snapshot",
            "/private/action/manifest.json",
            "--corroboration-snapshot-identity",
            &format!("sha256:{}", "cc".repeat(32)),
            "--sponsorship-release-profile-digest",
            &format!("sha256:{}", "bb".repeat(32)),
        ])
        .unwrap();
        match finality.action {
            AgentAccountAction::EconomicPaymentSponsorshipFinality(command) => {
                assert_eq!(command.agreement_payment_request_cbor, "/private/action/payment.cbor");
                assert_eq!(command.finality_profile_cbor, "/private/action/finality.cbor");
                assert_eq!(command.corroboration_snapshot, "/private/action/manifest.json");
            }
            _ => panic!("sponsorship corroborated terminal parsed as another command"),
        }
        assert_eq!(
            ECONOMIC_PAYMENT_SPONSORSHIP_FINALITY_SCHEMA,
            "tosctl.agent-account.agreement-payment-sponsorship-corroborated-terminal.v1"
        );

        let verify = AccountActionParser::try_parse_from([
            "agent-account",
            "economic-payment-sponsorship-proof-verify",
            "--proof-bundle-cbor",
            "/private/client/proof.cbor",
            "--agreement-payment-request-cbor",
            "/private/client/payment.cbor",
            "--finality-profile-cbor",
            "/private/client/finality.cbor",
            "--corroboration-snapshot",
            "/private/client/manifest.json",
            "--corroboration-snapshot-identity",
            &format!("sha256:{}", "dd".repeat(32)),
            "--sponsorship-release-profile-digest",
            &format!("sha256:{}", "bb".repeat(32)),
        ])
        .unwrap();
        match verify.action {
            AgentAccountAction::EconomicPaymentSponsorshipProofVerify(command) => {
                assert_eq!(command.proof_bundle_cbor, "/private/client/proof.cbor");
                assert_eq!(command.corroboration_snapshot, "/private/client/manifest.json");
            }
            _ => panic!("sponsorship proof verifier parsed as another command"),
        }
        assert_eq!(
            ECONOMIC_PAYMENT_SPONSORSHIP_PROOF_VERIFICATION_SCHEMA,
            "tosctl.agent-account.agreement-payment-sponsorship-proof-verification.v1"
        );

        assert!(
            AccountActionParser::try_parse_from([
                "agent-account",
                "economic-payment-resolve",
                "--wallet",
                "provider",
                "--stable-action-id",
                &action_id,
                "--corroboration-snapshot",
                "/private/action/manifest.json",
                "--sponsorship-release-profile-digest",
                &format!("sha256:{}", "bb".repeat(32)),
            ])
            .is_err()
        );
    }

    #[test]
    fn transaction_maturity_uses_hash_bound_time_and_rejects_wrapper_split() {
        assert_eq!(exact_transaction_utime(1_800_000_000, 1_800_000_000).unwrap(), 1_800_000_000);
        assert!(exact_transaction_utime(1_800_000_000, 1).is_err());
        assert!(exact_transaction_utime(0, 0).is_err());
    }

    #[test]
    fn sponsorship_nonterminal_categories_do_not_hide_integrity_conflicts() {
        assert!(sponsorship_rpc_not_found(
            "submitted Agreement payment was not found in the bounded RPC account history"
        ));
        assert!(sponsorship_rpc_not_found(
            "authorized destination credit was not found in the bounded RPC account history"
        ));
        assert!(sponsorship_rpc_temporarily_unavailable(
            "RPC temporarily unavailable: transport timeout"
        ));

        for hard_failure in [
            "RPC wrapper time differs from the hash-bound transaction BOC time",
            "signed top-up transaction does not commit the exact PaymentRequest",
            "destination transaction has no credit phase",
            "no strict majority corroborated the sponsorship transaction",
            "custody sponsorship exact signed BOC digest is inconsistent",
        ] {
            assert!(!sponsorship_rpc_not_found(hard_failure));
            assert!(!sponsorship_rpc_temporarily_unavailable(hard_failure));
        }
    }

    #[test]
    fn rpc_capability_paths_never_enter_public_profiles_snapshots_or_diagnostics() {
        let directory = TemporaryDirectory::create("private-rpc-path-redaction");
        let members = (0..3)
            .map(|index| {
                let secret = format!("secret-capability-token-{index}");
                let endpoint = format!("https://rpc-{index}.example/tenant/{secret}/jsonRPC");
                test_corroboration_member_at(&directory.0, index, &endpoint)
            })
            .collect::<Vec<_>>();
        for (index, member) in members.iter().enumerate() {
            assert_eq!(member.display_origin, format!("https://rpc-{index}.example"));
        }

        let (profile, profile_digest, _) =
            economic_payment_corroboration_profile(&test_network(), &members, 500).unwrap();
        let profile_json = serde_json::to_string(&profile).unwrap();
        assert!(!profile_json.contains("secret-capability-token"));
        assert!(!profile_json.contains("/tenant/"));
        assert!(!profile_json.contains("config_content_digest"));
        assert!(profile_json.contains("locator_identity_digest"));

        let snapshot_parent = directory.0.join("snapshots");
        fs::create_dir(&snapshot_parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&snapshot_parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &snapshot_parent,
            test_network(),
            &members,
            500,
            profile,
            profile_digest,
        )
        .unwrap();
        let snapshot_json = serde_json::to_string(&snapshot).unwrap();
        assert!(!snapshot_json.contains("secret-capability-token"));
        assert!(!snapshot_json.contains("/tenant/"));
        assert!(snapshot_json.contains("config_content_digest"));
        let snapshot_handle = corroboration_snapshot_handle(&snapshot.snapshot_identity).unwrap();
        let capability = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-rpc-corroboration-capability.v1",
            "evidence_profile": snapshot.evidence_profile.clone(),
            "corroboration_snapshot_handle": snapshot_handle,
            "corroboration_snapshot_identity": snapshot.snapshot_identity.clone(),
        });
        let capability_json = serde_json::to_string(&capability).unwrap();
        assert!(!capability_json.contains(directory.0.to_str().unwrap()));
        assert!(!capability_json.contains("snapshot_nonce"));
        assert!(!capability_json.contains("config_content_digest"));
        assert!(!capability_json.contains("secret-capability-token"));
        assert!(
            capability["corroboration_snapshot_handle"]
                .as_str()
                .unwrap()
                .starts_with("corroboration-")
        );
        assert!(
            capability["corroboration_snapshot_handle"]
                .as_str()
                .unwrap()
                .ends_with("/manifest.json")
        );
        let (_, restored, _) = load_economic_payment_corroboration_snapshot(
            &manifest,
            &snapshot.evidence_profile_digest,
            &snapshot.snapshot_identity,
        )
        .unwrap();
        assert!(restored.iter().all(|member| member.endpoint.contains("/tenant/")));
        assert!(
            restored
                .iter()
                .all(|member| !member.display_origin.contains("secret-capability-token"))
        );

        let raw_error = anyhow::anyhow!(
            "transport failed while requesting {} with secret-capability-token-0",
            members[0].endpoint
        );
        let diagnostic = rpc_failure_diagnostic(&members[0].endpoint, &raw_error);
        assert_eq!(
            diagnostic,
            "https://rpc-0.example: rpc_failure_category=invalid_or_conflicting_response"
        );
        assert!(!diagnostic.contains("secret-capability-token"));
        assert!(!diagnostic.contains("/tenant/"));

        let chain_diagnostic = chain_query_failure_diagnostic(&raw_error);
        assert_eq!(
            chain_diagnostic,
            "chain_query_failure_category=invalid_or_conflicting_response"
        );
        assert!(!chain_diagnostic.contains("secret-capability-token"));
        assert!(!chain_diagnostic.contains("/tenant/"));
    }

    #[test]
    fn sponsorship_signed_boc_commits_exact_payment_and_rejects_old_native_send() {
        let source = format!("0:{}", "3".repeat(64)).parse::<MsgAddressInt>().unwrap();
        let target = format!("0:{}", "4".repeat(64)).parse::<MsgAddressInt>().unwrap();
        let payment_digest = format!("sha256:{}", "1".repeat(64));
        let action_id = format!("sha256:{}", "2".repeat(64));
        let commitment =
            AgentAccountContract::build_sponsorship_payment_commitment(&payment_digest, &action_id)
                .unwrap();
        assert_eq!(
            hex::encode(commitment.hash(0)),
            "00fa7b6beeb7e8ec086d2eff5fd9bff0136c4cdf8d3428c09db2b32d0a0d87a3"
        );
        let payload = AgentAccountContract::build_task_send_payload(
            42,
            7,
            9,
            1_800_000_100,
            &target,
            50,
            commitment,
        )
        .unwrap();
        let controller = SigningKey::from_bytes(&[0x42; 32]);
        let hash_to_sign =
            AgentAccountContract::controller_hash_to_sign(&source, 42, &payload).unwrap();
        let signature = controller.sign(&hash_to_sign).to_bytes();
        let signed =
            AgentAccountContract::build_signed_controller_message(payload.clone(), &signature)
                .unwrap();
        let message =
            AgentAccountContract::build_external_controller_message(source.clone(), signed)
                .unwrap();
        let boc = write_boc(&message).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&boc);
        let digest = canonical_file_digest(&boc);
        let cell_hash =
            format!("tvm-cell-sha256:{}", hex::encode(read_single_root_boc(&boc).unwrap().hash(0)));
        let parsed = validate_exact_sponsorship_top_up_boc(
            &boc,
            &encoded,
            &digest,
            &cell_hash,
            &source,
            42,
            9,
            1_800_000_100,
            &target,
            50,
            &payment_digest,
            &action_id,
        )
        .unwrap();
        assert_eq!(parsed.controller_epoch, 7);
        verify_parsed_controller_authorization(&parsed, controller.verifying_key().as_bytes())
            .unwrap();
        let wrong_controller = SigningKey::from_bytes(&[0x43; 32]);
        assert!(
            verify_parsed_controller_authorization(
                &parsed,
                wrong_controller.verifying_key().as_bytes(),
            )
            .is_err()
        );
        verify_current_controller_authorization(&parsed, 7, controller.verifying_key().as_bytes())
            .expect("same-epoch finalized controller authority verifies the exact signature");
        assert!(
            verify_current_controller_authorization(
                &parsed,
                7,
                wrong_controller.verifying_key().as_bytes(),
            )
            .is_err(),
            "an arbitrary nonzero signature must not pass under the bound controller key"
        );
        assert!(
            verify_current_controller_authorization(
                &parsed,
                8,
                wrong_controller.verifying_key().as_bytes(),
            )
            .is_err(),
            "the current key must not be substituted for a rotated-out signing epoch"
        );

        let zero_signed =
            AgentAccountContract::build_signed_controller_message(payload, &[0; 64]).unwrap();
        let zero_message =
            AgentAccountContract::build_external_controller_message(source.clone(), zero_signed)
                .unwrap();
        let zero_boc = write_boc(&zero_message).unwrap();
        assert!(
            validate_exact_sponsorship_top_up_boc(
                &zero_boc,
                &base64::engine::general_purpose::STANDARD.encode(&zero_boc),
                &canonical_file_digest(&zero_boc),
                &format!(
                    "tvm-cell-sha256:{}",
                    hex::encode(read_single_root_boc(&zero_boc).unwrap().hash(0))
                ),
                &source,
                42,
                9,
                1_800_000_100,
                &target,
                50,
                &payment_digest,
                &action_id,
            )
            .is_err()
        );
        assert!(
            validate_exact_sponsorship_top_up_boc(
                &boc,
                &encoded,
                &digest,
                &cell_hash,
                &source,
                42,
                9,
                1_800_000_100,
                &target,
                50,
                &format!("sha256:{}", "9".repeat(64)),
                &action_id,
            )
            .is_err()
        );

        let old_payload =
            AgentAccountContract::build_native_send_payload(42, 7, 9, 1_800_000_100, &target, 50)
                .unwrap();
        let old_signed = AgentAccountContract::build_signed_controller_message(
            old_payload,
            &controller.sign(&[0x33; 32]).to_bytes(),
        )
        .unwrap();
        let old_message =
            AgentAccountContract::build_external_controller_message(source.clone(), old_signed)
                .unwrap();
        let old_boc = write_boc(&old_message).unwrap();
        assert!(
            validate_exact_sponsorship_top_up_boc(
                &old_boc,
                &base64::engine::general_purpose::STANDARD.encode(&old_boc),
                &canonical_file_digest(&old_boc),
                &format!(
                    "tvm-cell-sha256:{}",
                    hex::encode(read_single_root_boc(&old_boc).unwrap().hash(0))
                ),
                &source,
                42,
                9,
                1_800_000_100,
                &target,
                50,
                &payment_digest,
                &action_id,
            )
            .is_err()
        );
    }

    #[test]
    fn sponsorship_destination_credit_is_terminal_even_if_optional_body_compute_aborts() {
        let expected = CurrencyCollection::with_coins(50);
        let credited_on_abort = TransactionDescrOrdinary {
            credit_first: true,
            credit_ph: Some(TrCreditPhase::new(expected.clone())),
            aborted: true,
            bounce: None,
            ..Default::default()
        };
        validate_destination_credit_semantics(&credited_on_abort, &expected).unwrap();

        let mut not_credit_first = credited_on_abort.clone();
        not_credit_first.credit_first = false;
        assert!(validate_destination_credit_semantics(&not_credit_first, &expected).is_err());

        let mut wrong_amount = credited_on_abort;
        wrong_amount.credit_ph = Some(TrCreditPhase::new(CurrencyCollection::with_coins(49)));
        assert!(validate_destination_credit_semantics(&wrong_amount, &expected).is_err());

        let pending_delivery =
            TransactionDescrOrdinary { credit_first: true, credit_ph: None, ..Default::default() };
        assert!(validate_destination_credit_semantics(&pending_delivery, &expected).is_err());
    }

    #[test]
    fn corroboration_profile_is_independent_of_member_input_order() {
        let directory = TemporaryDirectory::create("profile-order");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let (first, first_digest, first_threshold) =
            economic_payment_corroboration_profile(&test_network(), &members, 500).unwrap();
        let reversed = members.iter().rev().cloned().collect::<Vec<_>>();
        let (second, second_digest, second_threshold) =
            economic_payment_corroboration_profile(&test_network(), &reversed, 500).unwrap();
        assert_eq!(first, second);
        assert_eq!(first_digest, second_digest);
        assert_eq!(first_threshold, 2);
        assert_eq!(second_threshold, 2);
    }

    #[test]
    fn release_profile_rpc_locator_rejects_canonical_aliases() {
        assert_eq!(
            validate_release_profile_rpc_locator("https://rpc.example/jsonRPC").unwrap(),
            ("https://rpc.example/jsonRPC".to_owned(), "https://rpc.example".to_owned())
        );
        assert_eq!(
            validate_release_profile_rpc_locator("https://rpc.example").unwrap(),
            ("https://rpc.example".to_owned(), "https://rpc.example".to_owned())
        );
        for alias in [
            "HTTPS://rpc.example/jsonRPC",
            "https://RPC.example/jsonRPC",
            "https://rpc.example:443/jsonRPC",
            "https://rpc.example/jsonRPC/",
            "https://rpc.example/a//b",
            "https://rpc.example/a/../b",
            "https://rpc.example/a\\b",
        ] {
            assert!(
                validate_release_profile_rpc_locator(alias).is_err(),
                "release-profile locator alias was accepted: {alias}"
            );
        }
    }

    #[test]
    fn release_profile_member_loading_rejects_raw_locator_aliases() {
        for (case, alias, legacy) in [
            ("leading-space", " https://rpc-a.example/jsonRPC", false),
            ("uppercase-host", "https://RPC-A.example/jsonRPC", false),
            ("default-port", "https://rpc-a.example:443/jsonRPC", false),
            ("trailing-slash", "https://rpc-a.example/jsonRPC/", false),
            ("empty-segment", "https://rpc-a.example/a//b", false),
            ("dot-segment", "https://rpc-a.example/a/../b", false),
            ("legacy-leading-space", " https://rpc-a.example/jsonRPC", true),
        ] {
            let directory = TemporaryDirectory::create(&format!("profile-alias-{case}"));
            let endpoints = [
                alias.to_owned(),
                "https://rpc-b.example/jsonRPC".to_owned(),
                "https://rpc-c.example/jsonRPC".to_owned(),
            ];
            let mut paths = Vec::new();
            for (index, endpoint) in endpoints.iter().enumerate() {
                let chain_rpc = if index == 0 && legacy {
                    serde_json::json!({
                        "url": endpoint,
                        "urls": [],
                        "api_key": format!("private-key-{index}"),
                        "operator_provenance": format!("sha256:{:064x}", index + 1),
                    })
                } else {
                    serde_json::json!({
                        "urls": [endpoint],
                        "api_key": format!("private-key-{index}"),
                        "operator_provenance": format!("sha256:{:064x}", index + 1),
                    })
                };
                let value = serde_json::json!({
                    "nodes": {},
                    "chain_rpc": chain_rpc,
                    "http": {},
                    "master_wallet": null,
                    "log": null,
                });
                let path = directory.0.join(format!("member-{index}.json"));
                write_private_snapshot_file(&path, &serde_json::to_vec_pretty(&value).unwrap())
                    .unwrap();
                paths.push(path);
            }
            let quorum =
                paths[1..].iter().map(|path| path.display().to_string()).collect::<Vec<_>>();
            assert!(
                load_economic_payment_corroboration_members(&paths[0], &quorum).is_err(),
                "release-profile member loader accepted {case} alias"
            );
        }
    }

    #[test]
    fn rpc_locator_identity_matches_frozen_vectors_and_binds_path() {
        assert_eq!(
            rpc_locator_identity_digest("https://rpc-a.example/jsonRPC").unwrap(),
            "sha256:7852a333f799e340dd1ca5f6080532fc4d78fc0decb0293569235f7c2d553e52"
        );
        assert_eq!(
            rpc_locator_identity_digest("https://rpc-b.example/jsonRPC").unwrap(),
            "sha256:ca6875601647a5c18d36f1e21597c1f25767ecc07bc460282a8d388d45487ee4"
        );
        assert_eq!(
            rpc_locator_identity_digest("https://rpc-c.example/jsonRPC").unwrap(),
            "sha256:d62360d879eecb5e45c4ced25d3c856b9090f54f92040e4807df4bfd6ce998e2"
        );
        assert_eq!(
            rpc_locator_identity_digest("https://rpc-a.example/other").unwrap(),
            "sha256:e31f790d1e9b90b1598aa914a6e8ac2ec40eb4de5afc3682495fdc3928377334"
        );
    }

    #[test]
    fn corroboration_profile_is_independent_of_private_config_bytes() {
        let directory = TemporaryDirectory::create("profile-private-config");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let (first, first_digest, _) =
            economic_payment_corroboration_profile(&test_network(), &members, 500).unwrap();
        let mut differently_encoded = members.clone();
        for (index, member) in differently_encoded.iter_mut().enumerate() {
            member.content_digest = format!("sha256:{:064x}", index + 100);
        }
        let (second, second_digest, _) =
            economic_payment_corroboration_profile(&test_network(), &differently_encoded, 500)
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(first_digest, second_digest);
    }

    #[test]
    fn corroboration_profile_matches_cross_language_vector() {
        let directory = TemporaryDirectory::create("profile-vector");
        let mut members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        for (index, member) in members.iter_mut().enumerate() {
            let label = char::from(b'a' + index as u8);
            member.endpoint = format!("https://rpc-{label}.example/jsonRPC");
            member.display_origin = format!("https://rpc-{label}.example");
            member.locator_identity_digest = rpc_locator_identity_digest(&member.endpoint).unwrap();
            member.operator_provenance = format!("sha256:{}", label.to_string().repeat(64));
        }
        let network = RelayNetworkDomainPin {
            network_id: "tos:testnet".to_owned(),
            global_id: 42,
            zero_state_root_hash: format!("sha256:{}", "1".repeat(64)),
            zero_state_file_hash: format!("sha256:{}", "2".repeat(64)),
            workchain_id: 0,
        };
        let (descriptor, digest, threshold) =
            economic_payment_corroboration_profile(&network, &members, 1000).unwrap();
        assert_eq!(serde_json::to_vec(&descriptor).unwrap().len(), 1209);
        assert_eq!(threshold, 2);
        assert_eq!(
            digest,
            "sha256:bdc62291e5dde10074b58a5c5ba2c017fc2a4a89a51c8233d951105ff1d5c8f0"
        );
    }

    #[test]
    fn sponsorship_payment_cbor_matches_released_go_vectors_and_rejects_mutation() {
        let directory = TemporaryDirectory::create("payment-cbor-vector");
        let destination = format!("0:{}", "1".repeat(64));
        let value = serde_json::json!({
            "schema_version": 3,
            "owner_id": "owner:provider",
            "agent_id": "agent:provider",
            "agreement_body_digest": "sha256:73a957cd7cb5071f151469f859a44bfccabaeb0bd2e9ead1728949b33d642b7b",
            "agreement_obligation_id": "obligation:sponsorship",
            "obligation_instance_id": format!("sha256:{}", "1".repeat(64)),
            "payer_agent_id": "agent:provider",
            "payee_agent_id": "agent:client",
            "network_id": "tos:testnet",
            "network_domain_digest": "sha256:2bb4cdc2e2e1001bc54e519087598582717217b82cbfd005c0acfe03269f6a69",
            "amount": {
                "asset_namespace": "tos.native",
                "asset_identifier": "tos:testnet",
                "amount_atomic": "50",
                "unit": "nanotos"
            },
            "destination": base64::engine::general_purpose::STANDARD.encode(destination.as_bytes()),
            "settlement_adapter_uri": "tos.payment.direct.v1",
            "stable_action_id": "sha256:63376b35343ff6bd7bf2973fe21c906606b1b90aea68571fe94b88a11d5b77f1",
            "expires_at_unix": 1_800_000_100u64
        });
        let mut canonical = Vec::new();
        encode_protocol_json_cbor(&value, &mut canonical, 0).unwrap();
        assert_eq!(
            protocol_cbor_digest("tos.agreement-payment-request.v1", &canonical).unwrap(),
            "sha256:01a3bfbd898518c5fda6770cb102118a7129c6453ac0900397ad25876c892f8a"
        );
        assert_eq!(
            exact_protocol_action_request_digest(&canonical).unwrap(),
            "sha256:e32961bbde8f8489bbb216de7c5547918927aab67e353f339d51d1b625abc79d"
        );
        let path = directory.0.join("payment.cbor");
        write_private_snapshot_file(&path, &canonical).unwrap();
        let (decoded_bytes, decoded) = decode_exact_protocol_cbor(&path).unwrap();
        assert_eq!(decoded_bytes, canonical);
        assert_eq!(decoded, value);

        let mut changed = value;
        changed["destination"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(format!("0:{}", "2".repeat(64))),
        );
        let mut changed_canonical = Vec::new();
        encode_protocol_json_cbor(&changed, &mut changed_canonical, 0).unwrap();
        assert_ne!(
            protocol_cbor_digest("tos.agreement-payment-request.v1", &changed_canonical).unwrap(),
            "sha256:01a3bfbd898518c5fda6770cb102118a7129c6453ac0900397ad25876c892f8a"
        );
        assert_ne!(
            exact_protocol_action_request_digest(&changed_canonical).unwrap(),
            "sha256:e32961bbde8f8489bbb216de7c5547918927aab67e353f339d51d1b625abc79d"
        );
    }

    #[test]
    fn sponsorship_proof_bundle_digest_has_cross_language_vector() {
        let bundle = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-sponsorship-proof-bundle.v1",
            "agreement_payment_request_digest": format!("sha256:{}", "1".repeat(64)),
            "sponsorship_stable_action_id": format!("sha256:{}", "2".repeat(64)),
            "confirmation_depth": 1,
            "observations": [{
                "endpoint": "https://rpc-a.example",
                "locator_identity_digest": "sha256:7852a333f799e340dd1ca5f6080532fc4d78fc0decb0293569235f7c2d553e52",
                "operator_provenance": format!("sha256:{}", "3".repeat(64)),
                "transaction_hash": format!("sha256:{}", "4".repeat(64))
            }]
        });
        let mut canonical = Vec::new();
        encode_protocol_json_cbor(&bundle, &mut canonical, 0).unwrap();
        assert_eq!(canonical.len(), 632);
        assert_eq!(
            protocol_cbor_digest(SPONSORSHIP_FINALITY_PROOF_BUNDLE_DOMAIN, &canonical).unwrap(),
            "sha256:61280872b5cc6f30fabe301020d7a8f7c29e86a0c806bec61d3bb51bbb36414f"
        );
        let mut changed = bundle;
        changed["confirmation_depth"] = serde_json::Value::from(2);
        let mut changed_canonical = Vec::new();
        encode_protocol_json_cbor(&changed, &mut changed_canonical, 0).unwrap();
        assert_ne!(canonical, changed_canonical);
    }

    #[test]
    fn sponsorship_request_and_finality_profile_fail_closed_on_identity_or_depth_change() {
        let network = RelayNetworkDomainPin {
            network_id: "tos:testnet".into(),
            global_id: 42,
            zero_state_root_hash: format!("sha256:{}", "1".repeat(64)),
            zero_state_file_hash: format!("sha256:{}", "2".repeat(64)),
            workchain_id: 0,
        };
        assert_eq!(
            relay_network_domain_digest(&network).unwrap(),
            "sha256:2bb4cdc2e2e1001bc54e519087598582717217b82cbfd005c0acfe03269f6a69"
        );
        let source = format!("0:{}", "3".repeat(64));
        let destination = format!("0:{}", "1".repeat(64));
        let action = "sha256:63376b35343ff6bd7bf2973fe21c906606b1b90aea68571fe94b88a11d5b77f1";
        let request_digest =
            "sha256:01a3bfbd898518c5fda6770cb102118a7129c6453ac0900397ad25876c892f8a";
        let request = SponsorshipAgreementPaymentRequestV3 {
            schema_version: 3,
            owner_id: "owner:provider".into(),
            agent_id: "agent:provider".into(),
            agreement_body_digest:
                "sha256:73a957cd7cb5071f151469f859a44bfccabaeb0bd2e9ead1728949b33d642b7b".into(),
            agreement_obligation_id: "obligation:sponsorship".into(),
            obligation_instance_id: format!("sha256:{}", "1".repeat(64)),
            payer_agent_id: "agent:provider".into(),
            payee_agent_id: "agent:client".into(),
            network_id: "tos:testnet".into(),
            network_domain_digest: relay_network_domain_digest(&network).unwrap(),
            amount: super::SponsorshipAgreementAmount {
                asset_namespace: "tos.native".into(),
                asset_identifier: "tos:testnet".into(),
                amount_atomic: "50".into(),
                unit: "nanotos".into(),
            },
            destination: base64::engine::general_purpose::STANDARD.encode(destination.as_bytes()),
            settlement_adapter_uri: "tos.payment.direct.v1".into(),
            semantic_action_kind: String::new(),
            adapter_profile_digest: String::new(),
            external_system_id: String::new(),
            stable_action_id: action.into(),
            expires_at_unix: 1_800_000_100,
        };
        let commitment =
            AgentAccountContract::build_sponsorship_payment_commitment(request_digest, action)
                .unwrap();
        let claim = ControllerActionClaim {
            account: source.clone(),
            network_global_id: 42,
            network_domain: Some(network.clone()),
            deployment_id: "5".repeat(64),
            controller_epoch: 7,
            seqno: 9,
            target: destination.clone(),
            value_atomic: 50,
            body_hash: Some(format!("tvm-cell-sha256:{}", hex::encode(commitment.hash(0)))),
            action_kind: "agent-task-send".into(),
            idempotency_key: action[7..].into(),
            action_identity: action.into(),
            valid_until: 1_800_000_100,
        };
        let authorization = EconomicActionAuthorization {
            schema_version: 3,
            authority_id: "authority:provider".into(),
            owner_id: request.owner_id.clone(),
            agent_id: request.agent_id.clone(),
            source_account: source,
            network_id: request.network_id.clone(),
            network_global_id: 42,
            network_domain: Some(network.clone()),
            stable_action_id: action.into(),
            exact_request_digest:
                "sha256:e32961bbde8f8489bbb216de7c5547918927aab67e353f339d51d1b625abc79d".into(),
            agreement_payment_request_digest: Some(request_digest.into()),
            sponsorship_finality_profile_cbor_digest: Some(format!("sha256:{}", "a".repeat(64))),
            sponsorship_release_profile_digest: Some(format!("sha256:{}", "b".repeat(64))),
            sponsorship_corroboration_snapshot_identity: Some(format!("sha256:{}", "c".repeat(64))),
            writer_generation: 1,
            writer_fence_digest: format!("sha256:{}", "3".repeat(64)),
            policy_revision: 1,
            mandate_digest: format!("sha256:{}", "4".repeat(64)),
            approval_digest_or_zero: format!("sha256:{}", "0".repeat(64)),
            agreement_body_digest: request.agreement_body_digest.clone(),
            obligation_instance_id: request.obligation_instance_id.clone(),
            destination,
            amount_atomic: 50,
            expires_at_unix: request.expires_at_unix,
            public_key: format!("ed25519:{}", "6".repeat(64)),
            proof: format!("ed25519:{}", "7".repeat(128)),
        };
        let record = ControllerActionRecord {
            claim,
            status: ControllerActionStatus::Broadcasting,
            exact_signed_boc_base64: None,
            exact_signed_boc_digest: Some(format!("sha256:{}", "8".repeat(64))),
            cancellation_identity: None,
            cancellation_boc_base64: None,
            economic_authorization: Some(authorization.clone()),
            economic_effect_authorization: None,
            exact_winner_resolution: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        validate_sponsorship_payment_request(
            &request,
            authorization.agreement_payment_request_digest.as_deref().unwrap(),
            &authorization.exact_request_digest,
            &network,
            &record,
            &authorization,
        )
        .unwrap();
        validate_sponsorship_custody_evidence_context(
            &authorization,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
            &format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap();
        assert!(
            validate_sponsorship_custody_evidence_context(
                &authorization,
                &format!("sha256:{}", "d".repeat(64)),
                &format!("sha256:{}", "b".repeat(64)),
                &format!("sha256:{}", "c".repeat(64)),
            )
            .is_err()
        );
        let mut changed = request.clone();
        changed.stable_action_id = format!("sha256:{}", "9".repeat(64));
        assert!(
            validate_sponsorship_payment_request(
                &changed,
                authorization.agreement_payment_request_digest.as_deref().unwrap(),
                &authorization.exact_request_digest,
                &network,
                &record,
                &authorization,
            )
            .is_err()
        );

        let profile = SponsorshipFinalityProfile {
            profile_uri: SPONSORSHIP_CORROBORATED_TERMINAL_PROFILE_URI.into(),
            profile_digest: format!("sha256:{}", "a".repeat(64)),
            terminal_evidence_class: "client_corroborated".into(),
            minimum_confirmation_depth: 1,
            minimum_observers: 2,
            minimum_operator_domains: 2,
            reorg_window_seconds: 0,
            maximum_resolution_seconds: 300,
        };
        validate_sponsorship_finality_profile(&profile, 3).unwrap();
        let mut wrong_class = profile.clone();
        wrong_class.terminal_evidence_class = "validator_finality".into();
        assert!(validate_sponsorship_finality_profile(&wrong_class, 3).is_err());
        let mut too_deep = profile;
        too_deep.minimum_confirmation_depth = 2;
        assert!(validate_sponsorship_finality_profile(&too_deep, 3).is_err());
        let mut observed_only = too_deep;
        observed_only.minimum_confirmation_depth = 1;
        observed_only.profile_uri = "agreement-payment-rpc-corroboration.v1".into();
        assert!(validate_sponsorship_finality_profile(&observed_only, 3).is_err());
    }

    #[test]
    fn frozen_corroboration_snapshot_rejects_profile_and_config_mutation() {
        let directory = TemporaryDirectory::create("frozen-profile");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest.clone(),
        )
        .unwrap();

        let (restored, restored_members, threshold) = load_economic_payment_corroboration_snapshot(
            &manifest,
            &digest,
            &snapshot.snapshot_identity,
        )
        .unwrap();
        assert_eq!(restored.snapshot_identity, snapshot.snapshot_identity);
        assert_eq!(restored_members.len(), 3);
        assert_eq!(threshold, 2);

        let wrong_digest = format!("sha256:{}", "ff".repeat(32));
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &wrong_digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &format!("sha256:{}", "ee".repeat(32)),
            )
            .is_err()
        );

        // Change only a credential, leaving endpoint and operator identity
        // untouched. The exact content binding must still reject the member.
        let member_path = manifest.parent().unwrap().join(&snapshot.members[0].config_path);
        let mut member: serde_json::Value =
            serde_json::from_slice(&fs::read(&member_path).unwrap()).unwrap();
        member["chain_rpc"]["api_key"] = serde_json::json!("rotated-after-quote");
        fs::write(&member_path, serde_json::to_vec_pretty(&member).unwrap()).unwrap();
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
    }

    #[test]
    fn frozen_corroboration_snapshot_nonce_randomizes_private_identity() {
        let directory = TemporaryDirectory::create("snapshot-nonce");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (first_manifest, first) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network.clone(),
            &members,
            500,
            descriptor.clone(),
            digest.clone(),
        )
        .unwrap();
        let (second_manifest, second) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest,
        )
        .unwrap();

        for snapshot in [&first, &second] {
            assert_eq!(snapshot.snapshot_nonce.len(), 64);
            assert!(
                snapshot
                    .snapshot_nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(snapshot.members.iter().all(|member| {
                !Path::new(&member.config_path).is_absolute()
                    && Path::new(&member.config_path).components().count() == 1
            }));
        }
        assert_ne!(first.snapshot_nonce, second.snapshot_nonce);
        assert_ne!(first.snapshot_identity, second.snapshot_identity);
        assert_ne!(first_manifest, second_manifest);
        assert_eq!(first.evidence_profile_digest, second.evidence_profile_digest);
    }

    #[test]
    fn frozen_corroboration_snapshot_rejects_member_path_escape() {
        let directory = TemporaryDirectory::create("snapshot-member-path");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest.clone(),
        )
        .unwrap();
        let original_manifest = fs::read(&manifest).unwrap();

        for escaped in [
            "../member-000.json",
            "/tmp/member-000.json",
            "nested/member-000.json",
            "nested\\member-000.json",
            ".",
            "..",
        ] {
            let mut mutated = snapshot.clone();
            mutated.members[0].config_path = escaped.to_owned();
            fs::write(&manifest, serde_json::to_vec_pretty(&mutated).unwrap()).unwrap();
            let error = load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &snapshot.snapshot_identity,
            )
            .err()
            .expect("snapshot member path escape accepted");
            assert!(error.to_string().contains("one relative basename"));
        }
        fs::write(&manifest, original_manifest).unwrap();
        load_economic_payment_corroboration_snapshot(
            &manifest,
            &digest,
            &snapshot.snapshot_identity,
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn frozen_corroboration_snapshot_rejects_symlink_manifest() {
        use std::os::unix::fs::symlink;

        let directory = TemporaryDirectory::create("snapshot-symlink");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest.clone(),
        )
        .unwrap();
        let link = directory.0.join("manifest-link.json");
        symlink(&manifest, &link).unwrap();
        assert!(
            load_economic_payment_corroboration_snapshot(
                &link,
                &digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn frozen_corroboration_snapshot_rejects_symlink_member() {
        use std::os::unix::fs::symlink;

        let directory = TemporaryDirectory::create("snapshot-member-symlink");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest.clone(),
        )
        .unwrap();
        let member = manifest.parent().unwrap().join(&snapshot.members[0].config_path);
        let target = directory.0.join("source-0.json");
        fs::remove_file(&member).unwrap();
        symlink(target, member).unwrap();
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn frozen_corroboration_snapshot_rejects_hardlinked_manifest_and_member() {
        let directory = TemporaryDirectory::create("snapshot-hardlinks");
        let members =
            (0..3).map(|index| test_corroboration_member(&directory.0, index)).collect::<Vec<_>>();
        let network = test_network();
        let (descriptor, digest, _) =
            economic_payment_corroboration_profile(&network, &members, 500).unwrap();
        let (manifest, snapshot) = freeze_economic_payment_corroboration_snapshot(
            &directory.0,
            network,
            &members,
            500,
            descriptor,
            digest.clone(),
        )
        .unwrap();

        let member = manifest.parent().unwrap().join(&snapshot.members[0].config_path);
        let member_alias = directory.0.join("member-hardlink-alias.json");
        fs::hard_link(&member, &member_alias).unwrap();
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
        fs::remove_file(member_alias).unwrap();
        load_economic_payment_corroboration_snapshot(
            &manifest,
            &digest,
            &snapshot.snapshot_identity,
        )
        .unwrap();

        let manifest_alias = directory.0.join("manifest-hardlink-alias.json");
        fs::hard_link(&manifest, manifest_alias).unwrap();
        assert!(
            load_economic_payment_corroboration_snapshot(
                &manifest,
                &digest,
                &snapshot.snapshot_identity,
            )
            .is_err()
        );
    }

    #[test]
    fn validates_controller_task_authority_and_lifecycle() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let context = controller_task_context(&task_address);
        validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap();
        validate_controller_task_action(
            &AgentTaskOperation::Reject,
            &controller_task(0),
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap();
        let mut open_task = controller_task(0);
        open_task.assigned_agent = None;
        validate_controller_task_action(
            &AgentTaskOperation::Claim,
            &open_task,
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap();
        validate_controller_task_action(
            &AgentTaskOperation::Result,
            &controller_task(1),
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap();

        let wrong_account = validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(4),
            permission_hash,
            &context,
        )
        .unwrap_err();
        assert!(wrong_account.to_string().contains("not assigned"));

        let wrong_permission = validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(2),
            [9; 32],
            &context,
        )
        .unwrap_err();
        assert!(wrong_permission.to_string().contains("permission ID"));

        let wrong_status = validate_controller_task_action(
            &AgentTaskOperation::Result,
            &controller_task(0),
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap_err();
        assert!(wrong_status.to_string().contains("must be accepted"));

        let assigned_claim = validate_controller_task_action(
            &AgentTaskOperation::Claim,
            &controller_task(0),
            &address(2),
            permission_hash,
            &context,
        )
        .unwrap_err();
        assert!(assigned_claim.to_string().contains("already assigned"));
    }

    #[test]
    fn controller_settle_matches_contract_state_authority_and_limits() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let context = controller_task_context(&task_address);
        let mut task = controller_task(2);
        task.review_deadline = 100;
        task.verifier = Some(address(3));

        for authorized in [address(1), address(3)] {
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &authorized,
                permission_hash,
                &context,
            )
            .unwrap();
        }

        let mut wrong_status = task.clone();
        wrong_status.status = 1;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &wrong_status,
                &address(1),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("must be result_submitted")
        );
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(2),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("creator or designated verifier")
        );

        let mut expired = controller_task_context(&task_address);
        expired.now = 101;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &expired,
            )
            .is_err()
        );
        let mut excessive = controller_task_context(&task_address);
        excessive.payout = Some(task.budget + 1);
        excessive.available_balance = task.budget + 1;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &excessive,
            )
            .unwrap_err()
            .to_string()
            .contains("remaining budget")
        );
        let mut insufficient_balance = controller_task_context(&task_address);
        insufficient_balance.available_balance = 499_999_999;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &insufficient_balance,
            )
            .unwrap_err()
            .to_string()
            .contains("available balance")
        );
    }

    #[test]
    fn controller_timeout_matches_contract_deadlines_and_has_no_sender_restriction() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let mut context = controller_task_context(&task_address);
        context.now = 100;

        for status in [0, 1] {
            let mut task = controller_task(status);
            task.deadline = 100;
            validate_controller_task_action(
                &AgentTaskOperation::Timeout,
                &task,
                &address(55),
                permission_hash,
                &context,
            )
            .unwrap();
        }
        let mut submitted = controller_task(2);
        submitted.review_deadline = 100;
        validate_controller_task_action(
            &AgentTaskOperation::Timeout,
            &submitted,
            &address(55),
            permission_hash,
            &context,
        )
        .unwrap();

        let mut too_early = controller_task(0);
        too_early.deadline = 101;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Timeout,
                &too_early,
                &address(55),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("has not passed")
        );
        let mut review_too_early = controller_task(2);
        review_too_early.review_deadline = 101;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Timeout,
                &review_too_early,
                &address(55),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("review deadline has not passed")
        );
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Timeout,
                &controller_task(3),
                &address(55),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("open, accepted or result_submitted")
        );
    }

    #[test]
    fn controller_dispute_matches_contract_state_authority_and_window() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let context = controller_task_context(&task_address);
        let mut task = controller_task(2);
        task.verifier = Some(address(3));
        task.review_deadline = 100;
        validate_controller_task_action(
            &AgentTaskOperation::Dispute,
            &task,
            &address(1),
            permission_hash,
            &context,
        )
        .unwrap();

        let mut wrong_status = task.clone();
        wrong_status.status = 1;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Dispute,
                &wrong_status,
                &address(1),
                permission_hash,
                &context,
            )
            .is_err()
        );
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Dispute,
                &task,
                &address(3),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("creator Agent Account")
        );
        let mut no_verifier = task.clone();
        no_verifier.verifier = None;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Dispute,
                &no_verifier,
                &address(1),
                permission_hash,
                &context,
            )
            .is_err()
        );
        let mut zero_hash = controller_task_context(&task_address);
        zero_hash.dispute_hash = Some([0; 32]);
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Dispute,
                &task,
                &address(1),
                permission_hash,
                &zero_hash,
            )
            .is_err()
        );
        let mut expired = controller_task_context(&task_address);
        expired.now = 101;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Dispute,
                &task,
                &address(1),
                permission_hash,
                &expired,
            )
            .unwrap_err()
            .to_string()
            .contains("review deadline has passed")
        );
    }

    #[test]
    fn controller_resolve_matches_contract_state_authority_and_limits() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let context = controller_task_context(&task_address);
        let mut task = controller_task(7);
        task.verifier = Some(address(3));
        validate_controller_task_action(
            &AgentTaskOperation::Resolve,
            &task,
            &address(3),
            permission_hash,
            &context,
        )
        .unwrap();

        let mut wrong_status = task.clone();
        wrong_status.status = 2;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Resolve,
                &wrong_status,
                &address(3),
                permission_hash,
                &context,
            )
            .is_err()
        );
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Resolve,
                &task,
                &address(1),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("designated verifier")
        );
        let mut insufficient_balance = controller_task_context(&task_address);
        insufficient_balance.available_balance = 499_999_999;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Resolve,
                &task,
                &address(3),
                permission_hash,
                &insufficient_balance,
            )
            .unwrap_err()
            .to_string()
            .contains("available balance")
        );
        let mut excessive = controller_task_context(&task_address);
        excessive.payout = Some(task.budget + 1);
        excessive.available_balance = task.budget + 1;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Resolve,
                &task,
                &address(3),
                permission_hash,
                &excessive,
            )
            .unwrap_err()
            .to_string()
            .contains("remaining budget")
        );
    }

    #[test]
    fn controller_cancel_matches_contract_state_and_creator_authority() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let context = controller_task_context(&task_address);
        validate_controller_task_action(
            &AgentTaskOperation::Cancel,
            &controller_task(0),
            &address(1),
            permission_hash,
            &context,
        )
        .unwrap();
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Cancel,
                &controller_task(1),
                &address(1),
                permission_hash,
                &context,
            )
            .is_err()
        );
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Cancel,
                &controller_task(0),
                &address(2),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("creator Agent Account")
        );
    }

    #[test]
    fn controller_attestation_is_bound_to_task_state_and_payout() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        let task_address = address(9);
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let mut task = controller_task(2);
        task.review_deadline = 100;
        task.result_hash = [8; 32];
        task.attestor_pubkey = Some(signing_key.verifying_key().to_bytes());
        let domain =
            contracts::settle_domain_hash(&task_address, &task.result_hash, 500_000_000).unwrap();
        let signature = signing_key.sign(&domain).to_bytes();
        let mut context = controller_task_context(&task_address);
        context.attestation_signature = Some(&signature);
        validate_controller_task_action(
            &AgentTaskOperation::Settle,
            &task,
            &address(1),
            permission_hash,
            &context,
        )
        .unwrap();

        let mut task_without_attestor = task.clone();
        task_without_attestor.attestor_pubkey = None;
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task_without_attestor,
                &address(1),
                permission_hash,
                &context,
            )
            .unwrap_err()
            .to_string()
            .contains("has no attestor")
        );

        let missing = controller_task_context(&task_address);
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &missing,
            )
            .is_err()
        );
        let mut changed_payout = controller_task_context(&task_address);
        changed_payout.payout = Some(400_000_000);
        changed_payout.attestation_signature = Some(&signature);
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &changed_payout,
            )
            .is_err()
        );
        let other_task_address = address(10);
        let mut other_task = controller_task_context(&other_task_address);
        other_task.attestation_signature = Some(&signature);
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Settle,
                &task,
                &address(1),
                permission_hash,
                &other_task,
            )
            .is_err()
        );

        let mut disputed = task.clone();
        disputed.status = 7;
        disputed.verifier = Some(address(3));
        disputed.dispute_hash = [11; 32];
        let resolve_domain = contracts::resolve_domain_hash(
            &task_address,
            &disputed.result_hash,
            &disputed.dispute_hash,
            500_000_000,
        )
        .unwrap();
        let resolve_signature = signing_key.sign(&resolve_domain).to_bytes();
        let mut resolve_context = controller_task_context(&task_address);
        resolve_context.attestation_signature = Some(&resolve_signature);
        validate_controller_task_action(
            &AgentTaskOperation::Resolve,
            &disputed,
            &address(3),
            permission_hash,
            &resolve_context,
        )
        .unwrap();

        disputed.dispute_hash = [12; 32];
        assert!(
            validate_controller_task_action(
                &AgentTaskOperation::Resolve,
                &disputed,
                &address(3),
                permission_hash,
                &resolve_context,
            )
            .is_err()
        );
    }

    #[test]
    fn controller_resolution_accepts_every_contract_terminal_state() {
        for (operation, accepted) in [
            (AgentTaskOperation::Dispute, vec![7]),
            (AgentTaskOperation::Resolve, vec![3]),
            (AgentTaskOperation::Settle, vec![3]),
            (AgentTaskOperation::Cancel, vec![4]),
            (AgentTaskOperation::Timeout, vec![3, 5]),
        ] {
            for status in 0..=7 {
                assert_eq!(
                    operation.accepts_resolved_status(status).unwrap(),
                    accepted.contains(&status),
                    "{} status {}",
                    operation.as_str(),
                    status
                );
            }
        }
    }
}
