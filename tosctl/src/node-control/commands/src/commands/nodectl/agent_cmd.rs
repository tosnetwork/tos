/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use super::capability_registry_cmd::CapabilityRegistryCmd;
use super::aipow_cmd::AipowCmd;
use super::aipow_dist_cmd::AipowDistCmd;
use super::dispute_cmd::DisputeCmd;
use super::output_format::OutputFormat;
use super::proof_attestation_cmd::ProofAttestationCmd;
use super::service_actor_cmd::ServiceActorCmd;
use super::utils::{
    DEPLOY_TIMEOUT, SEND_TIMEOUT, calculate_wallet_address, get_wallet_config, load_config_vault,
    load_config_vault_rpc_client, make_wallet, save_config, try_create_rpc_client, wait_for_deploy,
    wait_for_seqno_change, wallet_info,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::data_models::AccountState;
use clap::ValueEnum;
use colored::Colorize;
use common::{
    WalletVersion,
    app_config::{
        AgentRuntimeBinding, AgentTaskConfig, AgentWalletConfig, AgentWalletPolicy, KeyConfig,
        WalletConfig,
    },
    chain_utils::{display_tos, tos_to_nanotos},
    time_format,
};
use contracts::{
    AgentAccountContract, AgentAccountData, AgentAccountInit, AgentAccountPolicyUpdate,
    TaskEscrowContract, TaskEscrowData, TaskEscrowInit, Wallet,
};
use futures_util::{StreamExt, stream};
use secrets_vault::types::{
    algorithm::Algorithm, secret::Secret, secret_id::SecretId, secret_spec::SecretSpec,
};
use secrets_vault::vault::SecretVault;
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, str::FromStr};

const AGENT_WALLET_FUND_GAS: u64 = 1_000_000; // 0.001 TOS
const AGENT_ACCOUNT_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const AGENT_ACCOUNT_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

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
    /// AIPoW score-commitment operations
    Aipow(AipowCmd),
    /// AIPoW reward distributor operations
    AipowDist(AipowDistCmd),
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
        help = "Sign the on-chain result_hash with this vault key instead of passing --attestation-signature directly"
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
    #[arg(long, help = "Skip confirmation prompt")]
    yes: bool,
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
            AgentAction::Aipow(cmd) => cmd.run(&self.config).await,
            AgentAction::AipowDist(cmd) => cmd.run(&self.config).await,
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
) -> anyhow::Result<()> {
    if task.permission_hash != permission_hash {
        anyhow::bail!("local permission ID does not match the Task Escrow on-chain hash");
    }
    let (expected_status, expected_name) = match operation {
        AgentTaskOperation::Accept => (0, "open"),
        AgentTaskOperation::Claim => (0, "open"),
        AgentTaskOperation::Reject => (0, "open"),
        AgentTaskOperation::Result => (1, "accepted"),
        _ => anyhow::bail!(
            "--via-agent-account supports only claim, accept, reject and result operations"
        ),
    };
    if task.status != expected_status {
        anyhow::bail!(
            "Task Escrow must be {} for this controller action (current status: {})",
            expected_name,
            task_status_name(task.status)
        );
    }
    match operation {
        AgentTaskOperation::Claim if task.assigned_agent.is_some() => {
            anyhow::bail!("Task Escrow is already assigned and cannot be claimed")
        }
        AgentTaskOperation::Claim => {}
        _ if task.assigned_agent.as_ref() != Some(agent_account) => {
            anyhow::bail!("Task Escrow is not assigned to the selected Agent Account")
        }
        _ => {}
    }
    Ok(())
}

impl AgentTaskSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let amount_nanotos =
            resolve_nanotos("amount", self.amount, self.amount_nanotos, Some(0.01))?;
        let mut body: Option<Cell> = match self.operation {
            AgentTaskOperation::Accept => Some(TaskEscrowContract::accept(self.query_id)?),
            AgentTaskOperation::Claim => Some(TaskEscrowContract::claim(self.query_id)?),
            AgentTaskOperation::Reject => Some(TaskEscrowContract::reject(self.query_id)?),
            AgentTaskOperation::Result => Some(TaskEscrowContract::result(
                self.query_id,
                parse_required_hash("result-hash", &self.result_hash)?,
                parse_required_hash("evidence-hash", &self.evidence_hash)?,
            )?),
            AgentTaskOperation::Dispute => Some(TaskEscrowContract::dispute(
                self.query_id,
                parse_required_hash("dispute-hash", &self.dispute_hash)?,
            )?),
            AgentTaskOperation::Resolve => {
                let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
                match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
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
                match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
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
            let vault_key = self.signer_vault_key.as_deref().expect("checked above");
            match self.operation {
                AgentTaskOperation::Settle => {
                    let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
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
                    body =
                        Some(TaskEscrowContract::settle_signed(self.query_id, payout, &signature)?);
                }
                AgentTaskOperation::Resolve => {
                    let payout = resolve_payout_nanotos(self.payout, self.payout_nanotos)?;
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
                            .expect("vault key provided");
                    body = Some(TaskEscrowContract::rotate_attestor_key(self.query_id, pubkey)?);
                }
                _ => unreachable!(
                    "only settle, resolve and rotate-attestor-key defer body resolution"
                ),
            }
        }
        let body = body.expect("body resolved for every operation");
        if let Some(agent_wallet) = &self.via_agent_account {
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
            let provider = contracts::contract_provider!(rpc_client.clone());
            let stack =
                provider.get_method(destination.to_string(), "get_task_data", vec![]).await?;
            let chain_task = TaskEscrowContract::decode_data(&stack)?;
            validate_controller_task_action(
                &self.operation,
                &chain_task,
                &account,
                permission_id_hash(record.permission_id.as_deref()),
            )?;
            let body_boc = base64::engine::general_purpose::STANDARD.encode(write_boc(&body)?);
            return AgentAccountTaskSendCmd {
                wallet: agent_wallet.clone(),
                target: destination.to_string(),
                value: nanotos_to_tos_f64(amount_nanotos)?,
                body_boc: Some(body_boc),
                valid_until: self.valid_until.unwrap_or_else(|| time_format::now() as u32 + 300),
                yes: self.yes,
            }
            .run(config_path)
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
                    Err(error) => record.chain_error = Some(format!("{error:#}")),
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
        let (config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;

        let (init, owner_address) =
            build_agent_account_init(&self.wallet, agent_wallet, vault).await?;
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
        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;

        let (init, _owner_address) =
            build_agent_account_init(&self.wallet, agent_wallet, vault.clone()).await?;
        let owner = init.owner.clone();
        let state_init = AgentAccountContract::build_state_init(&init)?;
        let address = AgentAccountContract::calculate_address(self.workchain, &init)?;
        let address_info = rpc_client.get_address_information(&address).await?;
        if address_info.state == AccountState::Active {
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
            payer: self.from.clone(),
            payer_address: payer_address.to_string(),
            amount: display_tos(amount_nanotos),
            code_hash: hex::encode(code_cell.hash(0)),
            data_hash: hex::encode(data_cell.hash(0)),
            status: "deployed".to_string(),
        };
        config
            .agent_wallets
            .get_mut(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?
            .agent_account_address = Some(address.to_string());
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
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
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
        let payload = AgentAccountContract::build_task_send_payload(
            data.seqno,
            self.valid_until,
            &target,
            value,
            body,
        )?;
        let hash_to_sign = AgentAccountContract::task_send_hash_to_sign(&account, &payload)?;
        let signature = keypair.sign(&hash_to_sign).await?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
        let signed = AgentAccountContract::build_signed_task_send_message(payload, &signature)?;
        let message =
            AgentAccountContract::build_external_task_send_message(account.clone(), signed)?;
        if !self.yes && !confirm(&format!("Send controller action from {}?", account))? {
            return Ok(());
        }
        rpc_client.send_boc(&write_boc(&message)?).await?;
        println!("{} controller task action sent from {}", "OK".green().bold(), account);
        Ok(())
    }
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

    Ok((
        AgentAccountInit {
            owner,
            controller_pubkey,
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
fn resolve_payout_nanotos(value_tos: Option<f64>, value_nanotos: Option<u64>) -> anyhow::Result<u64> {
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
        AgentTaskOperation, permission_id_hash, resolve_nanotos, resolve_payout_nanotos,
        validate_controller_task_action,
    };
    use chain_block::MsgAddressInt;
    use contracts::TaskEscrowData;

    fn address(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
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
    fn validates_controller_task_authority_and_lifecycle() {
        let permission_hash = permission_id_hash(Some("bounded-task"));
        validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(2),
            permission_hash,
        )
        .unwrap();
        validate_controller_task_action(
            &AgentTaskOperation::Reject,
            &controller_task(0),
            &address(2),
            permission_hash,
        )
        .unwrap();
        let mut open_task = controller_task(0);
        open_task.assigned_agent = None;
        validate_controller_task_action(
            &AgentTaskOperation::Claim,
            &open_task,
            &address(2),
            permission_hash,
        )
        .unwrap();
        validate_controller_task_action(
            &AgentTaskOperation::Result,
            &controller_task(1),
            &address(2),
            permission_hash,
        )
        .unwrap();

        let wrong_account = validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(4),
            permission_hash,
        )
        .unwrap_err();
        assert!(wrong_account.to_string().contains("not assigned"));

        let wrong_permission = validate_controller_task_action(
            &AgentTaskOperation::Accept,
            &controller_task(0),
            &address(2),
            [9; 32],
        )
        .unwrap_err();
        assert!(wrong_permission.to_string().contains("permission ID"));

        let wrong_status = validate_controller_task_action(
            &AgentTaskOperation::Result,
            &controller_task(0),
            &address(2),
            permission_hash,
        )
        .unwrap_err();
        assert!(wrong_status.to_string().contains("must be accepted"));

        let assigned_claim = validate_controller_task_action(
            &AgentTaskOperation::Claim,
            &controller_task(0),
            &address(2),
            permission_hash,
        )
        .unwrap_err();
        assert!(assigned_claim.to_string().contains("already assigned"));
    }
}
