/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use super::agent_cmd::{
    confirm, parse_optional_hash, parse_optional_signature, parse_required_hash,
    resolve_attestor_pubkey, send_wallet_message, send_wallet_message_with_state_init,
    sign_hash_with_vault_key, validate_tos_amount,
};
use super::output_format::OutputFormat;
use super::utils::{
    get_wallet_config, load_config_vault_rpc_client, make_wallet, save_config,
    try_create_rpc_client, wallet_info,
};
use anyhow::Context;
use chain_block::{BuilderData, MsgAddressInt};
use chain_rpc_client::v2::data_models::AccountState;
use clap::ValueEnum;
use colored::Colorize;
use common::{
    app_config::ServiceActorConfig,
    chain_utils::{display_tos, tos_to_nanotos},
    time_format,
};
use contracts::{
    PendingRequestData, RefundData, ServiceActorContract, ServiceActorData, ServiceActorInit,
};
use futures_util::{StreamExt, stream};
use std::{path::Path, str::FromStr};

const SERVICE_ACTOR_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const SERVICE_ACTOR_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent service` -- Service Actor operations.
#[derive(clap::Args, Clone)]
#[command(about = "Service Actor operations")]
pub struct ServiceActorCmd {
    #[command(subcommand)]
    action: ServiceActorAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ServiceActorAction {
    /// Deploy and fund a Service Actor
    Deploy(ServiceActorDeployCmd),
    /// List locally tracked Service Actor records
    Ls(ServiceActorLsCmd),
    /// Show Service Actor policy/accounting state by address or local record name
    Show(ServiceActorShowCmd),
    /// Show a single request by ID (`get_request`)
    RequestShow(ServiceActorRequestShowCmd),
    /// Show a single unclaimed refund by request ID (`get_refund`)
    RefundShow(ServiceActorRefundShowCmd),
    /// Send a Service Actor lifecycle message
    Send(ServiceActorSendCmd),
    /// Build deterministic Service Actor StateInit
    BuildState(ServiceActorBuildStateCmd),
}

impl ServiceActorCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            ServiceActorAction::Deploy(cmd) => cmd.run(config_path).await,
            ServiceActorAction::Ls(cmd) => cmd.run(config_path).await,
            ServiceActorAction::Show(cmd) => cmd.run(config_path).await,
            ServiceActorAction::RequestShow(cmd) => cmd.run(config_path).await,
            ServiceActorAction::RefundShow(cmd) => cmd.run(config_path).await,
            ServiceActorAction::Send(cmd) => cmd.run(config_path).await,
            ServiceActorAction::BuildState(cmd) => cmd.run(),
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy and fund a Service Actor")]
pub struct ServiceActorDeployCmd {
    #[arg(long, help = "Local service record name; defaults to service-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Owner address; must match the funding wallet")]
    owner: String,
    #[arg(
        long,
        conflicts_with = "open_access",
        help = "Single caller authorized to call this service"
    )]
    authorized_caller: Option<String>,
    #[arg(long, conflicts_with = "authorized_caller", help = "Allow any caller")]
    open_access: bool,
    #[arg(long, help = "Price per call, in TOS")]
    price_per_call: f64,
    #[arg(
        long,
        help = "Fixed, non-refundable fee collected alongside price-per-call at call time, in TOS \
                (must cover the protocol's MINIMUM_STORAGE_FEE plus cleanup-bounty)"
    )]
    storage_fee: f64,
    #[arg(
        long,
        help = "Paid to whoever calls sweep-expired-request once a request's rights window \
                lapses, in TOS (bounded by the protocol's MINIMUM/MAXIMUM_CLEANUP_BOUNTY)"
    )]
    cleanup_bounty: f64,
    #[arg(long, default_value_t = 0, help = "Max calls accepted per day; 0 means unlimited")]
    rate_limit_per_day: u32,
    #[arg(long, help = "Seconds a submitted call has to be responded to")]
    response_sla: u32,
    #[arg(
        long,
        help = "Seconds after response_deadline an expired request's refund stays claimable"
    )]
    refund_claim_window: u32,
    #[arg(long, help = "32-byte hash of general service metadata")]
    metadata_hash: String,
    #[arg(long, help = "32-byte hash identifying the supported proof/attestation scheme")]
    proof_scheme_hash: String,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "Optional 32-byte ed25519 public key; when set, respond also requires a signature \
                over the request-bound attestation domain"
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
    #[arg(long, default_value_t = 0.2, help = "Message value funding the deploy, in TOS")]
    amount: f64,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(long)]
    yes: bool,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked Service Actor records")]
pub struct ServiceActorLsCmd {
    #[arg(long, help = "Read current policy/accounting state from each service")]
    on_chain: bool,
    #[arg(long, help = "Filter by owner address")]
    owner: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Service Actor policy/accounting state by address or local record name")]
pub struct ServiceActorShowCmd {
    #[arg(long, conflicts_with = "name", help = "Service Actor address")]
    address: Option<String>,
    #[arg(long, help = "Local service record name from `agent service ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a single request by ID")]
pub struct ServiceActorRequestShowCmd {
    #[arg(long, conflicts_with = "name", help = "Service Actor address")]
    address: Option<String>,
    #[arg(long, help = "Local service record name from `agent service ls`")]
    name: Option<String>,
    #[arg(long, help = "Request ID assigned by `call`")]
    request_id: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a single unclaimed refund by request ID")]
pub struct ServiceActorRefundShowCmd {
    #[arg(long, conflicts_with = "name", help = "Service Actor address")]
    address: Option<String>,
    #[arg(long, help = "Local service record name from `agent service ls`")]
    name: Option<String>,
    #[arg(long, help = "Request ID the refund was created for (see `agent service request-show`)")]
    request_id: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum ServiceActorOperation {
    Call,
    Respond,
    Expire,
    ClaimRefund,
    SweepExpiredRequest,
    UpdatePolicy,
    WithdrawRevenue,
    RotateAttestorKey,
    RevokeAttestor,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a Service Actor lifecycle message")]
pub struct ServiceActorSendCmd {
    #[arg(long, value_enum)]
    operation: ServiceActorOperation,
    #[arg(long, conflicts_with = "name", help = "Service Actor address")]
    address: Option<String>,
    #[arg(long, help = "Local service record name from `agent service ls`")]
    name: Option<String>,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "Request hash for call")]
    request_hash: Option<String>,
    #[arg(
        long,
        help = "Request ID for respond, expire, claim-refund, sweep-expired-request (see \
                `agent service request-show`/`refund-show`, or the ID printed by `call`)"
    )]
    request_id: Option<u64>,
    #[arg(long, help = "Response hash for respond")]
    response_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "64-byte ed25519 signature over the request-bound attestation domain hash, for \
                respond on a service deployed with --attestor-pubkey"
    )]
    attestation_signature: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestation_signature",
        help = "Sign the request-bound attestation domain hash with this vault key instead of \
                passing --attestation-signature directly (fetches the request's on-chain terms \
                first, since the domain binds them)"
    )]
    signer_vault_key: Option<String>,
    #[arg(long, help = "Refund destination address for claim-refund")]
    destination: Option<String>,
    #[arg(long, help = "New price per call, in TOS, for update-policy")]
    price_per_call: Option<f64>,
    #[arg(long, help = "New storage fee, in TOS, for update-policy")]
    storage_fee: Option<f64>,
    #[arg(long, help = "New cleanup bounty, in TOS, for update-policy")]
    cleanup_bounty: Option<f64>,
    #[arg(long, help = "New response SLA, in seconds, for update-policy")]
    response_sla: Option<u32>,
    #[arg(long, help = "New refund claim window, in seconds, for update-policy")]
    refund_claim_window: Option<u32>,
    #[arg(
        long,
        help = "New active flag for update-policy (there is no separate deactivate/reactivate op \
                any more -- toggle it here alongside the rest of the policy)"
    )]
    active: Option<bool>,
    #[arg(long, help = "New rate limit per day for update-policy; 0 means unlimited")]
    rate_limit_per_day: Option<u32>,
    #[arg(long, conflicts_with = "authorized_caller", help = "Set open access for update-policy")]
    open_access: bool,
    #[arg(
        long,
        conflicts_with = "open_access",
        help = "New single authorized caller for update-policy"
    )]
    authorized_caller: Option<String>,
    #[arg(long, help = "New metadata hash for update-policy")]
    metadata_hash: Option<String>,
    #[arg(long, help = "New proof scheme hash for update-policy")]
    proof_scheme_hash: Option<String>,
    #[arg(long, help = "Amount to withdraw from revenue, in TOS, for withdraw-revenue")]
    withdraw_amount: Option<f64>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "New 32-byte ed25519 public key for rotate-attestor-key (owner-only)"
    )]
    new_attestor_pubkey: Option<String>,
    #[arg(
        long,
        default_value_t = 0.01,
        help = "Message value in TOS; for call this is the payment (must cover price_per_call + \
                storage_fee)"
    )]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Build deterministic Service Actor StateInit")]
pub struct ServiceActorBuildStateCmd {
    #[arg(long, help = "Owner address")]
    owner: String,
    #[arg(long, conflicts_with = "open_access")]
    authorized_caller: Option<String>,
    #[arg(long, conflicts_with = "authorized_caller")]
    open_access: bool,
    #[arg(long, help = "Price per call, in TOS")]
    price_per_call: f64,
    #[arg(long, help = "Fixed, non-refundable fee collected at call time, in TOS")]
    storage_fee: f64,
    #[arg(long, help = "Paid to whoever calls sweep-expired-request, in TOS")]
    cleanup_bounty: f64,
    #[arg(long, default_value_t = 0, help = "Max calls accepted per day; 0 means unlimited")]
    rate_limit_per_day: u32,
    #[arg(long, help = "Seconds a submitted call has to be responded to")]
    response_sla: u32,
    #[arg(long, help = "Seconds after response_deadline a refund stays claimable")]
    refund_claim_window: u32,
    #[arg(long, help = "32-byte hash of general service metadata")]
    metadata_hash: String,
    #[arg(long, help = "32-byte hash identifying the supported proof/attestation scheme")]
    proof_scheme_hash: String,
    #[arg(
        long,
        help = "Optional 32-byte ed25519 public key; when set, respond also requires a signature \
                over the request-bound attestation domain"
    )]
    attestor_pubkey: Option<String>,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

/// Resolve the service address from an explicit `--address` or a stored `--name` record.
fn resolve_service_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .service_actors
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!("Service record '{}' not found; see `agent service ls`", name)
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid Service Actor address")
}

#[allow(clippy::too_many_arguments)]
fn build_init(
    owner: MsgAddressInt,
    authorized_caller: Option<MsgAddressInt>,
    open_access: bool,
    price_per_call: f64,
    storage_fee: f64,
    cleanup_bounty: f64,
    rate_limit_per_day: u32,
    response_sla: u32,
    refund_claim_window: u32,
    metadata_hash: &str,
    proof_scheme_hash: &str,
    attestor_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<ServiceActorInit> {
    validate_tos_amount("price-per-call", price_per_call)?;
    validate_tos_amount("storage-fee", storage_fee)?;
    validate_tos_amount("cleanup-bounty", cleanup_bounty)?;
    if !open_access && authorized_caller.is_none() {
        anyhow::bail!("provide --authorized-caller or --open-access");
    }
    Ok(ServiceActorInit {
        owner,
        authorized_caller,
        open_access,
        price_per_call: tos_to_nanotos(price_per_call),
        storage_fee: tos_to_nanotos(storage_fee),
        cleanup_bounty: tos_to_nanotos(cleanup_bounty),
        rate_limit_per_day,
        response_sla,
        refund_claim_window,
        metadata_hash: parse_required_hash("metadata-hash", &Some(metadata_hash.to_owned()))?,
        proof_scheme_hash: parse_required_hash(
            "proof-scheme-hash",
            &Some(proof_scheme_hash.to_owned()),
        )?,
        attestor_pubkey,
    })
}

impl ServiceActorDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let owner = self.owner.parse::<MsgAddressInt>().context("invalid owner address")?;
        let authorized_caller = self
            .authorized_caller
            .as_deref()
            .map(str::parse)
            .transpose()
            .context("invalid authorized-caller address")?;
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let attestor_pubkey =
            resolve_attestor_pubkey(&self.attestor_pubkey, &self.signer_vault_key, vault.clone())
                .await?;
        let init = build_init(
            owner.clone(),
            authorized_caller,
            self.open_access,
            self.price_per_call,
            self.storage_fee,
            self.cleanup_bounty,
            self.rate_limit_per_day,
            self.response_sla,
            self.refund_claim_window,
            &self.metadata_hash,
            &self.proof_scheme_hash,
            attestor_pubkey,
        )?;
        let address = ServiceActorContract::calculate_address(self.workchain, &init)?;
        let state_init = ServiceActorContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("service-{}", &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.service_actors.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "Service record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .service_actors
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!(
                "Service Actor address {} is already tracked as '{}'",
                address,
                existing_name
            );
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != owner {
            anyhow::bail!("owner address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        let amount_nanotos = tos_to_nanotos(self.amount);
        if amount_nanotos == 0
            || payer_info.balance < amount_nanotos.saturating_add(SERVICE_ACTOR_DEPLOY_GAS)
        {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Service Actor deployment?")? {
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
        config.service_actors.insert(
            record_name.clone(),
            ServiceActorConfig {
                address: address.to_string(),
                owner: owner.to_string(),
                authorized_caller: init.authorized_caller.as_ref().map(|v| v.to_string()),
                open_access: init.open_access,
                price_per_call: init.price_per_call,
                storage_fee: init.storage_fee,
                cleanup_bounty: init.cleanup_bounty,
                response_sla: init.response_sla,
                refund_claim_window: init.refund_claim_window,
                rate_limit_per_day: init.rate_limit_per_day,
                metadata_hash: hex::encode(init.metadata_hash),
                proof_scheme_hash: hex::encode(init.proof_scheme_hash),
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
                    "owner": owner.to_string(),
                })
            );
        } else {
            println!(
                "{} Service Actor '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ServiceActorDataView {
    address: String,
    owner: String,
    active: bool,
    policy_version: u32,
    authorized_caller: Option<String>,
    open_access: bool,
    price_per_call: String,
    storage_fee: String,
    cleanup_bounty: String,
    response_sla: u32,
    refund_claim_window: u32,
    rate_limit_per_day: u32,
    calls_today: u32,
    metadata_hash: String,
    proof_scheme_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_pubkey: Option<String>,
    next_request_id: u64,
    pending_count: u32,
    live_count: u32,
    withdrawable_revenue: String,
    locked_storage_fees: String,
    pending_liability: String,
    refundable_liability: String,
}

fn data_view(address: &MsgAddressInt, data: ServiceActorData) -> ServiceActorDataView {
    ServiceActorDataView {
        address: address.to_string(),
        owner: data.owner.to_string(),
        active: data.active,
        policy_version: data.policy_version,
        authorized_caller: data.authorized_caller.map(|v| v.to_string()),
        open_access: data.open_access,
        price_per_call: display_tos(data.price_per_call),
        storage_fee: display_tos(data.storage_fee),
        cleanup_bounty: display_tos(data.cleanup_bounty),
        response_sla: data.response_sla,
        refund_claim_window: data.refund_claim_window,
        rate_limit_per_day: data.rate_limit_per_day,
        calls_today: data.calls_today,
        metadata_hash: hex::encode(data.metadata_hash),
        proof_scheme_hash: hex::encode(data.proof_scheme_hash),
        attestor_pubkey: data.attestor_pubkey.map(hex::encode),
        next_request_id: data.next_request_id,
        pending_count: data.pending_count,
        live_count: data.live_count,
        withdrawable_revenue: display_tos(data.withdrawable_revenue),
        locked_storage_fees: display_tos(data.locked_storage_fees),
        pending_liability: display_tos(data.pending_liability),
        refundable_liability: display_tos(data.refundable_liability),
    }
}

impl ServiceActorShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_service_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack = provider.get_method(address.to_string(), "get_service_data", vec![]).await?;
        let data = ServiceActorContract::decode_data(&stack)?;
        let view = data_view(&address, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Service Actor: {}", view.address);
            println!("Owner: {}", view.owner);
            println!("Active: {}  (policy version {})", view.active, view.policy_version);
            println!(
                "Access: {}",
                if view.open_access {
                    "open".to_string()
                } else {
                    format!("restricted to {}", view.authorized_caller.as_deref().unwrap_or("none"))
                }
            );
            println!("Price per call: {} TOS", view.price_per_call);
            println!("Storage fee: {} TOS", view.storage_fee);
            println!("Cleanup bounty: {} TOS", view.cleanup_bounty);
            println!("Response SLA: {}s", view.response_sla);
            println!("Refund claim window: {}s", view.refund_claim_window);
            println!(
                "Rate limit/day: {}  (calls today: {})",
                view.rate_limit_per_day, view.calls_today
            );
            println!("Attestor pubkey: {}", view.attestor_pubkey.as_deref().unwrap_or("none"));
            println!(
                "Requests: next_id={} pending={} live={}",
                view.next_request_id, view.pending_count, view.live_count
            );
            println!(
                "Accounting: withdrawable={} TOS  locked_storage_fees={} TOS  pending_liability={} TOS  refundable_liability={} TOS",
                view.withdrawable_revenue,
                view.locked_storage_fees,
                view.pending_liability,
                view.refundable_liability,
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct RequestView {
    request_id: u64,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cleanup_bounty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_deadline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_claim_deadline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_pubkey: Option<String>,
}

fn request_view(request_id: u64, data: Option<PendingRequestData>) -> RequestView {
    match data {
        None => RequestView {
            request_id,
            found: false,
            caller: None,
            price: None,
            storage_fee: None,
            cleanup_bounty: None,
            response_deadline: None,
            refund_claim_deadline: None,
            policy_version: None,
            request_hash: None,
            terms_hash: None,
            attestor_pubkey: None,
        },
        Some(data) => RequestView {
            request_id,
            found: true,
            caller: Some(data.caller.to_string()),
            price: Some(display_tos(data.price)),
            storage_fee: Some(display_tos(data.storage_fee)),
            cleanup_bounty: Some(display_tos(data.cleanup_bounty)),
            response_deadline: Some(time_format::format_ts(data.response_deadline)),
            refund_claim_deadline: Some(time_format::format_ts(data.refund_claim_deadline)),
            policy_version: Some(data.policy_version),
            request_hash: Some(hex::encode(data.request_hash)),
            terms_hash: Some(hex::encode(data.terms_hash)),
            attestor_pubkey: data.attestor_pubkey.map(hex::encode),
        },
    }
}

impl ServiceActorRequestShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_service_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack = provider
            .get_method(
                address.to_string(),
                "get_request",
                vec![contracts::stack_utils::u64_to_stack_entry(self.request_id)],
            )
            .await?;
        let data = ServiceActorContract::decode_request(&stack)?;
        let view = request_view(self.request_id, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else if !view.found {
            println!(
                "Request {} not found (never existed, already resolved, or swept)",
                self.request_id
            );
        } else {
            println!("Request: {}", view.request_id);
            println!("Caller: {}", view.caller.unwrap());
            println!("Price: {} TOS", view.price.unwrap());
            println!("Storage fee: {} TOS", view.storage_fee.unwrap());
            println!("Cleanup bounty: {} TOS", view.cleanup_bounty.unwrap());
            println!("Response deadline: {}", view.response_deadline.unwrap());
            println!("Refund claim deadline: {}", view.refund_claim_deadline.unwrap());
            println!("Policy version: {}", view.policy_version.unwrap());
            println!("Request hash: {}", view.request_hash.unwrap());
            println!("Terms hash: {}", view.terms_hash.unwrap());
            println!("Attestor pubkey: {}", view.attestor_pubkey.as_deref().unwrap_or("none"));
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct RefundView {
    request_id: u64,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cleanup_bounty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_claim_deadline: Option<String>,
}

fn refund_view(request_id: u64, data: Option<RefundData>) -> RefundView {
    match data {
        None => RefundView {
            request_id,
            found: false,
            caller: None,
            price: None,
            storage_fee: None,
            cleanup_bounty: None,
            refund_claim_deadline: None,
        },
        Some(data) => RefundView {
            request_id,
            found: true,
            caller: Some(data.caller.to_string()),
            price: Some(display_tos(data.price)),
            storage_fee: Some(display_tos(data.storage_fee)),
            cleanup_bounty: Some(display_tos(data.cleanup_bounty)),
            refund_claim_deadline: Some(time_format::format_ts(data.refund_claim_deadline)),
        },
    }
}

impl ServiceActorRefundShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_service_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack = provider
            .get_method(
                address.to_string(),
                "get_refund",
                vec![contracts::stack_utils::u64_to_stack_entry(self.request_id)],
            )
            .await?;
        let data = ServiceActorContract::decode_refund(&stack)?;
        let view = refund_view(self.request_id, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else if !view.found {
            println!(
                "Refund for request {} not found (never expired, already claimed, or swept)",
                self.request_id
            );
        } else {
            println!("Refund for request: {}", view.request_id);
            println!("Caller: {}", view.caller.unwrap());
            println!("Price: {} TOS", view.price.unwrap());
            println!("Storage fee (locked): {} TOS", view.storage_fee.unwrap());
            println!("Cleanup bounty: {} TOS", view.cleanup_bounty.unwrap());
            println!("Refund claim deadline: {}", view.refund_claim_deadline.unwrap());
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ServiceActorRecordView {
    name: String,
    address: String,
    owner: String,
    authorized_caller: Option<String>,
    open_access: bool,
    price_per_call: String,
    rate_limit_per_day: u32,
    created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_withdrawable_revenue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_calls_today: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_live_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_error: Option<String>,
}

impl ServiceActorLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let owner_filter = self
            .owner
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .context("owner filter must be a valid native address")?;
        let mut records: Vec<ServiceActorRecordView> = config
            .service_actors
            .iter()
            .filter(|(_, entry)| {
                owner_filter.as_ref().is_none_or(|owner| {
                    entry.owner.parse::<MsgAddressInt>().ok().as_ref() == Some(owner)
                })
            })
            .map(|(name, entry)| ServiceActorRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                owner: entry.owner.clone(),
                authorized_caller: entry.authorized_caller.clone(),
                open_access: entry.open_access,
                price_per_call: display_tos(entry.price_per_call),
                rate_limit_per_day: entry.rate_limit_per_day,
                created_at: entry.created_at,
                chain_active: None,
                chain_withdrawable_revenue: None,
                chain_calls_today: None,
                chain_live_count: None,
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
                            .context("invalid persisted Service Actor address")?;
                        let stack = provider
                            .get_method(address.to_string(), "get_service_data", vec![])
                            .await?;
                        ServiceActorContract::decode_data(&stack)
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
                        record.chain_active = Some(data.active);
                        record.chain_withdrawable_revenue =
                            Some(display_tos(data.withdrawable_revenue));
                        record.chain_calls_today = Some(data.calls_today);
                        record.chain_live_count = Some(data.live_count);
                    }
                    Err(error) => record.chain_error = Some(format!("{error:#}")),
                }
            }
        }
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No Service Actor records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address: {}\n  Owner:   {}\n  Access:  {}\n  Price:   {} TOS",
                record.name.bold(),
                record.address,
                record.owner,
                if record.open_access {
                    "open".to_string()
                } else {
                    format!(
                        "restricted to {}",
                        record.authorized_caller.as_deref().unwrap_or("none")
                    )
                },
                record.price_per_call,
            );
            if let Some(active) = record.chain_active {
                println!("  Chain active:  {}", active);
            }
            if let Some(revenue) = &record.chain_withdrawable_revenue {
                println!("  Chain withdrawable revenue: {} TOS", revenue);
            }
            if let Some(calls) = record.chain_calls_today {
                println!("  Chain calls today: {}", calls);
            }
            if let Some(live) = record.chain_live_count {
                println!("  Chain live requests: {}", live);
            }
            if let Some(error) = &record.chain_error {
                println!("  Chain error:   {}", error);
            }
        }
        Ok(())
    }
}

impl ServiceActorSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination_service = resolve_service_address(&config, &self.address, &self.name)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault.clone()).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }

        let request_id = || -> anyhow::Result<u64> {
            self.request_id.ok_or_else(|| anyhow::anyhow!("--request-id is required"))
        };

        // A call ID is allocated by the contract. Capture the allocation
        // frontier and the exact request hash before submitting so we can
        // identify this call after it lands without assuming that it was the
        // last call processed (other callers may race us).
        let call_request_hash = matches!(self.operation, ServiceActorOperation::Call)
            .then(|| parse_required_hash("request-hash", &self.request_hash))
            .transpose()?;
        let call_frontier = if call_request_hash.is_some() {
            let provider = contracts::contract_provider!(rpc_client.clone());
            Some(
                ServiceActorContract::decode_data(
                    &provider
                        .get_method(destination_service.to_string(), "get_service_data", vec![])
                        .await?,
                )?
                .next_request_id,
            )
        } else {
            None
        };

        let body = match self.operation {
            ServiceActorOperation::Call => ServiceActorContract::call(
                self.query_id,
                call_request_hash.expect("call hash parsed above"),
            )?,
            ServiceActorOperation::Respond => {
                let id = request_id()?;
                let response_hash = parse_required_hash("response-hash", &self.response_hash)?;
                let signature = match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
                    Some(signature) => Some(signature),
                    None => match &self.signer_vault_key {
                        Some(name) => {
                            // The signature must bind the exact request this
                            // response answers, under the terms it was
                            // accepted with -- fetch it on chain rather than
                            // signing response_hash alone.
                            let provider = contracts::contract_provider!(rpc_client.clone());
                            let stack = provider
                                .get_method(
                                    destination_service.to_string(),
                                    "get_request",
                                    vec![contracts::stack_utils::u64_to_stack_entry(id)],
                                )
                                .await?;
                            let request = ServiceActorContract::decode_request(&stack)?
                                .ok_or_else(|| {
                                    anyhow::anyhow!("request {id} is not pending on chain")
                                })?;
                            let domain_hash = contracts::service_respond_domain_hash(
                                &destination_service,
                                &request.caller,
                                id,
                                &request.request_hash,
                                &response_hash,
                                &request.terms_hash,
                                request.price,
                                request.response_deadline,
                                request.refund_claim_deadline,
                            )?;
                            Some(sign_hash_with_vault_key(name, &domain_hash, vault.clone()).await?)
                        }
                        None => None,
                    },
                };
                match signature {
                    Some(signature) => ServiceActorContract::respond_signed(
                        self.query_id,
                        id,
                        response_hash,
                        &signature,
                    )?,
                    None => ServiceActorContract::respond(self.query_id, id, response_hash)?,
                }
            }
            ServiceActorOperation::Expire => {
                ServiceActorContract::expire(self.query_id, request_id()?)?
            }
            ServiceActorOperation::ClaimRefund => {
                let raw_destination = self
                    .destination
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--destination is required"))?;
                let destination = raw_destination
                    .parse::<MsgAddressInt>()
                    .context("invalid claim-refund destination address")?;
                ServiceActorContract::claim_refund(self.query_id, request_id()?, &destination)?
            }
            ServiceActorOperation::SweepExpiredRequest => {
                ServiceActorContract::sweep_expired_request(self.query_id, request_id()?)?
            }
            ServiceActorOperation::UpdatePolicy => {
                let authorized_caller = self
                    .authorized_caller
                    .as_deref()
                    .map(str::parse::<MsgAddressInt>)
                    .transpose()
                    .context("invalid authorized-caller address")?;
                if !self.open_access && authorized_caller.is_none() {
                    anyhow::bail!("provide --authorized-caller or --open-access");
                }
                let price_per_call = self
                    .price_per_call
                    .ok_or_else(|| anyhow::anyhow!("--price-per-call is required"))?;
                let storage_fee =
                    self.storage_fee.ok_or_else(|| anyhow::anyhow!("--storage-fee is required"))?;
                let cleanup_bounty = self
                    .cleanup_bounty
                    .ok_or_else(|| anyhow::anyhow!("--cleanup-bounty is required"))?;
                validate_tos_amount("price-per-call", price_per_call)?;
                validate_tos_amount("storage-fee", storage_fee)?;
                validate_tos_amount("cleanup-bounty", cleanup_bounty)?;
                ServiceActorContract::update_policy(
                    self.query_id,
                    tos_to_nanotos(price_per_call),
                    tos_to_nanotos(storage_fee),
                    tos_to_nanotos(cleanup_bounty),
                    self.response_sla
                        .ok_or_else(|| anyhow::anyhow!("--response-sla is required"))?,
                    self.refund_claim_window
                        .ok_or_else(|| anyhow::anyhow!("--refund-claim-window is required"))?,
                    self.active.ok_or_else(|| anyhow::anyhow!("--active is required"))?,
                    self.open_access,
                    authorized_caller.as_ref(),
                    // Only read on-chain when clearing the authorized caller,
                    // in which case the signing (owner) wallet's own address
                    // is exactly the right filler.
                    &owner_address,
                    self.rate_limit_per_day
                        .ok_or_else(|| anyhow::anyhow!("--rate-limit-per-day is required"))?,
                    parse_required_hash("metadata-hash", &self.metadata_hash)?,
                    parse_required_hash("proof-scheme-hash", &self.proof_scheme_hash)?,
                )?
            }
            ServiceActorOperation::WithdrawRevenue => ServiceActorContract::withdraw_revenue(
                self.query_id,
                tos_to_nanotos(
                    self.withdraw_amount
                        .ok_or_else(|| anyhow::anyhow!("--withdraw-amount is required"))?,
                ),
            )?,
            ServiceActorOperation::RotateAttestorKey => {
                let pubkey = resolve_attestor_pubkey(
                    &self.new_attestor_pubkey,
                    &self.signer_vault_key,
                    vault.clone(),
                )
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "provide --new-attestor-pubkey or --signer-vault-key for rotate-attestor-key"
                    )
                })?;
                ServiceActorContract::rotate_attestor_key(self.query_id, pubkey)?
            }
            ServiceActorOperation::RevokeAttestor => {
                ServiceActorContract::revoke_attestor(self.query_id)?
            }
        };

        let amount_nanotos = tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(SERVICE_ACTOR_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Service Actor message?")? {
            return Ok(());
        }
        let wallet =
            make_wallet(rpc_client.clone(), wallet_config, owner_secret, &self.from).await?;
        send_wallet_message(
            &wallet,
            rpc_client.clone(),
            destination_service.clone(),
            amount_nanotos,
            body,
            true,
            owner_info.seqno,
            &owner_address,
        )
        .await?;
        println!(
            "{} Service Actor {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination_service
        );

        if let (Some(first_id), Some(request_hash)) = (call_frontier, call_request_hash) {
            let provider = contracts::contract_provider!(rpc_client);
            let data = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                loop {
                    let data = ServiceActorContract::decode_data(
                        &provider
                            .get_method(destination_service.to_string(), "get_service_data", vec![])
                            .await?,
                    )?;
                    if data.next_request_id > first_id {
                        return Ok::<_, anyhow::Error>(data);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            })
            .await
            .context("timed out waiting for the Service Actor call to land")??;
            let mut matches = Vec::new();
            for id in first_id..data.next_request_id {
                let stack = provider
                    .get_method(
                        destination_service.to_string(),
                        "get_request",
                        vec![contracts::stack_utils::u64_to_stack_entry(id)],
                    )
                    .await?;
                if let Some(request) = ServiceActorContract::decode_request(&stack)? {
                    if request.caller == owner_address && request.request_hash == request_hash {
                        matches.push(id);
                    }
                }
            }
            match matches.as_slice() {
                [id] => println!("  Assigned request ID: {id}"),
                [] => anyhow::bail!(
                    "call was submitted, but its assigned request ID could not be correlated; \
                     query the transaction/indexer using caller {} and request hash {}",
                    owner_address,
                    hex::encode(request_hash)
                ),
                _ => anyhow::bail!(
                    "call was submitted, but request ID correlation is ambiguous ({matches:?}); \
                     do not guess an ID"
                ),
            }
        }
        Ok(())
    }
}

impl ServiceActorBuildStateCmd {
    fn run(&self) -> anyhow::Result<()> {
        let owner = self.owner.parse::<MsgAddressInt>().context("invalid owner address")?;
        let authorized_caller = self
            .authorized_caller
            .as_deref()
            .map(str::parse)
            .transpose()
            .context("invalid authorized-caller address")?;
        let init = build_init(
            owner,
            authorized_caller,
            self.open_access,
            self.price_per_call,
            self.storage_fee,
            self.cleanup_bounty,
            self.rate_limit_per_day,
            self.response_sla,
            self.refund_claim_window,
            &self.metadata_hash,
            &self.proof_scheme_hash,
            parse_optional_hash("attestor-pubkey", &self.attestor_pubkey)?,
        )?;
        let address = ServiceActorContract::calculate_address(self.workchain, &init)?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::json!({ "address": address.to_string() }));
        } else {
            println!("Service Actor address: {}", address);
        }
        Ok(())
    }
}
