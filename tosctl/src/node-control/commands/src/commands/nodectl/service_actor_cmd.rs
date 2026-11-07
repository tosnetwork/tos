/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use super::agent_cmd::{
    confirm, parse_required_hash, send_wallet_message, send_wallet_message_with_state_init,
    validate_tos_amount,
};
use super::native_registry_cmd::read_controller_seed;
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
use contracts::service_actor::protocol_constants::{
    ADMISSION_GAS_ALLOWANCE, MINIMUM_OPERATING_RESERVE, PAYOUT_GAS_ALLOWANCE,
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
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Owner address; must match the funding wallet")]
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
        conflicts_with = "attestor_controller",
        help = "Optional ML-DSA-44 attestor public key (1,312 bytes, hex); when set, respond \
                also requires its signature over the request-bound attestation domain"
    )]
    attestor_pubkey: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestor_pubkey",
        help = "Derive --attestor-pubkey from this ML-DSA-44 controller in the vault \
                (secret native-registry-<name>; see `native-registry new-controller`)"
    )]
    attestor_controller: Option<String>,
    #[arg(long, help = "Funding wallet name or master_wallet")]
    from: String,
    #[arg(
        long,
        default_value_t = default_deploy_amount(),
        help = deploy_funding_help()
    )]
    amount: f64,
    #[arg(short = 'w', long = "workchain", allow_negative_numbers = true, default_value_t = super::utils::USER_CONTRACT_WORKCHAIN)]
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
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Filter by owner address")]
    owner: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Service Actor policy/accounting state by address or local record name")]
pub struct ServiceActorShowCmd {
    #[arg(
        allow_hyphen_values = true, value_parser = super::utils::address_arg,
        long,
        conflicts_with = "name",
        help = "Service Actor address"
    )]
    address: Option<String>,
    #[arg(long, help = "Local service record name from `agent service ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a single request by ID")]
pub struct ServiceActorRequestShowCmd {
    #[arg(
        allow_hyphen_values = true, value_parser = super::utils::address_arg,
        long,
        conflicts_with = "name",
        help = "Service Actor address"
    )]
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
    #[arg(
        allow_hyphen_values = true, value_parser = super::utils::address_arg,
        long,
        conflicts_with = "name",
        help = "Service Actor address"
    )]
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
    #[arg(
        allow_hyphen_values = true, value_parser = super::utils::address_arg,
        long,
        conflicts_with = "name",
        help = "Service Actor address"
    )]
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
        help = "Terms hash the call commits to (hex), as the accepted quote states it; required \
                for call, so terms that changed after the quote are refused on chain"
    )]
    expected_terms_hash: Option<String>,
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
        conflicts_with = "attestor_controller",
        help = "2,420-byte ML-DSA-44 signature (hex) over the request-bound attestation domain \
                hash, for respond on a service deployed with an attestor"
    )]
    attestation_signature: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestation_signature",
        help = "ML-DSA-44 controller in the vault (secret native-registry-<name>): signs the \
                request-bound attestation domain for respond (after fetching the request's \
                on-chain terms, which the domain binds), or names the new key for \
                rotate-attestor-key"
    )]
    attestor_controller: Option<String>,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Refund destination address for claim-refund")]
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
        conflicts_with = "attestor_controller",
        help = "New ML-DSA-44 attestor public key (1,312 bytes, hex) for rotate-attestor-key \
                (owner-only)"
    )]
    new_attestor_pubkey: Option<String>,
    #[arg(
        long,
        help = send_funding_help()
    )]
    amount: Option<f64>,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Build deterministic Service Actor StateInit")]
pub struct ServiceActorBuildStateCmd {
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Owner address")]
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
        help = "Optional ML-DSA-44 attestor public key (1,312 bytes, hex); when set, respond \
                also requires its signature over the request-bound attestation domain"
    )]
    attestor_pubkey: Option<String>,
    #[arg(short = 'w', long = "workchain", allow_negative_numbers = true, default_value_t = super::utils::USER_CONTRACT_WORKCHAIN)]
    workchain: i32,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

/// Text form of an ML-DSA-44 key id.
fn key_id_text(key_id: &[u8; 32]) -> String {
    format!("mldsa44:{}", hex::encode(key_id))
}

/// An ML-DSA-44 attestor public key given as hex: exactly 1,312 bytes.
fn parse_attestor_public_key(
    name: &str,
    value: &Option<String>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{name} must be hex"))?;
    // Deriving the key id checks the length.
    contracts::native_registry::controller_key_id(&bytes).with_context(|| name.to_owned())?;
    Ok(Some(bytes))
}

/// A respond attestation signature given as hex: exactly 2,420 bytes.
fn parse_attestation_signature(value: &Option<String>) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("attestation-signature must be hex")?;
    anyhow::ensure!(
        bytes.len() == contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES,
        "attestation-signature must be an ML-DSA-44 signature of {} bytes, not {}",
        contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES,
        bytes.len()
    );
    Ok(Some(bytes))
}

/// The attestor key: given directly, or derived from an ML-DSA-44 controller
/// seed held in the vault. At most one source may be named.
async fn resolve_attestor_key(
    public_key: &Option<String>,
    controller: &Option<String>,
    vault: &secrets_vault::vault::SecretVault,
) -> anyhow::Result<Option<Vec<u8>>> {
    match (public_key, controller) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide at most one attestor public key or attestor controller")
        }
        (Some(_), None) => parse_attestor_public_key("attestor public key", public_key),
        (None, Some(name)) => {
            let seed = read_controller_seed(vault, name).await?;
            Ok(Some(contracts::native_registry::native_public_key_from_seed(&seed)))
        }
        (None, None) => Ok(None),
    }
}

/// The terms hash a `call` commits to: required, and refused locally when it no
/// longer matches the live terms, since the contract would refuse it anyway.
fn call_terms_hash(expected: &Option<String>, live: &ServiceActorData) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        expected.is_some(),
        "--expected-terms-hash is required for call: pass the terms hash of the accepted quote \
         (`agent service show` prints the current one)"
    );
    let expected = parse_required_hash("expected-terms-hash", expected)?;
    let current = ServiceActorContract::terms_hash_of_data(live)?;
    anyhow::ensure!(
        expected == current,
        "the service's terms changed: the quote commits to {}, the service now offers {}",
        hex::encode(expected),
        hex::encode(current)
    );
    Ok(expected)
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
    attestor_pubkey: Option<Vec<u8>>,
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

const DEPLOY_FEE_MARGIN: u64 = 200_000_000;
const NANOTOS_PER_TOS: u64 = 1_000_000_000;
const DEFAULT_NON_PAYOUT_VALUE: u64 = 10_000_000;
const MINIMUM_DEPLOY_FUNDING: u64 = MINIMUM_OPERATING_RESERVE
    .checked_add(DEPLOY_FEE_MARGIN)
    .expect("Service Actor deploy funding constants must fit u64");

fn default_deploy_amount() -> f64 {
    MINIMUM_DEPLOY_FUNDING as f64 / NANOTOS_PER_TOS as f64
}

fn deploy_funding_help() -> String {
    format!(
        "Deploy funding in TOS; minimum {} ({} TOS reserve plus {} TOS fee margin)",
        default_deploy_amount(),
        MINIMUM_OPERATING_RESERVE as f64 / NANOTOS_PER_TOS as f64,
        DEPLOY_FEE_MARGIN as f64 / NANOTOS_PER_TOS as f64
    )
}

fn validate_deploy_amount(amount: f64) -> anyhow::Result<u64> {
    validate_tos_amount("amount", amount)?;
    let amount_nanotos = tos_to_nanotos(amount);
    anyhow::ensure!(
        amount_nanotos >= MINIMUM_DEPLOY_FUNDING,
        "Service Actor deploy requires at least {} TOS",
        default_deploy_amount()
    );
    Ok(amount_nanotos)
}

fn send_funding_help() -> String {
    format!(
        "Message value in TOS. Defaults to quoted price + storage fee + {} for call; \
         {} for claim-refund, sweep-expired-request and withdraw-revenue; {} otherwise. \
         Calls and payouts return unused execution funding to the sender. Explicit call and payout \
         values must cover their funding minimum",
        ADMISSION_GAS_ALLOWANCE as f64 / NANOTOS_PER_TOS as f64,
        PAYOUT_GAS_ALLOWANCE as f64 / NANOTOS_PER_TOS as f64,
        DEFAULT_NON_PAYOUT_VALUE as f64 / NANOTOS_PER_TOS as f64,
    )
}

impl ServiceActorOperation {
    fn execution_allowance(&self) -> u64 {
        match self {
            Self::Call => ADMISSION_GAS_ALLOWANCE,
            Self::ClaimRefund | Self::SweepExpiredRequest | Self::WithdrawRevenue => {
                PAYOUT_GAS_ALLOWANCE
            }
            _ => 0,
        }
    }
}

/// Reject a known funding shortfall before opening the wallet or contacting RPC.
/// The call's quoted price and storage fee are checked after fetching its policy.
fn validate_send_amount(
    operation: &ServiceActorOperation,
    amount: Option<f64>,
) -> anyhow::Result<Option<u64>> {
    amount
        .map(|amount| {
            validate_tos_amount("amount", amount)?;
            let amount_nanotos = tos_to_nanotos(amount);
            anyhow::ensure!(
                amount_nanotos >= operation.execution_allowance(),
                "Service Actor message requires at least {} TOS for execution, in addition \
                 to the price and storage fee for a call",
                operation.execution_allowance() as f64 / NANOTOS_PER_TOS as f64,
            );
            Ok(amount_nanotos)
        })
        .transpose()
}

fn send_amount_nanotos(
    operation: &ServiceActorOperation,
    explicit: Option<u64>,
    call_terms: Option<(u64, u64)>,
) -> anyhow::Result<u64> {
    let minimum = match operation {
        ServiceActorOperation::Call => {
            let (price, storage_fee) =
                call_terms.context("Service Actor call policy is unavailable")?;
            ServiceActorContract::minimum_call_payment(price, storage_fee)?
        }
        ServiceActorOperation::ClaimRefund
        | ServiceActorOperation::SweepExpiredRequest
        | ServiceActorOperation::WithdrawRevenue => PAYOUT_GAS_ALLOWANCE,
        _ => 0,
    };
    let amount =
        explicit.unwrap_or_else(|| if minimum == 0 { DEFAULT_NON_PAYOUT_VALUE } else { minimum });
    anyhow::ensure!(
        amount >= minimum,
        "Service Actor message requires at least {} nanoTOS ({} TOS), including execution funding",
        minimum,
        minimum as f64 / NANOTOS_PER_TOS as f64,
    );
    Ok(amount)
}

impl ServiceActorDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let amount_nanotos = validate_deploy_amount(self.amount)?;
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
            resolve_attestor_key(&self.attestor_pubkey, &self.attestor_controller, &vault).await?;
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
        let required_balance = amount_nanotos
            .checked_add(SERVICE_ACTOR_DEPLOY_GAS)
            .context("Service Actor deploy funding overflow")?;
        if payer_info.balance < required_balance {
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
                attestor_pubkey: init.attestor_pubkey.as_ref().map(hex::encode),
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
    /// Hash of the current terms; a `call` must carry it as `expected_terms_hash`.
    terms_hash: String,
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
    /// Key id of the current attestor key, `mldsa44:<hex>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_key_id: Option<String>,
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
        terms_hash: ServiceActorContract::terms_hash_of_data(&data)
            .map(hex::encode)
            .unwrap_or_default(),
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
        attestor_key_id: data.attestor_key_id.as_ref().map(key_id_text),
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
        super::utils::require_supported_contract(
            &rpc_client,
            &address,
            contracts::VersionedContract::ServiceActor,
        )
        .await?;
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
            println!("Attestor key: {}", view.attestor_key_id.as_deref().unwrap_or("none"));
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
    /// Key id of the attestor key this request snapshotted, `mldsa44:<hex>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_key_id: Option<String>,
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
            attestor_key_id: None,
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
            attestor_key_id: data.attestor_key_id.as_ref().map(key_id_text),
        },
    }
}

impl ServiceActorRequestShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_service_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        super::utils::require_supported_contract(
            &rpc_client,
            &address,
            contracts::VersionedContract::ServiceActor,
        )
        .await?;
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
            println!("Attestor key: {}", view.attestor_key_id.as_deref().unwrap_or("none"));
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
        super::utils::require_supported_contract(
            &rpc_client,
            &address,
            contracts::VersionedContract::ServiceActor,
        )
        .await?;
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
        let explicit_amount = validate_send_amount(&self.operation, self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination_service = resolve_service_address(&config, &self.address, &self.name)?;
        super::utils::require_supported_contract(
            &rpc_client,
            &destination_service,
            contracts::VersionedContract::ServiceActor,
        )
        .await?;
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
        let call_service_data = if call_request_hash.is_some() {
            let provider = contracts::contract_provider!(rpc_client.clone());
            Some(ServiceActorContract::decode_data(
                &provider
                    .get_method(destination_service.to_string(), "get_service_data", vec![])
                    .await?,
            )?)
        } else {
            None
        };
        let call_frontier = call_service_data.as_ref().map(|data| data.next_request_id);
        let amount_nanotos = send_amount_nanotos(
            &self.operation,
            explicit_amount,
            call_service_data.as_ref().map(|data| (data.price_per_call, data.storage_fee)),
        )?;

        let body = match self.operation {
            ServiceActorOperation::Call => {
                let data = call_service_data.as_ref().expect("service data fetched above");
                // The buyer states the terms it accepted; reading them from live state would
                // commit to whatever the service changed them to after the quote.
                let expected_terms_hash = call_terms_hash(&self.expected_terms_hash, data)?;
                println!(
                    "Terms committed to: hash {} (policy version {}, price {} nanoTOS, storage fee {} nanoTOS, attestor {})",
                    hex::encode(expected_terms_hash),
                    data.policy_version,
                    data.price_per_call,
                    data.storage_fee,
                    data.attestor_key_id
                        .as_ref()
                        .map(key_id_text)
                        .unwrap_or_else(|| "none".to_string()),
                );
                ServiceActorContract::call(
                    self.query_id,
                    call_request_hash.expect("call hash parsed above"),
                    expected_terms_hash,
                )?
            }
            ServiceActorOperation::Respond => {
                let id = request_id()?;
                let response_hash = parse_required_hash("response-hash", &self.response_hash)?;
                let signature = match parse_attestation_signature(&self.attestation_signature)? {
                    Some(signature) => Some(signature),
                    None => match &self.attestor_controller {
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
                                super::utils::network_global_id(&rpc_client).await?,
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
                            let seed = read_controller_seed(&vault, name).await?;
                            let (public_key, signature) =
                                contracts::service_actor::sign_service_response(
                                    &seed,
                                    &domain_hash,
                                )?;
                            let key_id =
                                contracts::native_registry::controller_key_id(&public_key)?;
                            anyhow::ensure!(
                                request.attestor_key_id == Some(key_id),
                                "controller {name} ({}) is not the attestor request {id} \
                                 snapshotted ({})",
                                key_id_text(&key_id),
                                request
                                    .attestor_key_id
                                    .as_ref()
                                    .map(key_id_text)
                                    .unwrap_or_else(|| "none".to_string())
                            );
                            contracts::service_actor::verify_service_response(
                                &public_key,
                                &signature,
                                &domain_hash,
                            )?;
                            Some(signature)
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
                let public_key = resolve_attestor_key(
                    &self.new_attestor_pubkey,
                    &self.attestor_controller,
                    &vault,
                )
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "provide --new-attestor-pubkey or --attestor-controller for \
                         rotate-attestor-key"
                    )
                })?;
                ServiceActorContract::rotate_attestor_key(self.query_id, &public_key)?
            }
            ServiceActorOperation::RevokeAttestor => {
                ServiceActorContract::revoke_attestor(self.query_id)?
            }
        };

        let required_balance = amount_nanotos
            .checked_add(SERVICE_ACTOR_ACTION_GAS)
            .context("Service Actor message funding exceeds the wallet amount range")?;
        if owner_info.balance < required_balance {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        println!("Message funding: {} TOS", display_tos(amount_nanotos));
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
            parse_attestor_public_key("attestor-pubkey", &self.attestor_pubkey)?,
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

#[cfg(test)]
mod solvency_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct DeployArgs {
        #[command(flatten)]
        deploy: ServiceActorDeployCmd,
    }

    #[derive(Parser)]
    struct SendArgs {
        #[command(flatten)]
        send: ServiceActorSendCmd,
    }

    fn send_args(operation: &str) -> ServiceActorSendCmd {
        SendArgs::try_parse_from([
            "send",
            "--operation",
            operation,
            "--name",
            "service",
            "--from",
            "master_wallet",
        ])
        .expect("send arguments")
        .send
    }

    fn deploy_args() -> ServiceActorDeployCmd {
        DeployArgs::try_parse_from([
            "deploy",
            "--owner",
            &format!("0:{}", "11".repeat(32)),
            "--open-access",
            "--price-per-call",
            "0.1",
            "--storage-fee",
            "0.2",
            "--cleanup-bounty",
            "0.1",
            "--response-sla",
            "3600",
            "--refund-claim-window",
            "3600",
            "--metadata-hash",
            &"11".repeat(32),
            "--proof-scheme-hash",
            &"22".repeat(32),
            "--from",
            "master_wallet",
        ])
        .expect("deploy arguments")
        .deploy
    }

    #[test]
    fn service_deploy_default_funds_reserve_and_margin() {
        let minimum = contracts::service_actor::protocol_constants::MINIMUM_OPERATING_RESERVE
            .checked_add(DEPLOY_FEE_MARGIN)
            .unwrap();
        assert_eq!(validate_deploy_amount(deploy_args().amount).unwrap(), minimum);
        assert!(
            validate_deploy_amount(minimum.checked_sub(1).unwrap() as f64 / NANOTOS_PER_TOS as f64)
                .is_err()
        );
        assert!(validate_deploy_amount(1.0).is_err());
        assert!(validate_deploy_amount(0.2).is_err());
        assert!(validate_deploy_amount(f64::NAN).is_err());
    }

    #[tokio::test]
    async fn service_deploy_rejects_underfunding_before_loading_wallet() {
        let mut cmd = deploy_args();
        cmd.amount = 0.2;
        let error = cmd.run("/nonexistent/service-solvency-config.json").await.unwrap_err();
        assert!(
            error.to_string().contains(&format!("at least {} TOS", default_deploy_amount())),
            "{error:#}"
        );
    }

    #[test]
    fn service_call_default_and_explicit_funding_include_execution_allowance() {
        let cmd = send_args("call");
        assert!(cmd.amount.is_none(), "call funding must follow the quoted policy");
        let price: u64 = 123_456_789;
        let storage_fee: u64 = 200_000_000;
        let expected =
            price.checked_add(storage_fee).unwrap().checked_add(ADMISSION_GAS_ALLOWANCE).unwrap();
        assert_eq!(
            send_amount_nanotos(&cmd.operation, None, Some((price, storage_fee))).unwrap(),
            expected
        );
        assert_eq!(
            send_amount_nanotos(&cmd.operation, Some(expected), Some((price, storage_fee)))
                .unwrap(),
            expected
        );
        assert!(
            send_amount_nanotos(&cmd.operation, Some(expected - 1), Some((price, storage_fee)))
                .is_err()
        );
        assert!(send_amount_nanotos(&cmd.operation, None, None).is_err());
        assert!(send_amount_nanotos(&cmd.operation, None, Some((u64::MAX, storage_fee))).is_err());
    }

    #[test]
    fn service_payout_defaults_cover_execution_and_do_not_change_other_operations() {
        for operation in ["claim-refund", "sweep-expired-request", "withdraw-revenue"] {
            let cmd = send_args(operation);
            assert_eq!(
                send_amount_nanotos(&cmd.operation, None, None).unwrap(),
                PAYOUT_GAS_ALLOWANCE
            );
            assert!(
                send_amount_nanotos(&cmd.operation, Some(PAYOUT_GAS_ALLOWANCE - 1), None).is_err()
            );
            assert_eq!(
                send_amount_nanotos(&cmd.operation, Some(PAYOUT_GAS_ALLOWANCE), None).unwrap(),
                PAYOUT_GAS_ALLOWANCE
            );
        }
        let respond = send_args("respond");
        assert_eq!(
            send_amount_nanotos(&respond.operation, None, None).unwrap(),
            DEFAULT_NON_PAYOUT_VALUE
        );
    }

    #[tokio::test]
    async fn service_send_rejects_insufficient_execution_funding_before_loading_wallet() {
        for operation in ["call", "claim-refund", "sweep-expired-request", "withdraw-revenue"] {
            let mut cmd = send_args(operation);
            cmd.amount = Some(0.01);
            let error = cmd.run("/nonexistent/service-solvency-config.json").await.unwrap_err();
            assert!(error.to_string().contains("for execution"), "{operation}: {error:#}");
            cmd.amount = Some(f64::NAN);
            let error = cmd.run("/nonexistent/service-solvency-config.json").await.unwrap_err();
            assert!(error.to_string().contains("amount"), "{operation}: {error:#}");
        }
    }
}

#[cfg(test)]
mod attestor_cli_tests {
    use super::*;

    fn live_data() -> ServiceActorData {
        ServiceActorData {
            owner: format!("0:{}", "11".repeat(32)).parse().unwrap(),
            active: true,
            policy_version: 3,
            price_per_call: 100_000_000,
            storage_fee: 200_000_000,
            cleanup_bounty: 100_000_000,
            response_sla: 3_600,
            refund_claim_window: 3_600,
            open_access: true,
            authorized_caller: None,
            rate_limit_per_day: 0,
            metadata_hash: [0x11; 32],
            proof_scheme_hash: [0x22; 32],
            attestor_key_id: None,
            next_request_id: 0,
            pending_count: 0,
            live_count: 0,
            withdrawable_revenue: 0,
            locked_storage_fees: 0,
            pending_liability: 0,
            refundable_liability: 0,
            call_day: 0,
            calls_today: 0,
        }
    }

    #[test]
    fn a_call_never_defaults_its_terms_to_live_state() {
        let data = live_data();
        let error = call_terms_hash(&None, &data).unwrap_err();
        assert!(error.to_string().contains("--expected-terms-hash is required"), "{error:#}");

        let current = ServiceActorContract::terms_hash_of_data(&data).unwrap();
        assert_eq!(call_terms_hash(&Some(hex::encode(current)), &data).unwrap(), current);

        let mut moved = data.clone();
        moved.price_per_call = moved.price_per_call.checked_add(1).unwrap();
        let error = call_terms_hash(&Some(hex::encode(current)), &moved).unwrap_err();
        assert!(error.to_string().contains("terms changed"), "{error:#}");
    }

    #[test]
    fn attestor_keys_and_signatures_have_ml_dsa_44_lengths() {
        let key = contracts::native_registry::native_public_key_from_seed(&[7; 32]);
        assert_eq!(
            parse_attestor_public_key("k", &Some(hex::encode(&key))).unwrap(),
            Some(key.clone())
        );
        assert_eq!(parse_attestor_public_key("k", &None).unwrap(), None);
        for bad in [hex::encode([1u8; 32]), hex::encode(&key[1..]), "zz".to_string()] {
            assert!(parse_attestor_public_key("k", &Some(bad)).is_err());
        }

        let signature = vec![3u8; contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES];
        assert_eq!(
            parse_attestation_signature(&Some(hex::encode(&signature))).unwrap(),
            Some(signature.clone())
        );
        for bad in [hex::encode([1u8; 64]), hex::encode(&signature[1..])] {
            assert!(parse_attestation_signature(&Some(bad)).is_err());
        }
    }

    #[test]
    fn a_controller_signed_response_verifies_under_its_own_key_only() {
        let domain = [0x42; 32];
        let (public_key, signature) =
            contracts::service_actor::sign_service_response(&[9; 32], &domain).unwrap();
        assert_eq!(public_key, contracts::native_registry::native_public_key_from_seed(&[9; 32]));
        contracts::service_actor::verify_service_response(&public_key, &signature, &domain)
            .unwrap();
        let other = contracts::native_registry::native_public_key_from_seed(&[8; 32]);
        assert!(
            contracts::service_actor::verify_service_response(&other, &signature, &domain).is_err()
        );
        assert!(
            contracts::service_actor::verify_service_response(&public_key, &signature, &[0x43; 32])
                .is_err()
        );
    }
}
