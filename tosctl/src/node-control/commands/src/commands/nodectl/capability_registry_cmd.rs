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
    app_config::CapabilityRegistryConfig,
    chain_utils::{display_tos, tos_to_nanotos},
    time_format,
};
use contracts::{CapabilityRegistryContract, CapabilityRegistryData, CapabilityRegistryInit};
use futures_util::{StreamExt, stream};
use std::{path::Path, str::FromStr};

const CAPABILITY_REGISTRY_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const CAPABILITY_REGISTRY_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent registry` -- Capability Registry operations.
#[derive(clap::Args, Clone)]
#[command(about = "Capability Registry operations")]
pub struct CapabilityRegistryCmd {
    #[command(subcommand)]
    action: CapabilityRegistryAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum CapabilityRegistryAction {
    /// Deploy and fund a Capability Registry entry
    Deploy(CapabilityRegistryDeployCmd),
    /// List locally tracked Capability Registry records
    Ls(CapabilityRegistryLsCmd),
    /// Show Capability Registry state by address or local record name
    Show(CapabilityRegistryShowCmd),
    /// Send a Capability Registry lifecycle message
    Send(CapabilityRegistrySendCmd),
    /// Build deterministic Capability Registry StateInit
    BuildState(CapabilityRegistryBuildStateCmd),
}

impl CapabilityRegistryCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            CapabilityRegistryAction::Deploy(cmd) => cmd.run(config_path).await,
            CapabilityRegistryAction::Ls(cmd) => cmd.run(config_path).await,
            CapabilityRegistryAction::Show(cmd) => cmd.run(config_path).await,
            CapabilityRegistryAction::Send(cmd) => cmd.run(config_path).await,
            CapabilityRegistryAction::BuildState(cmd) => cmd.run(),
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy and fund a Capability Registry entry")]
pub struct CapabilityRegistryDeployCmd {
    #[arg(long, help = "Local registry record name; defaults to registry-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Owner address; must match the funding wallet")]
    owner: String,
    #[arg(long, help = "Optional verifier allowed to adjust the reputation score")]
    verifier: Option<String>,
    #[arg(long, help = "32-byte hash of the advertised task categories")]
    task_categories_hash: String,
    #[arg(long, help = "32-byte hash of the advertised pricing model")]
    pricing_hash: String,
    #[arg(long, help = "32-byte hash of general capability/service metadata")]
    metadata_hash: String,
    #[arg(long, help = "32-byte hash identifying the supported verification method")]
    verification_method_hash: String,
    #[arg(long, default_value_t = 0.0, help = "Initial bond in TOS")]
    bond: f64,
    #[arg(long, help = "Unix registration timestamp; defaults to now")]
    registered_at: Option<u64>,
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
#[command(about = "List locally tracked Capability Registry records")]
pub struct CapabilityRegistryLsCmd {
    #[arg(long, help = "Read current bond, reputation and active status from each registry entry")]
    on_chain: bool,
    #[arg(long, help = "Filter by owner address")]
    owner: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Capability Registry state by address or local record name")]
pub struct CapabilityRegistryShowCmd {
    #[arg(long, conflicts_with = "name", help = "Capability Registry address")]
    address: Option<String>,
    #[arg(long, help = "Local registry record name from `agent registry ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum CapabilityRegistryOperation {
    UpdateMetadata,
    UpdateVerifier,
    Stake,
    WithdrawBond,
    UpdateReputation,
    Deactivate,
    Reactivate,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a Capability Registry lifecycle message")]
pub struct CapabilityRegistrySendCmd {
    #[arg(long, value_enum)]
    operation: CapabilityRegistryOperation,
    #[arg(long, conflicts_with = "name", help = "Capability Registry address")]
    address: Option<String>,
    #[arg(long, help = "Local registry record name from `agent registry ls`")]
    name: Option<String>,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "New task categories hash for update-metadata")]
    task_categories_hash: Option<String>,
    #[arg(long, help = "New pricing hash for update-metadata")]
    pricing_hash: Option<String>,
    #[arg(long, help = "New metadata hash for update-metadata")]
    metadata_hash: Option<String>,
    #[arg(long, help = "New verification method hash for update-metadata")]
    verification_method_hash: Option<String>,
    #[arg(long, help = "New verifier address for update-verifier; omit to clear the verifier")]
    verifier: Option<String>,
    #[arg(long, help = "Amount to withdraw from the bond, in TOS, for withdraw-bond")]
    withdraw_amount: Option<f64>,
    #[arg(long, help = "Signed reputation delta for update-reputation")]
    delta: Option<i32>,
    #[arg(
        long,
        default_value_t = 0.01,
        help = "Message value in TOS; for stake this is the amount added to the bond"
    )]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Build deterministic Capability Registry StateInit")]
pub struct CapabilityRegistryBuildStateCmd {
    #[arg(long, help = "Owner address")]
    owner: String,
    #[arg(long, help = "Optional verifier allowed to adjust the reputation score")]
    verifier: Option<String>,
    #[arg(long, help = "32-byte hash of the advertised task categories")]
    task_categories_hash: String,
    #[arg(long, help = "32-byte hash of the advertised pricing model")]
    pricing_hash: String,
    #[arg(long, help = "32-byte hash of general capability/service metadata")]
    metadata_hash: String,
    #[arg(long, help = "32-byte hash identifying the supported verification method")]
    verification_method_hash: String,
    #[arg(long, default_value_t = 0.0, help = "Initial bond in TOS")]
    bond: f64,
    #[arg(long, help = "Unix registration timestamp; defaults to now")]
    registered_at: Option<u64>,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

/// Resolve the registry address from an explicit `--address` or a stored `--name` record.
fn resolve_registry_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .capability_registries
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!("Registry record '{}' not found; see `agent registry ls`", name)
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid Capability Registry address")
}

fn build_init(
    owner: MsgAddressInt,
    verifier: Option<MsgAddressInt>,
    task_categories_hash: &str,
    pricing_hash: &str,
    metadata_hash: &str,
    verification_method_hash: &str,
    bond: f64,
    registered_at: Option<u64>,
) -> anyhow::Result<CapabilityRegistryInit> {
    validate_tos_amount("bond", bond)?;
    Ok(CapabilityRegistryInit {
        owner,
        verifier,
        task_categories_hash: parse_required_hash(
            "task-categories-hash",
            &Some(task_categories_hash.to_owned()),
        )?,
        pricing_hash: parse_required_hash("pricing-hash", &Some(pricing_hash.to_owned()))?,
        metadata_hash: parse_required_hash("metadata-hash", &Some(metadata_hash.to_owned()))?,
        verification_method_hash: parse_required_hash(
            "verification-method-hash",
            &Some(verification_method_hash.to_owned()),
        )?,
        initial_bond: tos_to_nanotos(bond),
        registered_at: registered_at.unwrap_or_else(time_format::now),
    })
}

impl CapabilityRegistryDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let owner = self.owner.parse::<MsgAddressInt>().context("invalid owner address")?;
        let verifier = self
            .verifier
            .as_deref()
            .map(str::parse)
            .transpose()
            .context("invalid verifier address")?;
        let init = build_init(
            owner.clone(),
            verifier,
            &self.task_categories_hash,
            &self.pricing_hash,
            &self.metadata_hash,
            &self.verification_method_hash,
            self.bond,
            self.registered_at,
        )?;
        if tos_to_nanotos(self.amount) < init.initial_bond {
            anyhow::bail!("--amount must cover at least --bond plus gas");
        }
        let address = CapabilityRegistryContract::calculate_address(self.workchain, &init)?;
        let state_init = CapabilityRegistryContract::build_state_init(&init)?;
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("registry-{}", &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.capability_registries.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "Registry record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .capability_registries
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!(
                "Capability Registry address {} is already tracked as '{}'",
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
            || payer_info.balance < amount_nanotos.saturating_add(CAPABILITY_REGISTRY_DEPLOY_GAS)
        {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Capability Registry deployment?")? {
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
        config.capability_registries.insert(
            record_name.clone(),
            CapabilityRegistryConfig {
                address: address.to_string(),
                owner: owner.to_string(),
                verifier: init.verifier.as_ref().map(|v| v.to_string()),
                task_categories_hash: hex::encode(init.task_categories_hash),
                pricing_hash: hex::encode(init.pricing_hash),
                metadata_hash: hex::encode(init.metadata_hash),
                verification_method_hash: hex::encode(init.verification_method_hash),
                registered_at: init.registered_at,
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
                "{} Capability Registry '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct CapabilityRegistryDataView {
    address: String,
    owner: String,
    verifier: Option<String>,
    active: bool,
    registered_at: u64,
    bond: String,
    reputation_score: i64,
    task_categories_hash: String,
    pricing_hash: String,
    metadata_hash: String,
    verification_method_hash: String,
}

fn data_view(address: &MsgAddressInt, data: CapabilityRegistryData) -> CapabilityRegistryDataView {
    CapabilityRegistryDataView {
        address: address.to_string(),
        owner: data.owner.to_string(),
        verifier: data.verifier.map(|v| v.to_string()),
        active: data.active,
        registered_at: data.registered_at,
        bond: display_tos(data.bond),
        reputation_score: data.reputation_score,
        task_categories_hash: hex::encode(data.task_categories_hash),
        pricing_hash: hex::encode(data.pricing_hash),
        metadata_hash: hex::encode(data.metadata_hash),
        verification_method_hash: hex::encode(data.verification_method_hash),
    }
}

impl CapabilityRegistryShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_registry_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack =
            provider.get_method(address.to_string(), "get_capability_registry_data", vec![]).await?;
        let data = CapabilityRegistryContract::decode_data(&stack)?;
        let view = data_view(&address, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Capability Registry: {}", view.address);
            println!("Owner: {}", view.owner);
            println!("Verifier: {}", view.verifier.as_deref().unwrap_or("none"));
            println!("Active: {}", view.active);
            println!("Registered at: {}", view.registered_at);
            println!("Bond: {} TOS", view.bond);
            println!("Reputation score: {}", view.reputation_score);
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct CapabilityRegistryRecordView {
    name: String,
    address: String,
    owner: String,
    verifier: Option<String>,
    task_categories_hash: String,
    pricing_hash: String,
    metadata_hash: String,
    verification_method_hash: String,
    registered_at: u64,
    created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_bond: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_reputation_score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_error: Option<String>,
}

impl CapabilityRegistryLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let owner_filter = self
            .owner
            .as_deref()
            .map(MsgAddressInt::from_str)
            .transpose()
            .context("owner filter must be a valid native address")?;
        let mut records: Vec<CapabilityRegistryRecordView> = config
            .capability_registries
            .iter()
            .filter(|(_, entry)| {
                owner_filter.as_ref().is_none_or(|owner| {
                    entry.owner.parse::<MsgAddressInt>().ok().as_ref() == Some(owner)
                })
            })
            .map(|(name, entry)| CapabilityRegistryRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                owner: entry.owner.clone(),
                verifier: entry.verifier.clone(),
                task_categories_hash: entry.task_categories_hash.clone(),
                pricing_hash: entry.pricing_hash.clone(),
                metadata_hash: entry.metadata_hash.clone(),
                verification_method_hash: entry.verification_method_hash.clone(),
                registered_at: entry.registered_at,
                created_at: entry.created_at,
                chain_active: None,
                chain_bond: None,
                chain_reputation_score: None,
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
                            .context("invalid persisted Capability Registry address")?;
                        let stack = provider
                            .get_method(address.to_string(), "get_capability_registry_data", vec![])
                            .await?;
                        CapabilityRegistryContract::decode_data(&stack)
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
                        record.chain_bond = Some(display_tos(data.bond));
                        record.chain_reputation_score = Some(data.reputation_score);
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
            println!("No Capability Registry records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:  {}\n  Owner:    {}\n  Verifier: {}",
                record.name.bold(),
                record.address,
                record.owner,
                record.verifier.as_deref().unwrap_or("none"),
            );
            if let Some(active) = record.chain_active {
                println!("  Chain active:      {}", active);
            }
            if let Some(bond) = &record.chain_bond {
                println!("  Chain bond:        {} TOS", bond);
            }
            if let Some(score) = record.chain_reputation_score {
                println!("  Chain reputation:  {}", score);
            }
            if let Some(error) = &record.chain_error {
                println!("  Chain error:       {}", error);
            }
        }
        Ok(())
    }
}

impl CapabilityRegistrySendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_registry_address(&config, &self.address, &self.name)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }

        let body = match self.operation {
            CapabilityRegistryOperation::UpdateMetadata => {
                CapabilityRegistryContract::update_metadata(
                    self.query_id,
                    parse_required_hash("task-categories-hash", &self.task_categories_hash)?,
                    parse_required_hash("pricing-hash", &self.pricing_hash)?,
                    parse_required_hash("metadata-hash", &self.metadata_hash)?,
                    parse_required_hash(
                        "verification-method-hash",
                        &self.verification_method_hash,
                    )?,
                )?
            }
            CapabilityRegistryOperation::UpdateVerifier => {
                let verifier = self
                    .verifier
                    .as_deref()
                    .map(str::parse::<MsgAddressInt>)
                    .transpose()
                    .context("invalid verifier address")?;
                // This operation is only accepted on-chain when `sender ==
                // owner`, so the signing wallet's own address is exactly the
                // right filler for the slot the contract ignores when
                // `has_verifier` is false -- not an arbitrary placeholder.
                CapabilityRegistryContract::update_verifier(
                    self.query_id,
                    verifier.as_ref(),
                    &owner_address,
                )?
            }
            CapabilityRegistryOperation::Stake => CapabilityRegistryContract::stake(self.query_id)?,
            CapabilityRegistryOperation::WithdrawBond => CapabilityRegistryContract::withdraw_bond(
                self.query_id,
                tos_to_nanotos(
                    self.withdraw_amount
                        .ok_or_else(|| anyhow::anyhow!("--withdraw-amount is required"))?,
                ),
            )?,
            CapabilityRegistryOperation::UpdateReputation => {
                CapabilityRegistryContract::update_reputation(
                    self.query_id,
                    self.delta.ok_or_else(|| anyhow::anyhow!("--delta is required"))?,
                )?
            }
            CapabilityRegistryOperation::Deactivate => {
                CapabilityRegistryContract::deactivate(self.query_id)?
            }
            CapabilityRegistryOperation::Reactivate => {
                CapabilityRegistryContract::reactivate(self.query_id)?
            }
        };

        let amount_nanotos = tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(CAPABILITY_REGISTRY_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Capability Registry message?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), wallet_config, owner_secret, &self.from).await?;
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
            "{} Capability Registry {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination
        );
        Ok(())
    }
}

impl CapabilityRegistryBuildStateCmd {
    fn run(&self) -> anyhow::Result<()> {
        let owner = self.owner.parse::<MsgAddressInt>().context("invalid owner address")?;
        let verifier = self
            .verifier
            .as_deref()
            .map(str::parse)
            .transpose()
            .context("invalid verifier address")?;
        let init = build_init(
            owner,
            verifier,
            &self.task_categories_hash,
            &self.pricing_hash,
            &self.metadata_hash,
            &self.verification_method_hash,
            self.bond,
            self.registered_at,
        )?;
        let address = CapabilityRegistryContract::calculate_address(self.workchain, &init)?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::json!({ "address": address.to_string() }));
        } else {
            println!("Capability Registry address: {}", address);
        }
        Ok(())
    }
}
