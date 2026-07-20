/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use super::agent_cmd::{
    confirm, parse_optional_signature, parse_required_hash, resolve_attestor_pubkey,
    send_wallet_message, sign_hash_with_vault_key, validate_tos_amount,
};
use super::output_format::OutputFormat;
use super::utils::{
    get_wallet_config, load_config_vault_rpc_client, make_wallet, save_config,
    try_create_rpc_client, wallet_info,
};
use anyhow::Context;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::data_models::AccountState;
use clap::ValueEnum;
use colored::Colorize;
use common::app_config::DisputeConfig;
use contracts::{
    DisputeContract, DisputeData, DisputeInit, RULING_CLAIMANT, RULING_NONE, RULING_RESPONDENT,
    RULING_SPLIT,
};
use std::path::Path;

const DISPUTE_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const DISPUTE_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent dispute` -- Dispute case operations.
#[derive(clap::Args, Clone)]
#[command(about = "Dispute case operations")]
pub struct DisputeCmd {
    #[command(subcommand)]
    action: DisputeAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum DisputeAction {
    /// Deploy a Dispute case
    Deploy(DisputeDeployCmd),
    /// List locally tracked Dispute records
    Ls(DisputeLsCmd),
    /// Show Dispute state by address or local record name
    Show(DisputeShowCmd),
    /// Send a Dispute lifecycle message
    Send(DisputeSendCmd),
}

impl DisputeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            DisputeAction::Deploy(cmd) => cmd.run(config_path).await,
            DisputeAction::Ls(cmd) => cmd.run(config_path).await,
            DisputeAction::Show(cmd) => cmd.run(config_path).await,
            DisputeAction::Send(cmd) => cmd.run(config_path).await,
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy a Dispute case")]
pub struct DisputeDeployCmd {
    #[arg(long, help = "Local dispute record name; defaults to dispute-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Claimant address; must match the funding wallet")]
    claimant: String,
    #[arg(long, help = "Respondent address")]
    respondent: String,
    #[arg(long, help = "Reviewer (arbitrator) address")]
    reviewer: String,
    #[arg(long, help = "Expected ruling deadline (Unix timestamp, informational only)")]
    deadline: u64,
    #[arg(long, help = "32-byte hash referencing the disputed subject (e.g. a Task Escrow)")]
    subject_hash: String,
    #[arg(long, help = "32-byte hash of the claimant's evidence")]
    claimant_evidence_hash: String,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "Optional 32-byte ed25519 public key; when set, rule also requires a signature over ruling_hash"
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
    #[arg(long, default_value_t = 0.05, help = "Message value funding the deploy, in TOS")]
    amount: f64,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(long)]
    yes: bool,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked Dispute records")]
pub struct DisputeLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Dispute state by address or local record name")]
pub struct DisputeShowCmd {
    #[arg(long, conflicts_with = "name", help = "Dispute address")]
    address: Option<String>,
    #[arg(long, help = "Local dispute record name from `agent dispute ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum DisputeOperation {
    SubmitRespondentEvidence,
    Rule,
    RotateAttestorKey,
    RevokeAttestor,
}

#[derive(Clone, clap::ValueEnum)]
enum DisputeRuling {
    Claimant,
    Respondent,
    Split,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a Dispute lifecycle message")]
pub struct DisputeSendCmd {
    #[arg(long, value_enum)]
    operation: DisputeOperation,
    #[arg(long, conflicts_with = "name", help = "Dispute address")]
    address: Option<String>,
    #[arg(long, help = "Local dispute record name from `agent dispute ls`")]
    name: Option<String>,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "Respondent evidence hash for submit-respondent-evidence")]
    respondent_evidence_hash: Option<String>,
    #[arg(long, value_enum, help = "Ruling outcome for rule")]
    ruling: Option<DisputeRuling>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Basis points awarded to the claimant, 0..=10000; only meaningful for a split ruling"
    )]
    split_bps: u16,
    #[arg(long, help = "Ruling rationale/evidence hash for rule")]
    ruling_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "64-byte ed25519 signature over ruling_hash, for rule on a dispute deployed with --attestor-pubkey"
    )]
    attestation_signature: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestation_signature",
        help = "Sign ruling_hash with this vault key instead of passing --attestation-signature directly"
    )]
    signer_vault_key: Option<String>,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "New 32-byte ed25519 public key for rotate-attestor-key (reviewer-only)"
    )]
    new_attestor_pubkey: Option<String>,
    #[arg(long, default_value_t = 0.01, help = "Message value in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

/// Resolve the dispute address from an explicit `--address` or a stored `--name` record.
fn resolve_dispute_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .disputes
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!("Dispute record '{}' not found; see `agent dispute ls`", name)
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid Dispute address")
}

impl DisputeDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let claimant = self.claimant.parse::<MsgAddressInt>().context("invalid claimant address")?;
        let respondent =
            self.respondent.parse::<MsgAddressInt>().context("invalid respondent address")?;
        let reviewer = self.reviewer.parse::<MsgAddressInt>().context("invalid reviewer address")?;
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let attestor_pubkey =
            resolve_attestor_pubkey(&self.attestor_pubkey, &self.signer_vault_key, vault.clone())
                .await?;
        let init = DisputeInit {
            claimant: claimant.clone(),
            respondent: respondent.clone(),
            reviewer: reviewer.clone(),
            deadline: self.deadline,
            subject_hash: parse_required_hash("subject-hash", &Some(self.subject_hash.clone()))?,
            claimant_evidence_hash: parse_required_hash(
                "claimant-evidence-hash",
                &Some(self.claimant_evidence_hash.clone()),
            )?,
            attestor_pubkey,
        };
        let address = DisputeContract::calculate_address(self.workchain, &init)?;
        let state_init = DisputeContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("dispute-{}", &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.disputes.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "Dispute record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .disputes
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!("Dispute address {} is already tracked as '{}'", address, existing_name);
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != claimant {
            anyhow::bail!("claimant address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if amount_nanotos == 0
            || payer_info.balance < amount_nanotos.saturating_add(DISPUTE_DEPLOY_GAS)
        {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Dispute deployment?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), payer_cfg, payer_secret, &self.from).await?;
        let body = chain_block::BuilderData::new().into_cell()?;
        super::agent_cmd::send_wallet_message_with_state_init(
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
        config.disputes.insert(
            record_name.clone(),
            DisputeConfig {
                address: address.to_string(),
                claimant: claimant.to_string(),
                respondent: respondent.to_string(),
                reviewer: reviewer.to_string(),
                deadline: init.deadline,
                subject_hash: hex::encode(init.subject_hash),
                claimant_evidence_hash: hex::encode(init.claimant_evidence_hash),
                attestor_pubkey: init.attestor_pubkey.map(hex::encode),
                created_at: Some(common::time_format::now()),
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
                    "claimant": claimant.to_string(),
                })
            );
        } else {
            println!("{} Dispute '{}' deployed at {}", "OK".green().bold(), record_name, address);
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct DisputeDataView {
    address: String,
    claimant: String,
    respondent: String,
    reviewer: String,
    status: String,
    ruling: String,
    split_bps: u16,
    deadline: u64,
    subject_hash: String,
    claimant_evidence_hash: String,
    respondent_evidence_hash: String,
    ruling_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestor_pubkey: Option<String>,
}

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "open",
        1 => "evidence_submitted",
        2 => "resolved",
        _ => "unknown",
    }
}

fn ruling_name(ruling: u8) -> &'static str {
    match ruling {
        RULING_NONE => "none",
        RULING_CLAIMANT => "claimant",
        RULING_RESPONDENT => "respondent",
        RULING_SPLIT => "split",
        _ => "unknown",
    }
}

fn data_view(address: &MsgAddressInt, data: DisputeData) -> DisputeDataView {
    DisputeDataView {
        address: address.to_string(),
        claimant: data.claimant.to_string(),
        respondent: data.respondent.to_string(),
        reviewer: data.reviewer.to_string(),
        status: status_name(data.status).to_owned(),
        ruling: ruling_name(data.ruling).to_owned(),
        split_bps: data.split_bps,
        deadline: data.deadline,
        subject_hash: hex::encode(data.subject_hash),
        claimant_evidence_hash: hex::encode(data.claimant_evidence_hash),
        respondent_evidence_hash: hex::encode(data.respondent_evidence_hash),
        ruling_hash: hex::encode(data.ruling_hash),
        attestor_pubkey: data.attestor_pubkey.map(hex::encode),
    }
}

impl DisputeShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_dispute_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack = provider.get_method(address.to_string(), "get_dispute_data", vec![]).await?;
        let data = DisputeContract::decode_data(&stack)?;
        let view = data_view(&address, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Dispute: {}", view.address);
            println!("Claimant:  {}", view.claimant);
            println!("Respondent: {}", view.respondent);
            println!("Reviewer:  {}", view.reviewer);
            println!("Status: {}", view.status);
            println!("Ruling: {}", view.ruling);
            if view.ruling == "split" {
                println!("Split (bps to claimant): {}", view.split_bps);
            }
            println!("Attestor pubkey: {}", view.attestor_pubkey.as_deref().unwrap_or("none"));
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct DisputeRecordView {
    name: String,
    address: String,
    claimant: String,
    respondent: String,
    reviewer: String,
    deadline: u64,
    created_at: Option<u64>,
}

impl DisputeLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let mut records: Vec<DisputeRecordView> = config
            .disputes
            .iter()
            .map(|(name, entry)| DisputeRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                claimant: entry.claimant.clone(),
                respondent: entry.respondent.clone(),
                reviewer: entry.reviewer.clone(),
                deadline: entry.deadline,
                created_at: entry.created_at,
            })
            .collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No Dispute records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:    {}\n  Claimant:   {}\n  Respondent: {}\n  Reviewer:   {}",
                record.name.bold(),
                record.address,
                record.claimant,
                record.respondent,
                record.reviewer,
            );
        }
        Ok(())
    }
}

impl DisputeSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_dispute_address(&config, &self.address, &self.name)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault.clone()).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }

        let body = match self.operation {
            DisputeOperation::SubmitRespondentEvidence => {
                DisputeContract::submit_respondent_evidence(
                    self.query_id,
                    parse_required_hash(
                        "respondent-evidence-hash",
                        &self.respondent_evidence_hash,
                    )?,
                )?
            }
            DisputeOperation::Rule => {
                let ruling = match self
                    .ruling
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("--ruling is required"))?
                {
                    DisputeRuling::Claimant => RULING_CLAIMANT,
                    DisputeRuling::Respondent => RULING_RESPONDENT,
                    DisputeRuling::Split => RULING_SPLIT,
                };
                if self.split_bps > 10_000 {
                    anyhow::bail!("--split-bps must be between 0 and 10000");
                }
                let ruling_hash = parse_required_hash("ruling-hash", &self.ruling_hash)?;
                let signature = match parse_optional_signature(
                    "attestation-signature",
                    &self.attestation_signature,
                )? {
                    Some(signature) => Some(signature),
                    None => match &self.signer_vault_key {
                        Some(name) => {
                            Some(sign_hash_with_vault_key(name, &ruling_hash, vault.clone()).await?)
                        }
                        None => None,
                    },
                };
                match signature {
                    Some(signature) => DisputeContract::rule_signed(
                        self.query_id,
                        ruling,
                        self.split_bps,
                        ruling_hash,
                        &signature,
                    )?,
                    None => {
                        DisputeContract::rule(self.query_id, ruling, self.split_bps, ruling_hash)?
                    }
                }
            }
            DisputeOperation::RotateAttestorKey => {
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
                DisputeContract::rotate_attestor_key(self.query_id, pubkey)?
            }
            DisputeOperation::RevokeAttestor => DisputeContract::revoke_attestor(self.query_id)?,
        };

        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(DISPUTE_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Dispute message?")? {
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
            "{} Dispute {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination
        );
        Ok(())
    }
}
