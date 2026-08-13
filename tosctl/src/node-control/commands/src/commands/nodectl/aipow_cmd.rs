/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use super::agent_cmd::{
    confirm, parse_required_hash, send_wallet_message, validate_tos_amount,
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
use common::app_config::AipowCommitmentConfig;
use contracts::{AipowCommitmentContract, AipowCommitmentData, AipowCommitmentInit};
use std::path::Path;

const AIPOW_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const AIPOW_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS
// The deploy must fund the bond plus a reserve the contract keeps to pay for
// its own outgoing bond returns (finalize/rule/timeout use mode-1 sends whose
// fees come from the contract balance), so it can never be left underfunded.
const AIPOW_MIN_DEPLOY_RESERVE: u64 = 100_000_000; // 0.1 TOS

/// `tosctl agent aipow` -- AIPoW epoch score-commitment operations.
#[derive(clap::Args, Clone)]
#[command(about = "AIPoW score-commitment operations")]
pub struct AipowCmd {
    #[command(subcommand)]
    action: AipowAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AipowAction {
    /// Deploy (commit) an epoch score root with a bonded challenge window
    Deploy(AipowDeployCmd),
    /// List locally tracked score-commitment records
    Ls(AipowLsCmd),
    /// Show score-commitment state by address or local record name
    Show(AipowShowCmd),
    /// Send a score-commitment lifecycle message
    Send(AipowSendCmd),
}

impl AipowCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AipowAction::Deploy(cmd) => cmd.run(config_path).await,
            AipowAction::Ls(cmd) => cmd.run(config_path).await,
            AipowAction::Show(cmd) => cmd.run(config_path).await,
            AipowAction::Send(cmd) => cmd.run(config_path).await,
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy (commit) an epoch score root with a bonded challenge window")]
pub struct AipowDeployCmd {
    #[arg(long, help = "Local record name; defaults to aipow-<epoch>-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Committer address; must match the funding wallet")]
    committer: String,
    #[arg(long, help = "Reviewer address authorized to rule a challenge")]
    reviewer: String,
    #[arg(long, help = "AIPoW epoch number this root scores")]
    epoch: u64,
    #[arg(
        long,
        help = "Unix timestamp: challenges land strictly before, finalize at or after"
    )]
    window_deadline: u64,
    #[arg(
        long,
        help = "Committer bond in TOS; a challenge must attach at least this much"
    )]
    commit_bond: f64,
    #[arg(long, help = "32-byte epoch score root (hex)")]
    score_root: String,
    #[arg(long, help = "32-byte methodology commitment (hex)")]
    methodology_hash: String,
    #[arg(
        long,
        help = "Epoch total score (pro-rata denominator); bound and bonded so a distributor over this root can be checked against it"
    )]
    total_score: u128,
    #[arg(
        long,
        help = "Epoch organic settled value in nanotos; bound so the phase C native path derives the pool from a committed value"
    )]
    organic_settled_value: u128,
    #[arg(long, help = "Funding wallet name or master_wallet")]
    from: String,
    #[arg(
        long,
        help = "Message value funding the deploy, in TOS; defaults to the bond plus a 1 TOS fee/storage margin"
    )]
    amount: Option<f64>,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(
        long,
        help = "AIPoW settlement account address this commitment registers to on finalization; omit to disable registration"
    )]
    settlement: Option<String>,
    #[arg(long)]
    yes: bool,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked score-commitment records")]
pub struct AipowLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show score-commitment state by address or local record name")]
pub struct AipowShowCmd {
    #[arg(long, conflicts_with = "name", help = "Score-commitment address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent aipow ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum AipowOperation {
    Announce,
    Challenge,
    Finalize,
    Rule,
    Timeout,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a score-commitment lifecycle message")]
pub struct AipowSendCmd {
    #[arg(long, value_enum)]
    operation: AipowOperation,
    #[arg(long, conflicts_with = "name", help = "Score-commitment address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent aipow ls`")]
    name: Option<String>,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(
        long,
        help = "32-byte nonzero evidence hash for challenge (hex); the bond is fixed at the commit bond, so --amount must cover it and any excess is refunded. The committer and reviewer cannot challenge"
    )]
    challenge_evidence_hash: Option<String>,
    #[arg(
        long,
        help = "Ruling for rule: true upholds the challenge (root rejected, bonds to the challenger), false dismisses it (root final, bonds to the committer)"
    )]
    uphold: Option<bool>,
    #[arg(long, default_value_t = 0.05, help = "Message value in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

/// Resolve the commitment address from an explicit `--address` or a stored
/// `--name` record.
fn resolve_aipow_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .aipow_commitments
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "AIPoW commitment record '{}' not found; see `agent aipow ls`",
                    name
                )
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid AIPoW commitment address")
}

impl AipowDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("commit-bond", self.commit_bond)?;
        let committer =
            self.committer.parse::<MsgAddressInt>().context("invalid committer address")?;
        let reviewer = self.reviewer.parse::<MsgAddressInt>().context("invalid reviewer address")?;
        let commit_bond = common::chain_utils::tos_to_nanotos(self.commit_bond);
        // Default deploy value: the bond plus a fee/storage margin, mirroring
        // the Task Escrow budget-plus-margin funding convention.
        let amount = match self.amount {
            Some(amount) => {
                validate_tos_amount("amount", amount)?;
                amount
            }
            None => self.commit_bond + 1.0,
        };
        let amount_nanotos = common::chain_utils::tos_to_nanotos(amount);
        if amount_nanotos < commit_bond.saturating_add(AIPOW_MIN_DEPLOY_RESERVE) {
            anyhow::bail!(
                "--amount must cover the commit bond plus at least a {} nanotos fee/storage reserve",
                AIPOW_MIN_DEPLOY_RESERVE
            );
        }
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let _ = vault;
        let init = AipowCommitmentInit {
            committer: committer.clone(),
            reviewer: reviewer.clone(),
            epoch: self.epoch,
            window_deadline: self.window_deadline,
            commit_bond,
            score_root: parse_required_hash("score-root", &Some(self.score_root.clone()))?,
            methodology_hash: parse_required_hash(
                "methodology-hash",
                &Some(self.methodology_hash.clone()),
            )?,
            total_score: self.total_score,
            organic_settled_value: self.organic_settled_value,
            // A commitment registers its finalized root to this settlement
            // account; omitting it stores addr_none, so the root finalizes but
            // is never advertised.
            settlement: match &self.settlement {
                Some(addr) => Some(
                    addr.parse().map_err(|e| anyhow::anyhow!("invalid --settlement address: {e}"))?,
                ),
                None => None,
            },
        };
        let address = AipowCommitmentContract::calculate_address(self.workchain, &init)?;
        let state_init = AipowCommitmentContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("aipow-{}-{}", self.epoch, &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.aipow_commitments.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "AIPoW commitment record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .aipow_commitments
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!(
                "AIPoW commitment address {} is already tracked as '{}'",
                address,
                existing_name
            );
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != committer {
            anyhow::bail!("committer address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        if payer_info.balance < amount_nanotos.saturating_add(AIPOW_DEPLOY_GAS) {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW score-commitment deployment?")? {
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
        config.aipow_commitments.insert(
            record_name.clone(),
            AipowCommitmentConfig {
                address: address.to_string(),
                committer: committer.to_string(),
                reviewer: reviewer.to_string(),
                epoch: self.epoch,
                window_deadline: self.window_deadline,
                commit_bond,
                score_root: hex::encode(init.score_root),
                methodology_hash: hex::encode(init.methodology_hash),
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
                    "epoch": self.epoch,
                    "committer": committer.to_string(),
                })
            );
        } else {
            println!(
                "{} AIPoW commitment '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct AipowDataView {
    address: String,
    committer: String,
    reviewer: String,
    status: String,
    epoch: u64,
    window_deadline: u64,
    review_deadline: u64,
    commit_bond: u64,
    challenge_bond: u64,
    score_root: String,
    methodology_hash: String,
    total_score: String,
    organic_settled_value: String,
    challenger: String,
    challenge_evidence_hash: String,
}

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "committed",
        1 => "challenged",
        2 => "final",
        3 => "rejected",
        _ => "unknown",
    }
}

fn data_view(address: &MsgAddressInt, data: AipowCommitmentData) -> AipowDataView {
    AipowDataView {
        address: address.to_string(),
        committer: data.committer.to_string(),
        reviewer: data.reviewer.to_string(),
        status: status_name(data.status).to_owned(),
        epoch: data.epoch,
        window_deadline: data.window_deadline,
        review_deadline: data.review_deadline,
        commit_bond: data.commit_bond,
        challenge_bond: data.challenge_bond,
        score_root: hex::encode(data.score_root),
        methodology_hash: hex::encode(data.methodology_hash),
        total_score: data.total_score.to_string(),
        organic_settled_value: data.organic_settled_value.to_string(),
        challenger: data.challenger.to_string(),
        challenge_evidence_hash: hex::encode(data.challenge_evidence_hash),
    }
}

impl AipowShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_aipow_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack =
            provider.get_method(address.to_string(), "get_aipow_commitment_data", vec![]).await?;
        let data = AipowCommitmentContract::decode_data(&stack)?;
        let view = data_view(&address, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("AIPoW commitment: {}", view.address);
            println!("Committer: {}", view.committer);
            println!("Reviewer:  {}", view.reviewer);
            println!("Status: {}", view.status);
            println!("Epoch:  {}", view.epoch);
            println!("Window deadline: {}", view.window_deadline);
            println!("Review deadline: {}", view.review_deadline);
            println!("Commit bond (nanotos):    {}", view.commit_bond);
            println!("Challenge bond (nanotos): {}", view.challenge_bond);
            println!("Total score:  {}", view.total_score);
            println!("Organic settled value (nanotos): {}", view.organic_settled_value);
            println!("Score root: {}", view.score_root);
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct AipowRecordView {
    name: String,
    address: String,
    committer: String,
    reviewer: String,
    epoch: u64,
    window_deadline: u64,
    created_at: Option<u64>,
}

impl AipowLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let mut records: Vec<AipowRecordView> = config
            .aipow_commitments
            .iter()
            .map(|(name, entry)| AipowRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                committer: entry.committer.clone(),
                reviewer: entry.reviewer.clone(),
                epoch: entry.epoch,
                window_deadline: entry.window_deadline,
                created_at: entry.created_at,
            })
            .collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No AIPoW commitment records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:   {}\n  Committer: {}\n  Reviewer:  {}\n  Epoch:     {}",
                record.name.bold(),
                record.address,
                record.committer,
                record.reviewer,
                record.epoch,
            );
        }
        Ok(())
    }
}

impl AipowSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_aipow_address(&config, &self.address, &self.name)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault.clone()).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }

        let body = match self.operation {
            AipowOperation::Announce => AipowCommitmentContract::announce(self.query_id)?,
            AipowOperation::Challenge => AipowCommitmentContract::challenge(
                self.query_id,
                parse_required_hash("challenge-evidence-hash", &self.challenge_evidence_hash)?,
            )?,
            AipowOperation::Finalize => AipowCommitmentContract::finalize(self.query_id)?,
            AipowOperation::Rule => AipowCommitmentContract::rule(
                self.query_id,
                self.uphold.ok_or_else(|| anyhow::anyhow!("--uphold is required for rule"))?,
            )?,
            AipowOperation::Timeout => AipowCommitmentContract::timeout(self.query_id)?,
        };

        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(AIPOW_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW commitment message?")? {
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
            "{} AIPoW commitment {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination
        );
        Ok(())
    }
}
