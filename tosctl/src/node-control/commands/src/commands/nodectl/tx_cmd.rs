/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use super::output_format::OutputFormat;
use super::utils::try_create_rpc_client;
use colored::Colorize;
use common::app_config::AppConfig;
use std::path::Path;

/// Top-level `tosctl tx` command.
#[derive(clap::Args, Clone)]
#[command(about = "Transaction build, sign, and submit operations")]
pub struct TxCmd {
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
    action: TxAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum TxAction {
    /// Build a canonical transaction intent
    BuildIntent(TxBuildIntentCmd),
    /// Get the canonical signing payload for a transaction
    SigningPayload(TxSigningPayloadCmd),
    /// Submit an already-signed transaction
    SubmitSigned(TxSubmitSignedCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Build a canonical transaction intent")]
pub struct TxBuildIntentCmd {
    /// Source account address
    #[arg(long)]
    address: String,

    /// Message body as base64-encoded BOC
    #[arg(long)]
    body: String,

    /// Optional init code as base64-encoded BOC
    #[arg(long)]
    init_code: Option<String>,

    /// Optional init data as base64-encoded BOC
    #[arg(long)]
    init_data: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Get signing payload for a transaction")]
pub struct TxSigningPayloadCmd {
    /// Source account address
    #[arg(long)]
    address: String,

    /// Message body as base64-encoded BOC
    #[arg(long)]
    body: String,

    /// Optional init code
    #[arg(long)]
    init_code: Option<String>,

    /// Optional init data
    #[arg(long)]
    init_data: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Submit a signed transaction")]
pub struct TxSubmitSignedCmd {
    /// Signed message as base64-encoded BOC
    #[arg(long)]
    boc: String,

    /// Signer address (optional metadata)
    #[arg(long)]
    signer: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

impl TxCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            TxAction::BuildIntent(cmd) => cmd.run(&self.config).await,
            TxAction::SigningPayload(cmd) => cmd.run(&self.config).await,
            TxAction::SubmitSigned(cmd) => cmd.run(&self.config).await,
        }
    }
}

impl TxBuildIntentCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let result = rpc_client
            .build_transaction_intent(
                &self.address,
                &self.body,
                self.init_code.as_deref(),
                self.init_data.as_deref(),
            )
            .await?;

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!();
            println!("  {}", "Transaction Intent".bold());
            println!("  {}", "\u{2500}".repeat(40));
            println!("  {:<22} {}", "From:".dimmed(), result.from);
            println!("  {:<22} {}", "Account model:".dimmed(), result.account_model);
            println!("  {:<22} {}", "Auth version:".dimmed(), result.authorization_version);
            println!();
        }

        Ok(())
    }
}

impl TxSigningPayloadCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let result = rpc_client
            .get_signing_payload(
                &self.address,
                &self.body,
                self.init_code.as_deref(),
                self.init_data.as_deref(),
            )
            .await?;

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!();
            println!("  {}", "Signing Payload".bold());
            println!("  {}", "\u{2500}".repeat(40));
            println!("  {:<22} {}", "Version:".dimmed(), result.payload_version);
            println!("  {:<22} {}", "Encoding:".dimmed(), result.payload_encoding);
            println!("  {:<22} {}", "Chain ID:".dimmed(), result.chain_id);
            println!("  {:<22} {}", "Payload:".dimmed(), result.payload);
            println!();
        }

        Ok(())
    }
}

impl TxSubmitSignedCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let result =
            rpc_client.submit_signed_transaction(&self.boc, self.signer.as_deref()).await?;

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!();
            println!("  {}", "Submission Result".bold());
            println!("  {}", "\u{2500}".repeat(40));
            println!(
                "  {:<22} {}",
                "Accepted:".dimmed(),
                if result.accepted { "yes".green().to_string() } else { "no".red().to_string() }
            );
            println!("  {:<22} {}", "Tx hash:".dimmed(), result.transaction_hash);
            println!("  {:<22} {}", "Submission ID:".dimmed(), result.submission_id);
            println!();
        }

        Ok(())
    }
}
