/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use super::output_format::OutputFormat;
use super::utils::{save_config, try_create_rpc_client};
use chain_block::MsgAddressInt;
use colored::Colorize;
use common::{app_config::AppConfig, chain_utils::display_tons, time_format::format_ts};
use std::{path::Path, str::FromStr};

/// Top-level `tosctl account` command.
#[derive(clap::Args, Clone)]
#[command(about = "Account operations")]
pub struct AccountCmd {
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
    action: AccountAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AccountAction {
    /// Account status and summary
    Status(AccountStatusCmd),
    /// Account transaction history
    Txs(AccountTxsCmd),
    /// Bookmark management
    Bookmark(AccountBookmarkCmd),
}

// ---------------------------------------------------------------------------
// account status
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Account status and summary")]
pub struct AccountStatusCmd {
    #[arg(long)]
    address: String,

    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

// ---------------------------------------------------------------------------
// account txs
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Account transaction history")]
pub struct AccountTxsCmd {
    #[arg(long)]
    address: String,

    #[arg(long, default_value_t = 10, help = "Number of transactions to fetch (max 100)")]
    limit: u32,

    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

// ---------------------------------------------------------------------------
// account bookmark
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Manage account bookmarks")]
pub struct AccountBookmarkCmd {
    #[command(subcommand)]
    action: AccountBookmarkAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AccountBookmarkAction {
    /// Add bookmark
    Add(AccountBookmarkAddCmd),
    /// List bookmarks
    Ls(AccountBookmarkLsCmd),
    /// Remove bookmark
    Rm(AccountBookmarkRmCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List bookmarks")]
pub struct AccountBookmarkLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
pub struct AccountBookmarkAddCmd {
    #[arg(long)]
    name: String,
    #[arg(long)]
    address: String,
}

#[derive(clap::Args, Clone)]
pub struct AccountBookmarkRmCmd {
    #[arg(long)]
    name: String,
}

// ===========================================================================
// Run implementations
// ===========================================================================

impl AccountCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AccountAction::Status(cmd) => cmd.run(&self.config).await,
            AccountAction::Txs(cmd) => cmd.run(&self.config).await,
            AccountAction::Bookmark(cmd) => cmd.run(&self.config).await,
        }
    }
}

impl AccountStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let address = MsgAddressInt::from_str(&self.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", self.address, e))?;

        let info = rpc_client.get_address_information(&address).await?;

        let balance_display = display_tons(info.balance);

        let state_str = match info.state {
            chain_rpc_client::v2::data_models::AccountState::Active => "active",
            chain_rpc_client::v2::data_models::AccountState::Uninitialized => "uninit",
            chain_rpc_client::v2::data_models::AccountState::Frozen => "frozen",
        };

        let tx_hash = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &info.last_transaction_id.hash,
        );

        let sync_time = format_ts(info.sync_utime);

        let code_info = match &info.code {
            Some(c) => format!("Yes ({} bytes)", c.len()),
            None => "No".to_string(),
        };

        let data_info = match &info.data {
            Some(d) => format!("Yes ({} bytes)", d.len()),
            None => "No".to_string(),
        };

        if self.format == OutputFormat::Json {
            let obj = serde_json::json!({
                "address": address.to_string(),
                "balance": balance_display,
                "state": state_str,
                "last_tx_lt": info.last_transaction_id.lt,
                "last_tx_hash": tx_hash,
                "sync_time": sync_time,
                "code_present": code_info,
                "data_present": data_info,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            let state_display = match state_str {
                "active" => "active".green().bold().to_string(),
                "uninit" => "uninit".yellow().bold().to_string(),
                _ => "frozen".red().bold().to_string(),
            };

            println!();
            println!("  {}", "Account Status".bold());
            println!("  {}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
            println!("  {:<18} {}", "Address:".dimmed(), address);
            println!("  {:<18} {} TOS", "Balance:".dimmed(), balance_display);
            println!("  {:<18} {}", "State:".dimmed(), state_display);
            println!("  {:<18} {}", "Last tx LT:".dimmed(), info.last_transaction_id.lt);
            println!("  {:<18} {}", "Last tx hash:".dimmed(), tx_hash);
            println!("  {:<18} {}", "Sync time:".dimmed(), sync_time);
            println!("  {:<18} {}", "Code present:".dimmed(), code_info);
            println!("  {:<18} {}", "Data present:".dimmed(), data_info);
            println!();
        }

        Ok(())
    }
}

impl AccountTxsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let address = MsgAddressInt::from_str(&self.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", self.address, e))?;

        let limit = self.limit.min(100);

        // Get account info to find last_transaction_id
        let info = rpc_client.get_address_information(&address).await?;
        let lt = info.last_transaction_id.lt;
        let hash_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &info.last_transaction_id.hash,
        );

        if lt == 0 {
            if self.format == OutputFormat::Json {
                println!("[]");
            } else {
                println!();
                println!("  No transactions found for {}", self.address);
                println!();
            }
            return Ok(());
        }

        let txs_res = rpc_client.get_transactions(&address, lt, &hash_b64, limit).await?;

        if self.format == OutputFormat::Json {
            let views: Vec<serde_json::Value> = txs_res.transactions.iter().map(|tx| {
                serde_json::json!({
                    "lt": tx.lt,
                    "utime": tx.utime,
                    "time": format_ts(tx.utime as u64),
                    "hash": tx.hash,
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&views)?);
        } else {
            println!();
            println!(
                "{}",
                format!("Recent Transactions for {}", self.address).bold()
            );
            println!("{}", "\u{2500}".repeat(72));
            println!(
                "  {:<4} {:<18} {:<22} {}",
                "#".bold(),
                "LT".bold(),
                "Time".bold(),
                "Hash".bold(),
            );
            println!("  {}", "\u{2500}".repeat(68));

            for (i, tx) in txs_res.transactions.iter().enumerate() {
                let time_str = format_ts(tx.utime as u64);
                let hash_short = if tx.hash.len() > 16 {
                    &tx.hash[..16]
                } else {
                    &tx.hash
                };
                println!(
                    "  {:<4} {:<18} {:<22} {}...",
                    i + 1,
                    tx.lt,
                    time_str,
                    hash_short,
                );
            }

            if txs_res.transactions.is_empty() {
                println!("  (no transactions)");
            }

            println!();
        }
        Ok(())
    }
}

impl AccountBookmarkCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        match &self.action {
            AccountBookmarkAction::Add(cmd) => cmd.run(path).await,
            AccountBookmarkAction::Ls(cmd) => {
                let config = AppConfig::load(path)?;

                if config.bookmarks.is_empty() {
                    if cmd.format == OutputFormat::Json {
                        println!("[]");
                    } else {
                        println!("No bookmarks saved.");
                    }
                    return Ok(());
                }

                let mut entries: Vec<_> = config.bookmarks.iter().collect();
                entries.sort_by_key(|(name, _)| (*name).clone());

                if cmd.format == OutputFormat::Json {
                    let views: Vec<serde_json::Value> = entries.iter().map(|(name, address)| {
                        serde_json::json!({
                            "name": name,
                            "address": address,
                        })
                    }).collect();
                    println!("{}", serde_json::to_string_pretty(&views)?);
                } else {
                    println!();
                    println!("  {}", "Account Bookmarks".bold());
                    println!("  {}", "\u{2500}".repeat(60));
                    println!(
                        "  {:<20} {}",
                        "Name".bold(),
                        "Address".bold(),
                    );
                    println!("  {}", "\u{2500}".repeat(60));

                    for (name, address) in entries {
                        println!("  {:<20} {}", name, address);
                    }
                    println!();
                }
                Ok(())
            }
            AccountBookmarkAction::Rm(cmd) => cmd.run(path).await,
        }
    }
}

impl AccountBookmarkAddCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        // Validate the address
        MsgAddressInt::from_str(&self.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", self.address, e))?;

        let mut config = AppConfig::load(config_path)?;
        config
            .bookmarks
            .insert(self.name.clone(), self.address.clone());
        save_config(&config, config_path)?;

        println!("OK Bookmark '{}' added → {}", self.name, self.address);
        Ok(())
    }
}

impl AccountBookmarkRmCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(config_path)?;

        if config.bookmarks.remove(&self.name).is_none() {
            anyhow::bail!("Bookmark '{}' not found", self.name);
        }

        save_config(&config, config_path)?;
        println!("OK Bookmark '{}' removed", self.name);
        Ok(())
    }
}
