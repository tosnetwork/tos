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
use chain_rpc_client::v2::{
    RPCStackEntry,
    data_models::{
        AccountAgentCapability, AccountDelegationGrant, AccountSessionCapability,
        LifecycleGrantRequest, LifecycleRevokeRequest, RunGetMethodParams,
    },
};
use colored::Colorize;
use common::{app_config::AppConfig, chain_utils::display_tos, time_format::format_ts};
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
    /// Account capability discovery
    Capability(AccountCapabilityCmd),
    /// Account delegations inspection
    Delegations(AccountDelegationsCmd),
    /// Account sessions inspection
    Sessions(AccountSessionsCmd),
    /// Account agents inspection
    Agents(AccountAgentsCmd),
    /// Account transaction history
    Txs(AccountTxsCmd),
    /// Bookmark management
    Bookmark(AccountBookmarkCmd),
    /// Run a get-method on a smart contract
    RunMethod(AccountRunMethodCmd),
    /// Send a raw BOC message
    SendBoc(AccountSendBocCmd),
    /// Grant a delegation to an account
    DelegationGrant(AccountDelegationGrantCmd),
    /// Revoke a delegation from an account
    DelegationRevoke(AccountDelegationRevokeCmd),
    /// Grant a session capability to an account
    SessionGrant(AccountSessionGrantCmd),
    /// Revoke a session capability from an account
    SessionRevoke(AccountSessionRevokeCmd),
    /// Grant an agent capability to an account
    AgentGrant(AccountAgentGrantCmd),
    /// Revoke an agent capability from an account
    AgentRevoke(AccountAgentRevokeCmd),
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

#[derive(clap::Args, Clone)]
#[command(about = "Inspect account capability")]
pub struct AccountCapabilityCmd {
    #[arg(long)]
    address: String,

    #[arg(long)]
    seqno: Option<u32>,

    #[arg(long, default_value_t = false)]
    include_experimental: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Inspect account delegations")]
pub struct AccountDelegationsCmd {
    #[arg(long)]
    address: String,

    #[arg(long, default_value_t = false)]
    include_inactive: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Inspect account sessions")]
pub struct AccountSessionsCmd {
    #[arg(long)]
    address: String,

    #[arg(long, default_value_t = false)]
    include_inactive: bool,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Inspect account agents")]
pub struct AccountAgentsCmd {
    #[arg(long)]
    address: String,

    #[arg(long, default_value_t = false)]
    include_inactive: bool,

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

// ---------------------------------------------------------------------------
// account run-method
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Run a get-method on a smart contract")]
pub struct AccountRunMethodCmd {
    /// Contract address (raw or friendly format)
    #[arg(long)]
    address: String,

    /// Method name (e.g. "seqno", "get_pool_data")
    method: String,

    /// Stack arguments as ["type","value"] pairs (e.g. '["num","123"]')
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

// ---------------------------------------------------------------------------
// account send-boc
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Send a raw BOC message to the blockchain")]
pub struct AccountSendBocCmd {
    /// Path to BOC file (binary or base64-encoded)
    boc_file: String,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

// ---------------------------------------------------------------------------
// account delegation-grant / delegation-revoke
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Grant a delegation (lifecycle mutation)")]
pub struct AccountDelegationGrantCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    grantee: String,
    #[arg(long)]
    scope: String,
    #[arg(long, default_value = "{}")]
    constraints: String,
    #[arg(long)]
    expires_at: Option<u64>,
    #[arg(long, default_value_t = false)]
    revocable: bool,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Revoke a delegation (lifecycle mutation)")]
pub struct AccountDelegationRevokeCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    permission_id: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Grant a session capability (lifecycle mutation)")]
pub struct AccountSessionGrantCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    grantee: String,
    #[arg(long)]
    scope: String,
    #[arg(long, default_value = "{}")]
    constraints: String,
    #[arg(long)]
    expires_at: Option<u64>,
    #[arg(long, default_value_t = false)]
    revocable: bool,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Revoke a session capability (lifecycle mutation)")]
pub struct AccountSessionRevokeCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    permission_id: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Grant an agent capability (lifecycle mutation)")]
pub struct AccountAgentGrantCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    grantee: String,
    #[arg(long)]
    scope: String,
    #[arg(long, default_value = "{}")]
    constraints: String,
    #[arg(long)]
    expires_at: Option<u64>,
    #[arg(long, default_value_t = false)]
    revocable: bool,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Revoke an agent capability (lifecycle mutation)")]
pub struct AccountAgentRevokeCmd {
    #[arg(long)]
    address: String,
    #[arg(long)]
    permission_id: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

// ===========================================================================
// Run implementations
// ===========================================================================

impl AccountCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AccountAction::Status(cmd) => cmd.run(&self.config).await,
            AccountAction::Capability(cmd) => cmd.run(&self.config).await,
            AccountAction::Delegations(cmd) => cmd.run(&self.config).await,
            AccountAction::Sessions(cmd) => cmd.run(&self.config).await,
            AccountAction::Agents(cmd) => cmd.run(&self.config).await,
            AccountAction::Txs(cmd) => cmd.run(&self.config).await,
            AccountAction::Bookmark(cmd) => cmd.run(&self.config).await,
            AccountAction::RunMethod(cmd) => cmd.run(&self.config).await,
            AccountAction::SendBoc(cmd) => cmd.run(&self.config).await,
            AccountAction::DelegationGrant(cmd) => cmd.run(&self.config).await,
            AccountAction::DelegationRevoke(cmd) => cmd.run(&self.config).await,
            AccountAction::SessionGrant(cmd) => cmd.run(&self.config).await,
            AccountAction::SessionRevoke(cmd) => cmd.run(&self.config).await,
            AccountAction::AgentGrant(cmd) => cmd.run(&self.config).await,
            AccountAction::AgentRevoke(cmd) => cmd.run(&self.config).await,
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

        let balance_display = display_tos(info.balance);

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

fn parse_account_address(address: &str) -> anyhow::Result<MsgAddressInt> {
    MsgAddressInt::from_str(address)
        .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", address, e))
}

fn print_permission_objects_json<T: serde::Serialize>(items: &[T]) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(items)?);
    Ok(())
}

fn print_delegations_table(items: &[AccountDelegationGrant]) {
    println!();
    println!("  {}", "Account Delegations".bold());
    println!("  {}", "\u{2500}".repeat(110));
    println!(
        "  {:<18} {:<18} {:<16} {:<12} {:<12} {}",
        "ID".bold(),
        "Account".bold(),
        "Grantee".bold(),
        "Scope".bold(),
        "Status".bold(),
        "Expires".bold(),
    );
    println!("  {}", "\u{2500}".repeat(110));
    if items.is_empty() {
        println!("  (no delegations)");
    } else {
        for item in items {
            let account_raw = item.account.as_deref().unwrap_or("-");
            let account = if account_raw.len() > 16 { &account_raw[..16] } else { account_raw };
            let grantee = if item.grantee.len() > 16 { &item.grantee[..16] } else { &item.grantee };
            let expires = item
                .expires_at
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  {:<18} {:<18} {:<16} {:<12} {:<12} {}",
                item.id,
                account,
                grantee,
                item.scope,
                item.status,
                expires,
            );
        }
    }
    println!();
}

fn print_sessions_table(items: &[AccountSessionCapability]) {
    println!();
    println!("  {}", "Account Sessions".bold());
    println!("  {}", "\u{2500}".repeat(106));
    println!(
        "  {:<18} {:<18} {:<16} {:<18} {:<12} {}",
        "Session ID".bold(),
        "Account".bold(),
        "Principal".bold(),
        "Scope".bold(),
        "Status".bold(),
        "Expires".bold(),
    );
    println!("  {}", "\u{2500}".repeat(106));
    if items.is_empty() {
        println!("  (no sessions)");
    } else {
        for item in items {
            let account_raw = item.account.as_deref().unwrap_or("-");
            let account = if account_raw.len() > 16 { &account_raw[..16] } else { account_raw };
            let principal =
                if item.principal.len() > 16 { &item.principal[..16] } else { &item.principal };
            let expires = item
                .expires_at
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  {:<18} {:<18} {:<16} {:<18} {:<12} {}",
                item.session_id,
                account,
                principal,
                item.scope,
                item.status,
                expires,
            );
        }
    }
    println!();
}

fn print_agents_table(items: &[AccountAgentCapability]) {
    println!();
    println!("  {}", "Account Agents".bold());
    println!("  {}", "\u{2500}".repeat(106));
    println!(
        "  {:<18} {:<18} {:<16} {:<18} {:<12} {}",
        "Agent ID".bold(),
        "Account".bold(),
        "Principal".bold(),
        "Scope".bold(),
        "Status".bold(),
        "Expires".bold(),
    );
    println!("  {}", "\u{2500}".repeat(106));
    if items.is_empty() {
        println!("  (no agents)");
    } else {
        for item in items {
            let account_raw = item.account.as_deref().unwrap_or("-");
            let account = if account_raw.len() > 16 { &account_raw[..16] } else { account_raw };
            let principal =
                if item.principal.len() > 16 { &item.principal[..16] } else { &item.principal };
            let expires = item
                .expires_at
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  {:<18} {:<18} {:<16} {:<18} {:<12} {}",
                item.agent_id,
                account,
                principal,
                item.scope,
                item.status,
                expires,
            );
        }
    }
    println!();
}

fn format_json_value_inline(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::Bool(v) => v.to_string(),
        serde_json::Value::Number(v) => v.to_string(),
        serde_json::Value::String(v) => v.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<invalid-json>".to_string()),
    }
}

fn print_lifecycle_json_section(title: &str, value: &serde_json::Value) {
    println!("  {}", title.bold());
    match value {
        serde_json::Value::Object(map) if !map.is_empty() => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (key, field_value) in entries {
                println!("  {:<22} {}", format!("{key}:").dimmed(), format_json_value_inline(field_value));
            }
        }
        _ => {
            println!("  {}", "(none)".dimmed());
        }
    }
    println!();
}

fn print_lifecycle_result_table(
    title: &str,
    result: &chain_rpc_client::v2::data_models::LifecycleMutationResultRes,
) {
    println!();
    println!("  {}", title.bold());
    println!("  {}", "\u{2500}".repeat(56));
    println!("  {:<22} {}", "Method:".dimmed(), result.method);
    println!("  {:<22} {}", "Account model:".dimmed(), result.account_model);
    println!("  {:<22} {}", "Accepted:".dimmed(), result.accepted);
    println!();
    print_lifecycle_json_section("Mutation Intent", &result.mutation_intent);
    print_lifecycle_json_section("Affected Preview", &result.affected_object_preview);
}

impl AccountCapabilityCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let capability = rpc_client
            .get_account_capability(&address, self.seqno, self.include_experimental)
            .await?;

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&capability)?);
        } else {
            println!();
            println!("  {}", "Account Capability".bold());
            println!("  {}", "\u{2500}".repeat(36));
            println!("  {:<22} {}", "Address:".dimmed(), capability.address);
            println!("  {:<22} {}", "Account model:".dimmed(), capability.account_model);
            println!(
                "  {:<22} {}",
                "Authorization ver.:".dimmed(),
                capability.authorization_version
            );
            println!("  {:<22} {}", "Account state:".dimmed(), capability.account_state);
            println!("  {:<22} {}", "Revision:".dimmed(), capability.revision);
            println!("  {:<22} {}", "Delegation support:".dimmed(), capability.supports_delegation);
            println!("  {:<22} {}", "Session support:".dimmed(), capability.supports_sessions);
            println!("  {:<22} {}", "Agent support:".dimmed(), capability.supports_agents);
            println!("  {:<22} {}", "Delegation source:".dimmed(), capability.delegation_source);
            println!("  {:<22} {}", "Session source:".dimmed(), capability.session_source);
            println!("  {:<22} {}", "Agent source:".dimmed(), capability.agent_source);
            println!("  {:<22} {}", "Capability maturity:".dimmed(), capability.capability_maturity);
            if let Some(supported) = capability.supports_sponsorship {
                println!("  {:<22} {}", "Sponsorship support:".dimmed(), supported);
            }
            println!();
        }

        Ok(())
    }
}

impl AccountDelegationsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let items = rpc_client.get_account_delegations(&address, self.include_inactive).await?;
        if self.format == OutputFormat::Json {
            print_permission_objects_json(&items)?;
        } else {
            print_delegations_table(&items);
        }
        Ok(())
    }
}

impl AccountSessionsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let items = rpc_client.get_account_sessions(&address, self.include_inactive).await?;
        if self.format == OutputFormat::Json {
            print_permission_objects_json(&items)?;
        } else {
            print_sessions_table(&items);
        }
        Ok(())
    }
}

impl AccountAgentsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let items = rpc_client.get_account_agents(&address, self.include_inactive).await?;
        if self.format == OutputFormat::Json {
            print_permission_objects_json(&items)?;
        } else {
            print_agents_table(&items);
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

impl AccountRunMethodCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        // Validate address
        MsgAddressInt::from_str(&self.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", self.address, e))?;

        let stack = if self.args.is_empty() {
            None
        } else {
            let entries: Vec<RPCStackEntry> = self
                .args
                .iter()
                .map(|arg| {
                    serde_json::from_str::<RPCStackEntry>(arg)
                        .map_err(|e| anyhow::anyhow!("Invalid stack argument '{}': {}", arg, e))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Some(entries)
        };

        let params = RunGetMethodParams {
            address: self.address.clone(),
            method_id: self.method.clone(),
            stack,
            seqno: None,
        };

        let result = rpc_client.run_get_method(&params).await?;

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!();
            println!("  {}", "Run Get-Method Result".bold());
            println!("  {}", "\u{2500}".repeat(40));
            println!("  {:<18} {}", "Exit code:".dimmed(), result.exit_code);
            println!("  {:<18} {}", "Gas used:".dimmed(), result.gas_used);
            println!("  {:<18} {}", "Stack entries:".dimmed(), result.stack.len());
            println!();
            for (i, entry) in result.stack.iter().enumerate() {
                let entry_json = serde_json::to_string(entry)
                    .unwrap_or_else(|_| "<serialization error>".to_string());
                println!("  [{}] {}", i, entry_json);
            }
            println!();
        }

        Ok(())
    }
}

impl AccountSendBocCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let raw_bytes = std::fs::read(&self.boc_file)
            .map_err(|e| anyhow::anyhow!("Failed to read BOC file '{}': {}", self.boc_file, e))?;

        // Detect binary vs base64: if all bytes are valid ASCII printable (base64
        // charset), attempt base64 decode; otherwise treat as raw binary.
        let boc_bytes = if raw_bytes.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            let trimmed = String::from_utf8_lossy(&raw_bytes);
            let trimmed = trimmed.trim();
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
                .unwrap_or(raw_bytes)
        } else {
            raw_bytes
        };

        rpc_client.send_boc(&boc_bytes).await?;

        if self.format == OutputFormat::Json {
            let obj = serde_json::json!({ "status": "ok", "message": "BOC sent successfully" });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!(
                "  {} BOC sent successfully ({} bytes)",
                "OK".green().bold(),
                boc_bytes.len()
            );
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

impl AccountDelegationGrantCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let grantee_address = parse_account_address(&self.grantee)?;
        let constraints: serde_json::Value = serde_json::from_str(&self.constraints)?;
        let req = LifecycleGrantRequest {
            address: address.to_string(),
            grantee: grantee_address.to_string(),
            scope: self.scope.clone(),
            constraints,
            expires_at: self.expires_at,
            revocable: self.revocable,
        };
        let result = rpc_client.grant_account_delegation(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Delegation Grant Result", &result);
        }
        Ok(())
    }
}

impl AccountDelegationRevokeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let req = LifecycleRevokeRequest {
            address: address.to_string(),
            permission_id: self.permission_id.clone(),
        };
        let result = rpc_client.revoke_account_delegation(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Delegation Revoke Result", &result);
        }
        Ok(())
    }
}

impl AccountSessionGrantCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let grantee_address = parse_account_address(&self.grantee)?;
        let constraints: serde_json::Value = serde_json::from_str(&self.constraints)?;
        let req = LifecycleGrantRequest {
            address: address.to_string(),
            grantee: grantee_address.to_string(),
            scope: self.scope.clone(),
            constraints,
            expires_at: self.expires_at,
            revocable: self.revocable,
        };
        let result = rpc_client.grant_account_session(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Session Grant Result", &result);
        }
        Ok(())
    }
}

impl AccountSessionRevokeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let req = LifecycleRevokeRequest {
            address: address.to_string(),
            permission_id: self.permission_id.clone(),
        };
        let result = rpc_client.revoke_account_session(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Session Revoke Result", &result);
        }
        Ok(())
    }
}

impl AccountAgentGrantCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let grantee_address = parse_account_address(&self.grantee)?;
        let constraints: serde_json::Value = serde_json::from_str(&self.constraints)?;
        let req = LifecycleGrantRequest {
            address: address.to_string(),
            grantee: grantee_address.to_string(),
            scope: self.scope.clone(),
            constraints,
            expires_at: self.expires_at,
            revocable: self.revocable,
        };
        let result = rpc_client.grant_account_agent(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Agent Grant Result", &result);
        }
        Ok(())
    }
}

impl AccountAgentRevokeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let address = parse_account_address(&self.address)?;
        let req = LifecycleRevokeRequest {
            address: address.to_string(),
            permission_id: self.permission_id.clone(),
        };
        let result = rpc_client.revoke_account_agent(&req).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_lifecycle_result_table("Agent Revoke Result", &result);
        }
        Ok(())
    }
}
