/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

#[derive(clap::Args, Clone)]
#[command(about = "Manage staking pools")]
pub struct PoolCmd {
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
    action: PoolAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum PoolAction {
    /// List all pools
    Ls(PoolLsCmd),
    /// Remove pool
    Rm(PoolRmCmd),
    /// Import pool address
    Import(PoolImportCmd),
    /// Query on-chain pool data
    Get(PoolGetCmd),
    /// Nominator pool commands
    Nominator(PoolNominatorCmd),
    /// Single-nominator pool commands
    Single(PoolSingleCmd),
    /// Liquid staking pool commands
    Liquid(PoolLiquidCmd),
}

// ---------------------------------------------------------------------------
// Direct pool subcommands
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "List all pools")]
pub struct PoolLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove pool")]
pub struct PoolRmCmd {
    #[arg(short = 'n', long = "name", help = "Pool name")]
    name: String,
    #[arg(long, help = "Skip confirmation")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Import pool address")]
pub struct PoolImportCmd {
    #[arg(short = 'n', long = "name", help = "Pool name")]
    name: String,
    #[arg(short = 'a', long = "address", help = "Pool contract address")]
    address: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Query on-chain pool data")]
pub struct PoolGetCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

// ---------------------------------------------------------------------------
// Nominator pool
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Nominator pool commands")]
pub struct PoolNominatorCmd {
    #[command(subcommand)]
    action: PoolNominatorAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum PoolNominatorAction {
    /// Create nominator pool
    Create(PoolNominatorCreateCmd),
    /// Activate / deploy nominator pool
    Activate(PoolNominatorActivateCmd),
    /// Sync validator set
    UpdateValidatorSet(PoolNominatorUpdateValidatorSetCmd),
    /// Deposit stake
    Deposit(PoolNominatorDepositCmd),
    /// Withdraw stake
    Withdraw(PoolNominatorWithdrawCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create nominator pool")]
pub struct PoolNominatorCreateCmd {
    #[arg(short = 'n', long = "name", help = "Pool name to save in config")]
    name: String,
    #[arg(long, help = "Owner wallet name from config")]
    owner: String,
    #[arg(long, help = "Validator wallet name from config (usually the node's wallet)")]
    validator: String,
    #[arg(
        long,
        help = "Validator reward share in basis points (e.g. 4000 = 40%)",
        default_value_t = 4000
    )]
    validator_reward_share: u16,
    #[arg(long, help = "Maximum number of nominators", default_value_t = 40)]
    max_nominators: u16,
    #[arg(long, help = "Minimum validator stake in TOS", default_value_t = 10000.0)]
    min_validator_stake: f64,
    #[arg(long, help = "Minimum nominator stake in TOS", default_value_t = 100.0)]
    min_nominator_stake: f64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Activate / deploy nominator pool")]
pub struct PoolNominatorActivateCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Sync validator set")]
pub struct PoolNominatorUpdateValidatorSetCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Deposit stake")]
pub struct PoolNominatorDepositCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
    #[arg(long, help = "Amount in TOS to deposit")]
    amount: f64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Withdraw stake")]
pub struct PoolNominatorWithdrawCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
}

// ---------------------------------------------------------------------------
// Single-nominator pool
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Single-nominator pool commands")]
pub struct PoolSingleCmd {
    #[command(subcommand)]
    action: PoolSingleAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum PoolSingleAction {
    /// Create single-nominator pool
    Create(PoolSingleCreateCmd),
    /// Activate single-nominator pool
    Activate(PoolSingleActivateCmd),
    /// Withdraw from single-nominator pool
    Withdraw(PoolSingleWithdrawCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create single-nominator pool")]
pub struct PoolSingleCreateCmd {
    #[arg(short = 'n', long = "name", help = "Pool name to save in config")]
    name: String,
    #[arg(long, help = "Owner wallet name from config")]
    owner: String,
    #[arg(long, help = "Validator wallet name from config (usually the node's wallet)")]
    validator: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Activate single-nominator pool")]
pub struct PoolSingleActivateCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Withdraw from single-nominator pool")]
pub struct PoolSingleWithdrawCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
    #[arg(long, help = "Amount in TOS to withdraw")]
    amount: f64,
}

// ---------------------------------------------------------------------------
// Liquid staking pool
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Liquid staking pool commands")]
pub struct PoolLiquidCmd {
    #[command(subcommand)]
    action: PoolLiquidAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum PoolLiquidAction {
    /// Controller management commands
    Controller(PoolLiquidControllerCmd),
    /// Liquid pool consistency check
    Check(PoolLiquidCheckCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Liquid pool consistency check")]
pub struct PoolLiquidCheckCmd {
    #[arg(
        short = 'n',
        long = "name",
        help = "Pool name from config (optional; checks all controllers if omitted)"
    )]
    name: Option<String>,
}

// ---------------------------------------------------------------------------
// Liquid staking controller
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Liquid staking controller commands")]
pub struct PoolLiquidControllerCmd {
    #[command(subcommand)]
    action: PoolLiquidControllerAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum PoolLiquidControllerAction {
    /// Create controller set
    Create(PoolLiquidControllerCreateCmd),
    /// Update controllers
    Update(PoolLiquidControllerUpdateCmd),
    /// List controllers
    Ls(PoolLiquidControllerLsCmd),
    /// Get controller data
    Get(PoolLiquidControllerGetCmd),
    /// Add controller
    Add(PoolLiquidControllerAddCmd),
    /// Stop controller
    Stop(PoolLiquidControllerStopCmd),
    /// Compound stop + withdraw
    StopWithdraw(PoolLiquidControllerStopWithdrawCmd),
    /// Deposit to controller
    Deposit(PoolLiquidControllerDepositCmd),
    /// Withdraw from controller
    Withdraw(PoolLiquidControllerWithdrawCmd),
    /// Sync validator set
    UpdateValidatorSet(PoolLiquidControllerUpdateValidatorSetCmd),
    /// APR analytics
    Apr(PoolLiquidControllerAprCmd),
    /// Expert diagnostics: test loan
    TestLoan(PoolLiquidControllerTestLoanCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create controller set")]
pub struct PoolLiquidControllerCreateCmd {
    #[arg(short = 'n', long = "name", help = "Controller set name to save in config")]
    name: String,
    #[arg(short = 'p', long = "pool-address", help = "Liquid staking pool address")]
    pool_address: String,
    /// Controller 0 address (if already deployed). If omitted and --deploy is set, will deploy automatically.
    #[arg(long = "controller-0-address")]
    controller_0_address: Option<String>,
    /// Controller 1 address (if already deployed). If omitted and --deploy is set, will deploy automatically.
    #[arg(long = "controller-1-address")]
    controller_1_address: Option<String>,
    /// Deploy controllers by sending pre-built BOC messages to the liquid pool. Requires --wallet.
    #[arg(long = "deploy")]
    deploy: bool,
    /// Wallet name to use for deployment (required with --deploy)
    #[arg(long = "wallet")]
    wallet: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Update controllers")]
pub struct PoolLiquidControllerUpdateCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "List controllers")]
pub struct PoolLiquidControllerLsCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Get controller data")]
pub struct PoolLiquidControllerGetCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Add controller")]
pub struct PoolLiquidControllerAddCmd {
    #[arg(short = 'n', long = "name", help = "Controller name to save in config")]
    name: String,
    #[arg(short = 'a', long = "address", help = "Controller contract address")]
    address: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Stop controller")]
pub struct PoolLiquidControllerStopCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Compound stop + withdraw")]
pub struct PoolLiquidControllerStopWithdrawCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Deposit to controller")]
pub struct PoolLiquidControllerDepositCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
    #[arg(long, help = "Amount in TOS to deposit")]
    amount: f64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Withdraw from controller")]
pub struct PoolLiquidControllerWithdrawCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
    #[arg(long, help = "Amount in TOS to withdraw")]
    amount: f64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Sync validator set")]
pub struct PoolLiquidControllerUpdateValidatorSetCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "APR analytics")]
pub struct PoolLiquidControllerAprCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Expert diagnostics: test loan")]
pub struct PoolLiquidControllerTestLoanCmd {
    #[arg(short = 'n', long = "name", help = "Controller name from config")]
    name: String,
    #[arg(long, help = "Desired credit amount in TOS")]
    credit: f64,
    #[arg(long, help = "Maximum interest rate in basis points (e.g. 100 = 1%)")]
    interest: u64,
}

// ===========================================================================
// run() implementations
// ===========================================================================

impl PoolCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let config_path = &self.config;
        match &self.action {
            PoolAction::Ls(cmd) => cmd.run(config_path).await,
            PoolAction::Rm(cmd) => cmd.run(config_path).await,
            PoolAction::Import(cmd) => cmd.run(config_path).await,
            PoolAction::Get(cmd) => cmd.run(config_path).await,
            PoolAction::Nominator(cmd) => cmd.run(config_path).await,
            PoolAction::Single(cmd) => cmd.run(config_path).await,
            PoolAction::Liquid(cmd) => cmd.run(config_path).await,
        }
    }
}

// --- Direct pool subcommands -----------------------------------------------

impl PoolLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;

        if config.pools.is_empty() {
            if self.format == super::output_format::OutputFormat::Json {
                println!("[]");
            } else {
                println!("\n{}\n", "No pools configured".yellow());
            }
            return Ok(());
        }

        let mut pool_list: Vec<(&String, &PoolConfig)> = config.pools.iter().collect();
        pool_list.sort_by_key(|(name, _)| name.as_str());

        if self.format == super::output_format::OutputFormat::Json {
            let views: Vec<serde_json::Value> = pool_list
                .iter()
                .map(|(name, pool)| {
                    let (pool_type, address) = match pool {
                        PoolConfig::SNP { address, .. } => {
                            ("single-nominator", address.as_deref().unwrap_or("-"))
                        }
                        PoolConfig::CorePool { addresses, .. } => ("core", addresses[0].as_str()),
                        PoolConfig::NominatorPool { address, .. } => {
                            ("nominator-pool", address.as_deref().unwrap_or("-"))
                        }
                    };
                    serde_json::json!({
                        "name": name,
                        "type": pool_type,
                        "address": address,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&views)?);
        } else {
            println!("\n{}\n{}", "Pools".cyan().bold(), "\u{2500}".repeat(60).dimmed());
            println!(
                "  {:<20} {:<18} {}",
                "Name".cyan().bold(),
                "Type".cyan().bold(),
                "Address".cyan().bold(),
            );
            println!("  {}", "\u{2500}".repeat(56).dimmed());

            for (name, pool) in &pool_list {
                let (pool_type, address) = match pool {
                    PoolConfig::SNP { address, .. } => {
                        ("single-nominator", address.as_deref().unwrap_or("-"))
                    }
                    PoolConfig::CorePool { addresses, .. } => ("core", addresses[0].as_str()),
                    PoolConfig::NominatorPool { address, .. } => {
                        ("nominator-pool", address.as_deref().unwrap_or("-"))
                    }
                };
                println!("  {:<20} {:<18} {}", name, pool_type, address);
            }
            println!();
        }

        Ok(())
    }
}

impl PoolRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::io::Write;
        use std::path::Path;

        let config_path = Path::new(config_path);
        let mut config = AppConfig::load(config_path)?;

        if !config.pools.contains_key(&self.name) {
            anyhow::bail!("Pool '{}' not found in configuration", self.name);
        }

        // Check for bindings referencing this pool
        let referencing_bindings: Vec<&String> = config
            .bindings
            .iter()
            .filter(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .map(|(node_name, _)| node_name)
            .collect();

        if !referencing_bindings.is_empty() {
            let nodes =
                referencing_bindings.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ");
            anyhow::bail!(
                "Cannot remove pool '{}': referenced by binding(s) for node(s): {}",
                self.name,
                nodes
            );
        }

        if !self.yes {
            print!("Remove pool '{}'? [y/N]: ", self.name);
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
                println!("{}", "Cancelled".yellow());
                return Ok(());
            }
        }

        config.pools.remove(&self.name);
        super::utils::save_config(&config, config_path)?;

        println!("\n{} Pool '{}' removed\n", "OK".green().bold(), self.name);
        Ok(())
    }
}

impl PoolImportCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use std::path::Path;
        use std::str::FromStr;

        // Validate address
        let addr_trimmed = self.address.trim();
        if addr_trimmed.is_empty() {
            anyhow::bail!("--address must not be empty");
        }
        MsgAddressInt::from_str(addr_trimmed).map_err(|_| {
            anyhow::anyhow!(
                "Invalid pool address: '{}'. Expected raw or base64url format",
                addr_trimmed
            )
        })?;

        let config_path = Path::new(config_path);
        let mut config = AppConfig::load(config_path)?;

        if config.pools.contains_key(&self.name) {
            anyhow::bail!(
                "Pool '{}' already exists. Remove it first or use a different name.",
                self.name
            );
        }

        let pool_config = PoolConfig::SNP { address: Some(addr_trimmed.to_string()), owner: None };
        config.pools.insert(self.name.clone(), pool_config);
        super::utils::save_config(&config, config_path)?;

        println!(
            "\n{} Pool '{}' imported (address='{}')\n",
            "OK".green().bold(),
            self.name,
            addr_trimmed
        );
        Ok(())
    }
}

impl PoolGetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::{
            app_config::{AppConfig, PoolConfig},
            chain_utils::display_tos,
        };
        use std::path::Path;
        use std::str::FromStr;

        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found", self.name))?;

        if self.format == super::output_format::OutputFormat::Json {
            let json_val = match pool {
                PoolConfig::SNP { address, owner } => {
                    let mut obj = serde_json::json!({
                        "name": self.name,
                        "type": "single-nominator",
                    });
                    if let Some(addr_str) = address {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        obj["address"] = serde_json::json!(addr.to_string());
                        if let Ok(info) = rpc_client.get_address_information(&addr).await {
                            obj["balance"] = serde_json::json!(display_tos(info.balance));
                            obj["state"] = serde_json::json!(info.state.to_string());
                        }
                    }
                    if let Some(owner_str) = owner {
                        obj["owner"] = serde_json::json!(owner_str);
                    }
                    obj
                }
                PoolConfig::CorePool { addresses, validator_share } => {
                    let mut addrs_info = Vec::new();
                    for addr_str in addresses {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        let mut entry = serde_json::json!({"address": addr.to_string()});
                        if let Ok(info) = rpc_client.get_address_information(&addr).await {
                            entry["balance"] = serde_json::json!(display_tos(info.balance));
                            entry["state"] = serde_json::json!(info.state.to_string());
                        }
                        addrs_info.push(entry);
                    }
                    serde_json::json!({
                        "name": self.name,
                        "type": "core",
                        "validator_share": validator_share,
                        "addresses": addrs_info,
                    })
                }
                PoolConfig::NominatorPool {
                    address,
                    owner,
                    validator_reward_share,
                    max_nominators,
                    min_validator_stake,
                    min_nominator_stake,
                } => {
                    let mut obj = serde_json::json!({
                        "name": self.name,
                        "type": "nominator-pool",
                        "validator_reward_share": *validator_reward_share as f64 / 100.0,
                        "max_nominators": max_nominators,
                        "min_validator_stake_tos": *min_validator_stake as f64 / 1_000_000_000.0,
                        "min_nominator_stake_tos": *min_nominator_stake as f64 / 1_000_000_000.0,
                    });
                    if let Some(addr_str) = address {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        obj["address"] = serde_json::json!(addr.to_string());
                        if let Ok(info) = rpc_client.get_address_information(&addr).await {
                            obj["balance"] = serde_json::json!(display_tos(info.balance));
                            obj["state"] = serde_json::json!(info.state.to_string());
                        }
                    }
                    if let Some(owner_str) = owner {
                        obj["owner"] = serde_json::json!(owner_str);
                    }
                    obj
                }
            };
            println!("{}", serde_json::to_string_pretty(&json_val)?);
        } else {
            match pool {
                PoolConfig::SNP { address, owner } => {
                    println!("\n{} Pool '{}' (single-nominator)", "Pool".cyan().bold(), self.name);
                    println!("  {}", "\u{2500}".repeat(56).dimmed());

                    if let Some(addr_str) = address {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        println!("  {:<12} {}", "Address:".cyan(), addr);

                        let info = rpc_client.get_address_information(&addr).await?;
                        println!("  {:<12} {}", "Balance:".cyan(), display_tos(info.balance));
                        println!("  {:<12} {}", "State:".cyan(), info.state);
                    } else if let Some(owner_str) = owner {
                        println!(
                            "  {:<12} {} (address must be calculated from binding)",
                            "Owner:".cyan(),
                            owner_str
                        );
                    } else {
                        println!("  {}", "No address or owner configured".yellow());
                    }
                    println!();
                }
                PoolConfig::CorePool { addresses, validator_share } => {
                    println!("\n{} Pool '{}' (core)", "Pool".cyan().bold(), self.name);
                    println!("  {}", "\u{2500}".repeat(56).dimmed());
                    println!("  {:<18} {}", "Validator share:".cyan(), validator_share);
                    for (i, addr_str) in addresses.iter().enumerate() {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        let info = rpc_client.get_address_information(&addr).await?;
                        println!("  {:<18} {}", format!("Address[{}]:", i).cyan(), addr);
                        println!(
                            "  {:<18} {}",
                            format!("Balance[{}]:", i).cyan(),
                            display_tos(info.balance)
                        );
                        println!("  {:<18} {}", format!("State[{}]:", i).cyan(), info.state);
                    }
                    println!();
                }
                PoolConfig::NominatorPool {
                    address,
                    owner,
                    validator_reward_share,
                    max_nominators,
                    min_validator_stake,
                    min_nominator_stake,
                } => {
                    println!("\n{} Pool '{}' (nominator-pool)", "Pool".cyan().bold(), self.name);
                    println!("  {}", "\u{2500}".repeat(56).dimmed());
                    println!(
                        "  {:<24} {}%",
                        "Validator reward share:".cyan(),
                        *validator_reward_share as f64 / 100.0
                    );
                    println!("  {:<24} {}", "Max nominators:".cyan(), max_nominators);
                    println!(
                        "  {:<24} {} TOS",
                        "Min validator stake:".cyan(),
                        *min_validator_stake as f64 / 1_000_000_000.0
                    );
                    println!(
                        "  {:<24} {} TOS",
                        "Min nominator stake:".cyan(),
                        *min_nominator_stake as f64 / 1_000_000_000.0
                    );

                    if let Some(addr_str) = address {
                        let addr = MsgAddressInt::from_str(addr_str).map_err(|_| {
                            anyhow::anyhow!("Invalid pool address in config: {}", addr_str)
                        })?;
                        println!("  {:<24} {}", "Address:".cyan(), addr);

                        let info = rpc_client.get_address_information(&addr).await?;
                        println!("  {:<24} {}", "Balance:".cyan(), display_tos(info.balance));
                        println!("  {:<24} {}", "State:".cyan(), info.state);
                    } else if let Some(owner_str) = owner {
                        println!("  {:<24} {} (not yet deployed)", "Owner:".cyan(), owner_str);
                    } else {
                        println!("  {}", "No address or owner configured".yellow());
                    }
                    println!();
                }
            }
        }

        Ok(())
    }
}

// --- Nominator pool --------------------------------------------------------

impl PoolNominatorCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            PoolNominatorAction::Create(cmd) => cmd.run(config_path).await,
            PoolNominatorAction::Activate(cmd) => cmd.run(config_path).await,
            PoolNominatorAction::UpdateValidatorSet(cmd) => cmd.run(config_path).await,
            PoolNominatorAction::Deposit(cmd) => cmd.run(config_path).await,
            PoolNominatorAction::Withdraw(cmd) => cmd.run(config_path).await,
        }
    }
}

impl PoolNominatorCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use common::chain_utils::tos_to_nanotos;
        use contracts::NominatorPoolWrapperImpl;
        use contracts::nominator::NOMINATOR_POOL_WORKCHAIN;
        use std::path::Path;

        let config_path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(config_path).await?;

        if config.pools.contains_key(&self.name) {
            anyhow::bail!("Pool '{}' already exists in config", self.name);
        }

        // Resolve validator wallet address (256-bit hash part)
        let validator_wallet_cfg = config
            .wallets
            .get(&self.validator)
            .ok_or_else(|| {
                anyhow::anyhow!("Validator wallet '{}' not found in config", self.validator)
            })?
            .clone();
        let (validator_addr, _) =
            super::utils::wallet_address(&validator_wallet_cfg, vault.clone()).await?;

        // Extract 256-bit address hash from the validator wallet address
        let validator_addr_bytes: [u8; 32] = {
            let hash = validator_addr.address().get_bytestring(0);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        };

        let min_validator_nanotos = tos_to_nanotos(self.min_validator_stake);
        let min_nominator_nanotos = tos_to_nanotos(self.min_nominator_stake);

        // Calculate pool address from code + init data
        let pool_addr = NominatorPoolWrapperImpl::calculate_address(
            NOMINATOR_POOL_WORKCHAIN,
            &validator_addr_bytes,
            self.validator_reward_share,
            self.max_nominators,
            min_validator_nanotos,
            min_nominator_nanotos,
        )?;
        let pool_addr_str = pool_addr.to_string();

        // Print the pool configuration
        println!("\n{}", "Nominator Pool Configuration".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<26} {}", "Name:".cyan(), self.name);
        println!("  {:<26} {}", "Owner wallet:".cyan(), self.owner);
        println!("  {:<26} {}", "Validator wallet:".cyan(), self.validator);
        println!("  {:<26} {}", "Validator address:".cyan(), validator_addr);
        println!(
            "  {:<26} {} ({}%)",
            "Validator reward share:".cyan(),
            self.validator_reward_share,
            self.validator_reward_share as f64 / 100.0
        );
        println!("  {:<26} {}", "Max nominators:".cyan(), self.max_nominators);
        println!("  {:<26} {} TOS", "Min validator stake:".cyan(), self.min_validator_stake);
        println!("  {:<26} {} TOS", "Min nominator stake:".cyan(), self.min_nominator_stake);
        println!("  {:<26} {}", "Pool address:".cyan(), pool_addr_str);
        println!();

        // Save to config with the computed address
        let pool_config = PoolConfig::NominatorPool {
            address: Some(pool_addr_str.clone()),
            owner: Some(self.owner.clone()),
            validator_reward_share: self.validator_reward_share,
            max_nominators: self.max_nominators,
            min_validator_stake: min_validator_nanotos,
            min_nominator_stake: min_nominator_nanotos,
        };
        config.pools.insert(self.name.clone(), pool_config);
        super::utils::save_config(&config, config_path)?;

        println!("{} Nominator pool '{}' created\n", "OK".green().bold(), self.name,);
        println!("  {:<12} {}", "Address:".cyan(), pool_addr_str);
        println!(
            "\n  Fund this address with at least 2 TOS, then run:\n  {}",
            format!("tosctl pool nominator activate --name {}", self.name).yellow().bold()
        );
        println!();

        Ok(())
    }
}

impl PoolNominatorActivateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{Cell, MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::display_tos, task_cancellation::CancellationCtx,
        };
        use contracts::NominatorPoolWrapperImpl;
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Look up pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let (
            pool_addr_str,
            owner_name,
            validator_reward_share,
            max_nominators,
            min_validator_stake,
            min_nominator_stake,
        ) = match pool {
            PoolConfig::NominatorPool {
                address,
                owner,
                validator_reward_share,
                max_nominators,
                min_validator_stake,
                min_nominator_stake,
            } => {
                let addr = address
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!(
                        "Pool '{}' has no address configured. Run `tosctl pool nominator create` first.",
                        self.name
                    ))?;
                let owner_name = owner
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!(
                        "Pool '{}' has no owner configured. Run `tosctl pool nominator create` with --owner.",
                        self.name
                    ))?;
                (
                    addr.clone(),
                    owner_name.clone(),
                    *validator_reward_share,
                    *max_nominators,
                    *min_validator_stake,
                    *min_nominator_stake,
                )
            }
            _ => anyhow::bail!("Pool '{}' is not a nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(&pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Check if already deployed
        let pool_info = rpc_client.get_address_information(&pool_addr).await?;
        if pool_info.state == AccountState::Active {
            println!(
                "\n{} Pool '{}' ({}) is already active\n",
                "OK".green().bold(),
                self.name,
                pool_addr
            );
            return Ok(());
        }
        if pool_info.state == AccountState::Frozen {
            anyhow::bail!("Pool '{}' ({}) is frozen", self.name, pool_addr);
        }

        // Get owner wallet
        let owner_wallet_cfg = config
            .wallets
            .get(&owner_name)
            .ok_or_else(|| anyhow::anyhow!("Owner wallet '{}' not found in config", owner_name))?;

        let (owner_addr, owner_secret) =
            super::utils::wallet_address(owner_wallet_cfg, vault.clone()).await?;

        // Find the validator address by searching bindings referencing this pool,
        // or by iterating wallets to find a match.
        let binding = config.bindings.iter().find(|(_, b)| b.pool.as_deref() == Some(&self.name));

        let validator_addr_bytes: [u8; 32] = if let Some((_, bind)) = binding {
            // Use the binding's wallet as the validator
            let validator_wallet_cfg = config
                .wallets
                .get(&bind.wallet)
                .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", bind.wallet))?;
            let (vaddr, _) =
                super::utils::wallet_address(validator_wallet_cfg, vault.clone()).await?;
            let hash = vaddr.address().get_bytestring(0);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        } else {
            // Try to find the validator by matching the pool address against all wallets
            let mut found: Option<[u8; 32]> = None;
            for (wname, wcfg) in &config.wallets {
                if wname == &owner_name {
                    continue;
                }
                if let Ok((waddr, _)) = super::utils::wallet_address(wcfg, vault.clone()).await {
                    let hash = waddr.address().get_bytestring(0);
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hash);
                    if let Ok(candidate) = NominatorPoolWrapperImpl::calculate_address(
                        -1,
                        &arr,
                        validator_reward_share,
                        max_nominators,
                        min_validator_stake,
                        min_nominator_stake,
                    ) {
                        if candidate == pool_addr {
                            found = Some(arr);
                            break;
                        }
                    }
                }
            }
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not find the validator wallet that matches pool address {}. \
                     Ensure the validator wallet is in config or bind a node to this pool.",
                    pool_addr
                )
            })?
        };

        // Build state_init
        let state_init = NominatorPoolWrapperImpl::build_state_init(
            &validator_addr_bytes,
            validator_reward_share,
            max_nominators,
            min_validator_stake,
            min_nominator_stake,
        )?;

        // Check pool balance (must have funds to deploy)
        if pool_info.balance < 1_000_000_000 {
            anyhow::bail!(
                "Pool balance {} is too low. Fund the pool address ({}) with at least 2 TOS before activating.",
                display_tos(pool_info.balance),
                pool_addr
            );
        }

        println!("\n{}", "Nominator Pool Activation".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<26} {}", "Pool name:".cyan(), self.name);
        println!("  {:<26} {}", "Address:".cyan(), pool_addr);
        println!(
            "  {:<26} {} ({}%)",
            "Validator reward share:".cyan(),
            validator_reward_share,
            validator_reward_share as f64 / 100.0
        );
        println!("  {:<26} {}", "Max nominators:".cyan(), max_nominators);
        println!(
            "  {:<26} {} TOS",
            "Min validator stake:".cyan(),
            min_validator_stake as f64 / 1_000_000_000.0
        );
        println!(
            "  {:<26} {} TOS",
            "Min nominator stake:".cyan(),
            min_nominator_stake as f64 / 1_000_000_000.0
        );
        println!("  {:<26} {}", "Balance:".cyan(), display_tos(pool_info.balance));
        println!();

        println!("Deploying nominator pool '{}' ({})...", self.name, pool_addr);

        // Get owner wallet info for seqno
        let owner_wallet_info = rpc_client.get_wallet_information(&owner_addr).await?;
        if owner_wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Owner wallet '{}' ({}) is not active (state: {})",
                owner_name,
                owner_addr,
                owner_wallet_info.account_state
            );
        }

        let wallet = super::utils::make_wallet(
            rpc_client.clone(),
            owner_wallet_cfg,
            owner_secret,
            &owner_name,
        )
        .await?;

        // Send a deploy message: small amount to carry the state_init
        let deploy_amount: u64 = 1_000_000_000; // 1 TOS for deploy gas
        let msg = wallet
            .build_message(
                pool_addr.clone(),
                deploy_amount,
                Cell::default(),
                false,
                owner_wallet_info.seqno,
                None,
                Some(state_init),
            )
            .await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_deploy(
            rpc_client.clone(),
            &pool_addr,
            &cancellation_ctx,
            true,
            super::utils::DEPLOY_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} Nominator pool '{}' ({}) activated\n",
            "OK".green().bold(),
            self.name,
            pool_addr
        );

        Ok(())
    }
}

impl PoolNominatorUpdateValidatorSetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{BuilderData, IBitstring, MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{app_config::PoolConfig, task_cancellation::CancellationCtx};
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let pool_addr_str = match pool {
            PoolConfig::NominatorPool { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Pool '{}' has no address configured (not yet deployed?)",
                    self.name
                )
            })?,
            _ => anyhow::bail!("Pool '{}' is not a nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Find the validator wallet from bindings that reference this pool
        let binding = config
            .bindings
            .iter()
            .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .ok_or_else(|| {
            anyhow::anyhow!(
                "No binding found referencing pool '{}'. Bind a node to this pool first.",
                self.name
            )
        })?;

        let wallet_name = &binding.1.wallet;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build update_validator_set payload: op=0x00000006, query_id=1
        let mut b = BuilderData::new();
        b.append_u32(0x00000006)?;
        b.append_u64(1u64)?;
        let payload = b.into_cell()?;

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, wallet_name)
                .await?;

        println!("\nSending update_validator_set to pool '{}' ({})...", self.name, pool_addr);

        let msg = wallet.message(pool_addr.clone(), 1_100_000_000, payload).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!("\n{} update_validator_set sent to pool '{}'\n", "OK".green().bold(), self.name);

        Ok(())
    }
}

impl PoolNominatorDepositCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{BuilderData, IBitstring, MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::tos_to_nanotos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        if self.amount <= 0.0 {
            anyhow::bail!("Deposit amount must be positive");
        }

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let (pool_addr_str, owner_name) = match pool {
            PoolConfig::NominatorPool { address, owner, .. } => {
                let addr = address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Pool '{}' has no address configured (not yet deployed?)",
                        self.name
                    )
                })?;
                (addr.clone(), owner.clone())
            }
            _ => anyhow::bail!("Pool '{}' is not a nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(&pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Find the owner wallet. If owner is set in pool config, use it; otherwise use
        // the first binding's wallet as the depositor.
        let wallet_name = if let Some(ref name) = owner_name {
            name.clone()
        } else {
            let binding = config
                .bindings
                .iter()
                .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No binding or owner found for pool '{}'. Configure an owner or binding.",
                        self.name
                    )
                })?;
            binding.1.wallet.clone()
        };

        let wallet_cfg = config
            .wallets
            .get(&wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build deposit body: comment "d" (op=0, then byte 0x64)
        let mut b = BuilderData::new();
        b.append_u32(0)?; // op=0 (text comment)
        b.append_raw(&[0x64], 8)?; // 'd'
        let body = b.into_cell()?;

        let amount_nanotos = tos_to_nanotos(self.amount);

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, &wallet_name)
                .await?;

        println!(
            "\nDepositing {} TOS to nominator pool '{}' ({})...",
            self.amount, self.name, pool_addr
        );

        let msg = wallet.message(pool_addr.clone(), amount_nanotos, body).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} Deposited {} TOS to pool '{}'\n",
            "OK".green().bold(),
            self.amount,
            self.name
        );

        Ok(())
    }
}

impl PoolNominatorWithdrawCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{BuilderData, IBitstring, MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{app_config::PoolConfig, task_cancellation::CancellationCtx};
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let (pool_addr_str, owner_name) = match pool {
            PoolConfig::NominatorPool { address, owner, .. } => {
                let addr = address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Pool '{}' has no address configured (not yet deployed?)",
                        self.name
                    )
                })?;
                (addr.clone(), owner.clone())
            }
            _ => anyhow::bail!("Pool '{}' is not a nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(&pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Find the owner wallet
        let wallet_name = if let Some(ref name) = owner_name {
            name.clone()
        } else {
            let binding = config
                .bindings
                .iter()
                .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No binding or owner found for pool '{}'. Configure an owner or binding.",
                        self.name
                    )
                })?;
            binding.1.wallet.clone()
        };

        let wallet_cfg = config
            .wallets
            .get(&wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build withdraw body: comment "w" (op=0, then byte 0x77)
        let mut b = BuilderData::new();
        b.append_u32(0)?; // op=0 (text comment)
        b.append_raw(&[0x77], 8)?; // 'w'
        let body = b.into_cell()?;

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, &wallet_name)
                .await?;

        println!(
            "\nSending withdrawal request to nominator pool '{}' ({})...",
            self.name, pool_addr
        );

        // Send 1 TOS for gas with the withdrawal comment
        let gas_fee: u64 = 1_000_000_000;
        let msg = wallet.message(pool_addr.clone(), gas_fee, body).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!("\n{} Withdrawal request sent to pool '{}'\n", "OK".green().bold(), self.name);

        Ok(())
    }
}

// --- Single-nominator pool -------------------------------------------------

impl PoolSingleCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            PoolSingleAction::Create(cmd) => cmd.run(config_path).await,
            PoolSingleAction::Activate(cmd) => cmd.run(config_path).await,
            PoolSingleAction::Withdraw(cmd) => cmd.run(config_path).await,
        }
    }
}

impl PoolSingleCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use contracts::nominator::{NOMINATOR_POOL_WORKCHAIN, NominatorWrapperImpl};
        use std::path::Path;

        let config_path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(config_path).await?;

        if config.pools.contains_key(&self.name) {
            anyhow::bail!("Pool '{}' already exists in config", self.name);
        }

        // Resolve owner wallet address
        let owner_wallet_cfg = config
            .wallets
            .get(&self.owner)
            .ok_or_else(|| anyhow::anyhow!("Owner wallet '{}' not found in config", self.owner))?
            .clone();
        let (owner_addr, _) =
            super::utils::wallet_address(&owner_wallet_cfg, vault.clone()).await?;

        // Resolve validator wallet address
        let validator_wallet_cfg = config
            .wallets
            .get(&self.validator)
            .ok_or_else(|| {
                anyhow::anyhow!("Validator wallet '{}' not found in config", self.validator)
            })?
            .clone();
        let (validator_addr, _) =
            super::utils::wallet_address(&validator_wallet_cfg, vault.clone()).await?;

        // Calculate pool address
        let pool_addr = NominatorWrapperImpl::calculate_address(
            NOMINATOR_POOL_WORKCHAIN,
            &owner_addr,
            &validator_addr,
        )?;

        let pool_addr_str = pool_addr.to_string();

        // Save to config
        let pool_config = PoolConfig::SNP {
            address: Some(pool_addr_str.clone()),
            owner: Some(self.owner.clone()),
        };
        config.pools.insert(self.name.clone(), pool_config);
        super::utils::save_config(&config, config_path)?;

        println!("\n{} Single-nominator pool '{}' created\n", "OK".green().bold(), self.name);
        println!("  {:<12} {}", "Address:".cyan(), pool_addr_str);
        println!("  {:<12} {}", "Owner:".cyan(), owner_addr);
        println!("  {:<12} {}", "Validator:".cyan(), validator_addr);
        println!(
            "\n  Fund this address with at least 2 TOS, then run:\n  {}",
            format!("tosctl pool single activate --name {}", self.name).yellow().bold()
        );
        println!();

        Ok(())
    }
}

impl PoolSingleActivateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{Cell, MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::display_tos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use contracts::nominator::{NOMINATOR_POOL_WORKCHAIN, NominatorWrapperImpl};
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Look up pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let (pool_addr_str, owner_name) = match pool {
            PoolConfig::SNP { address, owner } => {
                let addr = address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Pool '{}' has no address configured", self.name)
                })?;
                let owner_name = owner.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Pool '{}' has no owner configured", self.name)
                })?;
                (addr.clone(), owner_name.clone())
            }
            _ => anyhow::bail!("Pool '{}' is not a single-nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(&pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Check if already deployed
        let pool_info = rpc_client.get_address_information(&pool_addr).await?;
        if pool_info.state == AccountState::Active {
            println!(
                "\n{} Pool '{}' ({}) is already active\n",
                "OK".green().bold(),
                self.name,
                pool_addr
            );
            return Ok(());
        }
        if pool_info.state == AccountState::Frozen {
            anyhow::bail!("Pool '{}' ({}) is frozen", self.name, pool_addr);
        }

        // Get owner wallet
        let owner_wallet_cfg = config
            .wallets
            .get(&owner_name)
            .ok_or_else(|| anyhow::anyhow!("Owner wallet '{}' not found in config", owner_name))?;

        let (owner_addr, owner_secret) =
            super::utils::wallet_address(owner_wallet_cfg, vault.clone()).await?;

        // We also need the validator address to build state_init.
        // Derive it from the pool address by finding which wallet produces the matching address.
        // The simplest approach: iterate config wallets to find the validator.
        // But we can also just re-derive from all wallets. Instead, let's compute
        // owner_addr and then for each wallet check if calculate_address matches pool_addr.
        let mut validator_addr: Option<MsgAddressInt> = None;
        for (wname, wcfg) in &config.wallets {
            if wname == &owner_name {
                continue;
            }
            if let Ok((waddr, _)) = super::utils::wallet_address(wcfg, vault.clone()).await {
                if let Ok(candidate) = NominatorWrapperImpl::calculate_address(
                    NOMINATOR_POOL_WORKCHAIN,
                    &owner_addr,
                    &waddr,
                ) {
                    if candidate == pool_addr {
                        validator_addr = Some(waddr);
                        break;
                    }
                }
            }
        }

        let validator_addr = validator_addr.ok_or_else(|| {
            anyhow::anyhow!(
                "Could not find the validator wallet that matches pool address {}. \
                 Ensure the validator wallet is in config.",
                pool_addr
            )
        })?;

        // Build state_init
        let state_init = NominatorWrapperImpl::build_state_init(&owner_addr, &validator_addr)?;

        // Check pool balance (must have funds to deploy)
        if pool_info.balance < 1_000_000_000 {
            anyhow::bail!(
                "Pool balance {} is too low. Fund the pool address ({}) with at least 2 TOS before activating.",
                display_tos(pool_info.balance),
                pool_addr
            );
        }

        println!("Deploying single-nominator pool '{}' ({})...", self.name, pool_addr);

        // Get owner wallet info for seqno
        let owner_wallet_info = rpc_client.get_wallet_information(&owner_addr).await?;
        if owner_wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Owner wallet '{}' ({}) is not active (state: {})",
                owner_name,
                owner_addr,
                owner_wallet_info.account_state
            );
        }

        let wallet = super::utils::make_wallet(
            rpc_client.clone(),
            owner_wallet_cfg,
            owner_secret,
            &owner_name,
        )
        .await?;

        // Send a deploy message: small amount to carry the state_init
        let deploy_amount: u64 = 1_000_000_000; // 1 TOS for deploy gas
        let msg = wallet
            .build_message(
                pool_addr.clone(),
                deploy_amount,
                Cell::default(),
                false,
                owner_wallet_info.seqno,
                None,
                Some(state_init),
            )
            .await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_deploy(
            rpc_client.clone(),
            &pool_addr,
            &cancellation_ctx,
            true,
            super::utils::DEPLOY_TIMEOUT,
        )
        .await?;

        println!("\n{} Pool '{}' ({}) activated\n", "OK".green().bold(), self.name, pool_addr);

        Ok(())
    }
}

impl PoolSingleWithdrawCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::tos_to_nanotos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Look up pool in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found in config", self.name))?;

        let (pool_addr_str, owner_name) = match pool {
            PoolConfig::SNP { address, owner } => {
                let addr = address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Pool '{}' has no address configured", self.name)
                })?;
                let owner_name = owner.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Pool '{}' has no owner configured", self.name)
                })?;
                (addr.clone(), owner_name.clone())
            }
            _ => anyhow::bail!("Pool '{}' is not a single-nominator pool", self.name),
        };

        let pool_addr = MsgAddressInt::from_str(&pool_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid pool address: {}", pool_addr_str))?;

        // Get owner wallet
        let owner_wallet_cfg = config
            .wallets
            .get(&owner_name)
            .ok_or_else(|| anyhow::anyhow!("Owner wallet '{}' not found in config", owner_name))?;

        let (owner_addr, owner_secret) =
            super::utils::wallet_address(owner_wallet_cfg, vault.clone()).await?;
        let owner_wallet_info = rpc_client.get_wallet_information(&owner_addr).await?;

        if owner_wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Owner wallet '{}' ({}) is not active (state: {})",
                owner_name,
                owner_addr,
                owner_wallet_info.account_state
            );
        }

        // Build withdraw message body
        let amount_nanotos = tos_to_nanotos(self.amount);
        let withdraw_payload = contracts::nominator::withdraw(1, amount_nanotos)?;

        let wallet = super::utils::make_wallet(
            rpc_client.clone(),
            owner_wallet_cfg,
            owner_secret,
            &owner_name,
        )
        .await?;

        println!("\nWithdrawing {} TOS from pool '{}' ({})...", self.amount, self.name, pool_addr);

        let gas_fee: u64 = 1_000_000_000; // 1 TOS for gas
        let msg = wallet
            .build_message(
                pool_addr.clone(),
                gas_fee,
                withdraw_payload,
                false,
                owner_wallet_info.seqno,
                None,
                None,
            )
            .await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &owner_addr,
            owner_wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} Withdrawal of {} TOS from pool '{}' sent\n",
            "OK".green().bold(),
            self.amount,
            self.name
        );

        Ok(())
    }
}

// --- Liquid staking pool ---------------------------------------------------

impl PoolLiquidCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            PoolLiquidAction::Controller(cmd) => cmd.run(config_path).await,
            PoolLiquidAction::Check(cmd) => cmd.run(config_path).await,
        }
    }
}

impl PoolLiquidCheckCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use common::chain_utils::display_tos;
        use contracts::ControllerWrapperImpl;
        use contracts::SmartContract;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Find controller entries: SNP entries whose names end in _0 or _1
        let controller_entries: Vec<(&String, &PoolConfig)> = if let Some(ref name) = self.name {
            // If a specific name is given, filter to controllers matching that prefix
            config
                .pools
                .iter()
                .filter(|(entry_name, pool)| {
                    matches!(pool, PoolConfig::SNP { .. })
                        && (entry_name.as_str() == name.as_str()
                            || entry_name.starts_with(&format!("{}_", name)))
                })
                .collect()
        } else {
            config
                .pools
                .iter()
                .filter(|(name, pool)| {
                    matches!(pool, PoolConfig::SNP { .. })
                        && (name.ends_with("_0") || name.ends_with("_1"))
                })
                .collect()
        };

        if controller_entries.is_empty() {
            println!("\n{}\n", "No liquid staking controllers found in config".yellow());
            return Ok(());
        }

        println!("\n{}", "Liquid Staking Pool Consistency Check".cyan().bold());
        println!("{}", "\u{2500}".repeat(60).dimmed());
        println!();

        let mut issues: Vec<String> = Vec::new();
        let mut total_borrowed: u64 = 0;
        let mut total_balance: u64 = 0;
        let mut controller_count: usize = 0;

        for (name, pool) in &controller_entries {
            let addr_str = match pool {
                PoolConfig::SNP { address, .. } => address.as_deref(),
                _ => None,
            };

            let addr_str = match addr_str {
                Some(a) => a,
                None => {
                    println!("  {:<24} {}", name, "(no address configured)".dimmed());
                    issues.push(format!("{}: no address configured", name));
                    continue;
                }
            };

            let addr = match MsgAddressInt::from_str(addr_str) {
                Ok(a) => a,
                Err(_) => {
                    println!("  {:<24} {}", name, "invalid address".red());
                    issues.push(format!("{}: invalid address", name));
                    continue;
                }
            };

            let provider = contracts::contract_provider!(rpc_client.clone());
            let wrapper = ControllerWrapperImpl::new(provider, addr.clone());

            match wrapper.get_controller_data().await {
                Ok(data) => {
                    let balance = wrapper.balance().await.unwrap_or(0);
                    controller_count += 1;
                    total_borrowed += data.borrowed_amount;
                    total_balance += balance;

                    let state_label = match data.state {
                        0 => "REST",
                        1 => "SENT_BORROWING_REQUEST",
                        2 => "SENT_STAKE_REQUEST",
                        3 => "FUNDS_STAKEN",
                        4 => "SENT_RECOVER_REQUEST",
                        5 => "INSOLVENT",
                        _ => "UNKNOWN",
                    };

                    let status_icon = if data.halted {
                        "HALTED".red().bold().to_string()
                    } else if data.state == 5 {
                        "INSOLVENT".red().bold().to_string()
                    } else if !data.approved {
                        "NOT APPROVED".yellow().to_string()
                    } else {
                        "OK".green().to_string()
                    };

                    println!(
                        "  {:<20} [{:<6}] state={:<22} bal={:<14} borrowed={:<14}",
                        name,
                        status_icon,
                        state_label,
                        display_tos(balance),
                        display_tos(data.borrowed_amount),
                    );

                    // Check for issues
                    if data.halted {
                        issues.push(format!("{}: controller is HALTED", name));
                    }
                    if data.state == 5 {
                        issues.push(format!(
                            "{}: controller is INSOLVENT (borrowed={} TOS, balance={} TOS)",
                            name,
                            display_tos(data.borrowed_amount),
                            display_tos(balance),
                        ));
                    }
                    if !data.approved {
                        issues.push(format!("{}: controller is NOT APPROVED", name));
                    }
                    // Check if controller has borrowed funds but balance is suspiciously low
                    if data.borrowed_amount > 0 && data.state == 0 {
                        let min_storage: u64 = 2_000_000_000;
                        if balance < min_storage + data.borrowed_amount {
                            issues.push(format!(
                                "{}: balance ({} TOS) may be insufficient to repay loan ({} TOS)",
                                name,
                                display_tos(balance),
                                display_tos(data.borrowed_amount),
                            ));
                        }
                    }
                }
                Err(e) => {
                    println!("  {:<20} {}", name, format!("Error: {}", e).red());
                    issues.push(format!("{}: query failed - {}", name, e));
                }
            }
        }

        println!();
        println!("{}", "\u{2500}".repeat(60).dimmed());
        println!("  {:<28} {}", "Controllers checked:".cyan(), controller_count);
        println!("  {:<28} {} TOS", "Total balance:".cyan(), display_tos(total_balance));
        println!("  {:<28} {} TOS", "Total borrowed:".cyan(), display_tos(total_borrowed));
        println!();

        if issues.is_empty() {
            println!("  {} All controllers healthy.\n", "PASS".green().bold());
        } else {
            println!("  {} {} issue(s) found:\n", "WARN".yellow().bold(), issues.len());
            for issue in &issues {
                println!("    - {}", issue.yellow());
            }
            println!();
        }

        Ok(())
    }
}

// --- Liquid staking controller ---------------------------------------------

impl PoolLiquidControllerCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            PoolLiquidControllerAction::Create(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Update(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Ls(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Get(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Add(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Stop(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::StopWithdraw(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Deposit(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Withdraw(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::UpdateValidatorSet(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::Apr(cmd) => cmd.run(config_path).await,
            PoolLiquidControllerAction::TestLoan(cmd) => cmd.run(config_path).await,
        }
    }
}

impl PoolLiquidControllerCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let mut config = AppConfig::load(config_path)?;

        // Validate pool address format
        let pool_addr_trimmed = self.pool_address.trim();
        let pool_addr = MsgAddressInt::from_str(pool_addr_trimmed).map_err(|_| {
            anyhow::anyhow!(
                "Invalid pool address: '{}'. Expected raw or base64url format",
                pool_addr_trimmed
            )
        })?;

        // Validate optional controller addresses
        let ctrl0_addr = if let Some(ref addr) = self.controller_0_address {
            let trimmed = addr.trim();
            MsgAddressInt::from_str(trimmed).map_err(|_| {
                anyhow::anyhow!(
                    "Invalid controller-0 address: '{}'. Expected raw or base64url format",
                    trimmed
                )
            })?;
            Some(trimmed.to_string())
        } else {
            None
        };

        let ctrl1_addr = if let Some(ref addr) = self.controller_1_address {
            let trimmed = addr.trim();
            MsgAddressInt::from_str(trimmed).map_err(|_| {
                anyhow::anyhow!(
                    "Invalid controller-1 address: '{}'. Expected raw or base64url format",
                    trimmed
                )
            })?;
            Some(trimmed.to_string())
        } else {
            None
        };

        // Verify pool address exists on-chain
        println!("\n{}", "Validating pool address on-chain...".cyan());
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;
        match rpc_client.get_address_information(&pool_addr).await {
            Ok(info) => {
                if info.balance == 0 {
                    println!(
                        "  {} Pool account exists but has zero balance (not yet funded?)",
                        "[WARNING]".yellow().bold()
                    );
                } else {
                    println!(
                        "  {} Pool account verified (balance: {} nanoTOS)",
                        "OK".green().bold(),
                        info.balance
                    );
                }
            }
            Err(e) => {
                println!("  {} Could not verify pool address: {}", "[WARNING]".yellow().bold(), e);
                println!(
                    "  {}",
                    "The pool may not be deployed yet. Continuing with config setup.".dimmed()
                );
            }
        }

        // Validate controller addresses on-chain if provided
        if let Some(ref addr_str) = ctrl0_addr {
            let addr = MsgAddressInt::from_str(addr_str).unwrap();
            match rpc_client.get_address_information(&addr).await {
                Ok(_) => println!("  {} Controller 0 verified on-chain", "OK".green().bold()),
                Err(e) => println!(
                    "  {} Controller 0 not found on-chain: {}",
                    "[WARNING]".yellow().bold(),
                    e
                ),
            }
        }
        if let Some(ref addr_str) = ctrl1_addr {
            let addr = MsgAddressInt::from_str(addr_str).unwrap();
            match rpc_client.get_address_information(&addr).await {
                Ok(_) => println!("  {} Controller 1 verified on-chain", "OK".green().bold()),
                Err(e) => println!(
                    "  {} Controller 1 not found on-chain: {}",
                    "[WARNING]".yellow().bold(),
                    e
                ),
            }
        }

        // Create two controller entries for even/odd rotation
        let name_0 = format!("{}_0", self.name);
        let name_1 = format!("{}_1", self.name);

        if config.pools.contains_key(&name_0) || config.pools.contains_key(&name_1) {
            anyhow::bail!(
                "Controller set '{}' already exists in config (found '{}' or '{}')",
                self.name,
                name_0,
                name_1
            );
        }

        // Store pool address in the owner field for traceability
        let controller_0 = PoolConfig::SNP {
            address: ctrl0_addr.clone(),
            owner: Some(pool_addr_trimmed.to_string()),
        };
        let controller_1 = PoolConfig::SNP {
            address: ctrl1_addr.clone(),
            owner: Some(pool_addr_trimmed.to_string()),
        };

        config.pools.insert(name_0.clone(), controller_0);
        config.pools.insert(name_1.clone(), controller_1);
        super::utils::save_config(&config, config_path)?;

        let ctrl0_status =
            ctrl0_addr.as_deref().unwrap_or("(pending -- use `controller add` after deployment)");
        let ctrl1_status =
            ctrl1_addr.as_deref().unwrap_or("(pending -- use `controller add` after deployment)");

        println!("\n{}", "Liquid Staking Controller Set".cyan().bold());
        println!("{}", "\u{2500}".repeat(72).dimmed());
        println!("  {:<20} {}", "Set name:".cyan(), self.name);
        println!("  {:<20} {}", "Pool address:".cyan(), pool_addr_trimmed);
        println!("  {:<20} {}", "Controller 0:".cyan(), ctrl0_status);
        println!("  {:<20} {}", "Controller 1:".cyan(), ctrl1_status);
        println!();

        let has_pending = ctrl0_addr.is_none() || ctrl1_addr.is_none();

        // Deploy controllers if --deploy is set
        if self.deploy && has_pending {
            use super::utils::{
                SEND_TIMEOUT, get_wallet_config, load_config_vault_rpc_client, make_wallet,
                wait_for_seqno_change, wallet_info,
            };
            use chain_block::{read_single_root_boc, write_boc};
            use common::task_cancellation::CancellationCtx;
            use contracts::Wallet;
            use contracts::contract_codes::{DEPLOY_CONTROLLER_0_BOC, DEPLOY_CONTROLLER_1_BOC};

            let wallet_name = self
                .wallet
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--wallet is required with --deploy"))?;

            println!("\n{}", "Deploying controllers to liquid pool...".cyan().bold());

            let (config2, vault, rpc_client2) = load_config_vault_rpc_client(config_path).await?;
            let wallet_cfg =
                get_wallet_config(wallet_name, &config2.wallets, config2.master_wallet.as_ref())?;
            let (from_addr, from_info, from_secret) =
                wallet_info(rpc_client2.clone(), wallet_cfg, vault.clone()).await?;
            let wallet =
                make_wallet(rpc_client2.clone(), wallet_cfg, from_secret, wallet_name).await?;

            let deploy_amount: u64 = 1_100_000_000; // 1.1 TOS per controller

            // Deploy controller 0
            if ctrl0_addr.is_none() {
                println!("  Deploying controller 0...");
                let body_boc = hex::decode(DEPLOY_CONTROLLER_0_BOC)?;
                let body_cell = read_single_root_boc(body_boc)?;
                let msg = wallet
                    .build_message(
                        pool_addr.clone(),
                        deploy_amount,
                        body_cell,
                        false,
                        from_info.seqno,
                        None,
                        None,
                    )
                    .await?;
                let msg_boc = write_boc(&msg)?;
                rpc_client2.send_boc(&msg_boc).await?;
                wait_for_seqno_change(
                    rpc_client2.clone(),
                    &from_addr,
                    from_info.seqno,
                    &CancellationCtx::default(),
                    SEND_TIMEOUT,
                )
                .await?;
                println!("  {} Controller 0 deploy message sent", "OK".green().bold());
            }

            // Wait between deployments
            println!("  Waiting 10s between deployments...");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;

            // Deploy controller 1 — re-fetch seqno since it changed
            if ctrl1_addr.is_none() {
                let (_, from_info2, from_secret2) =
                    wallet_info(rpc_client2.clone(), wallet_cfg, vault.clone()).await?;
                let wallet2 =
                    make_wallet(rpc_client2.clone(), wallet_cfg, from_secret2, wallet_name).await?;

                println!("  Deploying controller 1...");
                let body_boc = hex::decode(DEPLOY_CONTROLLER_1_BOC)?;
                let body_cell = read_single_root_boc(body_boc)?;
                let msg = wallet2
                    .build_message(
                        pool_addr.clone(),
                        deploy_amount,
                        body_cell,
                        false,
                        from_info2.seqno,
                        None,
                        None,
                    )
                    .await?;
                let msg_boc = write_boc(&msg)?;
                rpc_client2.send_boc(&msg_boc).await?;
                wait_for_seqno_change(
                    rpc_client2.clone(),
                    &from_addr,
                    from_info2.seqno,
                    &CancellationCtx::default(),
                    SEND_TIMEOUT,
                )
                .await?;
                println!("  {} Controller 1 deploy message sent", "OK".green().bold());
            }

            println!("\n  {} Both controller deploy messages sent to pool", "OK".green().bold());
            println!("  The pool will create the controllers. Query their addresses with:");
            println!("     tosctl pool liquid controller update -n {}", self.name);
            println!();
        } else if has_pending && !self.deploy {
            println!("  {}", "Next steps:".yellow().bold());
            println!("  Deploy controllers with:");
            println!(
                "     tosctl pool liquid controller create -n {} -p {} --deploy --wallet <wallet-name>",
                self.name, pool_addr_trimmed
            );
            println!();
            println!("  Or deploy manually and register addresses:");
            println!(
                "     tosctl pool liquid controller add -n {}_0 -a <controller-0-address>",
                self.name
            );
            println!(
                "     tosctl pool liquid controller add -n {}_1 -a <controller-1-address>",
                self.name
            );
            println!();
        }

        println!("{} Controller set '{}' saved to config\n", "OK".green().bold(), self.name);

        Ok(())
    }
}

impl PoolLiquidControllerUpdateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use common::chain_utils::display_tos;
        use contracts::ControllerWrapperImpl;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Find controller-type entries (look for entries ending in _0 or _1)
        let controller_entries: Vec<(&String, &PoolConfig)> = config
            .pools
            .iter()
            .filter(|(name, pool)| {
                matches!(pool, PoolConfig::SNP { .. })
                    && (name.ends_with("_0") || name.ends_with("_1"))
            })
            .collect();

        if controller_entries.is_empty() {
            println!("\n{}\n", "No controller entries found in config".yellow());
            return Ok(());
        }

        println!("\n{}", "Controller Update".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());

        for (name, pool) in &controller_entries {
            let addr_str = match pool {
                PoolConfig::SNP { address, .. } => address.as_deref(),
                _ => None,
            };

            if let Some(addr_str) = addr_str {
                let addr = MsgAddressInt::from_str(addr_str)
                    .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", addr_str))?;

                let provider = contracts::contract_provider!(rpc_client.clone());
                let wrapper = ControllerWrapperImpl::new(provider, addr.clone());

                match wrapper.get_controller_data().await {
                    Ok(data) => {
                        let state_label = match data.state {
                            0 => "ready",
                            1 => "staking",
                            2 => "staked",
                            _ => "unknown",
                        };
                        println!(
                            "  {:<20} state={:<8} halted={:<6} approved={:<6} borrowed={}",
                            name,
                            state_label,
                            data.halted,
                            data.approved,
                            display_tos(data.borrowed_amount),
                        );
                    }
                    Err(e) => {
                        println!("  {:<20} {}", name, format!("Error: {}", e).red());
                    }
                }
            } else {
                println!("  {:<20} {}", name, "(no address configured)".dimmed());
            }
        }
        println!();

        Ok(())
    }
}

impl PoolLiquidControllerLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;

        // Collect controller entries: SNP entries whose names end in _0 or _1
        let mut controller_entries: Vec<(&String, &PoolConfig)> = config
            .pools
            .iter()
            .filter(|(name, pool)| {
                matches!(pool, PoolConfig::SNP { .. })
                    && (name.ends_with("_0") || name.ends_with("_1"))
            })
            .collect();
        controller_entries.sort_by_key(|(name, _)| name.as_str());

        if controller_entries.is_empty() {
            println!("\n{}\n", "No liquid staking controllers configured".yellow());
            println!(
                "  Use `tosctl pool liquid controller create` or `tosctl pool liquid controller add` to add one."
            );
            println!();
            return Ok(());
        }

        println!("\n{}", "Liquid Staking Controllers".cyan().bold());
        println!("{}", "\u{2500}".repeat(60).dimmed());
        println!(
            "  {:<24} {:<18} {}",
            "Name".cyan().bold(),
            "Type".cyan().bold(),
            "Address".cyan().bold(),
        );
        println!("  {}", "\u{2500}".repeat(56).dimmed());

        for (name, pool) in &controller_entries {
            let address = match pool {
                PoolConfig::SNP { address, .. } => address.as_deref().unwrap_or("-"),
                _ => "-",
            };
            println!("  {:<24} {:<18} {}", name, "controller", address);
        }
        println!();

        Ok(())
    }
}

impl PoolLiquidControllerGetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use common::chain_utils::display_tos;
        use contracts::ControllerWrapperImpl;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Look up controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Controller '{}' has no address configured. Use `controller add` to set it.",
                    self.name
                )
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller (SNP) type", self.name),
        };

        let addr = MsgAddressInt::from_str(addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", addr_str))?;

        let provider = contracts::contract_provider!(rpc_client.clone());
        let wrapper = ControllerWrapperImpl::new(provider, addr.clone());
        let data = wrapper.get_controller_data().await?;

        let state_label = match data.state {
            0 => "ready",
            1 => "staking",
            2 => "staked",
            _ => "unknown",
        };

        println!("\n{} Controller '{}'", "Controller".cyan().bold(), self.name);
        println!("  {}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<28} {}", "Address:".cyan(), addr);
        println!("  {:<28} {} ({})", "State:".cyan(), data.state, state_label);
        println!("  {:<28} {}", "Halted:".cyan(), data.halted);
        println!("  {:<28} {}", "Approved:".cyan(), data.approved);
        println!("  {:<28} {}", "Stake amount sent:".cyan(), display_tos(data.stake_amount_sent));
        println!("  {:<28} {}", "Stake at:".cyan(), data.stake_at);
        println!(
            "  {:<28} {}",
            "Validator set hash:".cyan(),
            hex::encode(data.saved_validator_set_hash)
        );
        println!("  {:<28} {}", "Validator set changes:".cyan(), data.validator_set_changes_count);
        println!(
            "  {:<28} {}",
            "Validator set change time:".cyan(),
            data.validator_set_change_time
        );
        println!("  {:<28} {}", "Stake held for:".cyan(), data.stake_held_for);
        println!("  {:<28} {}", "Borrowed amount:".cyan(), display_tos(data.borrowed_amount));
        println!("  {:<28} {}", "Borrowing time:".cyan(), data.borrowing_time);
        println!();

        Ok(())
    }
}

impl PoolLiquidControllerAddCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::{AppConfig, PoolConfig};
        use std::path::Path;
        use std::str::FromStr;

        // Validate address
        let addr_trimmed = self.address.trim();
        if addr_trimmed.is_empty() {
            anyhow::bail!("--address must not be empty");
        }
        MsgAddressInt::from_str(addr_trimmed).map_err(|_| {
            anyhow::anyhow!(
                "Invalid controller address: '{}'. Expected raw or base64url format",
                addr_trimmed
            )
        })?;

        let config_path = Path::new(config_path);
        let mut config = AppConfig::load(config_path)?;

        if config.pools.contains_key(&self.name) {
            // If it exists as SNP with no address, update it
            if let Some(PoolConfig::SNP { address: None, .. }) = config.pools.get(&self.name) {
                // Update existing entry with the address
                config.pools.insert(
                    self.name.clone(),
                    PoolConfig::SNP { address: Some(addr_trimmed.to_string()), owner: None },
                );
                super::utils::save_config(&config, config_path)?;

                println!(
                    "\n{} Controller '{}' updated with address '{}'\n",
                    "OK".green().bold(),
                    self.name,
                    addr_trimmed
                );
                return Ok(());
            }
            anyhow::bail!(
                "Entry '{}' already exists in config. Remove it first or use a different name.",
                self.name
            );
        }

        let pool_config = PoolConfig::SNP { address: Some(addr_trimmed.to_string()), owner: None };
        config.pools.insert(self.name.clone(), pool_config);
        super::utils::save_config(&config, config_path)?;

        println!(
            "\n{} Controller '{}' added (address='{}')\n",
            "OK".green().bold(),
            self.name,
            addr_trimmed
        );
        Ok(())
    }
}

impl PoolLiquidControllerStopCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use common::chain_utils::display_tos;
        use contracts::ControllerWrapperImpl;
        use contracts::Wallet;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = common::app_config::AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        let provider = contracts::contract_provider!(rpc_client.clone());
        let wrapper = ControllerWrapperImpl::new(provider, controller_addr.clone());
        let data = wrapper.get_controller_data().await?;

        let state_label = match data.state {
            0 => "REST",
            1 => "SENT_BORROWING_REQUEST",
            2 => "SENT_STAKE_REQUEST",
            3 => "FUNDS_STAKEN",
            4 => "SENT_RECOVER_REQUEST",
            5 => "INSOLVENT",
            _ => "UNKNOWN",
        };

        println!("\n{}", "Controller Stop Analysis".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<28} {}", "Controller:".cyan(), self.name);
        println!("  {:<28} {}", "Address:".cyan(), controller_addr);
        println!("  {:<28} {} ({})", "State:".cyan(), data.state, state_label);
        println!("  {:<28} {}", "Halted:".cyan(), data.halted);
        println!("  {:<28} {}", "Approved:".cyan(), data.approved);
        println!("  {:<28} {} TOS", "Borrowed:".cyan(), display_tos(data.borrowed_amount));
        println!();

        // The liquid staking controller has no dedicated "stop" opcode.
        // Stopping means: do not send new_stake in the next election cycle.
        // The validator simply refrains from calling send_request_loan / new_stake.
        //
        // If there is an outstanding loan, it must be returned first via
        // return_unused_loan (op 0xed7378a6), which can only be called when
        // state == REST and the borrowing round has ended.

        if data.state == 3 {
            // FUNDS_STAKEN
            println!("  {}", "Controller has funds staked in the elector.".yellow());
            println!("  To stop, wait for the validation cycle to end, then:");
            println!(
                "  1. Run `tosctl pool liquid controller update-validator-set -n {}`",
                self.name
            );
            println!("     (repeat until validator_set_changes_count >= 2)");
            println!(
                "  2. Run `tosctl pool liquid controller withdraw -n {} --amount <all>`",
                self.name
            );
            println!();
        } else if data.state == 0 && data.borrowed_amount > 0 {
            // REST with outstanding loan: need to return it
            println!("  {}", "Controller has an outstanding loan.".yellow());
            println!(
                "  Sending return_unused_loan to return {} TOS to the pool...",
                display_tos(data.borrowed_amount)
            );
            println!();

            // Send the return_unused_loan message
            let (_, vault, _) = super::utils::load_config_vault_rpc_client(config_path).await?;

            let binding = config
                .bindings
                .iter()
                .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No binding found referencing controller '{}'. Bind a node to this controller first.",
                        self.name
                    )
                })?;

            let wallet_name = &binding.1.wallet;
            let wallet_cfg = config
                .wallets
                .get(wallet_name)
                .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

            let (wallet_addr, wallet_secret) =
                super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
            let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

            let payload = contracts::liquid_controller::controller_messages::return_unused_loan(1)?;

            let wallet = super::utils::make_wallet(
                rpc_client.clone(),
                wallet_cfg,
                wallet_secret,
                wallet_name,
            )
            .await?;

            let gas_fee: u64 = 1_100_000_000;
            let msg = wallet.message(controller_addr.clone(), gas_fee, payload).await?;

            let boc = chain_block::write_boc(&msg)?;
            rpc_client.send_boc(&boc).await?;

            let cancellation_ctx = common::task_cancellation::CancellationCtx::default();
            super::utils::wait_for_seqno_change(
                rpc_client.clone(),
                &wallet_addr,
                wallet_info.seqno,
                &cancellation_ctx,
                super::utils::SEND_TIMEOUT,
            )
            .await?;

            println!(
                "  {} return_unused_loan sent. Controller will be idle after loan is returned.\n",
                "OK".green().bold(),
            );
        } else if data.state == 0 && data.borrowed_amount == 0 {
            println!(
                "  {} Controller is already in REST state with no outstanding loans.",
                "OK".green().bold(),
            );
            println!("  It will not enter the next election cycle unless you explicitly");
            println!("  call send_request_loan / new_stake.");
            println!();
        } else {
            println!(
                "  {} Controller is in state {} ({}).",
                "WARN".yellow().bold(),
                data.state,
                state_label,
            );
            println!("  Wait for the current operation to complete before stopping.");
            println!();
        }

        Ok(())
    }
}

impl PoolLiquidControllerStopWithdrawCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use common::chain_utils::display_tos;
        use contracts::ControllerWrapperImpl;
        use contracts::SmartContract;
        use contracts::Wallet;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        let provider = contracts::contract_provider!(rpc_client.clone());
        let wrapper = ControllerWrapperImpl::new(provider, controller_addr.clone());
        let data = wrapper.get_controller_data().await?;
        let balance = wrapper.balance().await?;

        let state_label = match data.state {
            0 => "REST",
            1 => "SENT_BORROWING_REQUEST",
            2 => "SENT_STAKE_REQUEST",
            3 => "FUNDS_STAKEN",
            4 => "SENT_RECOVER_REQUEST",
            5 => "INSOLVENT",
            _ => "UNKNOWN",
        };

        println!("\n{}", "Controller Stop + Withdraw".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<28} {}", "Controller:".cyan(), self.name);
        println!("  {:<28} {}", "Address:".cyan(), controller_addr);
        println!("  {:<28} {} ({})", "State:".cyan(), data.state, state_label);
        println!("  {:<28} {} TOS", "Balance:".cyan(), display_tos(balance));
        println!("  {:<28} {} TOS", "Borrowed:".cyan(), display_tos(data.borrowed_amount));
        println!();

        if data.state == 3 || data.state == 2 || data.state == 4 {
            // Staking in progress
            println!("  {}", "Cannot stop+withdraw while staking is in progress.".yellow());
            println!("  Current state: {} ({})", data.state, state_label);
            println!();
            println!("  Steps needed:");
            if data.state == 3 {
                println!("  1. Wait for the validation cycle to end");
                println!("  2. Run `update-validator-set` until changes_count >= 2");
                println!("  3. Recover stake from the elector");
                println!("  4. Run `stop-withdraw` again once state is REST");
            } else {
                println!("  1. Wait for the current operation to complete");
                println!("  2. Run `stop-withdraw` again once state is REST");
            }
            println!();
            return Ok(());
        }

        if data.state != 0 && data.state != 5 {
            println!(
                "  {} Controller is in state {} ({}). Cannot proceed.",
                "WARN".yellow().bold(),
                data.state,
                state_label,
            );
            println!();
            return Ok(());
        }

        // Find wallet from bindings
        let binding = config
            .bindings
            .iter()
            .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No binding found referencing controller '{}'. Bind a node to this controller first.",
                    self.name
                )
            })?;

        let wallet_name = &binding.1.wallet;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, wallet_name)
                .await?;

        // Step 1: return unused loan if borrowed
        if data.borrowed_amount > 0 {
            println!(
                "  Step 1: Returning unused loan ({} TOS) to pool...",
                display_tos(data.borrowed_amount)
            );

            let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;
            let payload = contracts::liquid_controller::controller_messages::return_unused_loan(1)?;

            let gas_fee: u64 = 1_100_000_000;
            let msg = wallet.message(controller_addr.clone(), gas_fee, payload).await?;

            let boc = chain_block::write_boc(&msg)?;
            rpc_client.send_boc(&boc).await?;

            let cancellation_ctx = common::task_cancellation::CancellationCtx::default();
            super::utils::wait_for_seqno_change(
                rpc_client.clone(),
                &wallet_addr,
                wallet_info.seqno,
                &cancellation_ctx,
                super::utils::SEND_TIMEOUT,
            )
            .await?;

            println!("  {} return_unused_loan sent.", "OK".green().bold());
            println!();
        } else {
            println!("  Step 1: No outstanding loan. {}", "Skipped.".dimmed());
        }

        // Step 2: withdraw remaining validator funds
        // MIN_TOS_FOR_STORAGE = 2 TOS, leave that in the contract
        let min_storage: u64 = 2_000_000_000;
        // Re-query balance after potential loan return
        let current_balance = wrapper.balance().await?;
        let withdrawable = current_balance.saturating_sub(min_storage);

        if withdrawable > 0 {
            println!("  Step 2: Withdrawing {} TOS from controller...", display_tos(withdrawable));

            let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;
            let payload =
                contracts::liquid_controller::controller_messages::withdraw(2, withdrawable)?;

            let gas_fee: u64 = 1_100_000_000;
            let msg = wallet.message(controller_addr.clone(), gas_fee, payload).await?;

            let boc = chain_block::write_boc(&msg)?;
            rpc_client.send_boc(&boc).await?;

            let cancellation_ctx = common::task_cancellation::CancellationCtx::default();
            super::utils::wait_for_seqno_change(
                rpc_client.clone(),
                &wallet_addr,
                wallet_info.seqno,
                &cancellation_ctx,
                super::utils::SEND_TIMEOUT,
            )
            .await?;

            println!(
                "  {} Withdrawal of {} TOS sent.",
                "OK".green().bold(),
                display_tos(withdrawable)
            );
        } else {
            println!(
                "  Step 2: No funds available to withdraw (balance {} TOS, min storage {} TOS).",
                display_tos(current_balance),
                display_tos(min_storage)
            );
        }

        println!(
            "\n  {} Controller '{}' stopped and withdrawal initiated.\n",
            "DONE".green().bold(),
            self.name,
        );

        Ok(())
    }
}

impl PoolLiquidControllerDepositCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::tos_to_nanotos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        if self.amount <= 0.0 {
            anyhow::bail!("Deposit amount must be positive");
        }

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        // Find the wallet from bindings that reference this controller
        let binding = config
            .bindings
            .iter()
            .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No binding found referencing controller '{}'. Bind a node to this controller first.",
                    self.name
                )
            })?;

        let wallet_name = &binding.1.wallet;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build top_up payload (op=0, query_id=1)
        let payload = contracts::liquid_controller::controller_messages::top_up(1)?;

        let amount_nanotos = tos_to_nanotos(self.amount);

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, wallet_name)
                .await?;

        println!(
            "\nDepositing {} TOS to controller '{}' ({})...",
            self.amount, self.name, controller_addr
        );

        let msg = wallet.message(controller_addr.clone(), amount_nanotos, payload).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} Deposited {} TOS to controller '{}'\n",
            "OK".green().bold(),
            self.amount,
            self.name
        );

        Ok(())
    }
}

impl PoolLiquidControllerWithdrawCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::tos_to_nanotos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        if self.amount <= 0.0 {
            anyhow::bail!("Withdraw amount must be positive");
        }

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        // Find the wallet from bindings
        let binding = config
            .bindings
            .iter()
            .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No binding found referencing controller '{}'. Bind a node to this controller first.",
                    self.name
                )
            })?;

        let wallet_name = &binding.1.wallet;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build withdraw payload (op=0x8efed779, query_id=1, amount)
        let amount_nanotos = tos_to_nanotos(self.amount);
        let payload =
            contracts::liquid_controller::controller_messages::withdraw(1, amount_nanotos)?;

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, wallet_name)
                .await?;

        println!(
            "\nWithdrawing {} TOS from controller '{}' ({})...",
            self.amount, self.name, controller_addr
        );

        // Send 1.1 TOS for gas with the withdraw payload
        let gas_fee: u64 = 1_100_000_000;
        let msg = wallet.message(controller_addr.clone(), gas_fee, payload).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} Withdrawal of {} TOS from controller '{}' sent\n",
            "OK".green().bold(),
            self.amount,
            self.name
        );

        Ok(())
    }
}

impl PoolLiquidControllerUpdateValidatorSetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::{MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{app_config::PoolConfig, task_cancellation::CancellationCtx};
        use contracts::Wallet;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let (config, vault, rpc_client) =
            super::utils::load_config_vault_rpc_client(config_path).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        // Find the wallet from bindings
        let binding = config
            .bindings
            .iter()
            .find(|(_, b)| b.pool.as_deref() == Some(&self.name))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No binding found referencing controller '{}'. Bind a node to this controller first.",
                    self.name
                )
            })?;

        let wallet_name = &binding.1.wallet;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_addr, wallet_secret) =
            super::utils::wallet_address(wallet_cfg, vault.clone()).await?;
        let wallet_info = rpc_client.get_wallet_information(&wallet_addr).await?;

        if wallet_info.account_state != AccountState::Active {
            anyhow::bail!(
                "Wallet '{}' ({}) is not active (state: {})",
                wallet_name,
                wallet_addr,
                wallet_info.account_state
            );
        }

        // Build update_validator_hash payload (op=0x17bfe11b, query_id=1)
        let payload = contracts::liquid_controller::controller_messages::update_validator_hash(1)?;

        let wallet =
            super::utils::make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, wallet_name)
                .await?;

        println!(
            "\nSending update_validator_hash to controller '{}' ({})...",
            self.name, controller_addr
        );

        let msg = wallet.message(controller_addr.clone(), 1_100_000_000, payload).await?;

        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;

        let cancellation_ctx = CancellationCtx::default();
        super::utils::wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_addr,
            wallet_info.seqno,
            &cancellation_ctx,
            super::utils::SEND_TIMEOUT,
        )
        .await?;

        println!(
            "\n{} update_validator_hash sent to controller '{}'\n",
            "OK".green().bold(),
            self.name
        );

        Ok(())
    }
}

impl PoolLiquidControllerAprCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use common::chain_utils::{display_tos, nanotos_to_tos};
        use contracts::ControllerWrapperImpl;
        use contracts::SmartContract;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = common::app_config::AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        let provider = contracts::contract_provider!(rpc_client.clone());
        let wrapper = ControllerWrapperImpl::new(provider, controller_addr.clone());
        let data = wrapper.get_controller_data().await?;
        let balance = wrapper.balance().await?;

        let state_label = match data.state {
            0 => "REST",
            1 => "SENT_BORROWING_REQUEST",
            2 => "SENT_STAKE_REQUEST",
            3 => "FUNDS_STAKEN",
            4 => "SENT_RECOVER_REQUEST",
            5 => "INSOLVENT",
            _ => "UNKNOWN",
        };

        println!("\n{}", "Controller APR Analytics".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<28} {}", "Controller:".cyan(), self.name);
        println!("  {:<28} {}", "Address:".cyan(), controller_addr);
        println!("  {:<28} {} ({})", "State:".cyan(), data.state, state_label);
        println!("  {:<28} {} TOS", "Balance:".cyan(), display_tos(balance));
        println!("  {:<28} {} TOS", "Stake sent:".cyan(), display_tos(data.stake_amount_sent));
        println!("  {:<28} {} TOS", "Borrowed:".cyan(), display_tos(data.borrowed_amount));
        println!("  {:<28} {}", "Borrowing time:".cyan(), data.borrowing_time);
        println!("  {:<28} {} TOS", "Stake held for:".cyan(), data.stake_held_for);
        println!();

        // APR estimation from current cycle data
        //
        // The controller borrows from the pool and stakes. After the cycle,
        // it recovers principal + reward from the elector and repays
        // principal + interest to the pool. The validator's yield is:
        //   yield = (elector_reward - pool_interest)
        //   APR = yield / validator_own_funds * (SECONDS_PER_YEAR / cycle_duration)
        //
        // We can estimate from the current state:
        // - If FUNDS_STAKEN: validator has staked, we can show the expected parameters
        // - If REST with no borrow: the last cycle is complete, yield is reflected in balance
        //
        // For a snapshot APR, we use:
        //   validator_own_funds = balance - borrowed_amount
        //   If borrowed_amount > 0 and borrowing_time > 0, we can estimate
        //   the implied interest from the pool rate.

        let seconds_per_year: f64 = 365.25 * 24.0 * 3600.0;

        if data.borrowed_amount > 0 && data.borrowing_time > 0 {
            let validator_own = balance.saturating_sub(data.borrowed_amount);
            let total_staked = nanotos_to_tos(data.stake_amount_sent);
            let own_tos = nanotos_to_tos(validator_own);
            let borrowed_tos = nanotos_to_tos(data.borrowed_amount);

            println!("  {}", "Current cycle estimate:".yellow().bold());
            println!("  {:<28} {} TOS", "Validator own funds:".cyan(), format!("{:.4}", own_tos));
            println!("  {:<28} {} TOS", "Total staked:".cyan(), format!("{:.4}", total_staked));
            println!(
                "  {:<28} {:.2}x",
                "Leverage:".cyan(),
                if own_tos > 0.0 { total_staked / own_tos } else { 0.0 }
            );
            println!();
            println!(
                "  {}",
                "Note: Actual APR depends on elector rewards and pool interest".dimmed()
            );
            println!("  {}", "rate, which are only known after the cycle completes.".dimmed());

            // Typical TOS validation round is ~18h (65536 seconds)
            let typical_round_seconds: f64 = 65536.0;
            let rounds_per_year = seconds_per_year / typical_round_seconds;

            // If we know the pool interest rate (SHARE_BASIS = 65536), we can estimate
            // Assume typical 1% per round interest as a reference
            println!();
            println!(
                "  {}",
                "Reference APR projections (per-round reward scenarios):".yellow().bold()
            );
            for reward_bps in [50u64, 100, 200, 500] {
                let reward_rate = reward_bps as f64 / 10000.0;
                let round_reward = total_staked * reward_rate / 100.0; // reward in TOS
                let round_interest = borrowed_tos * reward_rate / 100.0; // interest paid
                let net_yield = round_reward - round_interest;
                let apr = if own_tos > 0.0 {
                    (net_yield / own_tos) * rounds_per_year * 100.0
                } else {
                    0.0
                };
                println!(
                    "  {:<28} {:.2}%",
                    format!("  If reward = {:.2}% /round:", reward_rate).cyan(),
                    apr
                );
            }
        } else if data.state == 0 && data.borrowed_amount == 0 {
            println!("  {}", "Controller is idle (REST, no outstanding loan).".dimmed());
            println!("  {:<28} {} TOS", "Available balance:".cyan(), display_tos(balance));
            println!();
            println!("  {}", "APR can be estimated after the next validation cycle.".dimmed());
            println!("  {}", "Historical APR requires comparing balance across cycles.".dimmed());
        } else {
            println!("  {}", "Cannot compute APR in current state.".yellow());
            println!("  {}", "APR calculation requires either active staking data or".dimmed());
            println!("  {}", "idle state with historical balance snapshots.".dimmed());
        }

        println!();
        Ok(())
    }
}

impl PoolLiquidControllerTestLoanCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use chain_block::MsgAddressInt;
        use colored::Colorize;
        use common::app_config::PoolConfig;
        use common::chain_utils::{display_tos, tos_to_nanotos};
        use contracts::ControllerWrapperImpl;
        use contracts::SmartContract;
        use contracts::liquid_controller::ControllerWrapper;
        use std::path::Path;
        use std::str::FromStr;

        let config_path = Path::new(config_path);
        let config = common::app_config::AppConfig::load(config_path)?;
        let rpc_client = super::utils::try_create_rpc_client(&config).await?;

        // Find controller in config
        let pool = config
            .pools
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Controller '{}' not found in config", self.name))?;

        let controller_addr_str = match pool {
            PoolConfig::SNP { address, .. } => address.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Controller '{}' has no address configured", self.name)
            })?,
            _ => anyhow::bail!("Config entry '{}' is not a controller type", self.name),
        };

        let controller_addr = MsgAddressInt::from_str(controller_addr_str)
            .map_err(|_| anyhow::anyhow!("Invalid controller address: {}", controller_addr_str))?;

        let provider = contracts::contract_provider!(rpc_client.clone());
        let wrapper = ControllerWrapperImpl::new(provider, controller_addr.clone());

        // Get current controller state
        let data = wrapper.get_controller_data().await?;
        let balance = wrapper.balance().await?;

        // Convert credit from TOS to nanotos
        let credit_nanotos = tos_to_nanotos(self.credit);
        // Interest is passed as basis points in SHARE_BASIS (65536)
        // User provides basis points (e.g. 100 = 1%), convert to SHARE_BASIS
        let interest_share = self.interest * 65536 / 10000;

        println!("\n{}", "Controller Test Loan".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  {:<28} {}", "Controller:".cyan(), self.name);
        println!("  {:<28} {}", "Address:".cyan(), controller_addr);
        println!("  {:<28} {} TOS", "Current balance:".cyan(), display_tos(balance));
        println!("  {:<28} {}", "Approved:".cyan(), data.approved);
        println!("  {:<28} {} TOS", "Requested credit:".cyan(), display_tos(credit_nanotos));
        println!(
            "  {:<28} {} bps ({:.4}%)",
            "Interest rate:".cyan(),
            self.interest,
            self.interest as f64 / 100.0
        );
        println!();

        if !data.approved {
            println!("  {} Controller is not approved by the pool.", "WARN".yellow().bold());
            println!("  Loans are only available to approved controllers.");
            println!();
        }

        if data.borrowed_amount > 0 {
            println!(
                "  {} Controller already has an outstanding loan of {} TOS.",
                "WARN".yellow().bold(),
                display_tos(data.borrowed_amount)
            );
            println!("  Multiple loans are prohibited; return the current loan first.");
            println!();
        }

        // Call required_balance_for_loan get-method
        match wrapper.required_balance_for_loan(credit_nanotos, interest_share).await {
            Ok(result) => {
                let eligible = result.validator_amount >= result.required_balance;

                println!("  {}", "Loan feasibility analysis:".yellow().bold());
                println!(
                    "  {:<28} {} TOS",
                    "Required balance:".cyan(),
                    display_tos(result.required_balance)
                );
                println!(
                    "  {:<28} {} TOS",
                    "Validator own funds:".cyan(),
                    display_tos(result.validator_amount)
                );
                println!(
                    "  {:<28} {} TOS",
                    "Surplus / deficit:".cyan(),
                    if result.validator_amount >= result.required_balance {
                        format!(
                            "+{}",
                            display_tos(result.validator_amount - result.required_balance)
                        )
                    } else {
                        format!(
                            "-{}",
                            display_tos(result.required_balance - result.validator_amount)
                        )
                    }
                );
                println!();

                if eligible {
                    println!(
                        "  {} Controller has sufficient balance for this loan.",
                        "ELIGIBLE".green().bold()
                    );
                } else {
                    let deficit = result.required_balance - result.validator_amount;
                    println!(
                        "  {} Insufficient balance. Need {} TOS more.",
                        "NOT ELIGIBLE".red().bold(),
                        display_tos(deficit),
                    );
                    println!(
                        "  Top up the controller with at least {} TOS to qualify.",
                        display_tos(deficit)
                    );
                }
            }
            Err(e) => {
                println!(
                    "  {} Failed to query required_balance_for_loan: {}",
                    "ERROR".red().bold(),
                    e
                );
                println!("  The controller contract may not support this get-method,");
                println!("  or the contract may not be deployed yet.");
            }
        }

        println!();
        Ok(())
    }
}
