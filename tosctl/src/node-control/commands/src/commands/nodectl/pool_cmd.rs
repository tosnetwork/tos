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
    #[arg(
        allow_hyphen_values = true, value_parser = super::utils::address_arg,
        short = 'a',
        long = "address",
        help = "Pool contract address"
    )]
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
    #[arg(
        long,
        help = "Wallet name from config to use as the nominator (defaults to the pool owner or binding wallet)"
    )]
    wallet: Option<String>,
    #[arg(long, help = "Amount in TOS to deposit")]
    amount: f64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Withdraw stake")]
pub struct PoolNominatorWithdrawCmd {
    #[arg(short = 'n', long = "name", help = "Pool name from config")]
    name: String,
    #[arg(
        long,
        help = "Wallet name from config to use as the nominator (defaults to the pool owner or binding wallet)"
    )]
    wallet: Option<String>,
}

fn select_nominator_wallet_name<'a>(
    requested_wallet: Option<&'a str>,
    configured_owner: Option<&'a str>,
    binding_wallet: Option<&'a str>,
    pool_name: &str,
) -> anyhow::Result<&'a str> {
    requested_wallet.or(configured_owner).or(binding_wallet).ok_or_else(|| {
        anyhow::anyhow!(
            "No binding or owner found for pool '{}'. Configure an owner or binding, or pass --wallet.",
            pool_name
        )
    })
}

fn nominator_pool_chain_json(
    data: &contracts::NominatorPoolData,
    positions: &[contracts::NominatorPosition],
) -> serde_json::Value {
    let positions = positions
        .iter()
        .map(|position| {
            serde_json::json!({
                "address": position.address,
                "amount": position.amount.to_string(),
                "pending_deposit": position.pending_deposit.to_string(),
                "withdraw_requested": position.withdraw_requested,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "pool_data": {
            "state": data.state,
            "nominators_count": data.nominators_count,
            "stake_amount_sent": data.stake_amount_sent.to_string(),
            "validator_amount": data.validator_amount.to_string(),
            "validator_address": format!("0:{}", hex::encode(data.validator_address)),
            "validator_reward_share_bps": data.validator_reward_share,
            "max_nominators_count": data.max_nominators_count,
            "min_validator_stake": data.min_validator_stake.to_string(),
            "min_nominator_stake": data.min_nominator_stake.to_string(),
            "stake_at": data.stake_at,
            "saved_validator_set_hash": hex::encode(data.saved_validator_set_hash),
            "validator_set_changes_count": data.validator_set_changes_count,
            "validator_set_change_time": data.validator_set_change_time,
            "stake_held_for": data.stake_held_for,
        },
        "nominator_positions": positions,
    })
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
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::{AppConfig, PoolConfig},
            chain_utils::display_tos,
        };
        use contracts::{NominatorPoolWrapper, NominatorPoolWrapperImpl};
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
                            if info.state == AccountState::Active {
                                let provider = contracts::contract_provider!(rpc_client.clone());
                                let wrapper = NominatorPoolWrapperImpl::new(provider, addr);
                                let data = wrapper.get_pool_data().await?;
                                let positions = wrapper.list_nominators().await?;
                                let chain = nominator_pool_chain_json(&data, &positions);
                                obj["pool_data"] = chain["pool_data"].clone();
                                obj["nominator_positions"] = chain["nominator_positions"].clone();
                            }
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
        use chain_block::{MsgAddressInt, write_boc};
        use chain_rpc_client::v2::data_models::AccountState;
        use colored::Colorize;
        use common::{
            app_config::PoolConfig, chain_utils::display_tos, task_cancellation::CancellationCtx,
        };
        use contracts::Wallet;
        use contracts::{NominatorPoolWrapperImpl, nominator_pool::pool_messages};
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

        // Send a deploy message with the contract's no-op opcode.  The pool
        // always reads an opcode and query id, so an empty body aborts before
        // StateInit can activate the account.
        let deploy_amount: u64 = 1_000_000_000; // 1 TOS for deploy gas
        let deploy_body =
            pool_messages::accept_coins(owner_wallet_info.seqno.unwrap_or_default() as u64)?;
        let msg = wallet
            .build_message(
                pool_addr.clone(),
                deploy_amount,
                deploy_body,
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
        use common::{app_config::PoolConfig, chain_utils::tos_to_nanotos};
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

        // An explicit wallet lets any configured account act as a nominator. Without
        // it, preserve the historical owner-then-binding resolution order.
        let binding_wallet = config
            .bindings
            .iter()
            .find(|(_, binding)| binding.pool.as_deref() == Some(&self.name))
            .map(|(_, binding)| binding.wallet.as_str());
        let wallet_name = select_nominator_wallet_name(
            self.wallet.as_deref(),
            owner_name.as_deref(),
            binding_wallet,
            &self.name,
        )?
        .to_owned();

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
        super::agent_cmd::confirm_prepared_wallet_message(
            rpc_client.clone(),
            &boc,
            &wallet_addr,
            &pool_addr,
            super::utils::DEPLOY_TIMEOUT,
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

        // An explicit wallet lets the matching nominator request its own withdrawal.
        // Without it, preserve the historical owner-then-binding resolution order.
        let binding_wallet = config
            .bindings
            .iter()
            .find(|(_, binding)| binding.pool.as_deref() == Some(&self.name))
            .map(|(_, binding)| binding.wallet.as_str());
        let wallet_name = select_nominator_wallet_name(
            self.wallet.as_deref(),
            owner_name.as_deref(),
            binding_wallet,
            &self.name,
        )?
        .to_owned();

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct PoolTestCli {
        #[command(subcommand)]
        action: PoolAction,
    }

    #[test]
    fn parses_optional_nominator_wallet_for_deposit_and_withdraw() {
        let deposit = PoolTestCli::try_parse_from([
            "tosctl",
            "nominator",
            "deposit",
            "--name",
            "shared-pool",
            "--wallet",
            "nominator-a",
            "--amount",
            "12.5",
        ])
        .unwrap();
        match deposit.action {
            PoolAction::Nominator(PoolNominatorCmd {
                action: PoolNominatorAction::Deposit(command),
            }) => {
                assert_eq!(command.name, "shared-pool");
                assert_eq!(command.wallet.as_deref(), Some("nominator-a"));
                assert_eq!(command.amount, 12.5);
            }
            _ => panic!("deposit command parsed as another pool action"),
        }

        let withdraw = PoolTestCli::try_parse_from([
            "tosctl",
            "nominator",
            "withdraw",
            "--name",
            "shared-pool",
            "--wallet",
            "nominator-b",
        ])
        .unwrap();
        match withdraw.action {
            PoolAction::Nominator(PoolNominatorCmd {
                action: PoolNominatorAction::Withdraw(command),
            }) => {
                assert_eq!(command.name, "shared-pool");
                assert_eq!(command.wallet.as_deref(), Some("nominator-b"));
            }
            _ => panic!("withdraw command parsed as another pool action"),
        }
    }

    #[test]
    fn omitted_nominator_wallet_preserves_owner_then_binding_fallback() {
        let parsed = PoolTestCli::try_parse_from([
            "tosctl",
            "nominator",
            "deposit",
            "--name",
            "shared-pool",
            "--amount",
            "1",
        ])
        .unwrap();
        match parsed.action {
            PoolAction::Nominator(PoolNominatorCmd {
                action: PoolNominatorAction::Deposit(command),
            }) => assert!(command.wallet.is_none()),
            _ => panic!("deposit command parsed as another pool action"),
        }

        assert_eq!(
            select_nominator_wallet_name(
                Some("explicit"),
                Some("owner"),
                Some("binding"),
                "shared-pool"
            )
            .unwrap(),
            "explicit"
        );
        assert_eq!(
            select_nominator_wallet_name(None, Some("owner"), Some("binding"), "shared-pool")
                .unwrap(),
            "owner"
        );
        assert_eq!(
            select_nominator_wallet_name(None, None, Some("binding"), "shared-pool").unwrap(),
            "binding"
        );
        assert!(
            select_nominator_wallet_name(None, None, None, "shared-pool")
                .unwrap_err()
                .to_string()
                .contains("--wallet")
        );
    }

    #[test]
    fn serializes_exact_multi_nominator_chain_view() {
        let data = contracts::NominatorPoolData {
            state: 2,
            nominators_count: 1,
            stake_amount_sent: 9_007_199_254_740_993,
            validator_amount: 4_000_000_000,
            validator_address: [0x11; 32],
            validator_reward_share: 4000,
            max_nominators_count: 40,
            min_validator_stake: 10_000_000_000_000,
            min_nominator_stake: 100_000_000_000,
            stake_at: 123,
            saved_validator_set_hash: [0x22; 32],
            validator_set_changes_count: 2,
            validator_set_change_time: 456,
            stake_held_for: 65_536,
        };
        let positions = vec![contracts::NominatorPosition {
            address: format!("0:{}", "33".repeat(32)),
            amount: 9_007_199_254_740_993,
            pending_deposit: 500_000_000,
            withdraw_requested: true,
        }];

        let encoded = serde_json::to_string(&nominator_pool_chain_json(&data, &positions)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(parsed["pool_data"]["state"], 2);
        assert_eq!(parsed["pool_data"]["nominators_count"], 1);
        assert_eq!(parsed["pool_data"]["stake_amount_sent"], "9007199254740993");
        assert_eq!(parsed["pool_data"]["validator_address"], format!("0:{}", "11".repeat(32)));
        assert_eq!(parsed["pool_data"]["validator_reward_share_bps"], 4000);
        assert_eq!(parsed["pool_data"]["max_nominators_count"], 40);
        assert_eq!(parsed["pool_data"]["saved_validator_set_hash"], "22".repeat(32));
        assert_eq!(parsed["nominator_positions"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["nominator_positions"][0]["amount"], "9007199254740993");
        assert_eq!(parsed["nominator_positions"][0]["pending_deposit"], "500000000");
        assert_eq!(parsed["nominator_positions"][0]["withdraw_requested"], true);
    }
}
