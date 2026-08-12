/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::output_format::OutputFormat;
use super::utils::{
    load_config_vault_rpc_client, load_config_vault_rpc_client_fd, make_wallet, wallet_address, wallet_info,
    check_chain_rpc_connection, warn_chain_rpc_unavailable, get_wallet_config,
    wait_for_seqno_change, wait_for_deploy, SEND_TIMEOUT, DEPLOY_TIMEOUT,
};
use anyhow::Context;
use colored::Colorize;
use common::{
    app_config::WalletConfig,
    chain_utils::{display_tos, tos_to_nanotos},
    task_cancellation::CancellationCtx,
};
use contracts::Wallet;
use secrets_vault::{
    crypto::factory::{AutoCryptoFactory, CryptoFactory},
    errors::error::VaultError,
    vault::SecretVault,
};
use std::{borrow::Cow, io::Write, path::Path, sync::Arc};
use chain_block::{ADDR_FORMAT_BOUNCE, ADDR_FORMAT_URL_SAFE, BuilderData, Cell, IBitstring, MsgAddressInt, write_boc};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::AccountState;

#[derive(clap::Args, Clone)]
#[command(about = "Manage wallets")]
pub struct WalletCmd {
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
    action: WalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum WalletAction {
    /// Create a new wallet
    Create(WalletCreateCmd),
    /// Activate wallet
    Activate(WalletActivateCmd),
    /// List wallets
    Ls(WalletLsCmd),
    /// Import keypair
    Import(WalletImportCmd),
    /// Export wallet (use with caution)
    Export(WalletExportCmd),
    /// Remove wallet
    Rm(WalletRmCmd),
    /// Wallet version migration
    SetVersion(WalletSetVersionCmd),
    /// Generic transfer
    Send(WalletSendCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a new wallet")]
pub struct WalletCreateCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    #[arg(short = 'v', long = "version", default_value = "V3R2", help = "Wallet version")]
    version: String,
    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Workchain ID")]
    workchain: i32,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42", help = "Subwallet ID")]
    subwallet_id: u32,
}

#[derive(clap::Args, Clone)]
#[command(about = "Activate wallet")]
pub struct WalletActivateCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name (or --all)")]
    name: Option<String>,

    /// Activate all wallets
    #[arg(long)]
    all: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "List wallets")]
pub struct WalletLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
    /// Resolve configured wallet identities without querying chain state.
    #[arg(long)]
    offline: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Import keypair")]
pub struct WalletImportCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    #[arg(short = 'k', long = "private-key", help = "Base64-encoded private key")]
    private_key: String,
    #[arg(short = 'v', long = "version", default_value = "V3R2")]
    version: String,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42")]
    subwallet_id: u32,
}

#[derive(clap::Args, Clone)]
#[command(about = "Export wallet (use with caution — exposes private material)")]
pub struct WalletExportCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    #[arg(long = "yes", help = "Acknowledge security risk")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove wallet")]
pub struct WalletRmCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    /// Skip confirmation prompt
    #[arg(long)]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Wallet version migration")]
pub struct WalletSetVersionCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    #[arg(
        short = 'v',
        long = "version",
        help = "New wallet version (V1R3, V3R2, V4R2, V5R1)"
    )]
    version: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Generic transfer")]
pub struct WalletSendCmd {
    /// Send via proxy contract
    #[arg(long)]
    via_proxy: bool,

    #[arg(long, help = "Source wallet name from config")]
    from: String,

    #[arg(long, help = "Destination address")]
    to: String,

    #[arg(
        long,
        conflicts_with = "amount_nanotos",
        required_unless_present = "amount_nanotos",
        help = "Amount in TOS (e.g. 1.5)"
    )]
    amount: Option<f64>,

    #[arg(
        long,
        conflicts_with = "amount",
        required_unless_present = "amount",
        help = "Exact amount in nanoTOS for automation"
    )]
    amount_nanotos: Option<u64>,

    #[arg(long, help = "Optional message/comment")]
    message: Option<String>,

    #[arg(long, help = "Confirm the transfer non-interactively")]
    yes: bool,
    #[arg(long, requires = "config_format")]
    config_fd: Option<i32>,
    #[arg(long, value_parser = ["json", "yaml", "yml"], requires = "config_fd")]
    config_format: Option<String>,
}

impl WalletCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            WalletAction::Create(cmd) => cmd.run(&self.config).await,
            WalletAction::Activate(cmd) => cmd.run(&self.config).await,
            WalletAction::Ls(cmd) => cmd.run(&self.config).await,
            WalletAction::Import(cmd) => cmd.run(&self.config).await,
            WalletAction::Export(cmd) => cmd.run(&self.config).await,
            WalletAction::Rm(cmd) => cmd.run(&self.config).await,
            WalletAction::SetVersion(cmd) => cmd.run(&self.config).await,
            WalletAction::Send(cmd) => cmd.run(&self.config).await,
        }
    }

    /// Shortcut entry point for `tosctl wl` (wallet ls with default table format).
    pub async fn run_ls_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = WalletLsCmd {
            format: OutputFormat::Table,
            config_fd: None,
            config_format: None,
            offline: false,
        };
        cmd.run(&config_path).await
    }
}

impl WalletCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(path).await?;

        if config.wallets.contains_key(&self.name) {
            anyhow::bail!("Wallet '{}' already exists in config", self.name);
        }

        // Generate key in vault
        let secret_name = format!("wallet-{}", self.name);
        let spec = secrets_vault::types::secret_spec::SecretSpec::new(
            secrets_vault::types::algorithm::Algorithm::Ed25519,
        )
        .extractable(false);
        let secret_id = secret_name.as_str().into();
        vault.generate_secret(&spec, &secret_id).await?;
        vault.flush().await?;

        // Parse version
        let version: common::wallet_version::WalletVersion = self
            .version
            .parse()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                    self.version
                )
            })?;

        // Add wallet to config
        let wallet_config = common::app_config::WalletConfig {
            key: common::app_config::KeyConfig::VaultKey {
                name: secret_name.clone(),
            },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        config
            .wallets
            .insert(self.name.clone(), wallet_config.clone());
        super::utils::save_config(&config, path)?;

        // Calculate and display address
        let secret = vault.get(&secret_id).await?;
        if let secrets_vault::types::secret::Secret::KeyPair { keypair } = &secret {
            if let Some(pub_key) = keypair.public_key().await? {
                let address =
                    super::utils::calculate_wallet_address(&wallet_config, &pub_key)?;
                println!(
                    "\n{} Wallet '{}' created\n",
                    "OK".green().bold(),
                    self.name
                );
                println!("  Address:  {}", address);
                println!("  Version:  {}", self.version);
                println!("  Key:      {} (in vault)", secret_name);
            }
        }
        println!();
        Ok(())
    }
}

impl WalletActivateCmd {
    const MIN_BALANCE: u64 = 100_000_000; // 0.1 TOS

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.name.is_none() && !self.all {
            anyhow::bail!("Specify --name <wallet> or --all");
        }

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        // Collect the wallet names to activate
        let wallet_names: Vec<String> = if self.all {
            config.wallets.keys().cloned().collect()
        } else {
            let name = self.name.as_ref().unwrap();
            if !config.wallets.contains_key(name) {
                anyhow::bail!("Wallet '{}' not found in config", name);
            }
            vec![name.clone()]
        };

        if wallet_names.is_empty() {
            println!("{}", "No wallets configured".yellow());
            return Ok(());
        }

        let cancellation_ctx = CancellationCtx::default();

        for name in &wallet_names {
            let wallet_cfg = config.wallets.get(name).unwrap();

            let (address, info, secret) =
                wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

            if info.account_state == AccountState::Active {
                println!(
                    "{} Wallet '{}' ({}) already active, skipping",
                    "OK".green().bold(),
                    name,
                    address
                );
                continue;
            }

            if info.account_state == AccountState::Frozen {
                println!(
                    "{} Wallet '{}' ({}) is frozen, skipping",
                    "WARN".yellow().bold(),
                    name,
                    address
                );
                continue;
            }

            if info.balance < Self::MIN_BALANCE {
                println!(
                    "{} Wallet '{}' ({}) balance {} too low (min {}), skipping",
                    "WARN".yellow().bold(),
                    name,
                    address,
                    display_tos(info.balance),
                    display_tos(Self::MIN_BALANCE),
                );
                continue;
            }

            println!("Deploying wallet '{}' ({})...", name, address);

            let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, name).await?;
            let msg = wallet
                .deploy_message(Self::MIN_BALANCE / 10, Cell::default())
                .await?;
            let boc = write_boc(&msg)?;
            rpc_client.send_boc(&boc).await?;

            wait_for_deploy(
                rpc_client.clone(),
                &address,
                &cancellation_ctx,
                true,
                DEPLOY_TIMEOUT,
            )
            .await?;

            println!(
                "{} Wallet '{}' ({}) activated",
                "OK".green().bold(),
                name,
                address
            );
        }

        Ok(())
    }
}

/// JSON-serializable view of a wallet entry.
#[derive(serde::Serialize)]
struct WalletLsView {
    name: String,
    address: Option<String>,
    balance: Option<String>,
    state: Option<String>,
    wallet_type: Option<String>,
    seqno: Option<u32>,
}

impl WalletLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(config_path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };

        if !self.offline && let Err(e) = check_chain_rpc_connection(&rpc_client).await {
            if matches!(self.format, OutputFormat::Table) {
                warn_chain_rpc_unavailable(&e, "State and balances will not be available");
            }
        }

        if config.wallets.is_empty() {
            match self.format {
                OutputFormat::Json => println!("[]"),
                OutputFormat::Table => println!("\n{}\n", "No wallets configured".yellow()),
            }
            return Ok(());
        }

        let mut wallet_list: Vec<(&str, &WalletConfig)> =
            config.wallets.iter().map(|(k, v)| (k.as_str(), v)).collect();
        wallet_list.sort_by_key(|(name, _)| *name);

        match self.format {
            OutputFormat::Json => {
                print_wallets_json(&wallet_list, vault, rpc_client, self.offline).await?;
            }
            OutputFormat::Table => {
                print_wallets_table(&wallet_list, vault, rpc_client, self.offline).await;
            }
        }
        Ok(())
    }
}

async fn print_wallets_json(
    wallets: &[(&str, &WalletConfig)],
    vault: Arc<SecretVault>,
    rpc_client: Arc<ClientJsonRpc>,
    offline: bool,
) -> anyhow::Result<()> {
    let mut views = Vec::new();
    for (name, wallet_cfg) in wallets {
        let (address, state, balance, wallet_type, seqno) =
            match wallet_address(wallet_cfg, vault.clone()).await {
                Ok((address, _)) => {
                    let address_str = address
                        .to_string_custom(ADDR_FORMAT_BOUNCE | ADDR_FORMAT_URL_SAFE)
                        .unwrap_or_else(|_| address.to_string());
                    if offline {
                        (Some(address_str), None, None, None, None)
                    } else { match rpc_client.get_wallet_information(&address).await {
                        Ok(info) => (
                            Some(address_str),
                            Some(info.account_state.to_string()),
                            Some(display_tos(info.balance)),
                            info.wallet_type.map(|t| t.to_string()),
                            info.seqno,
                        ),
                        Err(_) => (Some(address_str), None, None, None, None),
                    } }
                }
                Err(_) => (None, None, None, None, None),
            };
        views.push(WalletLsView {
            name: name.to_string(),
            address,
            balance,
            state,
            wallet_type,
            seqno,
        });
    }
    println!("{}", serde_json::to_string_pretty(&views)?);
    Ok(())
}

async fn print_wallets_table(
    wallets: &[(&str, &WalletConfig)],
    vault: Arc<SecretVault>,
    rpc_client: Arc<ClientJsonRpc>,
    offline: bool,
) {
    println!(
        "\n{} {} ({})\n",
        "OK".green().bold(),
        "Wallets:".green(),
        wallets.len()
    );
    println!(
        "  {:<20} {:<50} {:>15} {:<10} {:<10} {:>6}",
        "Name".cyan().bold(),
        "Address".cyan().bold(),
        "Balance".cyan().bold(),
        "State".cyan().bold(),
        "Type".cyan().bold(),
        "Seqno".cyan().bold(),
    );
    println!("  {}", "─".repeat(120).dimmed());

    let red_dash = Cow::Borrowed(&"-".red());
    for (name, wallet_cfg) in wallets {
        let (address, account_state, balance, wallet_type, seqno) =
            match wallet_address(wallet_cfg, vault.clone()).await {
                Ok((addr, _)) => {
                    let address_str = addr
                        .to_string_custom(ADDR_FORMAT_BOUNCE | ADDR_FORMAT_URL_SAFE)
                        .unwrap_or_else(|_| addr.to_string());

                    if offline {
                        (address_str.white(), red_dash.clone(), red_dash.clone(), red_dash.clone(), red_dash.clone())
                    } else { match rpc_client.get_wallet_information(&addr).await {
                        Ok(info) => (
                            address_str.white(),
                            Cow::Owned(info.account_state.to_string().white()),
                            Cow::Owned(display_tos(info.balance).white()),
                            Cow::Owned(
                                info.wallet_type
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "-".to_string())
                                    .white(),
                            ),
                            Cow::Owned(
                                info.seqno
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "-".to_string())
                                    .white(),
                            ),
                        ),
                        Err(_) => (
                            address_str.white(),
                            red_dash.clone(),
                            red_dash.clone(),
                            red_dash.clone(),
                            red_dash.clone(),
                        ),
                    } }
                }
                Err(e) => {
                    let error_message = if e
                        .downcast_ref::<VaultError>()
                        .is_some_and(|e| e.code() == VaultError::NOT_FOUND)
                    {
                        "not found in the vault".red()
                    } else {
                        e.root_cause().to_string().red()
                    };
                    (
                        error_message,
                        red_dash.clone(),
                        red_dash.clone(),
                        red_dash.clone(),
                        red_dash.clone(),
                    )
                }
            };

        println!(
            "  {:<20} {:<50} {:>15} {:<10} {:<10} {:>6}",
            name, address, balance, account_state, wallet_type, seqno,
        );
    }
    println!();
}

impl WalletImportCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(path).await?;

        if config.wallets.contains_key(&self.name) {
            anyhow::bail!("Wallet '{}' already exists in config", self.name);
        }

        // Decode and import private key into vault
        let private_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        )
        .context("Invalid base64 private key")?;

        let secret_name = format!("wallet-{}", self.name);
        let secret_id = secret_name.as_str().into();
        let metadata = secrets_vault::types::metadata::Metadata::new(
            Some(&secret_id),
            secrets_vault::types::algorithm::Algorithm::Ed25519,
            false,
        );
        let secret = secrets_vault::types::secret::Secret::from_raw_data(
            &private_key_bytes,
            metadata,
            AutoCryptoFactory {}.new_crypto()?,
        )
        .await?;
        vault
            .put(&secret, secrets_vault::types::store_mode::StoreMode::CreateOrReplace)
            .await?;
        vault.flush().await?;

        // Parse version
        let version: common::wallet_version::WalletVersion = self
            .version
            .parse()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                    self.version
                )
            })?;

        // Add wallet to config
        let wallet_config = common::app_config::WalletConfig {
            key: common::app_config::KeyConfig::VaultKey {
                name: secret_name.clone(),
            },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        config
            .wallets
            .insert(self.name.clone(), wallet_config.clone());
        super::utils::save_config(&config, path)?;

        // Calculate and display address
        let imported_secret = vault.get(&secret_id).await?;
        if let secrets_vault::types::secret::Secret::KeyPair { keypair } = &imported_secret {
            if let Some(pub_key) = keypair.public_key().await? {
                let address =
                    super::utils::calculate_wallet_address(&wallet_config, &pub_key)?;
                println!(
                    "\n{} Wallet '{}' imported\n",
                    "OK".green().bold(),
                    self.name
                );
                println!("  Address:  {}", address);
                println!("  Version:  {}", self.version);
                println!("  Key:      {} (in vault)", secret_name);
            }
        }
        println!();
        Ok(())
    }
}

impl WalletExportCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if !self.yes {
            println!(
                "{}",
                "WARNING: Exporting a private key is a security risk!"
                    .red()
                    .bold()
            );
            println!("The key will be displayed in plaintext. Make sure no one is watching.");
            if !confirm("Continue?")? {
                println!("{}", "Cancelled".yellow());
                return Ok(());
            }
        }

        let path = Path::new(config_path);
        let (config, vault) = super::utils::load_config_vault(path).await?;

        let wallet_cfg = config
            .wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", self.name))?;

        let secret = wallet_cfg.key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;

        let pub_key = keypair
            .public_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Public key not available"))?;

        let pvt_key_guard = keypair.private_key().await?;
        let pvt_key = pvt_key_guard.lock().await?;

        let address = super::utils::calculate_wallet_address(wallet_cfg, &pub_key)?;

        println!();
        println!(
            "{} Export for wallet '{}'",
            "OK".green().bold(),
            self.name
        );
        println!("{}", "\u{2500}".repeat(50).dimmed());
        println!(
            "  Address:     {}",
            address
        );
        println!(
            "  Public key:  {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &pub_key,
            )
        );
        println!(
            "  Private key: {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                pvt_key.as_ref(),
            )
        );
        println!();
        Ok(())
    }
}

impl WalletRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let mut config = common::app_config::AppConfig::load(path)?;

        if !config.wallets.contains_key(&self.name) {
            anyhow::bail!("Wallet '{}' not found", self.name);
        }

        // Check for bindings referencing this wallet
        for (node_name, binding) in &config.bindings {
            if binding.wallet == self.name {
                anyhow::bail!(
                    "Cannot remove wallet '{}': referenced by binding for node '{}'",
                    self.name,
                    node_name
                );
            }
        }

        if !self.yes {
            // Prompt for confirmation
            print!("Remove wallet '{}'? [y/N]: ", self.name);
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes") {
                println!("{}", "Cancelled".yellow());
                return Ok(());
            }
        }

        config.wallets.remove(&self.name);
        super::utils::save_config(&config, path)?;
        println!(
            "\n{} Wallet '{}' removed\n",
            "OK".green().bold(),
            self.name
        );
        Ok(())
    }
}

impl WalletSetVersionCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(path).await?;

        let wallet_cfg = config
            .wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", self.name))?;

        let old_version = wallet_cfg.version;

        let new_version: common::wallet_version::WalletVersion =
            self.version.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                    self.version
                )
            })?;

        if old_version == new_version {
            println!(
                "{} Wallet '{}' is already version {}",
                "OK".green().bold(),
                self.name,
                old_version
            );
            return Ok(());
        }

        // Compute old address
        let secret = wallet_cfg.key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let pub_key = keypair
            .public_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Public key not available"))?;

        let old_address = super::utils::calculate_wallet_address(wallet_cfg, &pub_key)?;

        // Update version in config
        let wallet_cfg_mut = config.wallets.get_mut(&self.name).unwrap();
        wallet_cfg_mut.version = new_version;

        // Compute new address
        let new_address =
            super::utils::calculate_wallet_address(wallet_cfg_mut, &pub_key)?;

        super::utils::save_config(&config, path)?;

        println!(
            "\n{} Wallet '{}' version changed: {} -> {}\n",
            "OK".green().bold(),
            self.name,
            old_version,
            new_version
        );
        println!("  Old address: {}", old_address);
        println!("  New address: {}", new_address);
        println!();
        Ok(())
    }
}

const WALLET_SEND_GAS: u64 = 1_000_000; // 0.001 TOS

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Build a comment cell: 32-bit zero prefix followed by UTF-8 bytes.
fn build_comment_cell(text: &str) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_u32(0)?; // 0x00000000 comment tag
    builder.append_raw(text.as_bytes(), text.len() * 8)?;
    Ok(builder.into_cell()?)
}

impl WalletSendCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = match (self.config_fd, self.config_format.as_deref()) {
            (Some(fd), Some(format)) => load_config_vault_rpc_client_fd(fd, format).await?,
            (None, None) => load_config_vault_rpc_client(config_path).await?,
            _ => anyhow::bail!("--config-fd and --config-format must be used together"),
        };

        let wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;

        let (from_wallet_address, from_wallet_info, from_secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

        let amount_nanotos = match (self.amount, self.amount_nanotos) {
            (Some(amount), None) => tos_to_nanotos(amount),
            (None, Some(amount)) if amount > 0 => amount,
            _ => anyhow::bail!("Exactly one positive amount is required"),
        };
        let amount_tos = amount_nanotos as f64 / 1_000_000_000.0;

        if !(1..=from_wallet_info.balance.saturating_sub(WALLET_SEND_GAS))
            .contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                amount_tos,
                display_tos(from_wallet_info.balance)
            );
        }

        let dest_addr = self.to.parse::<MsgAddressInt>().context("Invalid destination address")?;

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, from_secret, &self.from).await?;

        if from_wallet_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }

        if from_wallet_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        let body = if let Some(msg) = &self.message {
            build_comment_cell(msg)?
        } else {
            Cell::default()
        };

        println!(
            "\n{}\n  From:    {} ({})\n  To:      {}\n  Amount:  {:.9} TOS{}\n",
            "Transfer summary:".cyan().bold(),
            self.from,
            from_wallet_address,
            dest_addr,
            amount_tos,
            if let Some(msg) = &self.message {
                format!("\n  Comment: {}", msg)
            } else {
                String::new()
            },
        );

        if !self.yes && !confirm("Confirm transfer?")? {
            println!("{}", "Transfer cancelled".yellow());
            return Ok(());
        }

        let msg = wallet
            .build_message(
                dest_addr,
                amount_nanotos,
                body,
                false,
                None,
                None,
                None,
            )
            .await?;

        let msg_boc = write_boc(&msg)?;
        rpc_client.send_boc(&msg_boc).await?;

        wait_for_seqno_change(
            rpc_client.clone(),
            &from_wallet_address,
            from_wallet_info.seqno,
            &CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await?;

        println!("{} Transfer sent", "OK".green().bold());
        Ok(())
    }
}

#[cfg(test)]
mod wallet_send_cli_tests {
    use super::{WalletLsCmd, WalletSendCmd};
    use clap::{Args, Command, FromArgMatches};

    #[test]
    fn parses_exact_nanotos_and_yes() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        let matches = command
            .try_get_matches_from(["send", "--from", "anchor", "--to", "0:abc", "--amount-nanotos", "7", "--yes"])
            .expect("exact send flags must parse");
        let parsed = WalletSendCmd::from_arg_matches(&matches).expect("parsed send args");
        assert_eq!(parsed.amount_nanotos, Some(7));
        assert_eq!(parsed.amount, None);
        assert!(parsed.yes);
    }

    #[test]
    fn rejects_both_amount_forms() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        assert!(command.try_get_matches_from(["send", "--from", "anchor", "--to", "0:abc", "--amount", "1", "--amount-nanotos", "1"]).is_err());
    }

    #[test]
    fn parses_inherited_json_config_fd() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        let matches = command.try_get_matches_from(["send", "--from", "anchor", "--to", "0:abc", "--amount-nanotos", "1", "--config-fd", "3", "--config-format", "json"]).unwrap();
        let parsed = WalletSendCmd::from_arg_matches(&matches).unwrap();
        assert_eq!(parsed.config_fd, Some(3));
        assert_eq!(parsed.config_format.as_deref(), Some("json"));
    }

    #[test]
    fn parses_offline_wallet_listing() {
        let command = WalletLsCmd::augment_args(Command::new("ls"));
        let matches = command.try_get_matches_from(["ls", "--format", "json", "--offline"]).unwrap();
        let parsed = WalletLsCmd::from_arg_matches(&matches).unwrap();
        assert!(parsed.offline);
    }
}
