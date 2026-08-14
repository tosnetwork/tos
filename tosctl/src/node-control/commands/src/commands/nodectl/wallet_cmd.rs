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
    DEPLOY_TIMEOUT, SEND_TIMEOUT, check_chain_rpc_connection, get_wallet_config,
    load_config_vault_rpc_client, load_config_vault_rpc_client_fd, make_wallet, wait_for_deploy,
    wait_for_seqno_change, wallet_address, wallet_info, warn_chain_rpc_unavailable,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    ADDR_FORMAT_BOUNCE, ADDR_FORMAT_URL_SAFE, BuilderData, Cell, Deserializable, IBitstring,
    MsgAddressInt, Serializable, StateInit, ed25519_create_private_key, ed25519_verify,
    read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::AccountState;
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
use std::{
    borrow::Cow,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
    /// Generate a recoverable TOS mnemonic and its TVM identity
    MnemonicGenerate(WalletMnemonicGenerateCmd),
    /// Recover a TVM wallet from a TOS mnemonic
    MnemonicImport(WalletMnemonicImportCmd),
    /// Sign exact bytes with a configured wallet key
    Sign(WalletSignCmd),
    /// Verify an Ed25519 signature over exact bytes
    Verify(WalletVerifyCmd),
    /// Generate real test-only mnemonics, keys, addresses, and proof signatures
    TestFixture(WalletTestFixtureCmd),
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
#[command(about = "Generate a TOS mnemonic without modifying the wallet vault")]
pub struct WalletMnemonicGenerateCmd {
    #[arg(long, default_value = "24", help = "Mnemonic word count (12 or 24)")]
    words: usize,
    #[arg(short = 'v', long = "version", default_value = "V3R2")]
    version: String,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42")]
    subwallet_id: u32,
}

#[derive(clap::Args, Clone)]
#[command(about = "Recover a TVM wallet from a TOS mnemonic")]
pub struct WalletMnemonicImportCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
    #[arg(
        long,
        conflicts_with = "mnemonic_file",
        required_unless_present = "mnemonic_file",
        help = "12- or 24-word TOS mnemonic phrase (prefer --mnemonic-file to avoid shell history)"
    )]
    mnemonic: Option<String>,
    #[arg(
        long,
        conflicts_with = "mnemonic",
        required_unless_present = "mnemonic",
        help = "Read the mnemonic from a mode-0600 file"
    )]
    mnemonic_file: Option<PathBuf>,
    #[arg(short = 'v', long = "version", default_value = "V3R2")]
    version: String,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42")]
    subwallet_id: u32,
}

#[derive(clap::Args, Clone)]
pub struct ExactMessageArgs {
    #[arg(long, conflicts_with_all = ["message_hex", "message_file"])]
    message: Option<String>,
    #[arg(long, conflicts_with_all = ["message", "message_file"])]
    message_hex: Option<String>,
    #[arg(long, conflicts_with_all = ["message", "message_hex"])]
    message_file: Option<PathBuf>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Sign exact bytes with a configured Ed25519 wallet key")]
pub struct WalletSignCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
    #[command(flatten)]
    input: ExactMessageArgs,
}

#[derive(clap::Args, Clone)]
#[command(about = "Verify an Ed25519 signature over exact bytes")]
pub struct WalletVerifyCmd {
    #[arg(long, help = "32-byte Ed25519 public key in hex")]
    public_key: String,
    #[arg(long, help = "64-byte Ed25519 signature in hex")]
    signature: String,
    #[command(flatten)]
    input: ExactMessageArgs,
}

#[derive(clap::Args, Clone)]
#[command(about = "Generate a mode-0600 test-only identity fixture")]
pub struct WalletTestFixtureCmd {
    #[arg(long)]
    output: PathBuf,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "buyer,provider-controller,execution-signer,refund-authority,relay-fee-payer"
    )]
    roles: Vec<String>,
    #[arg(long, default_value = "24", help = "Mnemonic word count (12 or 24)")]
    words: usize,
    #[arg(short = 'v', long = "version", default_value = "V3R2")]
    version: String,
    #[arg(short = 'w', long = "workchain", default_value = "0")]
    workchain: i32,
    #[arg(short = 'i', long = "subwallet-id", default_value = "0")]
    subwallet_id: u32,
    #[arg(long, help = "Replace an existing regular output file")]
    force: bool,
    #[arg(long, help = "Acknowledge that the output contains plaintext test secrets")]
    unsafe_test_secrets: bool,
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
    #[arg(short = 'v', long = "version", help = "New wallet version (V1R3, V3R2, V4R2, V5R1)")]
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

    #[arg(long, conflicts_with = "message", help = "Exact message body BOC as standard base64")]
    body_boc: Option<String>,

    #[arg(long, help = "Optional StateInit cell BOC as standard base64")]
    state_init_boc: Option<String>,

    #[arg(long, help = "Confirm the transfer non-interactively")]
    yes: bool,

    #[arg(
        long,
        help = "Build and sign the exact external message, emit versioned JSON, and do not broadcast"
    )]
    build_only: bool,
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
            WalletAction::MnemonicGenerate(cmd) => cmd.run().await,
            WalletAction::MnemonicImport(cmd) => cmd.run(&self.config).await,
            WalletAction::Sign(cmd) => cmd.run(&self.config).await,
            WalletAction::Verify(cmd) => cmd.run().await,
            WalletAction::TestFixture(cmd) => cmd.run().await,
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
        let version: common::wallet_version::WalletVersion =
            self.version.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                    self.version
                )
            })?;

        // Add wallet to config
        let wallet_config = common::app_config::WalletConfig {
            key: common::app_config::KeyConfig::VaultKey { name: secret_name.clone() },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        config.wallets.insert(self.name.clone(), wallet_config.clone());
        super::utils::save_config(&config, path)?;

        // Calculate and display address
        let secret = vault.get(&secret_id).await?;
        if let secrets_vault::types::secret::Secret::KeyPair { keypair } = &secret {
            if let Some(pub_key) = keypair.public_key().await? {
                let address = super::utils::calculate_wallet_address(&wallet_config, &pub_key)?;
                println!("\n{} Wallet '{}' created\n", "OK".green().bold(), self.name);
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
            let msg = wallet.deploy_message(Self::MIN_BALANCE / 10, Cell::default()).await?;
            let boc = write_boc(&msg)?;
            rpc_client.send_boc(&boc).await?;

            wait_for_deploy(rpc_client.clone(), &address, &cancellation_ctx, true, DEPLOY_TIMEOUT)
                .await?;

            println!("{} Wallet '{}' ({}) activated", "OK".green().bold(), name, address);
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

        if !self.offline
            && let Err(e) = check_chain_rpc_connection(&rpc_client).await
        {
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
                    } else {
                        match rpc_client.get_wallet_information(&address).await {
                            Ok(info) => (
                                Some(address_str),
                                Some(info.account_state.to_string()),
                                Some(display_tos(info.balance)),
                                info.wallet_type.map(|t| t.to_string()),
                                info.seqno,
                            ),
                            Err(_) => (Some(address_str), None, None, None, None),
                        }
                    }
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
    println!("\n{} {} ({})\n", "OK".green().bold(), "Wallets:".green(), wallets.len());
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
                        (
                            address_str.white(),
                            red_dash.clone(),
                            red_dash.clone(),
                            red_dash.clone(),
                            red_dash.clone(),
                        )
                    } else {
                        match rpc_client.get_wallet_information(&addr).await {
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
                        }
                    }
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
        let private_key_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.private_key)
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
        vault.put(&secret, secrets_vault::types::store_mode::StoreMode::CreateOrReplace).await?;
        vault.flush().await?;

        // Parse version
        let version: common::wallet_version::WalletVersion =
            self.version.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                    self.version
                )
            })?;

        // Add wallet to config
        let wallet_config = common::app_config::WalletConfig {
            key: common::app_config::KeyConfig::VaultKey { name: secret_name.clone() },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        config.wallets.insert(self.name.clone(), wallet_config.clone());
        super::utils::save_config(&config, path)?;

        // Calculate and display address
        let imported_secret = vault.get(&secret_id).await?;
        if let secrets_vault::types::secret::Secret::KeyPair { keypair } = &imported_secret {
            if let Some(pub_key) = keypair.public_key().await? {
                let address = super::utils::calculate_wallet_address(&wallet_config, &pub_key)?;
                println!("\n{} Wallet '{}' imported\n", "OK".green().bold(), self.name);
                println!("  Address:  {}", address);
                println!("  Version:  {}", self.version);
                println!("  Key:      {} (in vault)", secret_name);
            }
        }
        println!();
        Ok(())
    }
}

fn parse_wallet_identity(
    version: &str,
    workchain: i32,
    subwallet_id: u32,
) -> anyhow::Result<WalletConfig> {
    let version = version.parse().map_err(|_| {
        anyhow::anyhow!("Invalid wallet version '{version}'. Use V1R3, V3R2, V4R2, or V5R1")
    })?;
    Ok(WalletConfig {
        key: common::app_config::KeyConfig::PublicKey { type_id: 0, pub_key: Vec::new() },
        version,
        subwallet_id,
        workchain,
    })
}

fn friendly_address(wallet: &WalletConfig, public_key: &[u8]) -> anyhow::Result<String> {
    let address = super::utils::calculate_wallet_address(wallet, public_key)?;
    address
        .to_string_custom(ADDR_FORMAT_BOUNCE | ADDR_FORMAT_URL_SAFE)
        .context("format TVM wallet address")
}

impl WalletMnemonicGenerateCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let words = super::tos_mnemonic::generate(self.words)?;
        let phrase = words.join(" ");
        let mut seed = super::tos_mnemonic::private_seed(&phrase, "")?;
        let key = ed25519_create_private_key(&seed)?;
        let public_key = key.verifying_key();
        let wallet = parse_wallet_identity(&self.version, self.workchain, self.subwallet_id)?;
        let output = serde_json::json!({
            "schema": "tosctl-mnemonic-v1",
            "warning": "SECRET: store this mnemonic offline; never use it across algorithms or environments",
            "mnemonic": phrase,
            "public_key_hex": hex::encode(public_key),
            "address": friendly_address(&wallet, &public_key)?,
            "wallet_version": self.version,
            "workchain": self.workchain,
            "subwallet_id": self.subwallet_id,
        });
        seed.zeroize();
        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

impl WalletMnemonicImportCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let mut phrase = match (&self.mnemonic, &self.mnemonic_file) {
            (Some(phrase), None) => phrase.clone(),
            (None, Some(path)) => std::fs::read_to_string(path)
                .with_context(|| format!("read mnemonic file {}", path.display()))?,
            _ => anyhow::bail!("Provide exactly one of --mnemonic or --mnemonic-file"),
        };
        let mut seed = super::tos_mnemonic::private_seed(phrase.trim(), "")?;
        phrase.zeroize();
        let path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(path).await?;
        if config.wallets.contains_key(&self.name) {
            seed.zeroize();
            anyhow::bail!("Wallet '{}' already exists in config", self.name);
        }

        let secret_name = format!("wallet-{}", self.name);
        let secret_id = secret_name.as_str().into();
        let metadata = secrets_vault::types::metadata::Metadata::new(
            Some(&secret_id),
            secrets_vault::types::algorithm::Algorithm::Ed25519,
            false,
        );
        let secret = secrets_vault::types::secret::Secret::from_raw_data(
            &seed,
            metadata,
            AutoCryptoFactory {}.new_crypto()?,
        )
        .await?;
        seed.zeroize();
        vault.put(&secret, secrets_vault::types::store_mode::StoreMode::CreateOrReplace).await?;
        vault.flush().await?;

        let mut wallet = parse_wallet_identity(&self.version, self.workchain, self.subwallet_id)?;
        wallet.key = common::app_config::KeyConfig::VaultKey { name: secret_name.clone() };
        config.wallets.insert(self.name.clone(), wallet.clone());
        super::utils::save_config(&config, path)?;

        let public_key = secret
            .as_keypair()?
            .public_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Public key not available"))?;
        println!(
            "{} Wallet '{}' recovered at {}",
            "OK".green().bold(),
            self.name,
            friendly_address(&wallet, &public_key)?
        );
        Ok(())
    }
}

fn exact_message(input: &ExactMessageArgs) -> anyhow::Result<Vec<u8>> {
    match (&input.message, &input.message_hex, &input.message_file) {
        (Some(value), None, None) => Ok(value.as_bytes().to_vec()),
        (None, Some(value), None) => hex::decode(value).context("decode --message-hex"),
        (None, None, Some(path)) => {
            std::fs::read(path).with_context(|| format!("read message file {}", path.display()))
        }
        (None, None, None) => {
            anyhow::bail!("Provide exactly one of --message, --message-hex, or --message-file")
        }
        _ => anyhow::bail!("Message inputs are mutually exclusive"),
    }
}

impl WalletSignCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let message = exact_message(&self.input)?;
        let (config, vault) = super::utils::load_config_vault(Path::new(config_path)).await?;
        let wallet = config
            .wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", self.name))?;
        let secret = wallet.key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let public_key = keypair
            .public_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Public key not available"))?;
        let signature = keypair.sign(&message).await?;
        let output = serde_json::json!({
            "schema": "tosctl-ed25519-signature-v1",
            "algorithm": "Ed25519",
            "wallet": self.name,
            "address": friendly_address(wallet, &public_key)?,
            "public_key_hex": hex::encode(public_key),
            "message_hex": hex::encode(&message),
            "signature_hex": hex::encode(signature),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

impl WalletVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let message = exact_message(&self.input)?;
        let public_key = hex::decode(&self.public_key).context("decode --public-key")?;
        let signature = hex::decode(&self.signature).context("decode --signature")?;
        ed25519_verify(&public_key, &message, &signature)
            .context("signature verification failed")?;
        println!("{} Signature is valid", "OK".green().bold());
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct TestIdentity {
    role: String,
    mnemonic: String,
    private_seed_hex: String,
    public_key_hex: String,
    address: String,
    proof_message_hex: String,
    proof_signature_hex: String,
}

#[derive(serde::Serialize)]
struct TestIdentityFixture {
    schema: &'static str,
    test_only: bool,
    warning: &'static str,
    algorithm: &'static str,
    derivation: &'static str,
    wallet_version: String,
    workchain: i32,
    subwallet_id: u32,
    identities: Vec<TestIdentity>,
}

impl WalletTestFixtureCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        if !self.unsafe_test_secrets {
            anyhow::bail!("Refusing to write plaintext secrets without --unsafe-test-secrets");
        }
        if self.roles.is_empty() {
            anyhow::bail!("At least one role is required");
        }
        let mut unique = std::collections::HashSet::new();
        for role in &self.roles {
            if role.is_empty()
                || !role.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                anyhow::bail!("Invalid role '{role}'; use ASCII letters, numbers, '-' or '_'");
            }
            if !unique.insert(role) {
                anyhow::bail!("Duplicate role '{role}'");
            }
        }
        if self.output.exists() && !self.force {
            anyhow::bail!("{} already exists; use --force to replace it", self.output.display());
        }
        if let Ok(metadata) = std::fs::symlink_metadata(&self.output)
            && !metadata.file_type().is_file()
        {
            anyhow::bail!(
                "Refusing to replace symlink or non-regular path {}",
                self.output.display()
            );
        }

        let wallet = parse_wallet_identity(&self.version, self.workchain, self.subwallet_id)?;
        let mut identities = Vec::with_capacity(self.roles.len());
        for role in &self.roles {
            let words = super::tos_mnemonic::generate(self.words)?;
            let mnemonic = words.join(" ");
            let mut seed = super::tos_mnemonic::private_seed(&mnemonic, "")?;
            let key = ed25519_create_private_key(&seed)?;
            let public_key = key.verifying_key();
            let proof_message = format!("ATOS_TEST_IDENTITY_V1:{role}").into_bytes();
            let proof_signature = key.sign(&proof_message);
            identities.push(TestIdentity {
                role: role.clone(),
                mnemonic,
                private_seed_hex: hex::encode(seed),
                public_key_hex: hex::encode(public_key),
                address: friendly_address(&wallet, &public_key)?,
                proof_message_hex: hex::encode(proof_message),
                proof_signature_hex: hex::encode(proof_signature),
            });
            seed.zeroize();
        }
        let fixture = TestIdentityFixture {
            schema: "atos-test-identities-v1",
            test_only: true,
            warning: "PLAINTEXT TEST SECRETS: never fund or use these identities outside disposable test networks",
            algorithm: "Ed25519",
            derivation: "TOS mnemonic PBKDF2-HMAC-SHA512 (TOS default seed)",
            wallet_version: self.version.clone(),
            workchain: self.workchain,
            subwallet_id: self.subwallet_id,
            identities,
        };
        let encoded = serde_json::to_vec_pretty(&fixture)?;

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(self.force).create_new(!self.force);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&self.output)
            .with_context(|| format!("create {}", self.output.display()))?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        #[cfg(unix)]
        std::fs::set_permissions(&self.output, std::fs::Permissions::from_mode(0o600))?;

        println!(
            "{} Wrote {} test identities to {} (mode 0600)",
            "OK".green().bold(),
            self.roles.len(),
            self.output.display()
        );
        Ok(())
    }
}

impl WalletExportCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if !self.yes {
            println!("{}", "WARNING: Exporting a private key is a security risk!".red().bold());
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
        println!("{} Export for wallet '{}'", "OK".green().bold(), self.name);
        println!("{}", "\u{2500}".repeat(50).dimmed());
        println!("  Address:     {}", address);
        println!(
            "  Public key:  {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pub_key,)
        );
        println!(
            "  Private key: {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pvt_key.as_ref(),)
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
        println!("\n{} Wallet '{}' removed\n", "OK".green().bold(), self.name);
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
        let new_address = super::utils::calculate_wallet_address(wallet_cfg_mut, &pub_key)?;

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

        if !(1..=from_wallet_info.balance.saturating_sub(WALLET_SEND_GAS)).contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                amount_tos,
                display_tos(from_wallet_info.balance)
            );
        }

        let dest_addr = self.to.parse::<MsgAddressInt>().context("Invalid destination address")?;
        let destination_text = dest_addr.to_string();

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, from_secret, &self.from).await?;

        if from_wallet_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }

        if from_wallet_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        let body = match (&self.message, &self.body_boc) {
            (Some(msg), None) => build_comment_cell(msg)?,
            (None, Some(encoded)) => {
                read_single_root_boc(base64::engine::general_purpose::STANDARD.decode(encoded)?)?
            }
            (None, None) => Cell::default(),
            _ => anyhow::bail!("--message and --body-boc are mutually exclusive"),
        };
        let state_init = self
            .state_init_boc
            .as_ref()
            .map(|encoded| -> anyhow::Result<StateInit> {
                let root = read_single_root_boc(
                    base64::engine::general_purpose::STANDARD.decode(encoded)?,
                )?;
                Ok(StateInit::construct_from_cell(root)?)
            })
            .transpose()?;
        let body_hash = format!("tvm-cell-sha256:{:x}", body.repr_hash());
        let state_init_hash = state_init
            .as_ref()
            .map(|value| -> anyhow::Result<String> {
                let cell = value.write_to_new_cell()?.into_cell()?;
                Ok(format!("tvm-cell-sha256:{:x}", cell.repr_hash()))
            })
            .transpose()?
            .unwrap_or_default();

        if !self.build_only {
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
        }

        let msg = wallet
            .build_message(dest_addr, amount_nanotos, body, false, None, None, state_init)
            .await?;

        let msg_boc = write_boc(&msg)?;
        if self.build_only {
            println!(
                "{}",
                serde_json::json!({
                    "version": "tosctl.wallet-prepared-send.v1",
                    "message_boc_base64": base64::engine::general_purpose::STANDARD.encode(&msg_boc),
                    "wallet": self.from,
                    "payer": from_wallet_address.to_string(),
                    "destination": destination_text,
                    "amount_nanotos": amount_nanotos,
                    "body_hash": body_hash,
                    "state_init_hash": state_init_hash,
                })
            );
            return Ok(());
        }
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
            .try_get_matches_from([
                "send",
                "--from",
                "anchor",
                "--to",
                "0:abc",
                "--amount-nanotos",
                "7",
                "--yes",
            ])
            .expect("exact send flags must parse");
        let parsed = WalletSendCmd::from_arg_matches(&matches).expect("parsed send args");
        assert_eq!(parsed.amount_nanotos, Some(7));
        assert_eq!(parsed.amount, None);
        assert!(parsed.yes);
        assert!(!parsed.build_only);
    }

    #[test]
    fn parses_build_only_contract_send() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        let matches = command
            .try_get_matches_from([
                "send",
                "--from",
                "anchor",
                "--to",
                "0:abc",
                "--amount-nanotos",
                "7",
                "--body-boc",
                "te6ccgEBAQEAAgAAAA==",
                "--state-init-boc",
                "te6ccgEBAQEAAgAAAA==",
                "--build-only",
            ])
            .expect("build-only contract send flags must parse");
        let parsed = WalletSendCmd::from_arg_matches(&matches).expect("parsed send args");
        assert!(parsed.build_only);
        assert!(!parsed.yes);
    }

    #[test]
    fn rejects_both_amount_forms() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        assert!(
            command
                .try_get_matches_from([
                    "send",
                    "--from",
                    "anchor",
                    "--to",
                    "0:abc",
                    "--amount",
                    "1",
                    "--amount-nanotos",
                    "1"
                ])
                .is_err()
        );
    }

    #[test]
    fn parses_inherited_json_config_fd() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        let matches = command
            .try_get_matches_from([
                "send",
                "--from",
                "anchor",
                "--to",
                "0:abc",
                "--amount-nanotos",
                "1",
                "--config-fd",
                "3",
                "--config-format",
                "json",
            ])
            .unwrap();
        let parsed = WalletSendCmd::from_arg_matches(&matches).unwrap();
        assert_eq!(parsed.config_fd, Some(3));
        assert_eq!(parsed.config_format.as_deref(), Some("json"));
    }

    #[test]
    fn parses_exact_contract_cell_send() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        let matches = command
            .try_get_matches_from([
                "send",
                "--from",
                "payer",
                "--to",
                "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--amount-nanotos",
                "300000000",
                "--body-boc",
                "te6ccgEBAQEAAgAAAA==",
                "--state-init-boc",
                "te6ccgEBAQEAAgAAAA==",
                "--yes",
            ])
            .unwrap();
        let parsed = WalletSendCmd::from_arg_matches(&matches).unwrap();
        assert!(parsed.body_boc.is_some());
        assert!(parsed.state_init_boc.is_some());
        assert!(parsed.yes);
    }

    #[test]
    fn rejects_comment_with_contract_body() {
        let command = WalletSendCmd::augment_args(Command::new("send"));
        assert!(
            command
                .try_get_matches_from([
                    "send",
                    "--from",
                    "payer",
                    "--to",
                    "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--amount-nanotos",
                    "1",
                    "--message",
                    "x",
                    "--body-boc",
                    "AA==",
                ])
                .is_err()
        );
    }

    #[test]
    fn parses_offline_wallet_listing() {
        let command = WalletLsCmd::augment_args(Command::new("ls"));
        let matches =
            command.try_get_matches_from(["ls", "--format", "json", "--offline"]).unwrap();
        let parsed = WalletLsCmd::from_arg_matches(&matches).unwrap();
        assert!(parsed.offline);
    }
}
