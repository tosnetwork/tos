/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::nodectl::{
    output_format::OutputFormat,
    utils::{
        SEND_TIMEOUT, check_chain_rpc_connection, get_wallet_config, load_config_vault,
        load_config_vault_rpc_client, make_wallet, save_config, wait_for_seqno_change,
        wallet_address, wallet_info, warn_chain_rpc_unavailable, warn_missing_secret,
    },
};
use anyhow::Context;
use chain_block::{ADDR_FORMAT_BOUNCE, ADDR_FORMAT_URL_SAFE, Cell, MsgAddressInt, write_boc};
use chain_rpc_client::v2::{client_json_rpc::ClientJsonRpc, data_models::AccountState};
use colored::Colorize;
use common::{
    WalletVersion,
    app_config::{AppConfig, KeyConfig, PoolConfig, WalletConfig},
    chain_utils::{display_tos, tos_to_nanotos},
    task_cancellation::CancellationCtx,
    time_format,
};
use contracts::{
    DefaultChainProvider, ElectorWrapperImpl, NominatorWrapper, NominatorWrapperImpl,
    SmartContract, Wallet, contract_provider, nominator, nominator::NominatorRoles,
};
use elections::providers::{DefaultElectionsProvider, ElectionsProvider};
use secrets_vault::{errors::error::VaultError, vault::SecretVault};
use std::{borrow::Cow, io::Write, path::Path, sync::Arc};

const WALLET_SEND_GAS: u64 = 1_000_000; // 0.001 TOS
/// Value in nanotos required by elector to execute stake operations.
const ELECTOR_STAKE_FEE: u64 = 1_000_000_000;
/// Gas fee consumed by nominator pool.
const NPOOL_COMPUTE_FEE: u64 = 200_000_000;
/// Gas fee consumed by wallet to send message to nominator pool.
const WALLET_COMPUTE_FEE: u64 = 100_000_000;

#[derive(clap::Args, Clone)]
#[command(about = "Manage wallets in the configuration")]
pub struct WalletCmd {
    #[command(subcommand)]
    action: WalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum WalletAction {
    /// Add a wallet to the configuration
    Add(WalletAddCmd),
    /// List all configured wallets
    Ls(WalletLsCmd),
    /// Remove a wallet from the configuration
    Rm(WalletRmCmd),
    /// Send coins
    Send(WalletSendCmd),
    /// Send election stake from the wallet, or through its bound pool
    Stake(WalletStakeCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Add a wallet to the configuration")]
pub struct WalletAddCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name (unique identifier)")]
    name: String,
    #[arg(short = 's', long = "secret-name", help = "Vault secret name for wallet key")]
    secret_name: String,
    #[arg(
        short = 'v',
        long = "version",
        help = "Wallet version, required (case insensitive) [possible values: V1R3, V3R2, V4R2, V5R1; V3R2 only for bootstrap and operating keys]"
    )]
    version: WalletVersion,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42", help = "Subwallet ID")]
    subwallet_id: u32,
    #[arg(
        short = 'w',
        long = "workchain",
        allow_negative_numbers = true,
        default_value = "-1",
        help = "Workchain ID"
    )]
    workchain: i32,
}

#[derive(clap::Args, Clone)]
#[command(about = "List all configured wallets")]
pub struct WalletLsCmd {
    #[arg(long = "format", default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a wallet from the configuration")]
pub struct WalletRmCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send TOS")]
pub struct WalletSendCmd {
    #[arg(short = 'f', long = "from", help = "Wallet name")]
    from: String,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, short = 't', long = "to", help = "Destination address")]
    to: String,
    #[arg(short = 'a', long = "amount", help = "Amount in coins")]
    amount: f64,
    #[arg(
        short = 'b',
        long = "bounce",
        help = "Bounce transfer to the sender if recipient fails to process it"
    )]
    bounce: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send election stake from the wallet, or through its bound pool")]
pub struct WalletStakeCmd {
    #[arg(short = 'b', long = "binding", help = "Binding name")]
    binding: String,
    #[arg(short = 'a', long = "amount", help = "Stake amount in coins")]
    amount: f64,
    #[arg(short = 'm', long = "max-factor", default_value = "3.0", help = "Max factor (1.0..3.0)")]
    max_factor: f32,
}

impl WalletCmd {
    pub async fn run(&self, path: &Path, cancellation_ctx: CancellationCtx) -> anyhow::Result<()> {
        match &self.action {
            WalletAction::Add(cmd) => cmd.run(path).await,
            WalletAction::Ls(cmd) => cmd.run(path).await,
            WalletAction::Rm(cmd) => cmd.run(path).await,
            WalletAction::Send(cmd) => cmd.run(path, cancellation_ctx).await,
            WalletAction::Stake(cmd) => cmd.run(path, cancellation_ctx).await,
        }
    }
}

impl WalletAddCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        if self.name == "master_wallet" {
            anyhow::bail!("'master_wallet' is a reserved name");
        }

        let (config, vault) = load_config_vault(path).await?;

        if config.wallets.contains_key(&self.name) {
            anyhow::bail!(
                "Wallet '{}' already exists. Remove it first or use a different name.",
                self.name
            );
        }

        let wallet_config = WalletConfig {
            key: KeyConfig::VaultKey { name: self.secret_name.clone() },
            version: self.version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };

        let secret_id = self.secret_name.as_str().into();

        if !vault.exists(&secret_id).await? {
            warn_missing_secret(&self.secret_name);
        }

        let mut config = config.clone();
        config.wallets.insert(self.name.clone(), wallet_config);
        save_config(&config, path)?;

        println!("\n{} Wallet '{}' added\n", "OK".green().bold(), self.name);
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct WalletView {
    name: String,
    secret: String,
    version: String,
    state: Option<String>,
    balance: Option<String>,
    address: Option<String>,
}

impl WalletLsCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;

        if let Err(e) = check_chain_rpc_connection(&rpc_client).await {
            if matches!(self.format, OutputFormat::Table) {
                warn_chain_rpc_unavailable(&e, "State and balances will not be available");
            }
        }

        let mut all_wallets: Vec<(&str, &WalletConfig)> =
            config.wallets.iter().map(|(k, v)| (k.as_str(), v)).collect();
        if let Some(mw) = config.master_wallet.as_ref() {
            all_wallets.push(("master_wallet", mw));
        }

        if all_wallets.is_empty() {
            match self.format {
                OutputFormat::Json => println!("[]"),
                OutputFormat::Table => println!("\n{}\n", "No wallets configured".yellow()),
            }
            return Ok(());
        }

        match self.format {
            OutputFormat::Json => {
                print_wallets_json(all_wallets, vault, rpc_client).await?;
            }
            OutputFormat::Table => {
                print_wallets_table(all_wallets, vault, rpc_client).await;
            }
        }
        Ok(())
    }
}

async fn print_wallets_json(
    wallets: Vec<(&str, &WalletConfig)>,
    vault: Arc<SecretVault>,
    rpc_client: Arc<ClientJsonRpc>,
) -> anyhow::Result<()> {
    let mut views = Vec::new();
    for (name, wallet_cfg) in wallets {
        let secret = match &wallet_cfg.key {
            KeyConfig::VaultKey { name } => name.clone(),
            _ => "-".to_string(),
        };
        let (address, state, balance) = match wallet_address(wallet_cfg, vault.clone()).await {
            Ok((address, _)) => {
                let address_str = address
                    .to_string_custom(ADDR_FORMAT_BOUNCE | ADDR_FORMAT_URL_SAFE)
                    .unwrap_or_else(|_| address.to_string());
                match rpc_client.get_wallet_information(&address).await {
                    Ok(info) => (
                        Some(address_str),
                        Some(info.account_state.to_string()),
                        Some(display_tos(info.balance)),
                    ),
                    Err(_) => (Some(address_str), None, None),
                }
            }
            Err(_) => (None, None, None),
        };
        views.push(WalletView {
            name: name.to_string(),
            secret,
            version: wallet_cfg.version.to_string(),
            state,
            balance,
            address,
        });
    }
    println!("{}", serde_json::to_string_pretty(&views)?);
    Ok(())
}

async fn print_wallets_table(
    wallets: Vec<(&str, &WalletConfig)>,
    vault: Arc<SecretVault>,
    rpc_client: Arc<ClientJsonRpc>,
) {
    println!("\n{} {} ({})\n", "OK".green().bold(), "Wallets:".green(), wallets.len());
    println!(
        "  {:<20} {:<22} {:<8} {:<9} {:<14} {}",
        "Name".cyan().bold(),
        "Secret".cyan().bold(),
        "Version".cyan().bold(),
        "State".cyan().bold(),
        "Balance".cyan().bold(),
        "Address".cyan().bold(),
    );
    println!("  {}", "─".repeat(125).dimmed());

    let red_dash = Cow::Borrowed(&"-".red());
    for (name, wallet_cfg) in wallets {
        let (address, account_state, balance) =
            match wallet_address(wallet_cfg, vault.clone()).await {
                Ok((address, _)) => {
                    let address_str = address
                        .to_string_custom(ADDR_FORMAT_BOUNCE | ADDR_FORMAT_URL_SAFE)
                        .unwrap_or_else(|_| address.to_string());

                    match rpc_client.get_wallet_information(&address).await {
                        Ok(info) => (
                            address_str.white(),
                            Cow::Owned(info.account_state.to_string().white()),
                            Cow::Owned(display_tos(info.balance).white()),
                        ),
                        Err(_) => (address_str.white(), red_dash.clone(), red_dash.clone()),
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
                    (error_message, red_dash.clone(), red_dash.clone())
                }
            };

        let secret_name = match &wallet_cfg.key {
            KeyConfig::VaultKey { name } => Cow::Owned(name.white()),
            _ => red_dash.clone(),
        };
        println!(
            "  {:<20} {:<22} {:<8} {:<9} {:<14} {}",
            name,
            secret_name,
            wallet_cfg.version.to_string(),
            account_state,
            balance,
            address,
        );
    }
    println!();
}

impl WalletRmCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;

        if !config.wallets.contains_key(&self.name) {
            anyhow::bail!("Wallet '{}' not found in configuration", self.name);
        }

        for (node_name, binding) in &config.bindings {
            if binding.wallet == self.name {
                anyhow::bail!(
                    "Cannot remove wallet '{}': referenced by binding for node '{}'",
                    self.name,
                    node_name
                );
            }
        }

        config.wallets.remove(&self.name);
        save_config(&config, path)?;

        println!("\n{} Wallet '{}' removed\n", "OK".green().bold(), self.name);
        Ok(())
    }
}

impl WalletSendCmd {
    pub async fn run(&self, path: &Path, cancellation_ctx: CancellationCtx) -> anyhow::Result<()> {
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;

        let from_wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;

        let (from_wallet_address, from_wallet_info, from_secret) =
            wallet_info(rpc_client.clone(), from_wallet_cfg, vault.clone()).await?;

        if !(1..=from_wallet_info.balance.saturating_sub(WALLET_SEND_GAS))
            .contains(&tos_to_nanotos(self.amount))
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                self.amount,
                display_tos(from_wallet_info.balance)
            )
        }

        let to_wallet_address =
            self.to.parse::<MsgAddressInt>().context("Invalid destination address")?;

        let from_wallet =
            make_wallet(rpc_client.clone(), from_wallet_cfg, from_secret, &self.from).await?;

        if from_wallet_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }

        if from_wallet_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        println!(
            "\n{}\n  From:   {} ({})\n  To:     {}\n  Amount: {:.9} TOS\n  Bounce: {}\n",
            "Transfer summary:".cyan().bold(),
            self.from,
            from_wallet_address,
            to_wallet_address,
            self.amount,
            self.bounce,
        );

        if !confirm("Confirm transfer?")? {
            println!("{}", "Transfer cancelled".yellow());
            return Ok(());
        }

        let msg = from_wallet
            .build_message(
                to_wallet_address,
                tos_to_nanotos(self.amount),
                Cell::default(),
                self.bounce,
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
            &cancellation_ctx,
            SEND_TIMEOUT,
        )
        .await?;

        println!("{} Transfer complete", "OK".green().bold());
        Ok(())
    }
}

impl WalletStakeCmd {
    pub async fn run(&self, path: &Path, cancellation_ctx: CancellationCtx) -> anyhow::Result<()> {
        if !(1.0..=3.0).contains(&self.max_factor) {
            anyhow::bail!("max-factor must be between 1.0 and 3.0");
        }

        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;

        // Resolve binding → wallet, optional pool, node
        let binding = config
            .bindings
            .get(&self.binding)
            .ok_or_else(|| anyhow::anyhow!("Binding '{}' not found", self.binding))?;

        let wallet_cfg =
            get_wallet_config(&binding.wallet, &config.wallets, config.master_wallet.as_ref())?;

        let pool_cfg = match binding.pool.as_ref() {
            Some(pool_name) => Some(
                config
                    .pools
                    .get(pool_name)
                    .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found", pool_name))?,
            ),
            None => None,
        };

        let adnl_cfg = config
            .nodes
            .get(&self.binding)
            .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", self.binding))?;

        let (wallet_address, wallet_info_res, wallet_secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;
        if wallet_info_res.account_state != AccountState::Active {
            anyhow::bail!("Wallet '{}' is {}", binding.wallet, wallet_info_res.account_state);
        }
        let initial_seqno =
            require_observable_wallet_seqno(wallet_info_res.wallet, wallet_info_res.seqno)?;

        // With a pool, the pool sends the stake and the elector names the member by
        // the pool; without one, the wallet stakes and is named itself.
        let pool_address = match pool_cfg {
            Some(pool_cfg) => {
                let pool_address = resolve_pool_address(pool_cfg, &wallet_address)?;
                let live_pool = NominatorWrapperImpl::new(
                    contract_provider!(rpc_client.clone()),
                    pool_address.clone(),
                );
                let live_roles =
                    live_pool.get_roles().await.context("read live single-nominator pool roles")?;
                verify_live_pool_roles(&wallet_address, &live_roles)?;
                Some(pool_address)
            }
            None => None,
        };
        let elector_address =
            ElectorWrapperImpl::new(contract_provider!(rpc_client.clone())).address();

        // Connect to validator node via control protocol
        let adnl_client_cfg = adnl_cfg
            .to_node_adnl_config(Some(vault.clone()))
            .await
            .context("ADNL client config")?;
        let mut provider = DefaultElectionsProvider::new(
            adnl_client_cfg,
            Arc::new(DefaultChainProvider::new(rpc_client.clone())),
        );

        let elections_info = stake_elections_info(&mut provider).await?;
        let election_id = elections_info.election_id;
        if election_id == 0 {
            anyhow::bail!("No active elections");
        }
        if elections_info.finished {
            anyhow::bail!("Elections are already finished");
        }
        let stake_at = u32::try_from(election_id).context("election id does not fit u32")?;

        let stake_nanotos = tos_to_nanotos(self.amount);
        anyhow::ensure!(stake_nanotos > 0, "stake amount must be positive");
        if stake_nanotos < elections_info.min_stake {
            anyhow::bail!(
                "Stake {:.4} TOS is below minimum {:.4} TOS",
                self.amount,
                elections_info.min_stake as f64 / 1_000_000_000.0
            );
        }
        let route = StakeRoute::new(
            pool_address.as_ref(),
            &elector_address,
            &wallet_address,
            stake_nanotos,
        )?;
        let required =
            route.send_value.checked_add(WALLET_COMPUTE_FEE).context("stake value overflow")?;
        if wallet_info_res.balance < required {
            anyhow::bail!(
                "Insufficient wallet balance: required {:.4} TOS, available {:.4} TOS",
                required as f64 / 1_000_000_000.0,
                display_tos(wallet_info_res.balance)
            );
        }

        // Get election parameters for key expiration
        let cfg15 = provider.election_parameters().await.context("election_parameters")?;
        let key_expired_at =
            elections::pending_registration_until(election_id, common::time_format::now(), &cfg15)?;

        // Find or generate validator key
        let validator_config = provider.validator_config().await.context("validator_config")?;
        let existing_key = validator_config.find(election_id);

        let (_key_id, _pub_key, adnl_addr) = match existing_key {
            Some(entry) => {
                let pub_key =
                    provider.export_public_key(&entry.key_id).await.context("export_public_key")?;
                let adnl_addr = entry
                    .adnl_addr()
                    .ok_or_else(|| anyhow::anyhow!("Validator key has no ADNL address"))?;
                let until = key_expired_at
                    .max(entry.expired_at)
                    .max(entry.adnl_addrs.iter().map(|(_, expiry)| *expiry).max().unwrap_or(0));
                if entry.expired_at < key_expired_at
                    || entry.adnl_addrs.iter().any(|(_, expiry)| *expiry < key_expired_at)
                {
                    provider
                        .retain_validator_registration(
                            election_id,
                            &entry.key_id,
                            &adnl_addr,
                            until,
                        )
                        .await
                        .context("retain existing election registration")?;
                }
                println!(
                    "{} Reusing existing validator key for election {}: {}",
                    "Info:".cyan().bold(),
                    election_id,
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pub_key)
                );
                (entry.key_id, pub_key, adnl_addr)
            }
            None => {
                println!(
                    "\n{} No validator key found for election {}",
                    "Warning:".yellow().bold(),
                    election_id
                );
                if !confirm("Generate new validator key?")? {
                    anyhow::bail!("Aborted: no validator key for this election");
                }
                let (key_id, pub_key) = provider
                    .new_validator_key(election_id, key_expired_at)
                    .await
                    .context("new_validator_key")?;
                let adnl_addr = provider
                    .new_adnl_addr(key_id.clone(), key_expired_at)
                    .await
                    .context("new_adnl_addr")?;
                println!(
                    "{} Generated validator key: {}\n{} Generated ADNL address: {}",
                    "Info:".cyan().bold(),
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pub_key),
                    "Info:".cyan().bold(),
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &adnl_addr),
                );
                (key_id, pub_key, adnl_addr)
            }
        };

        // The node's custodied PQ signer authorizes the stake for the staking
        // account; the operator never signs an election preimage through the
        // generic Ed25519 keyring.
        let max_factor_raw = (self.max_factor * 65536.0) as u32;
        let authorization = provider
            .create_pq_stake_authorization(
                stake_at,
                max_factor_raw,
                &adnl_addr,
                &route.staking_account_id,
            )
            .await
            .context("create PQ stake authorization")?;
        // The elector names each member by the account its stake came from.
        if let Some(p) =
            elections_info.participants.iter().find(|p| p.wallet_addr == route.staking_account_id)
        {
            println!(
                "\n{} Already participating with stake {:.4} TOS",
                "Warning:".yellow().bold(),
                p.stake as f64 / 1_000_000_000.0
            );
        }

        // Confirmation
        println!(
            "\n{}\n  Binding:     {}\n  Wallet:      {} ({})\n  Staking via: {}\n  Send to:     {}\n  Election ID: {} ({})\n  Stake:       {:.9} TOS\n  Max Factor:  {:.2}\n  Min Stake:   {:.4} TOS\n",
            "Stake summary:".cyan().bold(),
            self.binding,
            binding.wallet,
            wallet_address,
            if route.pooled { "single-nominator pool" } else { "wallet" },
            route.destination,
            election_id,
            time_format::format_ts(election_id),
            self.amount,
            self.max_factor,
            elections_info.min_stake as f64 / 1_000_000_000.0,
        );

        if !confirm("Confirm stake?")? {
            println!("{}", "Stake cancelled".yellow());
            return Ok(());
        }

        // Refuse before constructing any wallet message if the node signed for
        // an account other than the one the stake is sent from.
        let payload = build_manual_stake_payload(
            &route,
            &authorization,
            time_format::now(),
            stake_nanotos,
            stake_at,
            max_factor_raw,
            &adnl_addr,
        )?;
        let wallet =
            make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, &binding.wallet).await?;
        let msg = wallet.message(route.destination.clone(), route.send_value, payload).await?;
        let msg_boc = write_boc(&msg)?;

        println!("{} Sending message to wallet...", "DOING".blue().bold());
        // Broadcast through chain RPC; validator control is only for node authorization.
        provider.send_boc(&msg_boc).await.context("send stake message")?;

        wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_address,
            Some(initial_seqno),
            &cancellation_ctx,
            SEND_TIMEOUT,
        )
        .await?;

        println!(
            "{} Message delivered, waiting for stake to appear in elector...",
            "OK   ".green().bold()
        );

        let previous_stake = elections_info
            .participants
            .iter()
            .find(|p| p.wallet_addr == route.staking_account_id)
            .map(|p| p.stake)
            .unwrap_or(0);
        let expected_stake =
            previous_stake.checked_add(stake_nanotos).context("expected stake overflow")?;

        let stake_timeout = tokio::time::Duration::from_secs(60);
        wait_for_stake_accepted(
            &mut provider,
            election_id,
            &route.staking_account_id,
            expected_stake,
            &cancellation_ctx,
            stake_timeout,
        )
        .await?;

        println!("{} Stake accepted by elector", "OK   ".green().bold());
        let _ = provider.shutdown().await;
        Ok(())
    }
}

fn require_observable_wallet_seqno(wallet: bool, seqno: Option<u32>) -> anyhow::Result<u32> {
    anyhow::ensure!(
        wallet,
        "active operator account is not recognized as a wallet by chain RPC; stake not sent"
    );
    seqno.ok_or_else(|| {
        anyhow::anyhow!("active operator wallet has no observable seqno; stake not sent")
    })
}

const STAKE_POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(3);

pub(crate) async fn stake_elections_info(
    provider: &mut dyn ElectionsProvider,
) -> anyhow::Result<contracts::ElectionsInfo> {
    Ok(provider.elector_snapshot(&[]).await?.elections)
}

pub(crate) async fn wait_for_stake_accepted(
    provider: &mut dyn ElectionsProvider,
    election_id: u64,
    staking_account_id: &[u8],
    expected_stake: u64,
    cancellation_ctx: &CancellationCtx,
    max_wait: tokio::time::Duration,
) -> anyhow::Result<()> {
    let poll = async {
        loop {
            if cancellation_ctx.is_cancelled() {
                anyhow::bail!("Task cancelled");
            }
            tokio::time::sleep(STAKE_POLL_INTERVAL).await;
            let info = stake_elections_info(provider).await?;
            anyhow::ensure!(
                info.election_id == election_id,
                "election changed while confirming stake"
            );
            if let Some(p) = info.participants.iter().find(|p| p.wallet_addr == staking_account_id)
            {
                if p.stake >= expected_stake {
                    return Ok(());
                }
            }
        }
    };
    tokio::time::timeout(max_wait, poll)
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for stake to appear in elector"))?
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn verify_live_pool_roles(
    wallet_address: &MsgAddressInt,
    roles: &NominatorRoles,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        &roles.validator_address == wallet_address,
        "stake wallet is not the live pool validator/operator"
    );
    Ok(())
}

/// Where a manual stake is sent, with what value, and which account the elector
/// will name the member by.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StakeRoute {
    /// The single-nominator pool when there is one, else the operator wallet.
    staking_account_id: Vec<u8>,
    /// The pool, or the elector for a direct wallet stake.
    destination: MsgAddressInt,
    /// What the wallet attaches: only fees when the pool holds the stake, the
    /// stake plus fees when the wallet stakes directly.
    send_value: u64,
    pooled: bool,
}

impl StakeRoute {
    fn new(
        pool_address: Option<&MsgAddressInt>,
        elector_address: &MsgAddressInt,
        wallet_address: &MsgAddressInt,
        stake: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(stake > 0, "stake amount must be positive");
        let fee = ELECTOR_STAKE_FEE.checked_add(NPOOL_COMPUTE_FEE).context("stake fee overflow")?;
        let (staking_account, destination, send_value, pooled) = match pool_address {
            Some(pool) => (pool, pool.clone(), fee, true),
            None => (
                wallet_address,
                elector_address.clone(),
                stake.checked_add(fee).context("stake value overflow")?,
                false,
            ),
        };
        let staking_account_id = staking_account.address().clone().storage().to_vec();
        anyhow::ensure!(
            staking_account_id.len() == 32,
            "staking account {} is not a 256-bit account id",
            staking_account
        );
        Ok(Self { staking_account_id, destination, send_value, pooled })
    }
}

/// The stake body for `route`, built only after the node's signed identity is
/// checked against the account the stake is sent from: the elector verifies the
/// signature against the sender, so any other identity would be refused there.
#[allow(clippy::too_many_arguments)]
fn build_manual_stake_payload(
    route: &StakeRoute,
    authorization: &control_client::client_api::PqStakeAuthorization,
    query_id: u64,
    stake_amount: u64,
    stake_at: u32,
    max_factor: u32,
    adnl_addr: &[u8],
) -> anyhow::Result<Cell> {
    anyhow::ensure!(query_id != 0, "stake query id must be non-zero");
    anyhow::ensure!(stake_amount > 0, "stake amount must be positive");
    anyhow::ensure!(
        authorization.algorithm_id == 1,
        "node returned unsupported PQ stake algorithm {}",
        authorization.algorithm_id
    );
    anyhow::ensure!(
        authorization.validator_id == route.staking_account_id,
        "node signs as validator {} but the stake is sent from {}; set the node's validator id to the staking account",
        hex::encode(&authorization.validator_id),
        hex::encode(&route.staking_account_id)
    );
    let params = nominator::NewStakeParams {
        query_id,
        stake_amount,
        validator_pubkey: &authorization.public_key,
        stake_at,
        max_factor,
        adnl_addr,
        signature: &authorization.signature,
    };
    if route.pooled { nominator::new_stake(&params) } else { nominator::elector_new_stake(&params) }
}

fn resolve_pool_address(
    pool_cfg: &PoolConfig,
    validator_addr: &MsgAddressInt,
) -> anyhow::Result<MsgAddressInt> {
    match pool_cfg {
        PoolConfig::SNP { address, owner } => match (address, owner) {
            (Some(addr), _) => addr.parse::<MsgAddressInt>().context("invalid pool address"),
            (None, Some(owner)) => {
                let owner_addr =
                    owner.parse::<MsgAddressInt>().context("invalid pool owner address")?;
                NominatorWrapperImpl::calculate_address(-1, &owner_addr, validator_addr)
            }
            (None, None) => anyhow::bail!("Pool has neither address nor owner configured"),
        },
        _ => anyhow::bail!("Unsupported pool kind for manual stake"),
    }
}

#[cfg(test)]
mod stake_route_tests {
    use super::*;
    use chain_block::{Coins, Deserializable, SliceData};

    #[test]
    fn operator_wallet_must_have_a_trackable_seqno_before_stake_send() {
        assert_eq!(require_observable_wallet_seqno(true, Some(7)).unwrap(), 7);
        let not_wallet = require_observable_wallet_seqno(false, None).unwrap_err().to_string();
        assert!(not_wallet.contains("not recognized as a wallet"), "wrong refusal: {not_wallet}");
        let no_seqno = require_observable_wallet_seqno(true, None).unwrap_err().to_string();
        assert!(no_seqno.contains("no observable seqno"), "wrong refusal: {no_seqno}");
    }

    #[test]
    fn stake_wallet_must_be_the_live_pool_validator() {
        let operator = MsgAddressInt::standard(-1, [0x55; 32]);
        let mut roles = NominatorRoles {
            owner_address: MsgAddressInt::standard(-1, [0x66; 32]),
            validator_address: operator.clone(),
        };
        verify_live_pool_roles(&operator, &roles).expect("matching live pool roles");
        roles.validator_address = MsgAddressInt::standard(-1, [0x88; 32]);
        let error = verify_live_pool_roles(&operator, &roles).unwrap_err().to_string();
        assert!(error.contains("not the live pool validator/operator"), "wrong refusal: {error}");
    }

    fn pool() -> MsgAddressInt {
        MsgAddressInt::standard(-1, [0x44; 32])
    }

    fn elector() -> MsgAddressInt {
        MsgAddressInt::standard(-1, [0x33; 32])
    }

    fn wallet() -> MsgAddressInt {
        MsgAddressInt::standard(-1, [0x55; 32])
    }

    const STAKE: u64 = 10_000_000_000_000;
    const FEE: u64 = ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE;

    #[test]
    fn a_pool_stake_goes_to_the_pool_with_only_fees() {
        let route = StakeRoute::new(Some(&pool()), &elector(), &wallet(), STAKE).unwrap();
        assert!(route.pooled);
        assert_eq!(route.destination, pool());
        assert_eq!(route.send_value, FEE);
        assert_eq!(route.staking_account_id, vec![0x44; 32]);
    }

    #[test]
    fn a_direct_stake_goes_to_the_elector_with_stake_and_fees() {
        let route = StakeRoute::new(None, &elector(), &wallet(), STAKE).unwrap();
        assert!(!route.pooled);
        assert_eq!(route.destination, elector());
        assert_eq!(route.send_value, STAKE + FEE);
        assert_eq!(route.staking_account_id, vec![0x55; 32]);
    }

    #[test]
    fn a_route_refuses_a_zero_or_overflowing_stake() {
        let error = StakeRoute::new(None, &elector(), &wallet(), 0).unwrap_err().to_string();
        assert!(error.contains("must be positive"), "wrong refusal: {error}");
        let error = StakeRoute::new(None, &elector(), &wallet(), u64::MAX).unwrap_err().to_string();
        assert!(error.contains("overflow"), "wrong refusal: {error}");
        // A pool stake attaches only fees, so even the largest stake fits.
        StakeRoute::new(Some(&pool()), &elector(), &wallet(), u64::MAX).expect("pool route");
    }

    fn authorization(validator_id: Vec<u8>) -> control_client::client_api::PqStakeAuthorization {
        control_client::client_api::PqStakeAuthorization {
            validator_id,
            key_id: vec![0x33; 32],
            algorithm_id: 1,
            public_key: vec![0x55; 1312],
            signature: vec![0x66; 2420],
        }
    }

    fn payload(
        route: &StakeRoute,
        authorization: &control_client::client_api::PqStakeAuthorization,
    ) -> anyhow::Result<Cell> {
        build_manual_stake_payload(
            route,
            authorization,
            77,
            STAKE,
            1_700_000_000,
            65_536,
            &[0x22; 32],
        )
    }

    #[test]
    fn a_pool_stake_carries_the_amount_for_the_pool() {
        let route = StakeRoute::new(Some(&pool()), &elector(), &wallet(), STAKE).unwrap();
        let body = payload(&route, &authorization(vec![0x44; 32])).expect("pool order");
        let mut fields = SliceData::load_cell(body).unwrap();
        assert_eq!(fields.get_next_u32().unwrap(), nominator::opcodes::NEW_STAKE);
        assert_eq!(fields.get_next_u64().unwrap(), 77);
        assert_eq!(Coins::construct_from(&mut fields).unwrap().as_u128(), u128::from(STAKE));
        assert_eq!(fields.get_next_u16().unwrap(), 1);
    }

    #[test]
    fn a_direct_stake_carries_no_amount() {
        let route = StakeRoute::new(None, &elector(), &wallet(), STAKE).unwrap();
        let body = payload(&route, &authorization(vec![0x55; 32])).expect("direct order");
        let mut fields = SliceData::load_cell(body).unwrap();
        assert_eq!(fields.get_next_u32().unwrap(), nominator::opcodes::NEW_STAKE);
        assert_eq!(fields.get_next_u64().unwrap(), 77);
        // The algorithm id follows the query id directly: no coins in between.
        assert_eq!(fields.get_next_u16().unwrap(), 1);
    }

    /// The node must sign for the account that sends the stake; a signature for
    /// any other account is refused before any wallet message exists.
    #[test]
    fn a_node_identity_other_than_the_staking_account_is_refused() {
        let pooled = StakeRoute::new(Some(&pool()), &elector(), &wallet(), STAKE).unwrap();
        let direct = StakeRoute::new(None, &elector(), &wallet(), STAKE).unwrap();
        // Signing for the wallet while staking through the pool, and the reverse.
        for (route, signer) in [(&pooled, vec![0x55; 32]), (&direct, vec![0x44; 32])] {
            let error = payload(route, &authorization(signer)).unwrap_err().to_string();
            assert!(error.contains("set the node's validator id"), "wrong refusal: {error}");
        }
        let mut wrong_algorithm = authorization(vec![0x55; 32]);
        wrong_algorithm.algorithm_id = 2;
        let error = payload(&direct, &wrong_algorithm).unwrap_err().to_string();
        assert!(error.contains("unsupported PQ stake algorithm"), "wrong refusal: {error}");
        let error = build_manual_stake_payload(
            &direct,
            &authorization(vec![0x55; 32]),
            0,
            STAKE,
            1_700_000_000,
            65_536,
            &[0x22; 32],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("query id must be non-zero"), "wrong refusal: {error}");
    }
}
