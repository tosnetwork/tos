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
    app_config::{AppConfig, KeyConfig, NodeBinding, PoolConfig, WalletConfig},
    chain_utils::{display_tos, tos_to_nanotos},
    task_cancellation::CancellationCtx,
    time_format,
};
use contracts::{
    DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, NominatorWrapper,
    NominatorWrapperImpl, Wallet, contract_provider, nominator, nominator::NominatorRoles,
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
    /// Send election stake via nominator pool
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
        default_value = "V3R2",
        help = "Wallet version (case insensitive) [possible values: V1R3, V3R2, V4R2, V5R1]"
    )]
    version: WalletVersion,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42", help = "Subwallet ID")]
    subwallet_id: u32,
    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Workchain ID")]
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
    #[arg(short = 't', long = "to", help = "Destination address")]
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
#[command(about = "Send election stake via nominator pool")]
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

        // Resolve binding → wallet, pool, node
        let binding = config
            .bindings
            .get(&self.binding)
            .ok_or_else(|| anyhow::anyhow!("Binding '{}' not found", self.binding))?;

        let wallet_cfg =
            get_wallet_config(&binding.wallet, &config.wallets, config.master_wallet.as_ref())?;

        let pool_name = binding
            .pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Binding '{}' has no pool configured", self.binding))?;
        let pool_cfg = config
            .pools
            .get(pool_name)
            .ok_or_else(|| anyhow::anyhow!("Pool '{}' not found", pool_name))?;

        let adnl_cfg = config
            .nodes
            .get(&self.binding)
            .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", self.binding))?;

        // Wallet and pool addresses
        let (wallet_address, wallet_info_res, wallet_secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;
        if wallet_info_res.account_state != AccountState::Active {
            anyhow::bail!("Wallet '{}' is {}", binding.wallet, wallet_info_res.account_state);
        }
        let pool_address = resolve_pool_address(pool_cfg, &wallet_address)?;
        let pool_addr_bytes = pool_address.address().clone().storage().to_vec();
        let live_roles =
            NominatorWrapperImpl::new(contract_provider!(rpc_client.clone()), pool_address.clone())
                .get_roles()
                .await
                .context("read live single-nominator pool roles")?;
        verify_live_pool_roles(pool_cfg, &wallet_address, &live_roles)?;

        // Connect to validator node via control protocol
        let adnl_client_cfg = adnl_cfg
            .to_node_adnl_config(Some(vault.clone()))
            .await
            .context("ADNL client config")?;
        let mut provider = DefaultElectionsProvider::new(
            adnl_client_cfg,
            Arc::new(DefaultChainProvider::new(rpc_client.clone())),
        );

        // Get active election ID from elector via RPC
        let elector = ElectorWrapperImpl::new(contract_provider!(rpc_client.clone()));
        let election_id =
            elector.get_active_election_id().await.context("get_active_election_id")?;
        if election_id == 0 {
            anyhow::bail!("No active elections");
        }
        let elections_info = elector.elections_info().await.context("elections_info")?;
        if elections_info.finished {
            anyhow::bail!("Elections are already finished");
        }

        let stake_nanotos = tos_to_nanotos(self.amount);
        if stake_nanotos < elections_info.min_stake {
            anyhow::bail!(
                "Stake {:.4} TOS is below minimum {:.4} TOS",
                self.amount,
                elections_info.min_stake as f64 / 1_000_000_000.0
            );
        }

        // Get election parameters for key expiration
        let cfg15 = provider.election_parameters().await.context("election_parameters")?;
        const KEY_EXPIRED_LAG: u64 = 300;
        let key_expired_at = election_id + cfg15.validators_elected_for as u64 + KEY_EXPIRED_LAG;

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

        // The node's custodied PQ signer binds the pool owner, identity, key,
        // algorithm and signature as one authorization. The operator never
        // signs an election preimage through the generic Ed25519 keyring.

        let max_factor_raw = (self.max_factor * 65536.0) as u32;
        let authorization = provider
            .create_pq_stake_authorization(
                election_id as u32,
                max_factor_raw,
                &adnl_addr,
                &pool_addr_bytes,
            )
            .await
            .context("create PQ stake authorization")?;
        anyhow::ensure!(
            authorization.algorithm_id == 1,
            "node returned unsupported PQ stake algorithm {}",
            authorization.algorithm_id
        );
        // The PQ elector indexes participants by validator identity, not by
        // the Ed25519 transport key generated above for ADNL.
        if let Some(p) =
            elections_info.participants.iter().find(|p| p.pub_key == authorization.validator_id)
        {
            println!(
                "\n{} Already participating with stake {:.4} TOS",
                "Warning:".yellow().bold(),
                p.stake as f64 / 1_000_000_000.0
            );
        }

        // The public birth artifact is separate from the node authorization:
        // the node signs with its custodied key, while live Param47 admits the
        // controller's deploy code. Refuse before constructing a wallet send.
        let live_policy = provider.live_controller_policy().await?;
        let payload = build_verified_manual_pool_stake(
            binding,
            &self.binding,
            pool_cfg,
            &authorization,
            &live_policy,
            time_format::now(),
            stake_nanotos,
            election_id as u32,
            max_factor_raw,
            &adnl_addr,
        )?;

        // Build wallet message to nominator pool (wallet sends only gas, pool has the stake)
        let wallet =
            make_wallet(rpc_client.clone(), wallet_cfg, wallet_secret, &binding.wallet).await?;
        let fee = ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE;
        if wallet_info_res.balance < fee + WALLET_COMPUTE_FEE {
            anyhow::bail!(
                "Insufficient wallet balance: required {:.4} TOS, available {:.4} TOS",
                (fee + WALLET_COMPUTE_FEE) as f64 / 1_000_000_000.0,
                display_tos(wallet_info_res.balance)
            );
        }
        let msg = wallet.message(pool_address.clone(), fee, payload).await?;
        let msg_boc = write_boc(&msg)?;

        // Confirmation
        println!(
            "\n{}\n  Binding:     {}\n  Wallet:      {} ({})\n  Pool:        {}\n  Election ID: {} ({})\n  Stake:       {:.9} TOS\n  Max Factor:  {:.2}\n  Min Stake:   {:.4} TOS\n",
            "Stake summary:".cyan().bold(),
            self.binding,
            binding.wallet,
            wallet_address,
            pool_address,
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

        println!("{} Sending message to wallet...", "DOING".blue().bold());
        // Broadcast through chain RPC; validator control is only for node authorization.
        provider.send_boc(&msg_boc).await.context("send stake message")?;

        wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_address,
            wallet_info_res.seqno,
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
            .find(|p| p.pub_key == authorization.validator_id)
            .map(|p| p.stake)
            .unwrap_or(0);
        let expected_stake = previous_stake + stake_nanotos;

        let stake_timeout = tokio::time::Duration::from_secs(60);
        wait_for_stake_accepted(
            &elector,
            &authorization.validator_id,
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

const STAKE_POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(3);

async fn wait_for_stake_accepted(
    elector: &ElectorWrapperImpl,
    validator_id: &[u8],
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
            let info = elector.elections_info().await.context("elections_info")?;
            if let Some(p) = info.participants.iter().find(|p| p.pub_key == validator_id) {
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

fn configured_birth_artifact_path<'a>(
    binding: &'a NodeBinding,
    name: &str,
) -> anyhow::Result<&'a Path> {
    let configured = binding.controller_birth_state_init_boc.as_deref().ok_or_else(|| {
        anyhow::anyhow!("binding '{name}' has no controller birth StateInit BOC configured; first PQ stake refused locally")
    })?;
    let path = Path::new(configured);
    anyhow::ensure!(
        path.is_absolute(),
        "binding '{name}' controller birth StateInit BOC path must be absolute; first PQ stake refused locally"
    );
    Ok(path)
}

fn verify_live_pool_roles(
    pool_cfg: &PoolConfig,
    wallet_address: &MsgAddressInt,
    roles: &NominatorRoles,
) -> anyhow::Result<()> {
    let configured_controller = match pool_cfg {
        PoolConfig::SNP { controller, .. } => controller
            .parse::<MsgAddressInt>()
            .context("invalid configured validator controller address")?,
        _ => anyhow::bail!("manual PQ stake requires a single-nominator pool"),
    };
    anyhow::ensure!(
        roles.controller_address == configured_controller,
        "live pool controller differs from the configured validator controller"
    );
    anyhow::ensure!(
        &roles.validator_address == wallet_address,
        "stake wallet is not the live pool validator/operator"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_verified_manual_pool_stake(
    binding: &NodeBinding,
    binding_name: &str,
    pool_cfg: &PoolConfig,
    authorization: &control_client::client_api::PqStakeAuthorization,
    live_policy: &Cell,
    query_id: u64,
    stake_amount: u64,
    stake_at: u32,
    max_factor: u32,
    adnl_addr: &[u8],
) -> anyhow::Result<Cell> {
    let artifact_path = configured_birth_artifact_path(binding, binding_name)?;
    let controller = match pool_cfg {
        PoolConfig::SNP { controller, .. } => controller
            .parse::<MsgAddressInt>()
            .context("invalid configured validator controller address")?,
        _ => anyhow::bail!("manual PQ stake requires a single-nominator pool"),
    };
    anyhow::ensure!(
        controller.workchain_id() == -1,
        "configured pool validator controller must be a masterchain account"
    );
    let node_id_bytes: [u8; 32] = authorization
        .validator_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("node PQ stake validator_id is not 32 bytes"))?;
    let pool_id_bytes: [u8; 32] = controller
        .address()
        .get_bytestring(0)
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pool validator controller ID is not 32 bytes"))?;
    nominator::new_stake_from_birth_artifact(
        &nominator::NewStakeParams {
            query_id,
            stake_amount,
            validator_pubkey: &authorization.public_key,
            stake_at,
            max_factor,
            adnl_addr,
            signature: &authorization.signature,
        },
        artifact_path,
        &node_id_bytes,
        &pool_id_bytes,
        live_policy,
    )
}

fn resolve_pool_address(
    pool_cfg: &PoolConfig,
    validator_addr: &MsgAddressInt,
) -> anyhow::Result<MsgAddressInt> {
    match pool_cfg {
        PoolConfig::SNP { address, owner, controller } => match (address, owner) {
            (Some(addr), _) => addr.parse::<MsgAddressInt>().context("invalid pool address"),
            (None, Some(owner)) => {
                let owner_addr =
                    owner.parse::<MsgAddressInt>().context("invalid pool owner address")?;
                let controller_addr = controller
                    .parse::<MsgAddressInt>()
                    .context("invalid validator controller address")?;
                NominatorWrapperImpl::calculate_address(
                    -1,
                    &owner_addr,
                    validator_addr,
                    &controller_addr,
                )
            }
            (None, None) => anyhow::bail!("Pool has neither address nor owner configured"),
        },
        _ => anyhow::bail!("Unsupported pool kind for manual stake"),
    }
}

#[cfg(test)]
mod birth_artifact_tests {
    use super::*;
    use chain_block::{
        BuilderData, Coins, Deserializable, HashmapE, HashmapType, IBitstring, Serializable,
        SliceData, StateInit,
    };
    use std::io::Write;

    fn binding(path: Option<&str>) -> NodeBinding {
        NodeBinding {
            wallet: "wallet".into(),
            pool: Some("pool".into()),
            controller_birth_state_init_boc: path.map(str::to_string),
            enable: true,
            status: Default::default(),
        }
    }

    #[test]
    fn wallet_stake_refuses_missing_or_relative_birth_artifact_locator() {
        let missing = binding(None);
        let error = configured_birth_artifact_path(&missing, "node-1").unwrap_err().to_string();
        assert!(error.contains("no controller birth StateInit BOC"), "wrong refusal: {error}");
        let relative = binding(Some("controller.boc"));
        let error = configured_birth_artifact_path(&relative, "node-1").unwrap_err().to_string();
        assert!(error.contains("must be absolute"), "wrong refusal: {error}");
        let absolute = binding(Some("/var/lib/tos/controller.boc"));
        assert_eq!(
            configured_birth_artifact_path(&absolute, "node-1").unwrap(),
            Path::new("/var/lib/tos/controller.boc")
        );
    }

    #[test]
    fn manual_pool_stake_requires_matching_birth_and_live_admission_before_wallet_send() {
        let code = BuilderData::with_raw(vec![0x11], 8).unwrap().into_cell().unwrap();
        let data = BuilderData::with_raw(vec![0x22], 8).unwrap().into_cell().unwrap();
        let state = StateInit::with_code_and_data(code.clone(), data);
        let state_cell = state.write_to_new_cell().unwrap().into_cell().unwrap();
        let controller_id = *state_cell.repr_hash().as_slice();
        let artifact_path = std::env::temp_dir().join(format!(
            "tosctl-manual-pool-birth-{}-{}.boc",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let mut artifact = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&artifact_path)
            .expect("unique test-only birth artifact");
        let _artifact_cleanup = scopeguard::guard(artifact_path.clone(), |path| {
            let _ = std::fs::remove_file(path);
        });
        artifact.write_all(&write_boc(&state_cell).unwrap()).unwrap();
        drop(artifact);

        let mut admitted = HashmapE::with_bit_len(256);
        let code_key = SliceData::load_builder(
            BuilderData::with_raw(code.repr_hash().as_slice().to_vec(), 256).unwrap(),
        )
        .unwrap();
        admitted.set(code_key, &SliceData::default()).unwrap();
        let mut policy_builder = BuilderData::new();
        policy_builder
            .append_bit_one()
            .unwrap()
            .checked_append_reference(HashmapType::data(&admitted).unwrap().clone())
            .unwrap();
        let live_policy = policy_builder.into_cell().unwrap();
        let artifact_name = artifact_path.to_str().unwrap();
        let configured_binding = binding(Some(artifact_name));
        let controller = MsgAddressInt::standard(-1, controller_id);
        let pool = PoolConfig::SNP {
            address: Some(MsgAddressInt::standard(-1, [0x44; 32]).to_string()),
            owner: None,
            controller: controller.to_string(),
        };
        let operator = MsgAddressInt::standard(-1, [0x55; 32]);
        let mut roles = NominatorRoles {
            owner_address: MsgAddressInt::standard(-1, [0x66; 32]),
            validator_address: operator.clone(),
            controller_address: controller.clone(),
        };
        verify_live_pool_roles(&pool, &operator, &roles).expect("matching live pool roles");
        roles.controller_address = MsgAddressInt::standard(-1, [0x77; 32]);
        let error = verify_live_pool_roles(&pool, &operator, &roles).unwrap_err().to_string();
        assert!(error.contains("live pool controller differs"), "wrong refusal: {error}");
        roles.controller_address = controller;
        roles.validator_address = MsgAddressInt::standard(-1, [0x88; 32]);
        let error = verify_live_pool_roles(&pool, &operator, &roles).unwrap_err().to_string();
        assert!(error.contains("not the live pool validator/operator"), "wrong refusal: {error}");
        let authorization = control_client::client_api::PqStakeAuthorization {
            validator_id: controller_id.to_vec(),
            key_id: vec![0x33; 32],
            algorithm_id: 1,
            public_key: vec![0x55; 1312],
            signature: vec![0x66; 2420],
        };
        let make = |binding: &NodeBinding,
                    pool: &PoolConfig,
                    authorization: &control_client::client_api::PqStakeAuthorization,
                    policy: &Cell| {
            build_verified_manual_pool_stake(
                binding,
                "node-1",
                pool,
                authorization,
                policy,
                77,
                10_000_000_000_000,
                1_700_000_000,
                65_536,
                &[0x22; 32],
            )
        };
        let body = make(&configured_binding, &pool, &authorization, &live_policy)
            .expect("admitted controller produces a witnessed pool order");
        let mut fields = SliceData::load_cell(body).unwrap();
        assert_eq!(fields.get_next_u32().unwrap(), nominator::opcodes::NEW_STAKE);
        assert_eq!(fields.get_next_u64().unwrap(), 77);
        assert_eq!(Coins::construct_from(&mut fields).unwrap().as_u128(), 10_000_000_000_000);
        assert_eq!(fields.get_next_u32().unwrap(), 1_700_000_000);
        assert_eq!(fields.get_next_u32().unwrap(), 65_536);
        assert_eq!(fields.get_next_bytes(32).unwrap(), [0x22; 32]);
        assert_eq!(fields.get_next_u16().unwrap(), 1);
        fields.checked_drain_reference().unwrap();
        fields.checked_drain_reference().unwrap();
        assert!(fields.get_next_bit().unwrap(), "first stake lost its birth witness");
        assert_eq!(fields.checked_drain_reference().unwrap().bit_length(), 544);
        assert_eq!(fields.remaining_bits(), 0);
        assert_eq!(fields.remaining_references(), 0);

        let error =
            make(&binding(None), &pool, &authorization, &live_policy).unwrap_err().to_string();
        assert!(error.contains("no controller birth StateInit BOC"), "wrong refusal: {error}");
        let mut wrong_authorization = authorization.clone();
        wrong_authorization.validator_id[0] ^= 1;
        let error = make(&configured_binding, &pool, &wrong_authorization, &live_policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("node PQ stake identity does not match"), "wrong refusal: {error}");
        let other_pool = PoolConfig::SNP {
            address: Some(MsgAddressInt::standard(-1, [0x44; 32]).to_string()),
            owner: None,
            controller: MsgAddressInt::standard(-1, [0x77; 32]).to_string(),
        };
        let error = make(&configured_binding, &other_pool, &authorization, &live_policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("node PQ stake identity does not match"), "wrong refusal: {error}");
        let empty_policy = BuilderData::with_raw(vec![0], 1).unwrap().into_cell().unwrap();
        let error = make(&configured_binding, &pool, &authorization, &empty_policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("live ConfigParam 47"), "wrong refusal: {error}");
        let mut wrong_admission = HashmapE::with_bit_len(256);
        let wrong_code_key =
            SliceData::load_builder(BuilderData::with_raw(vec![0x77; 32], 256).unwrap()).unwrap();
        wrong_admission.set(wrong_code_key, &SliceData::default()).unwrap();
        let mut wrong_policy_builder = BuilderData::new();
        wrong_policy_builder
            .append_bit_one()
            .unwrap()
            .checked_append_reference(HashmapType::data(&wrong_admission).unwrap().clone())
            .unwrap();
        let wrong_policy = wrong_policy_builder.into_cell().unwrap();
        let error = make(&configured_binding, &pool, &authorization, &wrong_policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not admitted by live ConfigParam 47"), "wrong refusal: {error}");
    }
}
