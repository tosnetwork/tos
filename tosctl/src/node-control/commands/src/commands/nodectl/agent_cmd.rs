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
    calculate_wallet_address, get_wallet_config, load_config_vault, load_config_vault_rpc_client,
    make_wallet, save_config, wait_for_deploy, wait_for_seqno_change, wallet_info,
    DEPLOY_TIMEOUT, SEND_TIMEOUT,
};
use anyhow::Context;
use chain_block::{write_boc, BuilderData, Cell, IBitstring, MsgAddressInt};
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use common::{
    app_config::{
        AgentRuntimeBinding, AgentWalletConfig, AgentWalletPolicy, KeyConfig, WalletConfig,
    },
    chain_utils::{display_tos, tos_to_nanotos},
    time_format, WalletVersion,
};
use contracts::Wallet;
use secrets_vault::types::{
    algorithm::Algorithm, secret::Secret, secret_id::SecretId, secret_spec::SecretSpec,
};
use std::{io::Write, path::Path, str::FromStr};

const AGENT_WALLET_FUND_GAS: u64 = 1_000_000; // 0.001 TOS

/// Top-level `tosctl agent` command.
#[derive(clap::Args, Clone)]
#[command(about = "AI agent wallet operations")]
pub struct AgentCmd {
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
    action: AgentAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentAction {
    /// Agent wallet operations
    Wallet(AgentWalletCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Manage AI agent wallets")]
pub struct AgentWalletCmd {
    #[command(subcommand)]
    action: AgentWalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AgentWalletAction {
    /// Create a local Agent Wallet profile
    Create(AgentWalletCreateCmd),
    /// List local Agent Wallet profiles
    Ls(AgentWalletLsCmd),
    /// Show a local Agent Wallet profile
    Show(AgentWalletShowCmd),
    /// Print only the machine-readable policy
    Policy(AgentWalletPolicyCmd),
    /// Update Agent Wallet policy and metadata
    UpdatePolicy(AgentWalletUpdatePolicyCmd),
    /// Bind an Agent Wallet to an off-chain runtime
    BindRuntime(AgentWalletBindRuntimeCmd),
    /// Rotate the controller key used by the agent runtime
    RotateController(AgentWalletRotateControllerCmd),
    /// Export the runtime-facing manifest
    ExportRuntime(AgentWalletExportRuntimeCmd),
    /// Fund an Agent Wallet from an existing configured wallet
    Fund(AgentWalletFundCmd),
    /// Show Agent Wallet chain status
    Status(AgentWalletStatusCmd),
    /// Activate the underlying Agent Wallet contract
    Activate(AgentWalletActivateCmd),
    /// Remove a local Agent Wallet profile
    Rm(AgentWalletRmCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a local Agent Wallet profile")]
pub struct AgentWalletCreateCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(
        short = 'v',
        long = "version",
        default_value = "V5R1",
        help = "Underlying wallet version"
    )]
    version: String,

    #[arg(short = 'w', long = "workchain", default_value = "-1", help = "Workchain ID")]
    workchain: i32,

    #[arg(short = 'i', long = "subwallet-id", default_value = "4242", help = "Subwallet ID")]
    subwallet_id: u32,

    #[arg(
        long = "max-per-tx",
        default_value = "1.0",
        help = "Max controller spend per action, in TOS"
    )]
    max_per_tx: f64,

    #[arg(
        long = "daily-limit",
        default_value = "10.0",
        help = "Max controller spend per day, in TOS"
    )]
    daily_limit: f64,

    #[arg(
        long = "approval-above",
        help = "Require owner approval above this per-action amount, in TOS"
    )]
    approval_above: Option<f64>,

    #[arg(long = "service", help = "Allowed service actor address or label")]
    allowed_service_actors: Vec<String>,

    #[arg(long = "task-category", help = "Allowed task category")]
    allowed_task_categories: Vec<String>,

    #[arg(long = "capability", help = "Capability label advertised by the agent")]
    capabilities: Vec<String>,

    #[arg(long = "metadata-hash", help = "Optional agent metadata hash")]
    metadata_hash: Option<String>,

    #[arg(long = "service-endpoint-hash", help = "Optional service endpoint descriptor hash")]
    service_endpoint_hash: Option<String>,

    #[arg(long = "default-task-timeout", default_value_t = 3600)]
    default_task_timeout_secs: u64,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List local Agent Wallet profiles")]
pub struct AgentWalletLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a local Agent Wallet profile")]
pub struct AgentWalletShowCmd {
    #[arg(short = 'n', long = "name")]
    name: String,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Print an Agent Wallet policy")]
pub struct AgentWalletPolicyCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Update Agent Wallet policy and metadata")]
pub struct AgentWalletUpdatePolicyCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "max-per-tx", help = "Max controller spend per action, in TOS")]
    max_per_tx: Option<f64>,

    #[arg(long = "daily-limit", help = "Max controller spend per day, in TOS")]
    daily_limit: Option<f64>,

    #[arg(long = "approval-above", help = "Require owner approval above this amount, in TOS")]
    approval_above: Option<f64>,

    #[arg(long = "clear-approval-above", help = "Remove the owner-approval threshold")]
    clear_approval_above: bool,

    #[arg(long = "service", help = "Replace allowed service actors with this repeated list")]
    allowed_service_actors: Vec<String>,

    #[arg(long = "clear-services", help = "Clear allowed service actors")]
    clear_services: bool,

    #[arg(long = "task-category", help = "Replace allowed task categories with this repeated list")]
    allowed_task_categories: Vec<String>,

    #[arg(long = "clear-task-categories", help = "Clear allowed task categories")]
    clear_task_categories: bool,

    #[arg(long = "capability", help = "Replace capability labels with this repeated list")]
    capabilities: Vec<String>,

    #[arg(long = "clear-capabilities", help = "Clear capability labels")]
    clear_capabilities: bool,

    #[arg(long = "metadata-hash", help = "Set agent metadata hash")]
    metadata_hash: Option<String>,

    #[arg(long = "clear-metadata-hash", help = "Clear agent metadata hash")]
    clear_metadata_hash: bool,

    #[arg(long = "service-endpoint-hash", help = "Set service endpoint descriptor hash")]
    service_endpoint_hash: Option<String>,

    #[arg(long = "clear-service-endpoint-hash", help = "Clear service endpoint descriptor hash")]
    clear_service_endpoint_hash: bool,

    #[arg(long = "default-task-timeout", help = "Default task timeout, in seconds")]
    default_task_timeout_secs: Option<u64>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Bind an Agent Wallet to an off-chain runtime")]
pub struct AgentWalletBindRuntimeCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "runner-id", help = "Stable agent runtime identifier")]
    runner_id: String,

    #[arg(long = "endpoint", help = "Runtime endpoint or local descriptor URI")]
    endpoint: String,

    #[arg(long = "attestation-hash", help = "Optional runtime attestation hash")]
    attestation_hash: Option<String>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Rotate the controller key used by the agent runtime")]
pub struct AgentWalletRotateControllerCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "key-name", help = "Optional vault key name for the new controller")]
    key_name: Option<String>,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Export the runtime-facing Agent Wallet manifest")]
pub struct AgentWalletExportRuntimeCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Fund an Agent Wallet from an existing configured wallet")]
pub struct AgentWalletFundCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "from", help = "Funding wallet name from config, or master_wallet")]
    from: String,

    #[arg(long = "amount", help = "Amount to transfer, in TOS")]
    amount: f64,

    #[arg(long = "message", help = "Optional transfer comment")]
    message: Option<String>,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Agent Wallet chain status")]
pub struct AgentWalletStatusCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Activate the underlying Agent Wallet contract")]
pub struct AgentWalletActivateCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a local Agent Wallet profile")]
pub struct AgentWalletRmCmd {
    #[arg(short = 'n', long = "name", help = "Agent wallet name")]
    name: String,

    #[arg(long = "delete-keys", help = "Also delete owner and controller vault keys")]
    delete_keys: bool,

    #[arg(long = "yes", help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(serde::Serialize)]
struct AgentWalletView {
    name: String,
    address: String,
    version: WalletVersion,
    workchain: i32,
    subwallet_id: u32,
    owner_key: String,
    controller_key: String,
    policy: AgentWalletPolicy,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
    capabilities: Vec<String>,
    runtime: Option<AgentRuntimeBinding>,
    created_at: Option<u64>,
}

#[derive(serde::Serialize)]
struct AgentRuntimeManifest {
    name: String,
    address: String,
    controller_key: String,
    policy: AgentWalletPolicy,
    metadata_hash: Option<String>,
    service_endpoint_hash: Option<String>,
    capabilities: Vec<String>,
    runtime: Option<AgentRuntimeBinding>,
}

#[derive(serde::Serialize)]
struct AgentWalletFundView {
    agent_wallet: String,
    from: String,
    from_address: String,
    to_address: String,
    amount: String,
    message: Option<String>,
    status: String,
}

#[derive(serde::Serialize)]
struct AgentWalletStatusView {
    name: String,
    address: String,
    balance: String,
    state: String,
    wallet_type: Option<String>,
    seqno: Option<u32>,
    controller_key: String,
    runtime: Option<AgentRuntimeBinding>,
}

impl AgentCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AgentAction::Wallet(cmd) => cmd.run(&self.config).await,
        }
    }
}

impl AgentWalletCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AgentWalletAction::Create(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Ls(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Show(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Policy(cmd) => cmd.run(config_path).await,
            AgentWalletAction::UpdatePolicy(cmd) => cmd.run(config_path).await,
            AgentWalletAction::BindRuntime(cmd) => cmd.run(config_path).await,
            AgentWalletAction::RotateController(cmd) => cmd.run(config_path).await,
            AgentWalletAction::ExportRuntime(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Fund(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Status(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Activate(cmd) => cmd.run(config_path).await,
            AgentWalletAction::Rm(cmd) => cmd.run(config_path).await,
        }
    }
}

impl AgentWalletCreateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("Agent wallet name cannot be empty");
        }
        validate_tos_amount("max-per-tx", self.max_per_tx)?;
        validate_tos_amount("daily-limit", self.daily_limit)?;
        if self.daily_limit < self.max_per_tx {
            anyhow::bail!("daily-limit must be greater than or equal to max-per-tx");
        }
        if let Some(value) = self.approval_above {
            validate_tos_amount("approval-above", value)?;
        }

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;

        if config.agent_wallets.contains_key(&self.name) {
            anyhow::bail!("Agent wallet '{}' already exists in config", self.name);
        }

        let version = WalletVersion::from_str(&self.version).map_err(|_| {
            anyhow::anyhow!(
                "Invalid wallet version '{}'. Use V1R3, V3R2, V4R2, or V5R1",
                self.version
            )
        })?;

        let owner_secret_name = format!("agent-wallet-{}-owner", self.name);
        let controller_secret_name = format!("agent-wallet-{}-controller", self.name);
        let owner_secret_id = owner_secret_name.as_str().into();
        let controller_secret_id = controller_secret_name.as_str().into();
        let spec = SecretSpec::new(Algorithm::Ed25519).extractable(false);

        vault.generate_secret(&spec, &owner_secret_id).await?;
        vault.generate_secret(&spec, &controller_secret_id).await?;
        vault.flush().await?;

        let wallet = WalletConfig {
            key: KeyConfig::VaultKey { name: owner_secret_name.clone() },
            version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        };
        let policy = AgentWalletPolicy {
            max_per_tx: tos_to_nanotos(self.max_per_tx),
            daily_limit: tos_to_nanotos(self.daily_limit),
            allowed_service_actors: self.allowed_service_actors.clone(),
            allowed_task_categories: self.allowed_task_categories.clone(),
            require_owner_approval_above: self.approval_above.map(tos_to_nanotos),
            default_task_timeout_secs: self.default_task_timeout_secs,
        };

        let agent_wallet = AgentWalletConfig {
            wallet: wallet.clone(),
            controller_key: KeyConfig::VaultKey { name: controller_secret_name.clone() },
            policy,
            metadata_hash: self.metadata_hash.clone(),
            service_endpoint_hash: self.service_endpoint_hash.clone(),
            capabilities: self.capabilities.clone(),
            runtime: None,
            created_at: Some(time_format::now()),
        };

        config.agent_wallets.insert(self.name.clone(), agent_wallet.clone());
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault.clone()))
            .await
            .context("build agent wallet view")?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        print_view(&view, self.format.clone())?;
        println!("\n{} Agent wallet '{}' created", "OK".green().bold(), self.name);
        println!("  Owner key:      {} (in vault)", owner_secret_name);
        println!("  Controller key: {} (in vault)", controller_secret_name);
        println!(
            "  Next step:      fund the address, then bind an agent runtime to the controller key"
        );
        Ok(())
    }
}

impl AgentWalletBindRuntimeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_non_empty("runner-id", &self.runner_id)?;
        validate_non_empty("endpoint", &self.endpoint)?;

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        agent_wallet.runtime = Some(AgentRuntimeBinding {
            runner_id: self.runner_id.clone(),
            endpoint: self.endpoint.clone(),
            attestation_hash: self.attestation_hash.clone(),
            bound_at: Some(time_format::now()),
        });
        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{} Runtime bound for '{}'", "OK".green().bold(), self.name);
        print_view(&view, self.format.clone())
    }
}

impl AgentWalletRotateControllerCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;

        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        let new_key_name = match &self.key_name {
            Some(name) => {
                validate_non_empty("key-name", name)?;
                name.clone()
            }
            None => format!("agent-wallet-{}-controller-{}", self.name, time_format::now()),
        };
        let secret_id = new_key_name.as_str().into();
        let spec = SecretSpec::new(Algorithm::Ed25519).extractable(false);

        vault.generate_secret(&spec, &secret_id).await?;
        vault.flush().await?;

        agent_wallet.controller_key = KeyConfig::VaultKey {
            name: new_key_name.clone(),
        };
        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;

        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!(
            "{} Controller key rotated for '{}'",
            "OK".green().bold(),
            self.name
        );
        println!("  New controller key: {} (in vault)", new_key_name);
        Ok(())
    }
}

impl AgentWalletExportRuntimeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        let manifest = AgentRuntimeManifest {
            name: view.name,
            address: view.address,
            controller_key: view.controller_key,
            policy: view.policy,
            metadata_hash: view.metadata_hash,
            service_endpoint_hash: view.service_endpoint_hash,
            capabilities: view.capabilities,
            runtime: view.runtime,
        };
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        Ok(())
    }
}

impl AgentWalletFundCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        if self.amount == 0.0 {
            anyhow::bail!("amount must be greater than zero");
        }

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault.clone())).await?;
        let dest_addr = view
            .address
            .parse::<MsgAddressInt>()
            .context("Invalid Agent Wallet destination address")?;

        let from_wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (from_wallet_address, from_wallet_info, from_secret) =
            wallet_info(rpc_client.clone(), from_wallet_cfg, vault).await?;

        let amount_nanotos = tos_to_nanotos(self.amount);
        if !(1..=from_wallet_info.balance.saturating_sub(AGENT_WALLET_FUND_GAS))
            .contains(&amount_nanotos)
        {
            anyhow::bail!(
                "Wrong amount value {} TOS. Wallet balance is {} TOS",
                self.amount,
                display_tos(from_wallet_info.balance)
            );
        }
        if from_wallet_info.account_state == AccountState::Frozen {
            anyhow::bail!("wallet '{}' is frozen", self.from);
        }
        if from_wallet_info.account_state == AccountState::Uninitialized {
            anyhow::bail!("wallet '{}' is uninitialized", self.from);
        }

        println!(
            "\n{}\n  Agent:   {}\n  From:    {} ({})\n  To:      {}\n  Amount:  {:.9} TOS{}\n",
            "Agent Wallet funding summary:".cyan().bold(),
            self.name,
            self.from,
            from_wallet_address,
            dest_addr,
            self.amount,
            if let Some(msg) = &self.message {
                format!("\n  Comment: {}", msg)
            } else {
                String::new()
            },
        );

        if !self.yes && !confirm("Confirm funding transfer?")? {
            println!("{}", "Funding transfer cancelled".yellow());
            return Ok(());
        }

        let wallet = make_wallet(rpc_client.clone(), from_wallet_cfg, from_secret, &self.from)
            .await
            .context("create funding wallet")?;
        let body = if let Some(msg) = &self.message {
            build_comment_cell(msg)?
        } else {
            Cell::default()
        };
        let msg = wallet
            .build_message(dest_addr, amount_nanotos, body, false, None, None, None)
            .await?;
        let msg_boc = write_boc(&msg)?;
        rpc_client.send_boc(&msg_boc).await?;
        wait_for_seqno_change(
            rpc_client.clone(),
            &from_wallet_address,
            from_wallet_info.seqno,
            &common::task_cancellation::CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await?;

        let result = AgentWalletFundView {
            agent_wallet: self.name.clone(),
            from: self.from.clone(),
            from_address: from_wallet_address.to_string(),
            to_address: view.address,
            amount: display_tos(amount_nanotos),
            message: self.message.clone(),
            status: "sent".to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

impl AgentWalletStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        let address = view
            .address
            .parse::<MsgAddressInt>()
            .context("Invalid Agent Wallet address")?;
        let info = rpc_client
            .get_wallet_information(&address)
            .await
            .context("get Agent Wallet chain status")?;
        let status = AgentWalletStatusView {
            name: self.name.clone(),
            address: view.address,
            balance: display_tos(info.balance),
            state: info.account_state.to_string(),
            wallet_type: info.wallet_type.map(|t| t.to_string()),
            seqno: info.seqno,
            controller_key: view.controller_key,
            runtime: view.runtime,
        };

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&status)?);
            return Ok(());
        }

        println!("{}", status.name.bold());
        println!("  Address:     {}", status.address);
        println!("  Balance:     {} TOS", status.balance);
        println!("  State:       {}", status.state);
        println!(
            "  Wallet type: {}",
            status.wallet_type.unwrap_or_else(|| "-".to_string())
        );
        println!(
            "  Seqno:       {}",
            status.seqno.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string())
        );
        println!("  Controller:  {}", status.controller_key);
        if let Some(runtime) = status.runtime {
            println!("  Runtime:     {} ({})", runtime.runner_id, runtime.endpoint);
        }
        Ok(())
    }
}

impl AgentWalletActivateCmd {
    const MIN_BALANCE: u64 = 100_000_000; // 0.1 TOS

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        let (address, info, secret) =
            wallet_info(rpc_client.clone(), &agent_wallet.wallet, vault).await?;
        if info.account_state == AccountState::Active {
            println!(
                "{} Agent Wallet '{}' ({}) already active",
                "OK".green().bold(),
                self.name,
                address
            );
            return Ok(());
        }
        if info.account_state == AccountState::Frozen {
            anyhow::bail!("Agent Wallet '{}' ({}) is frozen", self.name, address);
        }
        if info.balance < Self::MIN_BALANCE {
            anyhow::bail!(
                "Agent Wallet '{}' ({}) balance {} too low (min {})",
                self.name,
                address,
                display_tos(info.balance),
                display_tos(Self::MIN_BALANCE),
            );
        }

        println!("Deploying Agent Wallet '{}' ({})...", self.name, address);

        let wallet = make_wallet(rpc_client.clone(), &agent_wallet.wallet, secret, &self.name)
            .await
            .context("create Agent Wallet deployer")?;
        let msg = wallet.deploy_message(Self::MIN_BALANCE / 10, Cell::default()).await?;
        let boc = write_boc(&msg)?;
        rpc_client.send_boc(&boc).await?;
        wait_for_deploy(
            rpc_client,
            &address,
            &common::task_cancellation::CancellationCtx::default(),
            true,
            DEPLOY_TIMEOUT,
        )
        .await?;

        println!(
            "{} Agent Wallet '{}' ({}) activated",
            "OK".green().bold(),
            self.name,
            address
        );
        Ok(())
    }
}

impl AgentWalletRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        println!(
            "\n{}\n  Agent:       {}\n  Owner key:   {}\n  Controller:  {}\n  Delete keys: {}\n",
            "Remove Agent Wallet profile:".cyan().bold(),
            self.name,
            describe_key(&agent_wallet.wallet.key),
            describe_key(&agent_wallet.controller_key),
            if self.delete_keys { "yes" } else { "no" },
        );

        if !self.yes && !confirm("Confirm remove?")? {
            println!("{}", "Remove cancelled".yellow());
            return Ok(());
        }

        let agent_wallet = config
            .agent_wallets
            .remove(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        if self.delete_keys {
            delete_vault_key_if_present(&vault, &agent_wallet.wallet.key).await?;
            delete_vault_key_if_present(&vault, &agent_wallet.controller_key).await?;
            vault.flush().await?;
        }
        save_config(&config, path)?;

        println!("{} Agent Wallet '{}' removed", "OK".green().bold(), self.name);
        if !self.delete_keys {
            println!("  Vault keys were preserved");
        }
        Ok(())
    }
}

impl AgentWalletLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let mut views = Vec::new();
        for (name, agent_wallet) in &config.agent_wallets {
            views.push(build_view(name, agent_wallet, Some(vault.clone())).await?);
        }
        views.sort_by(|a, b| a.name.cmp(&b.name));

        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&views)?);
            return Ok(());
        }

        if views.is_empty() {
            println!("{}", "No agent wallets configured".yellow());
            return Ok(());
        }
        for view in views {
            print_table_summary(&view);
        }
        Ok(())
    }
}

impl AgentWalletShowCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        let view = build_view(&self.name, agent_wallet, Some(vault)).await?;
        print_view(&view, self.format.clone())
    }
}

impl AgentWalletPolicyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let agent_wallet = config
            .agent_wallets
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;
        println!("{}", serde_json::to_string_pretty(&agent_wallet.policy)?);
        Ok(())
    }
}

impl AgentWalletUpdatePolicyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        if self.clear_approval_above && self.approval_above.is_some() {
            anyhow::bail!("Use either --approval-above or --clear-approval-above, not both");
        }
        if self.clear_services && !self.allowed_service_actors.is_empty() {
            anyhow::bail!("Use either --service or --clear-services, not both");
        }
        if self.clear_task_categories && !self.allowed_task_categories.is_empty() {
            anyhow::bail!("Use either --task-category or --clear-task-categories, not both");
        }
        if self.clear_capabilities && !self.capabilities.is_empty() {
            anyhow::bail!("Use either --capability or --clear-capabilities, not both");
        }
        if self.clear_metadata_hash && self.metadata_hash.is_some() {
            anyhow::bail!("Use either --metadata-hash or --clear-metadata-hash, not both");
        }
        if self.clear_service_endpoint_hash && self.service_endpoint_hash.is_some() {
            anyhow::bail!(
                "Use either --service-endpoint-hash or --clear-service-endpoint-hash, not both"
            );
        }
        if let Some(value) = self.max_per_tx {
            validate_tos_amount("max-per-tx", value)?;
        }
        if let Some(value) = self.daily_limit {
            validate_tos_amount("daily-limit", value)?;
        }
        if let Some(value) = self.approval_above {
            validate_tos_amount("approval-above", value)?;
        }

        let path = Path::new(config_path);
        let (mut config, vault) = load_config_vault(path).await?;
        let agent_wallet = config
            .agent_wallets
            .get_mut(&self.name)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.name))?;

        if let Some(value) = self.max_per_tx {
            agent_wallet.policy.max_per_tx = tos_to_nanotos(value);
        }
        if let Some(value) = self.daily_limit {
            agent_wallet.policy.daily_limit = tos_to_nanotos(value);
        }
        if agent_wallet.policy.daily_limit < agent_wallet.policy.max_per_tx {
            anyhow::bail!("daily-limit must be greater than or equal to max-per-tx");
        }
        if self.clear_approval_above {
            agent_wallet.policy.require_owner_approval_above = None;
        } else if let Some(value) = self.approval_above {
            agent_wallet.policy.require_owner_approval_above = Some(tos_to_nanotos(value));
        }
        if self.clear_services {
            agent_wallet.policy.allowed_service_actors.clear();
        } else if !self.allowed_service_actors.is_empty() {
            agent_wallet.policy.allowed_service_actors = self.allowed_service_actors.clone();
        }
        if self.clear_task_categories {
            agent_wallet.policy.allowed_task_categories.clear();
        } else if !self.allowed_task_categories.is_empty() {
            agent_wallet.policy.allowed_task_categories = self.allowed_task_categories.clone();
        }
        if self.clear_capabilities {
            agent_wallet.capabilities.clear();
        } else if !self.capabilities.is_empty() {
            agent_wallet.capabilities = self.capabilities.clone();
        }
        if self.clear_metadata_hash {
            agent_wallet.metadata_hash = None;
        } else if let Some(value) = &self.metadata_hash {
            agent_wallet.metadata_hash = Some(value.clone());
        }
        if self.clear_service_endpoint_hash {
            agent_wallet.service_endpoint_hash = None;
        } else if let Some(value) = &self.service_endpoint_hash {
            agent_wallet.service_endpoint_hash = Some(value.clone());
        }
        if let Some(value) = self.default_task_timeout_secs {
            agent_wallet.policy.default_task_timeout_secs = value;
        }

        let agent_wallet = agent_wallet.clone();
        save_config(&config, path)?;
        let view = build_view(&self.name, &agent_wallet, Some(vault)).await?;
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        println!("{} Agent Wallet policy updated", "OK".green().bold());
        print_view(&view, self.format.clone())
    }
}

fn validate_tos_amount(name: &str, value: f64) -> anyhow::Result<()> {
    if !value.is_finite() || value < 0.0 {
        anyhow::bail!("{name} must be a finite non-negative TOS amount");
    }
    Ok(())
}

fn validate_non_empty(name: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    Ok(())
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn build_comment_cell(text: &str) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_u32(0)?;
    builder.append_raw(text.as_bytes(), text.len() * 8)?;
    Ok(builder.into_cell()?)
}

async fn build_view(
    name: &str,
    agent_wallet: &AgentWalletConfig,
    vault: Option<std::sync::Arc<secrets_vault::vault::SecretVault>>,
) -> anyhow::Result<AgentWalletView> {
    let owner_key = describe_key(&agent_wallet.wallet.key);
    let controller_key = describe_key(&agent_wallet.controller_key);
    let address = match &agent_wallet.wallet.key {
        KeyConfig::VaultKey { .. } => {
            let vault = vault
                .ok_or_else(|| anyhow::anyhow!("vault is required for address calculation"))?;
            let secret = agent_wallet.wallet.key.read_secret(Some(vault)).await?;
            let pub_key = public_key_from_secret(&secret).await?;
            calculate_wallet_address(&agent_wallet.wallet, &pub_key)?.to_string()
        }
        _ => {
            let secret = agent_wallet.wallet.key.read_secret(vault).await?;
            let pub_key = public_key_from_secret(&secret).await?;
            calculate_wallet_address(&agent_wallet.wallet, &pub_key)?.to_string()
        }
    };

    Ok(AgentWalletView {
        name: name.to_string(),
        address,
        version: agent_wallet.wallet.version,
        workchain: agent_wallet.wallet.workchain,
        subwallet_id: agent_wallet.wallet.subwallet_id,
        owner_key,
        controller_key,
        policy: agent_wallet.policy.clone(),
        metadata_hash: agent_wallet.metadata_hash.clone(),
        service_endpoint_hash: agent_wallet.service_endpoint_hash.clone(),
        capabilities: agent_wallet.capabilities.clone(),
        runtime: agent_wallet.runtime.clone(),
        created_at: agent_wallet.created_at,
    })
}

async fn public_key_from_secret(secret: &Secret) -> anyhow::Result<Vec<u8>> {
    let keypair = secret.as_keypair()?;
    keypair.public_key().await?.ok_or_else(|| anyhow::anyhow!("secret has no public key"))
}

fn describe_key(key: &KeyConfig) -> String {
    match key {
        KeyConfig::VaultKey { name } => format!("vault:{name}"),
        KeyConfig::PublicKey { .. } => "public-key".to_string(),
        KeyConfig::PrivateKey { .. } => "private-key".to_string(),
        KeyConfig::KeyPair(_) => "inline-keypair".to_string(),
    }
}

async fn delete_vault_key_if_present(
    vault: &secrets_vault::vault::SecretVault,
    key: &KeyConfig,
) -> anyhow::Result<()> {
    if let KeyConfig::VaultKey { name } = key {
        let secret_id: SecretId = name.as_str().into();
        if vault.exists(&secret_id).await? {
            vault.delete(&secret_id).await?;
        }
    }
    Ok(())
}

fn print_view(view: &AgentWalletView, format: OutputFormat) -> anyhow::Result<()> {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(view)?);
        return Ok(());
    }
    print_table_summary(view);
    println!("  Max per action:       {} TOS", display_tos(view.policy.max_per_tx));
    println!("  Daily limit:          {} TOS", display_tos(view.policy.daily_limit));
    if let Some(value) = view.policy.require_owner_approval_above {
        println!("  Owner approval above: {} TOS", display_tos(value));
    }
    println!("  Default task timeout: {}s", view.policy.default_task_timeout_secs);
    if !view.policy.allowed_service_actors.is_empty() {
        println!("  Allowed services:     {}", view.policy.allowed_service_actors.join(", "));
    }
    if !view.policy.allowed_task_categories.is_empty() {
        println!("  Task categories:      {}", view.policy.allowed_task_categories.join(", "));
    }
    if !view.capabilities.is_empty() {
        println!("  Capabilities:         {}", view.capabilities.join(", "));
    }
    if let Some(runtime) = &view.runtime {
        println!("  Runtime runner:       {}", runtime.runner_id);
        println!("  Runtime endpoint:     {}", runtime.endpoint);
        if let Some(hash) = &runtime.attestation_hash {
            println!("  Runtime attestation:  {}", hash);
        }
    }
    Ok(())
}

fn print_table_summary(view: &AgentWalletView) {
    println!("{}", view.name.bold());
    println!("  Address:       {}", view.address);
    println!("  Version:       {}", view.version);
    println!("  Workchain:     {}", view.workchain);
    println!("  Subwallet ID:  {}", view.subwallet_id);
    println!("  Owner key:     {}", view.owner_key);
    println!("  Controller:    {}", view.controller_key);
}
