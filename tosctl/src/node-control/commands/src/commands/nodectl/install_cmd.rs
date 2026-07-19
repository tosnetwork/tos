/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Install and setup commands
#[derive(clap::Args, Clone)]
#[command(about = "Installation and setup utilities")]
pub struct InstallCmd {
    #[command(subcommand)]
    action: InstallAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum InstallAction {
    /// Interactive setup wizard for new TOS operator
    Wizard(InstallWizardCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Interactive setup wizard for new TOS operator")]
pub struct InstallWizardCmd {}

impl InstallCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            InstallAction::Wizard(cmd) => cmd.run().await,
        }
    }
}

impl InstallWizardCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::{
            AppConfig, ElectionsConfig, HttpConfig,
            LogConfig, WalletConfig,
        };
        use common::{WalletVersion, app_config::KeyConfig};
        use std::collections::HashMap;
        use std::path::Path;

        println!();
        println!("{}", "TOS Operator Setup Wizard".cyan().bold());
        println!("{}", "=".repeat(56).dimmed());
        println!();

        // ── Step 1: Check prerequisites ────────────────────────────────
        println!("{}", "Step 1: Checking prerequisites...".cyan().bold());
        println!();

        let mut warnings = Vec::new();

        // Check for validator-engine binary
        let ve_found = which_exists("validator-engine");
        if ve_found {
            println!("  {} validator-engine binary found", "[OK]".green());
        } else {
            println!("  {} validator-engine binary not found in PATH", "[!!]".yellow());
            warnings.push("Install validator-engine and ensure it is in PATH".to_string());
        }

        // Check for fift binary
        let fift_found = which_exists("fift");
        if fift_found {
            println!("  {} fift binary found", "[OK]".green());
        } else {
            println!("  {} fift binary not found in PATH (optional, needed for some admin ops)", "[!!]".yellow());
        }

        // Check for FIFTPATH
        let fiftpath = std::env::var("FIFTPATH").ok();
        if let Some(ref fp) = fiftpath {
            println!("  {} FIFTPATH={}", "[OK]".green(), fp);
        } else {
            println!("  {} FIFTPATH not set (optional)", "[--]".dimmed());
        }

        println!();

        // ── Step 2: Config file ────────────────────────────────────────
        println!("{}", "Step 2: Configuration file".cyan().bold());
        println!();

        let config_path_str = prompt_with_default(
            "  Config file path",
            "tosctl-config.json",
        )?;
        let config_path = Path::new(&config_path_str);

        if config_path.exists() {
            println!("  {} Config file already exists at {}", "[OK]".green(), config_path_str);
            println!("  Skipping config generation (existing config will be used).");
            println!();
        } else {
            println!("  Creating new config at {}...", config_path_str);
            println!();

            // ── Step 3: Chain RPC URL ──────────────────────────────────
            println!("{}", "Step 3: Chain RPC endpoint".cyan().bold());
            println!();

            let rpc_url = prompt_with_default(
                "  Chain RPC URL",
                "http://127.0.0.1:3301/",
            )?;
            let rpc_api_key = prompt_optional("  Chain RPC API key (leave empty if none)")?;

            println!();

            // ── Step 4: Vault key ──────────────────────────────────────
            println!("{}", "Step 4: Vault key for wallet".cyan().bold());
            println!();

            let key_name = prompt_with_default(
                "  Key name in vault",
                "validator-key",
            )?;

            println!();

            // ── Step 5: Wallet ─────────────────────────────────────────
            println!("{}", "Step 5: Wallet configuration".cyan().bold());
            println!();

            let wallet_name = prompt_with_default(
                "  Wallet name",
                "validator",
            )?;

            let wallet_version_str = prompt_with_default(
                "  Wallet version (v3r2 / v4r2)",
                "v3r2",
            )?;
            let wallet_version = match wallet_version_str.to_lowercase().as_str() {
                "v4r2" | "v4" => WalletVersion::V4R2,
                _ => WalletVersion::V3R2,
            };

            let workchain_str = prompt_with_default(
                "  Wallet workchain (-1 for masterchain, 0 for basechain)",
                "-1",
            )?;
            let workchain: i32 = workchain_str.parse().unwrap_or(-1);

            println!();

            // ── Save config ────────────────────────────────────────────
            println!("{}", "Saving configuration...".cyan().bold());
            println!();

            let mut wallets = HashMap::new();
            wallets.insert(
                wallet_name.clone(),
                WalletConfig {
                    key: KeyConfig::VaultKey { name: key_name.clone() },
                    version: wallet_version,
                    subwallet_id: 698983191,
                    workchain,
                },
            );

            // Build chain_rpc via JSON deserialization to avoid private field issues
            let chain_rpc_json = if let Some(ref api_key) = rpc_api_key {
                serde_json::json!({
                    "urls": [rpc_url],
                    "api_key": api_key,
                })
            } else {
                serde_json::json!({
                    "urls": [rpc_url],
                })
            };
            let chain_rpc = serde_json::from_value(chain_rpc_json)?;

            // Nodes require ADNL key configuration which must be set up
            // after the validator-engine is running. Start with an empty map.
            let config = AppConfig {
                nodes: HashMap::new(),
                wallets,
                agent_wallets: HashMap::new(),
                agent_tasks: HashMap::new(),
                capability_registries: HashMap::new(),
                service_actors: HashMap::new(),
                disputes: HashMap::new(),
                pools: HashMap::new(),
                bindings: HashMap::new(),
                chain_rpc,
                elections: Some(ElectionsConfig::default()),
                voting: None,
                http: HttpConfig::default(),
                master_wallet: None,
                tick_interval: 40,
                log: Some(LogConfig::default()),
                bookmarks: HashMap::new(),
                alerts: Default::default(),
            };

            super::utils::save_config(&config, config_path)?;

            println!("  {} Config saved to {}", "[OK]".green(), config_path_str);
            println!();
        }

        // ── Next steps ─────────────────────────────────────────────────
        println!("{}", "Next steps".cyan().bold());
        println!("{}", "-".repeat(56).dimmed());
        println!();
        println!(
            "  {} Create a vault key (if not already done):",
            "1.".white().bold()
        );
        println!(
            "     {}",
            "tosctl key add --name validator-key".yellow()
        );
        println!();
        println!(
            "  {} Add a node to the config:",
            "2.".white().bold(),
        );
        println!(
            "     {}",
            "tosctl config node add --name default --address 127.0.0.1:3030 --server-key <ADNL_KEY>".yellow()
        );
        println!();
        println!(
            "  {} Fund your wallet address, then deploy it:",
            "3.".white().bold(),
        );
        println!(
            "     {}",
            "tosctl deploy wallet --name validator".yellow()
        );
        println!();
        println!(
            "  {} Create and activate a staking pool:",
            "4.".white().bold(),
        );
        println!(
            "     {}",
            "tosctl pool single create --name my-pool --owner validator --validator validator".yellow()
        );
        println!(
            "     {}",
            "tosctl pool single activate --name my-pool".yellow()
        );
        println!();
        println!(
            "  {} Bind the node to the pool and enable elections:",
            "5.".white().bold(),
        );
        println!(
            "     {}",
            "tosctl config bind add --node default --wallet validator --pool my-pool".yellow()
        );
        println!();

        if !warnings.is_empty() {
            println!("{}", "Warnings".yellow().bold());
            println!("{}", "-".repeat(56).dimmed());
            for w in &warnings {
                println!("  {} {}", "[!!]".yellow(), w);
            }
            println!();
        }

        println!(
            "{} Wizard complete. Review {} and follow the steps above.\n",
            "OK".green().bold(),
            config_path_str
        );

        Ok(())
    }
}

/// Check if a binary exists in PATH
fn which_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Prompt the user with a default value
fn prompt_with_default(prompt: &str, default: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{} [{}]: ", prompt, default);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Prompt the user for an optional value
fn prompt_optional(prompt: &str) -> anyhow::Result<Option<String>> {
    use std::io::Write;
    print!("{}: ", prompt);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}
