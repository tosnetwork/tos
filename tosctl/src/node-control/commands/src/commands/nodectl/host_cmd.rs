/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Host management commands
#[derive(clap::Args, Clone)]
#[command(about = "Host and node management")]
pub struct HostCmd {
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
    action: HostAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum HostAction {
    /// Static version and environment info
    About(HostAboutCmd),
    /// Host and node summary
    Status(HostStatusCmd),
    /// Manage runtime modes (validator, liteserver, collator, pool)
    Mode(HostModeCmd),
    /// Manage effective local settings
    Settings(HostSettingsCmd),
    /// Refresh package/source metadata
    Update(HostUpdateCmd),
    /// Perform host-side upgrade
    Upgrade(HostUpgradeCmd),
    /// Download archive blocks
    Archive(HostArchiveCmd),
    /// Run benchmarks
    Benchmark(HostBenchmarkCmd),
}

// ── Mode ─────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct HostModeCmd {
    #[command(subcommand)]
    action: HostModeAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum HostModeAction {
    /// Show active runtime modes
    Status(HostModeStatusCmd),
    /// Enable a mode (validator, liteserver, collator, pool)
    Enable(HostModeEnableCmd),
    /// Disable a mode
    Disable(HostModeDisableCmd),
}

#[derive(clap::Args, Clone)]
pub struct HostModeStatusCmd {}

#[derive(clap::Args, Clone)]
pub struct HostModeEnableCmd {
    /// Mode to enable (validator, liteserver, collator, pool)
    #[arg(required = true)]
    mode: String,
    /// Port for liteserver mode (default 43679)
    #[arg(long, default_value = "43679")]
    port: i32,
}

#[derive(clap::Args, Clone)]
pub struct HostModeDisableCmd {
    /// Mode to disable
    #[arg(required = true)]
    mode: String,
}

// ── Settings ─────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct HostSettingsCmd {
    #[command(subcommand)]
    action: HostSettingsAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum HostSettingsAction {
    /// Show effective local settings
    Show(HostSettingsShowCmd),
    /// Get a specific setting
    Get(HostSettingsGetCmd),
    /// Set a specific setting
    Set(HostSettingsSetCmd),
}

#[derive(clap::Args, Clone)]
pub struct HostSettingsShowCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
pub struct HostSettingsGetCmd {
    /// Setting key
    #[arg(required = true)]
    key: String,
}

#[derive(clap::Args, Clone)]
pub struct HostSettingsSetCmd {
    /// Setting key
    #[arg(required = true)]
    key: String,
    /// Setting value
    #[arg(required = true)]
    value: String,
}

// ── Archive ──────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct HostArchiveCmd {
    #[command(subcommand)]
    action: HostArchiveAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum HostArchiveAction {
    /// Download archive blocks
    Download(HostArchiveDownloadCmd),
}

#[derive(clap::Args, Clone)]
pub struct HostArchiveDownloadCmd {
    /// Target database path for archive blocks
    #[arg(long, default_value = "/var/tos-work/db")]
    db_path: String,
    /// URL to download archive from
    #[arg(long, help = "URL to download archive from")]
    url: String,
    /// Expected SHA256 checksum
    #[arg(long, help = "Expected SHA256 checksum")]
    checksum: Option<String>,
}

// ── Leaf subcommands ─────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct HostAboutCmd {}

#[derive(clap::Args, Clone)]
pub struct HostStatusCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
pub struct HostUpdateCmd {}

#[derive(clap::Args, Clone)]
pub struct HostUpgradeCmd {}

#[derive(clap::Args, Clone)]
pub struct HostBenchmarkCmd {}

// ── Implementations ──────────────────────────────────────────────────

impl HostCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            HostAction::About(cmd) => cmd.run().await,
            HostAction::Status(cmd) => cmd.run(&self.config).await,
            HostAction::Mode(cmd) => cmd.run(&self.config).await,
            HostAction::Settings(cmd) => cmd.run(&self.config).await,
            HostAction::Update(cmd) => cmd.run().await,
            HostAction::Upgrade(cmd) => cmd.run().await,
            HostAction::Archive(cmd) => cmd.run().await,
            HostAction::Benchmark(cmd) => cmd.run().await,
        }
    }
}

impl HostModeCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            HostModeAction::Status(cmd) => cmd.run(config_path).await,
            HostModeAction::Enable(cmd) => cmd.run(config_path).await,
            HostModeAction::Disable(cmd) => cmd.run(config_path).await,
        }
    }
}

impl HostSettingsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            HostSettingsAction::Show(cmd) => cmd.run(config_path).await,
            HostSettingsAction::Get(cmd) => cmd.run(config_path).await,
            HostSettingsAction::Set(cmd) => cmd.run(config_path).await,
        }
    }
}

impl HostArchiveCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            HostArchiveAction::Download(cmd) => cmd.run().await,
        }
    }
}

impl HostAboutCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        println!("{}", "About tosctl".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!("  Version:       {}", env!("CARGO_PKG_VERSION"));
        println!("  Binary:        {}", std::env::current_exe().unwrap_or_default().display());
        println!("  OS:            {}", std::env::consts::OS);
        println!("  Arch:          {}", std::env::consts::ARCH);
        println!(
            "  Config path:   {}",
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into())
        );
        println!();
        Ok(())
    }
}

impl HostStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let config_path = Path::new(config_path);
        let config = AppConfig::load(config_path)?;

        let endpoints = config.chain_rpc.endpoints();

        if self.format == super::output_format::OutputFormat::Json {
            let mut obj = serde_json::json!({
                "config": config_path.display().to_string(),
                "endpoints": endpoints,
                "wallets": config.wallets.len(),
                "pools": config.pools.len(),
                "nodes": config.nodes.len(),
            });

            // Attempt to query chain status via RPC
            if let Ok(rpc_client) = super::utils::try_create_rpc_client(&config).await {
                if let Ok(mc_info) = rpc_client.get_masterchain_info().await {
                    let last = &mc_info.last;
                    obj["chain"] = serde_json::json!({
                        "last_mc_block_seqno": last.seqno,
                        "mc_workchain": last.workchain,
                        "mc_shard": last.shard,
                    });
                }
            }

            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            let endpoints_display =
                if endpoints.is_empty() { "(none)".to_string() } else { endpoints.join(", ") };

            println!();
            println!("{}", "Host Status".bold());
            println!("{}", "───────────".dimmed());
            println!("  {:<18}{}", "Config:".bold(), config_path.display());
            println!("  {:<18}{}", "Endpoints:".bold(), endpoints_display);
            println!("  {:<18}{} configured", "Wallets:".bold(), config.wallets.len());
            println!("  {:<18}{} configured", "Pools:".bold(), config.pools.len());
            println!("  {:<18}{} configured", "Nodes:".bold(), config.nodes.len());

            // Attempt to query chain status via RPC
            println!();
            match super::utils::try_create_rpc_client(&config).await {
                Ok(rpc_client) => match rpc_client.get_masterchain_info().await {
                    Ok(mc_info) => {
                        let last = &mc_info.last;
                        println!("{}", "Chain Status".bold());
                        println!("{}", "────────────".dimmed());
                        println!(
                            "  {:<18}seqno {}",
                            "Last MC block:".bold(),
                            last.seqno.to_string().green()
                        );
                        println!("  {:<18}{}", "MC workchain:".bold(), last.workchain);
                        println!("  {:<18}{}", "MC shard:".bold(), last.shard);
                    }
                    Err(e) => {
                        super::utils::warn_chain_rpc_unavailable(
                            &e,
                            "Chain status is unavailable; showing config info only",
                        );
                    }
                },
                Err(e) => {
                    super::utils::warn_chain_rpc_unavailable(
                        &e,
                        "Chain RPC is not configured or unreachable; showing config info only",
                    );
                }
            }

            println!();
        }
        Ok(())
    }
}

impl HostModeStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;

        println!("{}", "Active Modes".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());

        let has_wallets = !config.wallets.is_empty();
        let has_pools = !config.pools.is_empty();
        let has_nodes = !config.nodes.is_empty();
        let active_bindings = config.bindings.values().filter(|b| b.enable).count();

        println!(
            "  Wallets:       {}",
            if has_wallets {
                format!("{} configured", config.wallets.len()).green()
            } else {
                "none".yellow()
            }
        );
        println!(
            "  Pools:         {}",
            if has_pools {
                format!("{} configured", config.pools.len()).green()
            } else {
                "none".yellow()
            }
        );
        println!(
            "  Nodes:         {}",
            if has_nodes {
                format!("{} configured", config.nodes.len()).green()
            } else {
                "none".yellow()
            }
        );
        println!(
            "  Elections:     {}",
            if active_bindings > 0 {
                format!("{} active bindings", active_bindings).green()
            } else {
                "disabled".yellow()
            }
        );
        println!();
        Ok(())
    }
}

impl HostModeEnableCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);

        match self.mode.as_str() {
            "validator" => {
                let mut config = AppConfig::load(path)?;
                let mut count = 0;
                for (_, binding) in config.bindings.iter_mut() {
                    if !binding.enable {
                        binding.enable = true;
                        count += 1;
                    }
                }
                if count == 0 {
                    println!("No bindings to enable. Add a binding first with `tosctl config`.");
                } else {
                    super::utils::save_config(&config, path)?;
                    println!("OK Enabled {} binding(s)", count);
                }
            }
            "liteserver" => {
                use control_client::client_api::{AddAdnlAddressRq, AddLiteserverRq, ClientAPI};

                println!("{}", "Enable Liteserver".cyan().bold());
                println!("{}", "\u{2500}".repeat(40).dimmed());
                println!();

                let (node_name, mut client) = Self::create_control_client(config_path).await?;
                println!("  Connected to node '{}'", node_name.green());

                // 1. Generate a new key pair for the liteserver
                println!("  Generating liteserver key pair...");
                let key_hash = client.generate_key_pair().await?;
                println!("  Key hash: {}", hex::encode(&key_hash));

                // 2. Export the public key
                let pub_key = client.export_key_pub(&key_hash).await?;
                println!("  Public key: {}", hex::encode(&pub_key));

                // 3. Add as ADNL address (category 0)
                println!("  Adding ADNL address (category 0)...");
                client
                    .add_adnl_address(&AddAdnlAddressRq { key_hash: key_hash.clone(), category: 0 })
                    .await?;

                // 4. Register liteserver on the node
                let port = self.port;
                println!("  Registering liteserver on port {}...", port);
                client
                    .add_liteserver(&AddLiteserverRq { key_hash: key_hash.clone(), port })
                    .await?;

                client.shutdown().await?;

                println!();
                println!("{} Liteserver enabled on port {}.", "OK".green().bold(), port);
                println!("  Key hash: {}", hex::encode(&key_hash));
                println!("  Public key (for global config): {}", hex::encode(&pub_key));
                println!();
            }
            "collator" => {
                use control_client::client_api::{AddAdnlAddressRq, AddCollatorRq, ClientAPI};

                println!("{}", "Enable Collator".cyan().bold());
                println!("{}", "\u{2500}".repeat(40).dimmed());
                println!();

                let (node_name, mut client) = Self::create_control_client(config_path).await?;
                println!("  Connected to node '{}'", node_name.green());

                // 1. Generate a new key pair
                println!("  Generating new key pair...");
                let key_hash = client.generate_key_pair().await?;
                println!("  Key hash: {}", hex::encode(&key_hash));

                // 2. Export the public key
                let pub_key = client.export_key_pub(&key_hash).await?;
                println!("  Public key: {}", hex::encode(&pub_key));

                // 3. Add as ADNL address (category 0)
                println!("  Adding ADNL address (category 0)...");
                client
                    .add_adnl_address(&AddAdnlAddressRq { key_hash: key_hash.clone(), category: 0 })
                    .await?;

                // 4. Add collator for basechain (workchain 0, full shard)
                println!("  Adding collator for basechain (0:{:016x})...", i64::MIN as u64);
                client
                    .add_collator(&AddCollatorRq {
                        adnl_id: key_hash.clone(),
                        workchain: 0,
                        shard: i64::MIN,
                    })
                    .await?;

                client.shutdown().await?;

                println!();
                println!("{} Collator setup complete.", "OK".green().bold());
                println!("  ADNL ID: {}", hex::encode(&key_hash));
                println!();
            }
            other => {
                anyhow::bail!(
                    "Unknown mode '{}'. Available: validator, liteserver, collator",
                    other
                );
            }
        }
        Ok(())
    }

    /// Helper: create a connected control client from the config file path.
    async fn create_control_client(
        config_path: &str,
    ) -> anyhow::Result<(String, control_client::client_adnl::ControlClientAdnl)> {
        use common::app_config::AppConfig;
        use control_client::client_adnl::ControlClientAdnl;
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;
        let (node_name, node_cfg) =
            config.nodes.iter().next().ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await?;
        Ok((node_name.clone(), client))
    }
}

impl HostModeDisableCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);

        match self.mode.as_str() {
            "validator" => {
                let mut config = AppConfig::load(path)?;
                let mut count = 0;
                for (_, binding) in config.bindings.iter_mut() {
                    if binding.enable {
                        binding.enable = false;
                        count += 1;
                    }
                }
                if count == 0 {
                    println!("No bindings to disable.");
                } else {
                    super::utils::save_config(&config, path)?;
                    println!("OK Disabled {} binding(s)", count);
                }
            }
            "liteserver" => {
                println!(
                    "{} Removing a liteserver requires restarting the node with an updated config.",
                    "NOTE:".yellow().bold()
                );
                println!("  1. Stop the validator:  systemctl stop validator");
                println!("  2. Remove the liteserver entry from the node's config.json");
                println!("  3. Start the validator:  systemctl start validator");
            }
            "collator" => {
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) =
                    HostModeEnableCmd::create_control_client(config_path).await?;
                client.clear_collators_list().await?;
                client.shutdown().await?;

                println!("{} All collators stopped (collator list cleared).", "OK".green().bold());
            }
            other => {
                anyhow::bail!(
                    "Unknown mode '{}'. Available: validator, liteserver, collator",
                    other
                );
            }
        }
        Ok(())
    }
}

impl HostSettingsShowCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);
        let config = AppConfig::load(path)?;

        let endpoints = config.chain_rpc.endpoints();

        if self.format == super::output_format::OutputFormat::Json {
            let obj = serde_json::json!({
                "tick_interval": config.tick_interval,
                "chain_rpc_urls": endpoints,
                "nodes": config.nodes.len(),
                "wallets": config.wallets.len(),
                "pools": config.pools.len(),
                "elections": if config.elections.is_some() { "configured" } else { "not configured" },
                "http_bind": config.http.bind,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            let endpoints_display =
                if endpoints.is_empty() { "(none)".to_string() } else { endpoints.join(", ") };

            println!();
            println!("{}", "Effective Settings".bold());
            println!("{}", "\u{2500}".repeat(40).dimmed());
            println!(
                "  {:<20}{}",
                "tick_interval:".bold(),
                format!("{} sec", config.tick_interval)
            );
            println!("  {:<20}{}", "chain_rpc urls:".bold(), endpoints_display);
            println!("  {:<20}{}", "nodes:".bold(), format!("{} configured", config.nodes.len()));
            println!(
                "  {:<20}{}",
                "wallets:".bold(),
                format!("{} configured", config.wallets.len())
            );
            println!("  {:<20}{}", "pools:".bold(), format!("{} configured", config.pools.len()));
            println!(
                "  {:<20}{}",
                "elections:".bold(),
                if config.elections.is_some() { "configured" } else { "not configured" }
            );
            println!("  {:<20}{}", "http bind:".bold(), config.http.bind);
            println!();
        }
        Ok(())
    }
}

impl HostSettingsGetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);
        let config = AppConfig::load(path)?;

        match self.key.as_str() {
            "tick_interval" => println!("{}", config.tick_interval),
            "chain_rpc.urls" => {
                let endpoints = config.chain_rpc.endpoints();
                println!("{}", endpoints.join(", "));
            }
            "nodes" => println!("{}", config.nodes.len()),
            "wallets" => println!("{}", config.wallets.len()),
            "pools" => println!("{}", config.pools.len()),
            "elections" => {
                println!(
                    "{}",
                    if config.elections.is_some() { "configured" } else { "not configured" }
                );
            }
            "http.bind" => println!("{}", config.http.bind),
            _ => anyhow::bail!(
                "Unknown setting: '{}'. Available keys: tick_interval, chain_rpc.urls, nodes, wallets, pools, elections, http.bind",
                self.key
            ),
        }
        Ok(())
    }
}

impl HostSettingsSetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);
        let mut config = AppConfig::load(path)?;

        match self.key.as_str() {
            "tick_interval" => {
                let val: u64 = self.value.parse().map_err(|_| {
                    anyhow::anyhow!(
                        "Invalid value '{}' for tick_interval: expected a positive integer (seconds)",
                        self.value
                    )
                })?;
                config.tick_interval = val;
                super::utils::save_config(&config, path)?;
                println!("OK tick_interval set to {}", config.tick_interval);
            }
            _ => anyhow::bail!(
                "Cannot set '{}' via CLI. Edit tosctl-config.json directly.",
                self.key
            ),
        }
        Ok(())
    }
}

impl HostUpdateCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        let current_version = env!("CARGO_PKG_VERSION");

        println!("{}", "Host Update".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();
        println!("  Current tosctl version: {}", current_version.green());

        // Try to check the latest release from GitHub
        let client = reqwest::Client::new();
        match client
            .get("https://api.github.com/repos/tosnetwork/tosctl/releases/latest")
            .header("User-Agent", "tosctl")
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(tag) = body.get("tag_name").and_then(|v| v.as_str()) {
                        let latest = tag.trim_start_matches('v');
                        if latest == current_version {
                            println!(
                                "  Latest release:        {} ({})",
                                latest.green(),
                                "up to date".green().bold()
                            );
                        } else {
                            println!(
                                "  Latest release:        {} ({})",
                                latest.yellow(),
                                "update available".yellow().bold()
                            );
                        }
                    }
                }
            }
            Ok(resp) => {
                tracing::debug!("GitHub API returned status {}", resp.status());
                println!(
                    "  Latest release:        {}",
                    "(could not check — GitHub API unavailable)".dimmed()
                );
            }
            Err(e) => {
                tracing::debug!("Failed to check for updates: {}", e);
                println!(
                    "  Latest release:        {}",
                    "(could not check — network error)".dimmed()
                );
            }
        }

        println!();
        println!("To update tosctl:");
        println!("  cargo install --path .");
        println!("  # or download latest from GitHub releases:");
        println!("  # https://github.com/tosnetwork/tosctl/releases");
        println!();
        println!("To update validator-engine:");
        println!("  cd ~/tos && git pull && cd build && ninja validator-engine/validator-engine");
        println!();
        Ok(())
    }
}

impl HostUpgradeCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        let current_version = env!("CARGO_PKG_VERSION");

        println!("{}", "Host Upgrade".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();
        println!("  tosctl version:           {}", current_version.green());

        // Try to detect installed validator-engine version
        match std::process::Command::new("tos-validator-engine").arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let version_str = version_str.trim();
                println!(
                    "  validator-engine version: {}",
                    if version_str.is_empty() {
                        "(empty output)".dimmed().to_string()
                    } else {
                        version_str.green().to_string()
                    }
                );
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Some binaries print version to stderr
                let stderr = stderr.trim();
                if !stderr.is_empty() {
                    println!("  validator-engine version: {}", stderr.green());
                } else {
                    println!(
                        "  validator-engine version: {}",
                        "(exited with error, version unknown)".dimmed()
                    );
                }
            }
            Err(_) => {
                println!(
                    "  validator-engine version: {}",
                    "not found (tos-validator-engine not in PATH)".yellow()
                );
            }
        }

        println!();
        println!("{}", "Before upgrading, create a backup:".yellow().bold());
        println!("  tosctl backup create");
        println!();
        println!("Upgrade steps:");
        println!("  1. Stop the validator:  systemctl stop validator");
        println!("  2. Build new version:   cd ~/tos && git pull && cd build && ninja");
        println!("  3. Start the validator: systemctl start validator");
        println!("  4. Verify:              tosctl node status");
        println!();
        Ok(())
    }
}

impl HostArchiveDownloadCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;
        use futures_util::StreamExt;
        use sha2::{Digest, Sha256};
        use std::io::Write;

        // Derive output filename from URL
        let filename =
            self.url.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("archive.tar.lz4");

        let output_path = format!("{}/{}", self.db_path, filename);

        println!("{}", "Archive Block Download".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();
        println!("  Source:  {}", self.url.cyan());
        println!("  Output:  {}", output_path.green());
        if let Some(ref checksum) = self.checksum {
            println!("  Checksum (SHA256): {}", checksum.green());
        } else {
            println!("  Checksum: {}", "none provided".yellow());
        }
        println!();

        // Ensure target directory exists
        std::fs::create_dir_all(&self.db_path)
            .map_err(|e| anyhow::anyhow!("Failed to create directory '{}': {}", self.db_path, e))?;

        // Download the file with streaming and progress
        println!("  Downloading...");
        let client = reqwest::Client::new();
        let resp = client
            .get(&self.url)
            .timeout(std::time::Duration::from_secs(3600))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Download request failed: {}", e))?;

        if !resp.status().is_success() {
            anyhow::bail!("Server returned HTTP {}", resp.status());
        }

        let total_size = resp.content_length().unwrap_or(0);
        let mut file = std::fs::File::create(&output_path)
            .map_err(|e| anyhow::anyhow!("Failed to create '{}': {}", output_path, e))?;

        let mut hasher = Sha256::new();
        let mut downloaded: u64 = 0;
        let mut last_pct: u64 = 0;
        let mut stream = resp.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| anyhow::anyhow!("Error reading download stream: {}", e))?;
            file.write_all(&chunk)
                .map_err(|e| anyhow::anyhow!("Error writing to '{}': {}", output_path, e))?;
            hasher.update(&chunk);
            downloaded += chunk.len() as u64;

            if total_size > 0 {
                let pct = downloaded * 100 / total_size;
                if pct != last_pct {
                    last_pct = pct;
                    let mb = downloaded as f64 / 1_048_576.0;
                    let total_mb = total_size as f64 / 1_048_576.0;
                    print!("\r  Progress: {:>5.1} / {:.1} MB ({:>3}%)", mb, total_mb, pct);
                    let _ = std::io::stdout().flush();
                }
            }
        }
        println!();

        let mb = downloaded as f64 / 1_048_576.0;
        println!("  {} Downloaded {:.1} MB to {}", "OK".green().bold(), mb, output_path);

        // Verify checksum if provided
        if let Some(ref expected) = self.checksum {
            let actual = format!("{:x}", hasher.finalize());
            if actual != expected.to_lowercase() {
                anyhow::bail!(
                    "Checksum mismatch!\n  Expected: {}\n  Actual:   {}",
                    expected,
                    actual
                );
            }
            println!("  {} Checksum verified.", "OK".green().bold());
        } else {
            println!(
                "  {} No checksum provided -- integrity was not verified.",
                "WARNING:".yellow().bold()
            );
        }

        // Print extraction guidance
        println!();
        println!("To extract the archive into the database path:");
        if filename.ends_with(".tar.lz4") || filename.ends_with(".lz4") {
            println!("  lz4 -d {} | tar xf - -C {}", output_path, self.db_path);
        } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            println!("  tar xzf {} -C {}", output_path, self.db_path);
        } else if filename.ends_with(".tar.zst") || filename.ends_with(".zst") {
            println!("  zstd -d {} | tar xf - -C {}", output_path, self.db_path);
        } else {
            println!("  tar xf {} -C {}", output_path, self.db_path);
        }
        println!();
        Ok(())
    }
}

impl HostBenchmarkCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;
        use std::time::Instant;

        println!("{}", "Host Benchmark".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();

        // Disk I/O benchmark: write 100 x 1 MB
        println!("  Running disk write benchmark (100 x 1 MB)...");
        let test_file = "/tmp/tosctl_benchmark_test";
        let data = vec![0u8; 1024 * 1024]; // 1 MB
        let start = Instant::now();
        for _ in 0..100 {
            std::fs::write(test_file, &data)?;
        }
        let elapsed = start.elapsed();
        let _ = std::fs::remove_file(test_file);

        println!("  Disk write: {:.1} MB/s", 100.0 / elapsed.as_secs_f64());
        println!();
        Ok(())
    }
}
