/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Top-level `tosctl node` command.
#[derive(clap::Args, Clone)]
#[command(about = "Node operations")]
pub struct NodeCmd {
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
    action: NodeAction,
}

/// Helper: parse a shard descriptor of the form `workchain:shard_hex`
/// (e.g. `0:8000000000000000`) into `(workchain, shard_i64)`.
fn parse_shard_descriptor(s: &str) -> anyhow::Result<(i32, i64)> {
    let (wc_str, shard_str) = s.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid shard format '{}'. Expected workchain:shard_hex (e.g. 0:8000000000000000)",
            s
        )
    })?;
    let workchain: i32 =
        wc_str.parse().map_err(|e| anyhow::anyhow!("Invalid workchain '{}': {}", wc_str, e))?;
    let shard: i64 = i64::from_str_radix(shard_str.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("Invalid shard hex '{}': {}", shard_str, e))?;
    Ok((workchain, shard))
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

#[derive(clap::Subcommand, Clone)]
pub enum NodeAction {
    /// Node status summary
    Status(NodeStatusCmd),
    /// Ping node
    Ping,
    /// Probe node health
    Probe,
    /// Collator management
    Collator(NodeCollatorCmd),
    /// Collator configuration
    #[command(name = "collator-config")]
    CollatorConfig(NodeCollatorConfigCmd),
    /// Collation whitelist management
    #[command(name = "collation-whitelist")]
    CollationWhitelist(NodeCollationWhitelistCmd),
    /// Overlay management
    Overlay(NodeOverlayCmd),
    /// Network settings
    Net(NodeNetCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Node status summary")]
pub struct NodeStatusCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

// ---------------------------------------------------------------------------
// node collator
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Manage collators")]
pub struct NodeCollatorCmd {
    #[command(subcommand)]
    action: NodeCollatorAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeCollatorAction {
    /// List collators
    Ls(NodeCollatorLsCmd),
    /// Local collator state
    Local,
    /// Add collator
    Add(NodeCollatorAddCmd),
    /// Remove collator
    Rm(NodeCollatorRmCmd),
    /// Clear collator list
    Reset,
    /// Collator setup flow
    Setup,
    /// Stop collator(s)
    Stop,
}

#[derive(clap::Args, Clone)]
#[command(about = "List collators")]
pub struct NodeCollatorLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
pub struct NodeCollatorAddCmd {
    #[arg(long)]
    adnl_id: String,
    #[arg(long)]
    shard: String,
}

#[derive(clap::Args, Clone)]
pub struct NodeCollatorRmCmd {
    #[arg(long)]
    adnl_id: String,
    #[arg(long)]
    shard: String,
}

// ---------------------------------------------------------------------------
// node collator-config
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Manage collation configuration")]
pub struct NodeCollatorConfigCmd {
    #[command(subcommand)]
    action: NodeCollatorConfigAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeCollatorConfigAction {
    /// Set collation config from a JSON string
    Set(NodeCollatorConfigSetCmd),
    /// Re-apply configured source (show current config)
    Refresh,
    /// Display active config
    Show,
}

#[derive(clap::Args, Clone)]
pub struct NodeCollatorConfigSetCmd {
    /// JSON string with collator options
    #[arg(long)]
    json: String,
}

// ---------------------------------------------------------------------------
// node collation-whitelist
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Manage collation whitelist")]
pub struct NodeCollationWhitelistCmd {
    #[command(subcommand)]
    action: NodeCollationWhitelistAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeCollationWhitelistAction {
    /// Add validator to whitelist
    Add(NodeCollationWhitelistAddCmd),
    /// Remove from whitelist
    Rm(NodeCollationWhitelistRmCmd),
    /// Disable whitelist enforcement
    Disable,
    /// Show whitelist
    Ls(NodeCollationWhitelistLsCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Show whitelist")]
pub struct NodeCollationWhitelistLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
pub struct NodeCollationWhitelistAddCmd {
    /// Hex-encoded ADNL ID of the validator to whitelist
    #[arg(long)]
    adnl_id: String,
}

#[derive(clap::Args, Clone)]
pub struct NodeCollationWhitelistRmCmd {
    /// Hex-encoded ADNL ID of the validator to remove
    #[arg(long)]
    adnl_id: String,
}

// ---------------------------------------------------------------------------
// node overlay
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Manage overlays")]
pub struct NodeOverlayCmd {
    #[command(subcommand)]
    action: NodeOverlayAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeOverlayAction {
    /// Add custom overlay
    Add(NodeOverlayAddCmd),
    /// List overlays
    Ls,
    /// Remove overlay
    Rm(NodeOverlayRmCmd),
}

#[derive(clap::Args, Clone)]
pub struct NodeOverlayAddCmd {
    /// Path to overlay JSON config
    #[arg(long)]
    config_file: String,
}

#[derive(clap::Args, Clone)]
pub struct NodeOverlayRmCmd {
    /// Name of the overlay to remove
    #[arg(long)]
    name: String,
}

// ---------------------------------------------------------------------------
// node net
// ---------------------------------------------------------------------------

#[derive(clap::Args, Clone)]
#[command(about = "Network settings")]
pub struct NodeNetCmd {
    #[command(subcommand)]
    action: NodeNetAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeNetAction {
    /// QUIC transport settings
    Quic(NodeNetQuicCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "QUIC transport settings")]
pub struct NodeNetQuicCmd {
    #[command(subcommand)]
    action: NodeNetQuicAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum NodeNetQuicAction {
    /// Set QUIC port
    Set(NodeNetQuicSetCmd),
}

#[derive(clap::Args, Clone)]
pub struct NodeNetQuicSetCmd {
    #[arg(long)]
    port: u16,
}

// ===========================================================================
// Run implementations
// ===========================================================================

impl NodeCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            NodeAction::Status(cmd) => {
                use colored::Colorize;
                use common::app_config::AppConfig;
                use std::path::Path;
                use std::str::FromStr;

                let config = AppConfig::load(Path::new(&self.config))?;

                let rpc_client = match super::utils::try_create_rpc_client(&config).await {
                    Ok(c) => c,
                    Err(e) => {
                        if cmd.format == super::output_format::OutputFormat::Json {
                            let obj = serde_json::json!({
                                "sync_status": "unknown",
                                "error": "RPC unavailable",
                            });
                            println!("{}", serde_json::to_string_pretty(&obj)?);
                        } else {
                            super::utils::warn_chain_rpc_unavailable(
                                &e,
                                "Cannot show node status without a reachable chain RPC endpoint",
                            );
                            println!();
                            println!("{}", "Node Status".bold());
                            println!("{}", "───────────".dimmed());
                            println!(
                                "  {:<18}{}",
                                "Sync status:".bold(),
                                "unknown (RPC unavailable)".yellow()
                            );
                            println!();
                        }
                        return Ok(());
                    }
                };

                let mc_info = rpc_client.get_masterchain_info().await?;
                let last = &mc_info.last;

                // Probe node responsiveness and obtain sync_utime by
                // querying the elector contract on the masterchain.
                let elector_addr = chain_block::MsgAddressInt::from_str(
                    "-1:3333333333333333333333333333333333333333333333333333333333333333",
                )
                .map_err(|e| anyhow::anyhow!("Invalid elector address: {}", e))?;

                let (block_time_display, sync_status_str) =
                    match rpc_client.get_address_information(&elector_addr).await {
                        Ok(info) => {
                            let block_time = common::time_format::format_ts(info.sync_utime);
                            ("synced".to_string(), block_time)
                        }
                        Err(_) => ("behind".to_string(), "unknown".to_string()),
                    };

                if cmd.format == super::output_format::OutputFormat::Json {
                    let obj = serde_json::json!({
                        "last_mc_block_seqno": last.seqno,
                        "block_time": sync_status_str,
                        "sync_status": block_time_display,
                    });
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                } else {
                    let (block_time_colored, sync_colored) = if block_time_display == "synced" {
                        (sync_status_str, "synced".green().bold().to_string())
                    } else {
                        (sync_status_str, "behind".yellow().bold().to_string())
                    };
                    println!();
                    println!("{}", "Node Status".bold());
                    println!("{}", "───────────".dimmed());
                    println!(
                        "  {:<18}seqno {}",
                        "Last MC block:".bold(),
                        last.seqno.to_string().green()
                    );
                    println!("  {:<18}{}", "Block time:".bold(), block_time_colored);
                    println!("  {:<18}{}", "Sync status:".bold(), sync_colored);
                    println!();
                }

                Ok(())
            }
            NodeAction::Ping => {
                use colored::Colorize;
                use common::app_config::AppConfig;
                use control_client::client_adnl::ControlClientAdnl;
                use std::path::Path;

                let config = AppConfig::load(Path::new(&self.config))?;
                let (node_name, node_adnl) = config
                    .nodes
                    .iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;

                println!("Pinging node '{}'...", node_name);

                let adnl_config = node_adnl.to_node_adnl_config(None).await?;
                let mut client = ControlClientAdnl::new(adnl_config, 1);
                client.connect().await?;

                let start = std::time::Instant::now();
                let _ping_secs = client.ping().await?;
                let elapsed_ms = start.elapsed().as_millis();

                client.shutdown().await?;

                println!(
                    "{} Node '{}' responded in {} ms",
                    "OK".green().bold(),
                    node_name,
                    elapsed_ms
                );
                Ok(())
            }
            NodeAction::Probe => {
                use colored::Colorize;
                use common::app_config::AppConfig;
                use control_client::client_adnl::ControlClientAdnl;
                use std::path::Path;

                let config = AppConfig::load(Path::new(&self.config))?;

                println!("{}", "Node Probe".cyan().bold());
                println!("{}", "\u{2500}".repeat(40).dimmed());
                println!();

                // --- ADNL control-client ping ---
                let adnl_result: Result<(String, u128), String> = async {
                    let (node_name, node_adnl) = config
                        .nodes
                        .iter()
                        .next()
                        .ok_or_else(|| "No nodes configured".to_string())?;

                    let adnl_config = node_adnl
                        .to_node_adnl_config(None)
                        .await
                        .map_err(|e| format!("ADNL config error: {e}"))?;

                    let mut client = ControlClientAdnl::new(adnl_config, 1);
                    client.connect().await.map_err(|e| format!("ADNL connect error: {e}"))?;

                    let start = std::time::Instant::now();
                    client.ping().await.map_err(|e| format!("ADNL ping error: {e}"))?;
                    let elapsed_ms = start.elapsed().as_millis();

                    client.shutdown().await.ok();
                    Ok((node_name.clone(), elapsed_ms))
                }
                .await;

                match &adnl_result {
                    Ok((node_name, ms)) => {
                        println!(
                            "  {:<20}{} (node '{}', {} ms)",
                            "ADNL control:".bold(),
                            "OK".green().bold(),
                            node_name,
                            ms,
                        );
                    }
                    Err(reason) => {
                        println!(
                            "  {:<20}{} ({})",
                            "ADNL control:".bold(),
                            "FAIL".red().bold(),
                            reason,
                        );
                    }
                }

                // --- JSON-RPC getMasterchainInfo ---
                let rpc_result: Result<u32, String> = async {
                    let rpc_client = super::utils::try_create_rpc_client(&config)
                        .await
                        .map_err(|e| format!("RPC connect error: {e}"))?;

                    let mc_info = rpc_client
                        .get_masterchain_info()
                        .await
                        .map_err(|e| format!("getMasterchainInfo error: {e}"))?;

                    Ok(mc_info.last.seqno)
                }
                .await;

                match &rpc_result {
                    Ok(seqno) => {
                        println!(
                            "  {:<20}{} (MC seqno {})",
                            "JSON-RPC:".bold(),
                            "OK".green().bold(),
                            seqno,
                        );
                    }
                    Err(reason) => {
                        println!(
                            "  {:<20}{} ({})",
                            "JSON-RPC:".bold(),
                            "FAIL".red().bold(),
                            reason,
                        );
                    }
                }

                println!();

                // If both failed, return an error
                if adnl_result.is_err() && rpc_result.is_err() {
                    anyhow::bail!("Both ADNL control and JSON-RPC probes failed");
                }

                Ok(())
            }
            NodeAction::Collator(cmd) => cmd.run(&self.config).await,
            NodeAction::CollatorConfig(cmd) => cmd.run(&self.config).await,
            NodeAction::CollationWhitelist(cmd) => cmd.run(&self.config).await,
            NodeAction::Overlay(cmd) => cmd.run(&self.config).await,
            NodeAction::Net(cmd) => cmd.run(&self.config).await,
        }
    }
}

impl NodeCollatorCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeCollatorAction::Ls(cmd) => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (node_name, mut client) = create_control_client(config_path).await?;
                let result = client.show_collators_list().await?;
                client.shutdown().await?;

                if cmd.format == super::output_format::OutputFormat::Json {
                    let shards: Vec<serde_json::Value> = result
                        .shards
                        .iter()
                        .map(|shard| {
                            let collators: Vec<String> =
                                shard.collators.iter().map(|c| hex::encode(&c.adnl_id)).collect();
                            serde_json::json!({
                                "workchain": shard.workchain,
                                "shard": format!("{:016x}", shard.shard as u64),
                                "self_collate": shard.self_collate,
                                "select_mode": shard.select_mode,
                                "collators": collators,
                            })
                        })
                        .collect();
                    let obj = serde_json::json!({
                        "node": node_name,
                        "shards": shards,
                    });
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                } else {
                    println!("{}", "Collators List".cyan().bold());
                    println!("{}", "\u{2500}".repeat(50).dimmed());
                    println!("  Node: {}", node_name.green());
                    println!();

                    if result.shards.is_empty() {
                        println!("  {}", "No collator shards configured.".dimmed());
                    } else {
                        for shard in &result.shards {
                            println!(
                                "  Shard {}:{:016x}  self_collate={}  mode={}",
                                shard.workchain,
                                shard.shard as u64,
                                if shard.self_collate {
                                    "yes".green().to_string()
                                } else {
                                    "no".yellow().to_string()
                                },
                                shard.select_mode,
                            );
                            if shard.collators.is_empty() {
                                println!("    {}", "(no collators)".dimmed());
                            } else {
                                for c in &shard.collators {
                                    println!("    - {}", hex::encode(&c.adnl_id));
                                }
                            }
                        }
                    }
                    println!();
                }
                Ok(())
            }
            NodeCollatorAction::Local => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (node_name, mut client) = create_control_client(config_path).await?;
                let stats = client.get_stats().await?;
                client.shutdown().await?;

                println!("{}", "Collator Local State".cyan().bold());
                println!("{}", "\u{2500}".repeat(50).dimmed());
                println!("  Node: {}", node_name.green());
                println!();

                let collation_stats: Vec<_> = stats
                    .stats
                    .iter()
                    .filter(|(key, _)| {
                        let k = key.to_lowercase();
                        k.contains("collat") || k.contains("shard")
                    })
                    .collect();

                if collation_stats.is_empty() {
                    println!("  {}", "No collation-related stats found.".dimmed());
                } else {
                    for (key, value) in &collation_stats {
                        println!("  {:<40} {}", key.bold(), value);
                    }
                }
                println!();
                Ok(())
            }
            NodeCollatorAction::Add(cmd) => cmd.run(config_path).await,
            NodeCollatorAction::Rm(cmd) => cmd.run(config_path).await,
            NodeCollatorAction::Reset => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client.clear_collators_list().await?;
                client.shutdown().await?;

                println!("{} Collators list cleared.", "OK".green().bold());
                Ok(())
            }
            NodeCollatorAction::Setup => {
                use colored::Colorize;
                use control_client::client_api::{AddAdnlAddressRq, AddCollatorRq, ClientAPI};

                println!("{}", "Collator Setup".cyan().bold());
                println!("{}", "\u{2500}".repeat(40).dimmed());
                println!();

                let (node_name, mut client) = create_control_client(config_path).await?;
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
                Ok(())
            }
            NodeCollatorAction::Stop => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client.clear_collators_list().await?;
                client.shutdown().await?;

                println!("{} All collators stopped (collator list cleared).", "OK".green().bold());
                Ok(())
            }
        }
    }
}

impl NodeCollatorAddCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use control_client::client_api::{AddCollatorRq, ClientAPI};

        let adnl_id_bytes = hex::decode(self.adnl_id.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid hex ADNL ID: {}", e))?;
        if adnl_id_bytes.len() != 32 {
            anyhow::bail!("ADNL ID must be 32 bytes (64 hex chars), got {}", adnl_id_bytes.len());
        }

        let (workchain, shard) = parse_shard_descriptor(&self.shard)?;

        let (_node_name, mut client) = create_control_client(config_path).await?;
        client.add_collator(&AddCollatorRq { adnl_id: adnl_id_bytes, workchain, shard }).await?;
        client.shutdown().await?;

        println!(
            "{} Collator added: adnl_id={} shard={}:{:016x}",
            "OK".green().bold(),
            self.adnl_id,
            workchain,
            shard as u64,
        );
        Ok(())
    }
}

impl NodeCollatorRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use control_client::client_api::{AddCollatorRq, ClientAPI};

        let adnl_id_bytes = hex::decode(self.adnl_id.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid hex ADNL ID: {}", e))?;
        if adnl_id_bytes.len() != 32 {
            anyhow::bail!("ADNL ID must be 32 bytes (64 hex chars), got {}", adnl_id_bytes.len());
        }

        let (workchain, shard) = parse_shard_descriptor(&self.shard)?;

        let (_node_name, mut client) = create_control_client(config_path).await?;
        client.del_collator(&AddCollatorRq { adnl_id: adnl_id_bytes, workchain, shard }).await?;
        client.shutdown().await?;

        println!(
            "{} Collator removed: adnl_id={} shard={}:{:016x}",
            "OK".green().bold(),
            self.adnl_id,
            workchain,
            shard as u64,
        );
        Ok(())
    }
}

impl NodeCollatorConfigCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeCollatorConfigAction::Set(cmd) => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client.set_collator_options_json(&cmd.json).await?;
                client.shutdown().await?;

                println!("{} Collator options updated.", "OK".green().bold());
                Ok(())
            }
            NodeCollatorConfigAction::Refresh => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                let json = client.get_collator_options_json().await?;
                client.shutdown().await?;

                println!("{}", "Current Collator Config".cyan().bold());
                println!("{}", "\u{2500}".repeat(50).dimmed());
                println!();
                println!("{}", json);
                println!();
                Ok(())
            }
            NodeCollatorConfigAction::Show => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                let json = client.get_collator_options_json().await?;
                client.shutdown().await?;

                println!("{}", "Collator Config".cyan().bold());
                println!("{}", "\u{2500}".repeat(50).dimmed());
                println!();
                println!("{}", json);
                println!();
                Ok(())
            }
        }
    }
}

impl NodeCollationWhitelistCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeCollationWhitelistAction::Add(cmd) => {
                use colored::Colorize;
                use control_client::client_api::{ClientAPI, CollatorNodeWhitelistRq};

                let adnl_id_bytes = hex::decode(cmd.adnl_id.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("Invalid hex ADNL ID: {}", e))?;
                if adnl_id_bytes.len() != 32 {
                    anyhow::bail!(
                        "ADNL ID must be 32 bytes (64 hex chars), got {}",
                        adnl_id_bytes.len()
                    );
                }

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client
                    .collator_node_set_whitelisted_validator(&CollatorNodeWhitelistRq {
                        adnl_id: adnl_id_bytes,
                        add: true,
                    })
                    .await?;
                client.shutdown().await?;

                println!("{} Validator {} added to whitelist.", "OK".green().bold(), cmd.adnl_id,);
                Ok(())
            }
            NodeCollationWhitelistAction::Rm(cmd) => {
                use colored::Colorize;
                use control_client::client_api::{ClientAPI, CollatorNodeWhitelistRq};

                let adnl_id_bytes = hex::decode(cmd.adnl_id.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("Invalid hex ADNL ID: {}", e))?;
                if adnl_id_bytes.len() != 32 {
                    anyhow::bail!(
                        "ADNL ID must be 32 bytes (64 hex chars), got {}",
                        adnl_id_bytes.len()
                    );
                }

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client
                    .collator_node_set_whitelisted_validator(&CollatorNodeWhitelistRq {
                        adnl_id: adnl_id_bytes,
                        add: false,
                    })
                    .await?;
                client.shutdown().await?;

                println!(
                    "{} Validator {} removed from whitelist.",
                    "OK".green().bold(),
                    cmd.adnl_id,
                );
                Ok(())
            }
            NodeCollationWhitelistAction::Disable => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client.collator_node_set_whitelist_enabled(false).await?;
                client.shutdown().await?;

                println!("{} Collation whitelist disabled.", "OK".green().bold());
                Ok(())
            }
            NodeCollationWhitelistAction::Ls(cmd) => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (node_name, mut client) = create_control_client(config_path).await?;
                let result = client.show_collator_node_whitelist().await?;
                client.shutdown().await?;

                if cmd.format == super::output_format::OutputFormat::Json {
                    let obj = serde_json::json!({
                        "node": node_name,
                        "enabled": result.enabled,
                        "adnl_ids": result.adnl_ids,
                    });
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                } else {
                    println!("{}", "Collation Whitelist".cyan().bold());
                    println!("{}", "\u{2500}".repeat(50).dimmed());
                    println!("  Node: {}", node_name.green());
                    println!(
                        "  Enabled: {}",
                        if result.enabled {
                            "yes".green().to_string()
                        } else {
                            "no".yellow().to_string()
                        }
                    );
                    println!();

                    if result.adnl_ids.is_empty() {
                        println!("  {}", "No validators in whitelist.".dimmed());
                    } else {
                        println!("  Whitelisted validators:");
                        for adnl_id in &result.adnl_ids {
                            println!("    - {}", adnl_id);
                        }
                    }
                    println!();
                }
                Ok(())
            }
        }
    }
}

impl NodeOverlayCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeOverlayAction::Add(cmd) => cmd.run(config_path).await,
            NodeOverlayAction::Ls => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (node_name, mut client) = create_control_client(config_path).await?;
                let result = client.show_custom_overlays().await?;
                client.shutdown().await?;

                println!("{}", "Custom Overlays".cyan().bold());
                println!("{}", "\u{2500}".repeat(50).dimmed());
                println!("  Node: {}", node_name.green());
                println!();

                if result.overlays.is_empty() {
                    println!("  {}", "No custom overlays configured.".dimmed());
                } else {
                    for overlay in &result.overlays {
                        println!("  Overlay: {}", overlay.name.green());
                        println!(
                            "    Nodes: {}  Sender shards: {}  Skip public msg send: {}  Use QUIC: {}",
                            overlay.nodes.len(),
                            overlay.sender_shards.len(),
                            overlay.skip_public_msg_send,
                            overlay.use_quic,
                        );
                        for node in &overlay.nodes {
                            println!(
                                "    - {}  msg_sender={}  priority={}  block_sender={}",
                                node.adnl_id,
                                node.msg_sender,
                                node.msg_sender_priority,
                                node.block_sender,
                            );
                        }
                    }
                }
                println!();
                Ok(())
            }
            NodeOverlayAction::Rm(cmd) => cmd.run(config_path).await,
        }
    }
}

impl NodeOverlayAddCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use control_client::client_api::{ClientAPI, CustomOverlayConfig};

        let json = std::fs::read_to_string(&self.config_file).map_err(|e| {
            anyhow::anyhow!("Failed to read config file '{}': {}", self.config_file, e)
        })?;

        let config: CustomOverlayConfig = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Failed to parse overlay config JSON: {}", e))?;

        let overlay_name = config.name.clone();

        let (_node_name, mut client) = create_control_client(config_path).await?;
        client.add_custom_overlay(&config).await?;
        client.shutdown().await?;

        println!("{} Custom overlay '{}' added.", "OK".green().bold(), overlay_name,);
        Ok(())
    }
}

impl NodeOverlayRmCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use control_client::client_api::ClientAPI;

        let (_node_name, mut client) = create_control_client(config_path).await?;
        client.del_custom_overlay(&self.name).await?;
        client.shutdown().await?;

        println!("{} Custom overlay '{}' removed.", "OK".green().bold(), self.name,);
        Ok(())
    }
}

impl NodeNetCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeNetAction::Quic(cmd) => cmd.run(config_path).await,
        }
    }
}

impl NodeNetQuicCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NodeNetQuicAction::Set(cmd) => {
                use colored::Colorize;
                use control_client::client_api::ClientAPI;

                let (_node_name, mut client) = create_control_client(config_path).await?;
                client.add_quic_addr(0, cmd.port as i32, vec![], vec![]).await?;
                client.shutdown().await?;

                println!("{} QUIC address configured on port {}.", "OK".green().bold(), cmd.port,);
                Ok(())
            }
        }
    }
}
