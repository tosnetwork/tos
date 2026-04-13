/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Observability commands
#[derive(clap::Args, Clone)]
#[command(about = "Observe validator network state")]
pub struct ObserveCmd {
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
    action: ObserveAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ObserveAction {
    /// Show validator list/table
    Validators(ObserveValidatorsCmd),
    /// Show validator efficiency view
    Efficiency(ObserveEfficiencyCmd),
    /// Manage alerts
    Alert(ObserveAlertCmd),
    /// Manage metrics
    Metrics(ObserveMetricsCmd),
}

// ── Validators ───────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Show validator list/table")]
pub struct ObserveValidatorsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

// ── Efficiency ───────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Show validator efficiency view")]
pub struct ObserveEfficiencyCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

// ── Alert ────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage alerts")]
pub struct ObserveAlertCmd {
    #[command(subcommand)]
    action: ObserveAlertAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ObserveAlertAction {
    /// Bootstrap alert bot
    Setup(ObserveAlertSetupCmd),
    /// Enable an alert
    Enable(ObserveAlertEnableCmd),
    /// Disable an alert
    Disable(ObserveAlertDisableCmd),
    /// List configured alerts
    Ls(ObserveAlertLsCmd),
    /// Fire a test alert
    Test(ObserveAlertTestCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Bootstrap alert bot")]
pub struct ObserveAlertSetupCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Enable an alert")]
pub struct ObserveAlertEnableCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Disable an alert")]
pub struct ObserveAlertDisableCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "List configured alerts")]
pub struct ObserveAlertLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Fire a test alert")]
pub struct ObserveAlertTestCmd {}

// ── Metrics ──────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage metrics")]
pub struct ObserveMetricsCmd {
    #[command(subcommand)]
    action: ObserveMetricsAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ObserveMetricsAction {
    /// Show current metrics
    Show(ObserveMetricsShowCmd),
    /// Push metrics to remote endpoint
    Push(ObserveMetricsPushCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Show current metrics")]
pub struct ObserveMetricsShowCmd {
    #[arg(long, help = "Prometheus metrics endpoint URL")]
    endpoint: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Push metrics to remote endpoint")]
pub struct ObserveMetricsPushCmd {
    #[arg(long, help = "Prometheus push gateway URL")]
    endpoint: Option<String>,

    #[arg(long, help = "Prometheus metrics source URL to scrape before pushing")]
    source: Option<String>,

    #[arg(long, default_value = "tosctl", help = "Job label for push gateway")]
    job: String,
}

// ── run() dispatch ───────────────────────────────────────────────────

impl ObserveCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            ObserveAction::Validators(cmd) => cmd.run(&self.config).await,
            ObserveAction::Efficiency(cmd) => cmd.run(&self.config).await,
            ObserveAction::Alert(cmd) => cmd.run(&self.config).await,
            ObserveAction::Metrics(cmd) => cmd.run().await,
        }
    }

    /// Shortcut entry point for `tosctl vl` (observe validators).
    pub async fn run_validators_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = ObserveValidatorsCmd {
            format: super::output_format::OutputFormat::Table,
        };
        cmd.run(&config_path).await
    }

    /// Shortcut entry point for `tosctl ef` (observe efficiency).
    pub async fn run_efficiency_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = ObserveEfficiencyCmd {
            format: super::output_format::OutputFormat::Table,
        };
        cmd.run(&config_path).await
    }
}

impl ObserveValidatorsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use chain_block::ConfigParamEnum;
        use colored::Colorize;
        use common::{app_config::AppConfig, time_format::format_ts};
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let config_param = rpc_client.get_config_param(34).await?;

        let vset = match config_param {
            ConfigParamEnum::ConfigParam34(param) => param.cur_validators,
            _ => anyhow::bail!("Unexpected config param type for param 34"),
        };

        let since = format_ts(vset.utime_since() as u64);
        let until = format_ts(vset.utime_until() as u64);

        if self.format == super::output_format::OutputFormat::Json {
            let validators: Vec<serde_json::Value> = vset.list().iter().map(|v| {
                let pubkey_hex: String =
                    v.public_key.key_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                serde_json::json!({
                    "public_key": pubkey_hex,
                    "weight": v.weight,
                })
            }).collect();
            let obj = serde_json::json!({
                "since": since,
                "until": until,
                "total": vset.total(),
                "main": vset.main(),
                "validators": validators,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!("{}", "Current Validators (param 34)".bold());
            println!("{}", "\u{2500}".repeat(72));
            println!("  {}  {}", "Since:".bold(), since);
            println!("  {}  {}", "Until:".bold(), until);
            println!("  {}  {}", "Total:".bold(), vset.total());
            println!("  {}   {}", "Main:".bold(), vset.main());
            println!();
            println!(
                "  {:<4} {:<66} {}",
                "#".bold(),
                "Public Key (hex)".bold(),
                "Weight".bold()
            );
            println!("  {}", "\u{2500}".repeat(78));

            for (i, validator) in vset.list().iter().enumerate() {
                let pubkey_hex: String =
                    validator.public_key.key_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                println!("  {:<4} {:<66} {}", i + 1, pubkey_hex, validator.weight);
            }

            println!();
        }
        Ok(())
    }
}

impl ObserveEfficiencyCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use chain_block::ConfigParamEnum;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;

        // Get current validator set (param 34)
        let config_param34 = rpc_client.get_config_param(34).await?;
        let vset = match config_param34 {
            ConfigParamEnum::ConfigParam34(param) => param.cur_validators,
            _ => anyhow::bail!("Unexpected config param type for param 34"),
        };

        let total_validators = vset.total();
        let total_weight = vset.total_weight();

        if self.format == super::output_format::OutputFormat::Json {
            let mut obj = serde_json::json!({
                "current_validators": total_validators,
                "total_weight": total_weight,
            });

            // Get election timing parameters (param 15)
            if let Ok(config_param15) = rpc_client.get_config_param(15).await {
                if let ConfigParamEnum::ConfigParam15(p) = config_param15 {
                    obj["election_params"] = serde_json::json!({
                        "validators_elected_for": p.validators_elected_for,
                        "elections_start_before": p.elections_start_before,
                        "elections_end_before": p.elections_end_before,
                        "stake_held_for": p.stake_held_for,
                    });
                }
            }

            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!("{}", "Validator Efficiency Overview".bold());
            println!("{}", "\u{2500}".repeat(29));
            println!("  {:<24} {}", "Current validators:", total_validators);
            println!("  {:<24} {}", "Total weight:", total_weight);

            // Get election timing parameters (param 15)
            match rpc_client.get_config_param(15).await {
                Ok(config_param15) => {
                    if let ConfigParamEnum::ConfigParam15(p) = config_param15 {
                        let elected_for_hrs =
                            p.validators_elected_for as f64 / 3600.0;

                        println!();
                        println!("  {}", "Election Parameters (param 15)".bold());
                        println!("  {}", "\u{2500}".repeat(18));
                        println!(
                            "  {:<24} {} sec (~{:.1} hrs)",
                            "Elected for:", p.validators_elected_for, elected_for_hrs
                        );
                        println!(
                            "  {:<24} {} sec before",
                            "Elections start:", p.elections_start_before
                        );
                        println!(
                            "  {:<24} {} sec before",
                            "Elections end:", p.elections_end_before
                        );
                        println!(
                            "  {:<24} {} sec after",
                            "Stake held:", p.stake_held_for
                        );
                    } else {
                        println!();
                        println!(
                            "  {}",
                            "Election parameters (param 15): unexpected format".dimmed()
                        );
                    }
                }
                Err(e) => {
                    println!();
                    println!(
                        "  {}",
                        format!("Election parameters (param 15): unavailable ({})", e).dimmed()
                    );
                }
            }

            println!();
        }
        Ok(())
    }
}

impl ObserveAlertCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            ObserveAlertAction::Setup(cmd) => cmd.run(config_path).await,
            ObserveAlertAction::Enable(cmd) => cmd.run(config_path).await,
            ObserveAlertAction::Disable(cmd) => cmd.run(config_path).await,
            ObserveAlertAction::Ls(cmd) => cmd.run(config_path).await,
            ObserveAlertAction::Test(cmd) => cmd.run(config_path).await,
        }
    }
}

impl ObserveAlertSetupCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::save_config;
        use colored::Colorize;
        use common::app_config::{AlertChannel, AlertRule, AppConfig};
        use std::io::{BufRead, Write};
        use std::path::Path;

        println!();
        println!("{}", "Alert Setup".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();

        let path = Path::new(config_path);
        let mut config = AppConfig::load(path)?;

        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut reader = stdin.lock();
        let mut out = stdout.lock();

        // Ask channel type
        write!(out, "  Channel type (telegram/webhook): ")?;
        out.flush()?;
        let mut channel_type = String::new();
        reader.read_line(&mut channel_type)?;
        let channel_type = channel_type.trim().to_lowercase();

        let channel = match channel_type.as_str() {
            "telegram" => {
                write!(
                    out,
                    "  Store bot token via [1] environment variable (recommended) or [2] config file? (1/2): "
                )?;
                out.flush()?;
                let mut storage_choice = String::new();
                reader.read_line(&mut storage_choice)?;
                let storage_choice = storage_choice.trim();

                let (bot_token, bot_token_env) = match storage_choice {
                    "1" | "" => {
                        // Environment variable mode
                        write!(
                            out,
                            "  Env var name for bot token [TOSCTL_TELEGRAM_TOKEN]: "
                        )?;
                        out.flush()?;
                        let mut env_name = String::new();
                        reader.read_line(&mut env_name)?;
                        let env_name = env_name.trim().to_string();
                        let env_name = if env_name.is_empty() {
                            "TOSCTL_TELEGRAM_TOKEN".to_string()
                        } else {
                            env_name
                        };

                        println!(
                            "  {}",
                            format!(
                                "Set the token in your shell: export {}=<your-bot-token>",
                                env_name
                            )
                            .yellow()
                        );

                        (None, Some(env_name))
                    }
                    "2" => {
                        // Inline token mode
                        println!();
                        println!(
                            "  {} The bot token will be stored in plaintext in {}.",
                            "WARNING:".yellow().bold(),
                            config_path
                        );
                        println!(
                            "  {} Protect this file with appropriate permissions (chmod 600).",
                            "WARNING:".yellow().bold(),
                        );
                        println!();

                        write!(out, "  Telegram bot token: ")?;
                        out.flush()?;
                        let mut bot_token = String::new();
                        reader.read_line(&mut bot_token)?;
                        let bot_token = bot_token.trim().to_string();
                        if bot_token.is_empty() {
                            anyhow::bail!("Bot token is required");
                        }
                        (Some(bot_token), None)
                    }
                    other => {
                        anyhow::bail!("Invalid choice: '{}'. Expected 1 or 2.", other);
                    }
                };

                write!(out, "  Telegram chat ID: ")?;
                out.flush()?;
                let mut chat_id = String::new();
                reader.read_line(&mut chat_id)?;
                let chat_id = chat_id.trim().to_string();

                if chat_id.is_empty() {
                    anyhow::bail!("Chat ID is required");
                }

                // Validate that the token is actually available when using env var
                if bot_token.is_none() && bot_token_env.is_some() {
                    let env_name = bot_token_env.as_ref().unwrap();
                    if std::env::var(env_name).unwrap_or_default().is_empty() {
                        println!(
                            "  {} ${} is not set in the current environment.",
                            "Note:".yellow().bold(),
                            env_name
                        );
                        println!(
                            "  {} Alerts will fail until the variable is exported.",
                            "Note:".yellow().bold(),
                        );
                    }
                }

                AlertChannel::Telegram {
                    bot_token,
                    bot_token_env,
                    chat_id,
                }
            }
            "webhook" => {
                write!(out, "  Webhook URL: ")?;
                out.flush()?;
                let mut url = String::new();
                reader.read_line(&mut url)?;
                let url = url.trim().to_string();

                if url.is_empty() {
                    anyhow::bail!("Webhook URL is required");
                }

                AlertChannel::Webhook { url }
            }
            other => {
                anyhow::bail!("Unknown channel type: '{}'. Supported: telegram, webhook", other);
            }
        };

        config.alerts.channels.push(channel);

        // Ask for optional alert rule
        println!();
        write!(out, "  Add alert rule? (sync_lag/balance_low/skip): ")?;
        out.flush()?;
        let mut rule_type = String::new();
        reader.read_line(&mut rule_type)?;
        let rule_type = rule_type.trim().to_lowercase();

        match rule_type.as_str() {
            "sync_lag" => {
                write!(out, "  Threshold (seconds, default 60): ")?;
                out.flush()?;
                let mut threshold = String::new();
                reader.read_line(&mut threshold)?;
                let threshold: u32 = threshold.trim().parse().unwrap_or(60);
                config.alerts.rules.push(AlertRule::SyncLag { threshold_seconds: threshold });
            }
            "balance_low" => {
                write!(out, "  Address to monitor: ")?;
                out.flush()?;
                let mut address = String::new();
                reader.read_line(&mut address)?;
                let address = address.trim().to_string();

                write!(out, "  Threshold (TOS, default 10.0): ")?;
                out.flush()?;
                let mut threshold = String::new();
                reader.read_line(&mut threshold)?;
                let threshold: f64 = threshold.trim().parse().unwrap_or(10.0);

                if address.is_empty() {
                    anyhow::bail!("Address is required for balance_low rule");
                }
                config
                    .alerts
                    .rules
                    .push(AlertRule::BalanceLow { address, threshold_tons: threshold });
            }
            "skip" | "" => {}
            other => {
                println!(
                    "  {}",
                    format!("Unknown rule type '{}', skipping.", other).yellow()
                );
            }
        }

        config.alerts.enabled = true;
        save_config(&config, path)?;

        println!();
        println!(
            "  {} Alert channel configured and saved to {}",
            "OK".green().bold(),
            config_path
        );
        println!();
        Ok(())
    }
}

impl ObserveAlertEnableCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::save_config;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);
        let mut config = AppConfig::load(path)?;

        config.alerts.enabled = true;
        save_config(&config, path)?;

        println!();
        println!("  {} Alerts enabled.", "OK".green().bold());
        println!();
        Ok(())
    }
}

impl ObserveAlertDisableCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::save_config;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use std::path::Path;

        let path = Path::new(config_path);
        let mut config = AppConfig::load(path)?;

        config.alerts.enabled = false;
        save_config(&config, path)?;

        println!();
        println!("  {} Alerts disabled.", "OK".green().bold());
        println!();
        Ok(())
    }
}

impl ObserveAlertLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::{AlertChannel, AlertRule, AppConfig};
        use std::path::Path;

        let path = Path::new(config_path);
        let config = AppConfig::load(path)?;
        let alerts = &config.alerts;

        if self.format == super::output_format::OutputFormat::Json {
            let channels: Vec<serde_json::Value> = alerts.channels.iter().map(|ch| {
                match ch {
                    AlertChannel::Telegram { bot_token_env, chat_id, .. } => {
                        let source = if let Some(env_name) = bot_token_env {
                            format!("env:{}", env_name)
                        } else {
                            "config (inline)".to_string()
                        };
                        serde_json::json!({
                            "type": "telegram",
                            "chat_id": chat_id,
                            "token_source": source,
                        })
                    }
                    AlertChannel::Webhook { url } => {
                        serde_json::json!({"type": "webhook", "url": url})
                    }
                }
            }).collect();
            let rules: Vec<serde_json::Value> = alerts.rules.iter().map(|rule| {
                match rule {
                    AlertRule::SyncLag { threshold_seconds } => {
                        serde_json::json!({"type": "sync_lag", "threshold_seconds": threshold_seconds})
                    }
                    AlertRule::BalanceLow { address, threshold_tons } => {
                        serde_json::json!({"type": "balance_low", "address": address, "threshold_tons": threshold_tons})
                    }
                }
            }).collect();
            let obj = serde_json::json!({
                "enabled": alerts.enabled,
                "channels": channels,
                "rules": rules,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!("{}", "Alert Configuration".cyan().bold());
            println!("{}", "\u{2500}".repeat(50).dimmed());
            println!(
                "  {:<16} {}",
                "Enabled:".bold(),
                if alerts.enabled {
                    "Yes".green().to_string()
                } else {
                    "No".yellow().to_string()
                }
            );
            println!();

            // Channels
            println!("  {}", "Channels".bold());
            if alerts.channels.is_empty() {
                println!("    {}", "(none configured)".dimmed());
            } else {
                println!(
                    "    {:<4} {:<12} {}",
                    "#".bold(),
                    "Type".bold(),
                    "Details".bold()
                );
                println!("    {}", "\u{2500}".repeat(46));
                for (i, ch) in alerts.channels.iter().enumerate() {
                    match ch {
                        AlertChannel::Telegram {
                            bot_token_env,
                            chat_id,
                            ..
                        } => {
                            let source = if let Some(env_name) = bot_token_env {
                                format!("token=env:{}", env_name)
                            } else {
                                "token=config".to_string()
                            };
                            println!(
                                "    {:<4} {:<12} chat_id={} {}",
                                i + 1,
                                "telegram",
                                chat_id,
                                source
                            );
                        }
                        AlertChannel::Webhook { url } => {
                            println!("    {:<4} {:<12} url={}", i + 1, "webhook", url);
                        }
                    }
                }
            }
            println!();

            // Rules
            println!("  {}", "Rules".bold());
            if alerts.rules.is_empty() {
                println!("    {}", "(none configured)".dimmed());
            } else {
                println!(
                    "    {:<4} {:<14} {}",
                    "#".bold(),
                    "Type".bold(),
                    "Parameters".bold()
                );
                println!("    {}", "\u{2500}".repeat(46));
                for (i, rule) in alerts.rules.iter().enumerate() {
                    match rule {
                        AlertRule::SyncLag { threshold_seconds } => {
                            println!(
                                "    {:<4} {:<14} threshold={}s",
                                i + 1,
                                "sync_lag",
                                threshold_seconds
                            );
                        }
                        AlertRule::BalanceLow { address, threshold_tons } => {
                            let addr_display = if address.len() > 20 {
                                format!("{}...", &address[..20])
                            } else {
                                address.clone()
                            };
                            println!(
                                "    {:<4} {:<14} addr={} threshold={} TOS",
                                i + 1,
                                "balance_low",
                                addr_display,
                                threshold_tons
                            );
                        }
                    }
                }
            }

            println!();
        }
        Ok(())
    }
}

impl ObserveAlertTestCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;
        use common::app_config::{AlertChannel, AppConfig};
        use std::path::Path;

        let path = Path::new(config_path);
        let config = AppConfig::load(path)?;
        let alerts = &config.alerts;

        println!();
        println!("{}", "Alert Test".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();

        if alerts.channels.is_empty() {
            println!(
                "  {}",
                "No alert channels configured. Run 'observe alert setup' first.".yellow()
            );
            println!();
            return Ok(());
        }

        let test_message = "tosctl alert test: this is a test notification from your TOS validator node control tool.";

        for (i, channel) in alerts.channels.iter().enumerate() {
            match channel {
                AlertChannel::Telegram { chat_id, .. } => {
                    println!("  Channel {} (telegram, chat_id={}):", i + 1, chat_id);
                    let resolved_token = match channel.resolve_telegram_token() {
                        Ok(t) => t,
                        Err(e) => {
                            println!(
                                "    {} Cannot resolve bot token: {}",
                                "FAIL".red().bold(),
                                e
                            );
                            continue;
                        }
                    };
                    let url = format!(
                        "https://api.telegram.org/bot{}/sendMessage",
                        resolved_token
                    );
                    let payload = serde_json::json!({
                        "chat_id": chat_id,
                        "text": test_message,
                        "parse_mode": "HTML"
                    });
                    match reqwest::Client::new()
                        .post(&url)
                        .json(&payload)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                println!(
                                    "    {} Test message sent successfully.",
                                    "OK".green().bold()
                                );
                            } else {
                                let body = resp
                                    .text()
                                    .await
                                    .unwrap_or_else(|_| "(no body)".to_string());
                                println!(
                                    "    {} HTTP {}: {}",
                                    "FAIL".red().bold(),
                                    status,
                                    body
                                );
                            }
                        }
                        Err(e) => {
                            println!(
                                "    {} Request failed: {}",
                                "FAIL".red().bold(),
                                e
                            );
                        }
                    }
                }
                AlertChannel::Webhook { url } => {
                    println!("  Channel {} (webhook, url={}):", i + 1, url);
                    let payload = serde_json::json!({
                        "source": "tosctl",
                        "level": "test",
                        "message": test_message,
                        "timestamp": chrono_now_iso()
                    });
                    match reqwest::Client::new()
                        .post(url)
                        .json(&payload)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                println!(
                                    "    {} Test message sent successfully.",
                                    "OK".green().bold()
                                );
                            } else {
                                let body = resp
                                    .text()
                                    .await
                                    .unwrap_or_else(|_| "(no body)".to_string());
                                println!(
                                    "    {} HTTP {}: {}",
                                    "FAIL".red().bold(),
                                    status,
                                    body
                                );
                            }
                        }
                        Err(e) => {
                            println!(
                                "    {} Request failed: {}",
                                "FAIL".red().bold(),
                                e
                            );
                        }
                    }
                }
            }
        }

        println!();
        Ok(())
    }
}

/// Returns current timestamp in ISO 8601 format (no chrono dependency).
fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

impl ObserveMetricsCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            ObserveMetricsAction::Show(cmd) => cmd.run().await,
            ObserveMetricsAction::Push(cmd) => cmd.run().await,
        }
    }
}

impl ObserveMetricsShowCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        let url = self
            .endpoint
            .as_deref()
            .unwrap_or("http://127.0.0.1:9100/metrics");

        println!();
        println!("{}", "Metrics".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();
        println!("  Fetching metrics from {} ...", url.white().bold());
        println!();

        let client = reqwest::Client::new();
        match client
            .get(url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    println!(
                        "  {} HTTP {} from {}",
                        "FAIL".red().bold(),
                        resp.status(),
                        url
                    );
                    println!(
                        "  {}",
                        "Ensure validator-engine is running with --exporter-address"
                            .dimmed()
                    );
                    println!();
                    return Ok(());
                }
                let text = resp.text().await?;
                if text.is_empty() {
                    println!("  No metrics returned from {}", url);
                } else {
                    println!("{}", text);
                }
            }
            Err(e) => {
                println!(
                    "  {} Failed to fetch metrics from {}: {}",
                    "FAIL".red().bold(),
                    url,
                    e
                );
                println!(
                    "  {}",
                    "Ensure validator-engine is running with --exporter-address"
                        .dimmed()
                );
            }
        }

        println!();
        Ok(())
    }
}

impl ObserveMetricsPushCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        println!();
        println!("{}", "Metrics Push".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();

        let gateway_url = match self.endpoint.as_deref() {
            Some(url) => url,
            None => {
                println!(
                    "  {} --endpoint is required (Prometheus push gateway URL)",
                    "ERROR".red().bold()
                );
                println!();
                println!(
                    "  Example: tosctl observe metrics push --endpoint http://pushgateway:9091"
                );
                println!();
                return Ok(());
            }
        };

        // Scrape metrics from the source (validator exporter)
        let source_url = self
            .source
            .as_deref()
            .unwrap_or("http://127.0.0.1:9100/metrics");

        println!(
            "  Scraping metrics from {} ...",
            source_url.white().bold()
        );

        let client = reqwest::Client::new();
        let metrics_text = match client
            .get(source_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    println!(
                        "  {} HTTP {} from source {}",
                        "FAIL".red().bold(),
                        resp.status(),
                        source_url
                    );
                    println!();
                    return Ok(());
                }
                resp.text().await?
            }
            Err(e) => {
                println!(
                    "  {} Failed to scrape metrics from {}: {}",
                    "FAIL".red().bold(),
                    source_url,
                    e
                );
                println!(
                    "  {}",
                    "Ensure validator-engine is running with --exporter-address"
                        .dimmed()
                );
                println!();
                return Ok(());
            }
        };

        if metrics_text.is_empty() {
            println!("  No metrics returned from source {}", source_url);
            println!();
            return Ok(());
        }

        // Push to the gateway
        let push_url = format!(
            "{}/metrics/job/{}",
            gateway_url.trim_end_matches('/'),
            self.job
        );
        println!(
            "  Pushing to {} ...",
            push_url.white().bold()
        );

        match client
            .post(&push_url)
            .header("Content-Type", "text/plain")
            .body(metrics_text)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    println!(
                        "  {} Metrics pushed successfully to {}",
                        "OK".green().bold(),
                        push_url
                    );
                } else {
                    let status = resp.status();
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "(no body)".to_string());
                    println!(
                        "  {} HTTP {}: {}",
                        "FAIL".red().bold(),
                        status,
                        body
                    );
                }
            }
            Err(e) => {
                println!(
                    "  {} Failed to push metrics to {}: {}",
                    "FAIL".red().bold(),
                    push_url,
                    e
                );
            }
        }

        println!();
        Ok(())
    }
}
