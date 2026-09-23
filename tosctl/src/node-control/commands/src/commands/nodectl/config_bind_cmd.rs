/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::nodectl::{output_format::OutputFormat, utils::save_config};
use colored::Colorize;
use common::app_config::{AppConfig, BindingStatus, NodeBinding};
use std::path::Path;

#[derive(clap::Args, Clone)]
#[command(about = "Manage node bindings in the configuration")]
pub struct BindCmd {
    #[command(subcommand)]
    action: BindAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum BindAction {
    /// Bind a wallet (and optionally a pool) to a node
    Add(BindAddCmd),
    /// Remove a node binding (only allowed when binding is in idle state)
    Rm(BindRmCmd),
    /// List all node bindings
    Ls(BindLsCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Bind a wallet and optional pool to a node")]
pub struct BindAddCmd {
    #[arg(short = 'n', long = "node", help = "Node name (must exist in nodes)")]
    node: String,
    #[arg(short = 'w', long = "wallet", help = "Wallet name (must exist in wallets)")]
    wallet: String,
    #[arg(short = 'p', long = "pool", help = "Pool name (optional, must exist in pools)")]
    pool: Option<String>,
    #[arg(
        long = "controller-birth-state-init-boc",
        help = "Absolute path to the controller's original public deployment StateInit BOC"
    )]
    controller_birth_state_init_boc: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a node binding")]
pub struct BindRmCmd {
    #[arg(short = 'n', long = "node", help = "Node name to remove from bindings")]
    node: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "List all node bindings")]
pub struct BindLsCmd {
    #[arg(long = "format", default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
}

impl BindCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        match &self.action {
            BindAction::Add(cmd) => cmd.run(path).await,
            BindAction::Rm(cmd) => cmd.run(path).await,
            BindAction::Ls(cmd) => cmd.run(path).await,
        }
    }
}

impl BindAddCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;

        if !config.nodes.contains_key(&self.node) {
            anyhow::bail!("Node '{}' not found in configuration", self.node);
        }

        if !config.wallets.contains_key(&self.wallet) {
            anyhow::bail!("Wallet '{}' not found in configuration", self.wallet);
        }

        if let Some(pool_name) = &self.pool {
            if !config.pools.contains_key(pool_name) {
                anyhow::bail!("Pool '{}' not found in configuration", pool_name);
            }
            for (node_name, binding) in &config.bindings {
                if binding.pool.as_deref() == Some(pool_name) && *node_name != self.node {
                    anyhow::bail!(
                        "Pool '{}' is already bound to node '{}'. A pool can only be bound to one node.",
                        pool_name,
                        node_name
                    );
                }
            }
        }

        let previous = config.bindings.get(&self.node);
        let birth_artifact = select_birth_artifact_path(
            self.controller_birth_state_init_boc.as_deref(),
            previous,
            self.pool.as_deref(),
        )?;
        let binding = NodeBinding {
            wallet: self.wallet.clone(),
            pool: self.pool.clone(),
            controller_birth_state_init_boc: birth_artifact,
            enable: false,
            status: Default::default(),
        };
        config.bindings.insert(self.node.clone(), binding);
        save_config(&config, path)?;

        let pool_info = self.pool.as_deref().map(|p| format!(", pool='{}'", p)).unwrap_or_default();
        println!(
            "\n{} Binding added: node='{}', wallet='{}'{}\n",
            "OK".green().bold(),
            self.node,
            self.wallet,
            pool_info
        );
        Ok(())
    }
}

fn select_birth_artifact_path(
    requested: Option<&str>,
    previous: Option<&NodeBinding>,
    pool: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if requested.is_some() && pool.is_none() {
        anyhow::bail!("controller birth StateInit BOC requires a pool binding");
    }
    let value = requested.or_else(|| {
        previous.and_then(|old| {
            (old.pool.as_deref() == pool)
                .then(|| old.controller_birth_state_init_boc.as_deref())
                .flatten()
        })
    });
    if let Some(path) = value {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "controller birth StateInit BOC path must be absolute"
        );
    }
    Ok(value.map(str::to_string))
}

#[cfg(test)]
mod birth_artifact_binding_tests {
    use super::*;

    #[test]
    fn binding_preserves_artifact_only_for_the_same_pool() {
        let old = NodeBinding {
            wallet: "wallet".into(),
            pool: Some("pool-a".into()),
            controller_birth_state_init_boc: Some("/var/lib/tos/controller.boc".into()),
            enable: false,
            status: Default::default(),
        };
        assert_eq!(
            select_birth_artifact_path(None, Some(&old), Some("pool-a")).unwrap(),
            old.controller_birth_state_init_boc
        );
        assert_eq!(select_birth_artifact_path(None, Some(&old), Some("pool-b")).unwrap(), None);
        let error = select_birth_artifact_path(Some("relative.boc"), Some(&old), Some("pool-a"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be absolute"), "wrong refusal: {error}");
        let error = select_birth_artifact_path(Some("/tmp/controller.boc"), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a pool"), "wrong refusal: {error}");
    }
}

impl BindRmCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;

        let binding = config
            .bindings
            .get(&self.node)
            .ok_or_else(|| anyhow::anyhow!("Binding for node '{}' not found", self.node))?;

        if binding.status != BindingStatus::Idle {
            anyhow::bail!(
                "Cannot remove binding for node '{}': status is '{}', must be 'idle'. \
                 Disable elections first and wait for stake recovery to complete.",
                self.node,
                binding.status
            );
        }

        config.bindings.remove(&self.node);
        save_config(&config, path)?;

        println!("\n{} Binding {} removed\n", "OK".green().bold(), self.node);
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct BindingView {
    node: String,
    wallet: String,
    pool: Option<String>,
    enable: bool,
    status: String,
}

impl BindLsCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let config = AppConfig::load(path)?;

        if config.bindings.is_empty() {
            match self.format {
                OutputFormat::Json => println!("[]"),
                OutputFormat::Table => println!("\n{}\n", "No bindings configured".yellow()),
            }
            return Ok(());
        }

        let mut views: Vec<BindingView> = config
            .bindings
            .into_iter()
            .map(|(node, b)| BindingView {
                node,
                wallet: b.wallet,
                pool: b.pool,
                enable: b.enable,
                status: b.status.to_string(),
            })
            .collect();
        views.sort_by(|a, b| a.node.cmp(&b.node));

        match self.format {
            OutputFormat::Json => print_bindings_json(&views)?,
            OutputFormat::Table => print_bindings_table(&views),
        }
        Ok(())
    }
}

fn print_bindings_json(views: &[BindingView]) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(views)?);
    Ok(())
}

fn print_bindings_table(views: &[BindingView]) {
    println!("\n{} {} ({})\n", "OK".green().bold(), "Bindings:".green(), views.len());
    println!(
        "  {:<20} {:<20} {:<20} {:<12} {}",
        "Node".cyan().bold(),
        "Wallet".cyan().bold(),
        "Pool".cyan().bold(),
        "Enable".cyan().bold(),
        "Status".cyan().bold(),
    );
    println!("  {}", "─".repeat(90).dimmed());

    for v in views {
        let enable_str = if v.enable { "yes".green().to_string() } else { "no".red().to_string() };
        println!(
            "  {:<20} {:<20} {:<20} {:<21} {}",
            v.node,
            v.wallet,
            v.pool.as_deref().unwrap_or("-"),
            enable_str,
            v.status,
        );
    }
    println!();
}
