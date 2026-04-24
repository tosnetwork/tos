/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Admin commands (expert only)
#[derive(clap::Args, Clone)]
#[command(about = "Administrative commands (expert only)")]
pub struct AdminCmd {
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
    action: AdminAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AdminAction {
    /// Manage BTC teleport
    BtcTeleport(AdminBtcTeleportCmd),
}

#[derive(clap::Args, Clone)]
pub struct AdminBtcTeleportCmd {
    #[command(subcommand)]
    action: AdminBtcTeleportAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AdminBtcTeleportAction {
    /// Remove BTC teleport (expert only)
    Rm(AdminBtcTeleportRmCmd),
}

#[derive(clap::Args, Clone)]
pub struct AdminBtcTeleportRmCmd {}

// ── Implementations ──────────────────────────────────────────────────

impl AdminCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AdminAction::BtcTeleport(cmd) => cmd.run().await,
        }
    }
}

impl AdminBtcTeleportCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            AdminBtcTeleportAction::Rm(cmd) => cmd.run().await,
        }
    }
}

impl AdminBtcTeleportRmCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        println!("{}", "BTC Teleport Removal".cyan().bold());
        println!("{}", "\u{2500}".repeat(40).dimmed());
        println!();
        println!("  {}", "This command removes BTC teleport integration.".white());
        println!("  {}", "It is an expert-only operation inherited from legacy operator tooling.".white());
        println!();
        println!("  {}", "BTC teleport is not used in standard TOS validator operations.".yellow());
        println!("  {}", "If you need this functionality, contact TOS support.".dimmed());
        println!();
        Ok(())
    }
}
