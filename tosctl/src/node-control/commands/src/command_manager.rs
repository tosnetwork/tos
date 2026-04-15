/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::cli_cmd::Commands;
use common::{log::setup_log, task_cancellation::CancellationCtx};

pub struct CommandManager {}

impl CommandManager {
    pub async fn execute(
        cmd: &Commands,
        cancellation_ctx: CancellationCtx,
    ) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
        let _log_guard = if !matches!(cmd, Commands::Service(_)) { setup_log(None)? } else { None };

        match &cmd {
            // ─── Existing commands ───────────────────────────────────
            Commands::GetConfigParam(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Api(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Config(cmd) => {
                cmd.run(cancellation_ctx).await?;
                Ok(None)
            }
            Commands::Deploy(cmd) => {
                cmd.run(cancellation_ctx).await?;
                Ok(None)
            }
            Commands::Auth(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Key(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Service(cmd) => Ok(Some(cmd.run(cancellation_ctx).await?)),

            // ─── New operator commands ───────────────────────────────
            Commands::Host(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Backup(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Wallet(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Pool(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Vote(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Node(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Account(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Tx(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Observe(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Admin(cmd) => {
                cmd.run().await?;
                Ok(None)
            }
            Commands::Install(cmd) => {
                cmd.run().await?;
                Ok(None)
            }

            // ─── Hidden shortcuts (mytonctrl-style mnemonics) ───────
            Commands::WalletLs => {
                use crate::commands::nodectl::wallet_cmd::WalletCmd;
                WalletCmd::run_ls_shortcut().await?;
                Ok(None)
            }
            Commands::ValidatorList => {
                use crate::commands::nodectl::observe_cmd::ObserveCmd;
                ObserveCmd::run_validators_shortcut().await?;
                Ok(None)
            }
            Commands::Efficiency => {
                use crate::commands::nodectl::observe_cmd::ObserveCmd;
                ObserveCmd::run_efficiency_shortcut().await?;
                Ok(None)
            }
            Commands::OfferList => {
                use crate::commands::nodectl::vote_cmd::VoteCmd;
                VoteCmd::run_offer_ls_shortcut().await?;
                Ok(None)
            }
            Commands::ElectionList => {
                use crate::commands::nodectl::vote_cmd::VoteCmd;
                VoteCmd::run_election_ls_shortcut().await?;
                Ok(None)
            }
        }
    }
}
