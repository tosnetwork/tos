/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::app_cli_args::AppCliArgs;
use commands::command_manager::CommandManager;
use common::{
    os_signals,
    task_cancellation::{CancellationCtx, CancellationReason},
};
use std::process::exit;

mod app_cli_args;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let code = commands::exit_code(&error);
            eprintln!("{error:#}");
            std::process::ExitCode::from(code)
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let args = AppCliArgs::parse()?;

    // Spawn signal handler task
    let mut cancellation_ctx = CancellationCtx::new();
    let signals_cancellation_ctx = cancellation_ctx.clone();
    let signal_handle = tokio::spawn(async move {
        os_signals::wait(signals_cancellation_ctx).await;
    });

    let cmd = args.command.as_ref().unwrap_or_else(|| {
        AppCliArgs::print_help();
        exit(0);
    });

    let run_handle = match CommandManager::execute(cmd, cancellation_ctx.clone()).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("command failed")),
    };

    // Wait for the service to complete. Its error, or its panic, becomes the
    // process's exit status after the orderly shutdown below, so a supervisor
    // sees a failed service as failed.
    let outcome = match run_handle {
        Some(run_handle) => match run_handle.await {
            Ok(result) => result,
            Err(join_error) => Err(anyhow::anyhow!("service task did not complete: {join_error}")),
        },
        None => Ok(()),
    };
    if !cancellation_ctx.is_cancelled() {
        cancellation_ctx.cancel(CancellationReason::GracefullyShutdown());
    }
    // Wait for signal handler to complete
    let _ = signal_handle.await;
    tracing::debug!("shutdown completed");
    outcome.map_err(|e| e.context("service failed"))
}
