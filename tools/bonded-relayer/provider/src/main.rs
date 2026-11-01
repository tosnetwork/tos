// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
mod bootstrap;
mod candidate;
mod chain;
mod config;
mod evidence;
mod funding;
mod identity;
mod nonacceptance;
mod pinned_helper;
mod prepared;
mod private_io;
mod protocol;
mod provider;
mod provision;
mod quotes;
mod simulation;
mod store;
mod transport;
use anyhow::{bail, Result};
use std::io::Write;
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    if args.len() == 3 && args[0] == "--provision" {
        return runtime.block_on(provision::run(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
        ));
    }
    if args.len() == 2 && args[0] == "--bootstrap" {
        return runtime.block_on(bootstrap::run(&args[1]));
    }
    if args.len() != 2 || args[0] != "--stdio" {
        bail!("expected --stdio OPERATION or --provision INPUT NEW_DIRECTORY");
    }
    let invocation = protocol::Invocation::read(std::io::stdin().lock(), &args[1])?;
    let outcome = runtime.block_on(provider::dispatch(&invocation.operation, &invocation.payload));
    let result = invocation.reply(outcome)?;
    std::io::stdout().lock().write_all(&result)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("BR1 native invocation refused");
            std::process::ExitCode::from(2)
        }
    }
}
