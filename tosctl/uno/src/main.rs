//! `tosctl-uno` — Uno Workchain (wc=2) wallet CLI, P.6 foundation scaffold.
//!
//! This commit wires the clap subcommand surface and module layout. Each
//! subcommand is a stub returning "not yet implemented"; subsequent commits
//! on this branch fill them in — see `README.md` for the landing plan.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

/// Uno Workchain (wc=2) wallet CLI — P.6 foundation build.
#[derive(Debug, Parser)]
#[command(name = "tosctl-uno", version = tosctl_uno::VERSION, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Derive the Uno key hierarchy from a TOS mnemonic or seed file.
    Keygen,
    /// Generate a diversified address from the wallet's FVK.
    Address,
    /// Scan a block range for notes belonging to this wallet.
    Scan,
    /// Summarize balance = Σ unspent(owned notes).
    Balance,
    /// Fetch chain-info from an RPC endpoint (smoke test).
    ChainInfo,
    /// Build, prove, and submit a Transfer. **Not implemented in P.6
    /// foundation** — needs the full P.2 Transfer AIR.
    Send,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let name = match cli.cmd {
        Command::Keygen    => "keygen",
        Command::Address   => "address",
        Command::Scan      => "scan",
        Command::Balance   => "balance",
        Command::ChainInfo => "chain-info",
        Command::Send      => "send",
    };
    Err(anyhow!(
        "tosctl-uno {name}: scaffold only — implementation arrives in the next \
         commit on this branch. See tosctl/uno/README.md for the landing plan."
    ))
}
