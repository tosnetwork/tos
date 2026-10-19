/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#![cfg(feature = "secrets-vault-cli")]

mod delete;
mod generate;
mod get;
mod import;
mod init;
mod list;
mod migrate;
mod sign;
mod utils;
mod verify;

use crate::utils::{parse_hex_bytes, HexBytes};
use clap::Parser;
use colored::Colorize;
use secrets_vault::types::algorithm::Algorithm;
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(name = "vault")]
#[command(version = "0.1.0")]
#[command(about = "CLI client for SecretsVault operations", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Init {},
    List {},
    Delete {
        #[arg(required = true)]
        secret_ids: Vec<String>,
    },
    Import {
        #[arg(long, required = true)]
        secret_id: String,

        #[arg(long, default_value = "None")]
        algorithm: String,

        #[arg(long)]
        extractable: bool,

        #[arg(long)]
        overwrite: bool,

        /// Read the hex-encoded secret from a file owned by you with mode 0600.
        #[arg(long, conflicts_with = "data_fd")]
        data_file: Option<PathBuf>,

        /// Read the hex-encoded secret from an inherited file descriptor
        /// (0 for standard input, or 3 and above).
        #[arg(long, conflicts_with = "data_file")]
        data_fd: Option<i32>,

        /// No longer accepted; kept only to explain the replacement.
        #[arg(long, hide = true, allow_hyphen_values = true)]
        data: Option<String>,
    },
    Generate {
        #[arg(long, required = true)]
        secret_id: String,

        #[arg(long, required = true)]
        algorithm: String,

        #[arg(long)]
        extractable: bool,
    },
    Get {
        #[arg(long, required = true)]
        secret_id: String,
    },
    Sign {
        #[arg(long, required = true)]
        secret_id: String,

        #[arg(long, required = true, value_parser = parse_hex_bytes, action = clap::ArgAction::Set)]
        data: HexBytes,
    },
    Verify {
        #[arg(long, required = true)]
        secret_id: String,

        #[arg(long, required = true, value_parser = parse_hex_bytes, action = clap::ArgAction::Set)]
        data: HexBytes,

        #[arg(long, required = true, value_parser = parse_hex_bytes, action = clap::ArgAction::Set)]
        signature: HexBytes,
    },
    Migrate {},
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init {} => init::execute().await,
        Commands::List {} => list::execute().await,
        Commands::Delete { secret_ids } => delete::execute(&secret_ids).await,
        Commands::Import {
            secret_id,
            algorithm,
            extractable,
            overwrite,
            data_file,
            data_fd,
            data,
        } => {
            let algo: Algorithm = match algorithm.parse() {
                Ok(algo) => algo,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            match import::read_import_secret(data.is_some(), data_file.as_deref(), data_fd) {
                Ok(secret) => {
                    import::execute(&secret_id, &secret, algo, extractable, overwrite).await
                }
                Err(e) => Err(e),
            }
        }
        Commands::Generate { secret_id, algorithm, extractable } => {
            let algo: Algorithm = match algorithm.parse() {
                Ok(algo) => algo,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            generate::execute(&secret_id, algo, extractable).await
        }
        Commands::Get { secret_id } => get::execute(&secret_id).await,
        Commands::Sign { secret_id, data } => sign::execute(&secret_id, data.0.as_slice()).await,
        Commands::Verify { secret_id, data, signature } => {
            verify::execute(&secret_id, data.0.as_slice(), signature.0.as_slice()).await
        }
        Commands::Migrate {} => migrate::execute().await,
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
