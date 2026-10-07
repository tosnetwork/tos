/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::nodectl::utils::save_config;
use colored::Colorize;
use common::app_config::{AppConfig, EndpointEntry};
use secrets_vault::secret_input::{read_secret, select_source, trim_ascii};
use std::path::{Path, PathBuf};

#[derive(clap::Args, Clone)]
#[command(about = "Manage chain RPC endpoint configuration")]
pub struct ChainRpcCmd {
    #[command(subcommand)]
    action: ChainRpcAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ChainRpcAction {
    /// Set chain RPC url and optional api key
    Set(ChainRpcSetCmd),
    /// Add one or more failover endpoint URLs
    Add(ChainRpcAddCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Set chain RPC url and optional api key")]
pub struct ChainRpcSetCmd {
    #[arg(short = 'u', long = "url")]
    url: String,
    #[command(flatten)]
    secret: ApiKeyInput,
}

#[derive(clap::Args, Clone)]
#[command(about = "Add one or more failover endpoint URLs for chain RPC")]
pub struct ChainRpcAddCmd {
    #[arg(short = 'u', long = "url", required = true)]
    urls: Vec<String>,
    /// Per-endpoint API key applied to all URLs in this invocation.
    /// When omitted, the endpoints inherit the global api_key.
    #[command(flatten)]
    secret: ApiKeyInput,
}

#[derive(clap::Args, Clone)]
pub struct ApiKeyInput {
    /// Read the API key from an operator-owned mode-0600 file.
    #[arg(long, conflicts_with_all = ["api_key_fd", "api_key_prompt"])]
    api_key_file: Option<PathBuf>,
    /// Read the API key from a protected file descriptor or pipe.
    #[arg(long, conflicts_with = "api_key_prompt")]
    api_key_fd: Option<i32>,
    /// Read the API key with terminal echo disabled.
    #[arg(long)]
    api_key_prompt: bool,
}

impl ApiKeyInput {
    fn read(&self) -> anyhow::Result<Option<String>> {
        if self.api_key_file.is_none() && self.api_key_fd.is_none() && !self.api_key_prompt {
            return Ok(None);
        }
        let source = select_source(
            self.api_key_file.as_deref(),
            self.api_key_fd,
            "--api-key-file",
            "--api-key-fd",
            "Chain RPC API key: ",
        )?;
        let bytes = read_secret(&source)?;
        let key = std::str::from_utf8(trim_ascii(&bytes))
            .map_err(|_| anyhow::anyhow!("API key must be UTF-8"))?;
        Ok(Some(key.to_owned()))
    }
}

impl ChainRpcCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        match &self.action {
            ChainRpcAction::Set(cmd) => cmd.run(path).await,
            ChainRpcAction::Add(cmd) => cmd.run(path).await,
        }
    }
}

impl ChainRpcSetCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;
        let url = self.url.trim().to_string();
        if url.is_empty() {
            anyhow::bail!("--url value must not be empty");
        }

        config.chain_rpc.urls = vec![EndpointEntry::Url(url)];
        config.chain_rpc.api_key = self.secret.read()?;
        save_config(&config, path)?;

        let api_key_info = config
            .chain_rpc
            .api_key
            .as_deref()
            .map(|_| ", api_key=***")
            .unwrap_or(", api_key=none");
        println!(
            "\n{} chain-rpc set: url='{}'{}\n",
            "OK".green().bold(),
            config.chain_rpc.urls[0].url(),
            api_key_info
        );
        Ok(())
    }
}

impl ChainRpcAddCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;
        let new_urls: Vec<String> =
            self.urls.iter().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect();

        if new_urls.is_empty() {
            anyhow::bail!("At least one non-empty --url value is required");
        }

        let api_key = self.secret.read()?;
        let mut existing = config.chain_rpc.endpoints();
        for url in &new_urls {
            if !existing.iter().any(|e| e == url) {
                let entry = match &api_key {
                    Some(key) => EndpointEntry::WithKey { url: url.clone(), api_key: key.clone() },
                    None => EndpointEntry::Url(url.clone()),
                };
                config.chain_rpc.urls.push(entry);
                existing.push(url.clone());
            }
        }
        save_config(&config, path)?;

        println!(
            "\n{} chain-rpc endpoints: [{}]\n",
            "OK".green().bold(),
            config.chain_rpc.endpoints().join(", "),
        );
        Ok(())
    }
}

#[cfg(test)]
mod secret_channel_tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        set: ChainRpcSetCmd,
    }
    #[test]
    fn literal_secret_is_refused_and_protected_sources_are_exclusive() {
        assert!(
            Cli::try_parse_from([
                "test",
                "--url",
                "https://rpc.example",
                "--api-key",
                "fake-token"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "test",
                "--url",
                "https://rpc.example",
                "--api-key-file",
                "/private/key"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "test",
                "--url",
                "https://rpc.example",
                "--api-key-fd",
                "3",
                "--api-key-prompt"
            ])
            .is_err()
        );
    }
    #[test]
    fn protected_file_is_read_without_logging_secret() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"fake-token\n").unwrap();
        let input = ApiKeyInput {
            api_key_file: Some(file.path().to_owned()),
            api_key_fd: None,
            api_key_prompt: false,
        };
        assert_eq!(input.read().unwrap().as_deref(), Some("fake-token"));
    }
}
