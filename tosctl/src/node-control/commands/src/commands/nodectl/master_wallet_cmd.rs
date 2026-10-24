/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::nodectl::{
    output_format::OutputFormat,
    utils::{
        load_config_vault, load_config_vault_rpc_client, save_config, wallet_info,
        warn_missing_secret,
    },
};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use colored::Colorize;
use common::{
    WalletVersion,
    app_config::{AppConfig, KeyConfig, WalletConfig},
    chain_utils::display_tos,
};
use secrets_vault::{types::secret::Secret, vault::SecretVault};
use std::{path::Path, sync::Arc};

#[derive(clap::Args, Clone)]
#[command(about = "Configure and inspect the master wallet")]
pub struct MasterWalletCmd {
    #[command(subcommand)]
    action: MasterWalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum MasterWalletAction {
    /// Show master wallet info (address, version, etc.)
    Info(MasterWalletInfoCmd),
    /// Configure the master wallet with an explicit version
    Set(MasterWalletSetCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Configure the master wallet with an explicit version")]
pub struct MasterWalletSetCmd {
    #[arg(short = 's', long = "secret-name", help = "Vault secret name for the master wallet key")]
    secret_name: String,
    #[arg(short = 'v', long = "version", help = super::wallet_cmd::WALLET_VERSION_HELP)]
    version: WalletVersion,
    #[arg(short = 'i', long = "subwallet-id", default_value = "42", help = "Subwallet ID")]
    subwallet_id: u32,
    #[arg(
        short = 'w',
        long = "workchain",
        allow_negative_numbers = true,
        default_value_t = 0,
        help = "Workchain ID"
    )]
    workchain: i32,
    #[arg(long = "force", help = "Replace an already configured master wallet")]
    force: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show master wallet info")]
pub struct MasterWalletInfoCmd {
    #[arg(long = "format", default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
}

impl MasterWalletCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        match &self.action {
            MasterWalletAction::Info(cmd) => cmd.run(path).await,
            MasterWalletAction::Set(cmd) => cmd.run(path).await,
        }
    }
}

/// The configuration with `wallet` as its master wallet. An already configured
/// master wallet may hold funds, so it is replaced only when `force` is set.
/// Only the configuration changes: no key is created or deleted, nothing is sent.
fn set_master_wallet(
    config: &AppConfig,
    wallet: WalletConfig,
    force: bool,
) -> anyhow::Result<AppConfig> {
    if config.master_wallet.is_some() && !force {
        anyhow::bail!(
            "a master wallet is already configured; inspect it with `config master-wallet info` \
             and pass --force to replace it"
        );
    }
    let mut config = config.clone();
    config.master_wallet = Some(wallet);
    Ok(config)
}

impl MasterWalletSetCmd {
    fn wallet_config(&self) -> WalletConfig {
        WalletConfig {
            key: KeyConfig::VaultKey { name: self.secret_name.clone() },
            version: self.version,
            subwallet_id: self.subwallet_id,
            workchain: self.workchain,
        }
    }

    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let (config, vault) = load_config_vault(path).await?;
        let config = set_master_wallet(&config, self.wallet_config(), self.force)?;
        if !vault.exists(&self.secret_name.as_str().into()).await? {
            warn_missing_secret(&self.secret_name);
        }
        save_config(&config, path)?;
        println!(
            "\n{} Master wallet set: {} (subwallet {}, workchain {}). Check its address with \
             `config master-wallet info` before funding it.\n",
            "OK".green().bold(),
            self.version,
            self.subwallet_id,
            self.workchain
        );
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct MasterWalletView {
    address: Option<String>,
    balance: Option<String>,
    state: Option<String>,
    version: String,
    subwallet_id: u32,
    secret: String,
    public_key: Option<String>,
}

impl MasterWalletInfoCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;

        let master_wallet = config
            .master_wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("master_wallet is not configured"))?;

        let secret_name = match &master_wallet.key {
            KeyConfig::VaultKey { name } => name.clone(),
            _ => "-".to_string(),
        };

        match self.format {
            OutputFormat::Json => {
                print_master_wallet_json(master_wallet, &secret_name, rpc_client, vault).await?
            }
            OutputFormat::Table => {
                print_master_wallet_table(master_wallet, &secret_name, rpc_client, vault).await?
            }
        }

        Ok(())
    }
}

async fn print_master_wallet_json(
    master_wallet: &WalletConfig,
    secret_name: &str,
    rpc_client: Arc<ClientJsonRpc>,
    vault: Arc<SecretVault>,
) -> anyhow::Result<()> {
    let (address, state, balance, public_key) =
        match wallet_info(rpc_client, master_wallet, vault).await {
            Ok((address, info, secret)) => {
                let pk = if let Secret::KeyPair { keypair } = secret {
                    keypair.public_key().await.ok().flatten().map(|pk| {
                        base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            pk.as_slice(),
                        )
                    })
                } else {
                    None
                };
                (
                    Some(address.to_string()),
                    Some(info.account_state.to_string()),
                    Some(display_tos(info.balance)),
                    pk,
                )
            }
            Err(_) => (None, None, None, None),
        };

    let view = MasterWalletView {
        address,
        balance,
        state,
        version: master_wallet.version.to_string(),
        subwallet_id: master_wallet.subwallet_id,
        secret: secret_name.to_string(),
        public_key,
    };
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

async fn print_master_wallet_table(
    master_wallet: &WalletConfig,
    secret_name: &str,
    rpc_client: Arc<ClientJsonRpc>,
    vault: Arc<SecretVault>,
) -> anyhow::Result<()> {
    let (address, account_state, balance, public_key) =
        match wallet_info(rpc_client, master_wallet, vault).await {
            Ok((address, info, secret)) => (
                address.to_string().white(),
                info.account_state.to_string().white(),
                display_tos(info.balance).white(),
                if let Secret::KeyPair { keypair } = secret {
                    let public_key = keypair
                        .public_key()
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("no public key"))?;
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        public_key.as_slice(),
                    )
                    .white()
                } else {
                    "unknown".red()
                },
            ),
            Err(_) => ("unknown".red(), "unknown".red(), "unknown".red(), "unknown".red()),
        };

    println!("\n{} {}\n", "OK".green().bold(), "Master Wallet".green());
    println!("  {:<16} {}", "Address:".cyan().bold(), address);
    println!("  {:<16} {}", "Balance:".cyan().bold(), balance);
    println!("  {:<16} {}", "State:".cyan().bold(), account_state);
    println!("  {:<16} {}", "Version:".cyan().bold(), master_wallet.version);
    println!("  {:<16} {}", "Subwallet ID:".cyan().bold(), master_wallet.subwallet_id);
    println!("  {:<16} {}", "Secret:".cyan().bold(), secret_name);
    println!("  {:<16} {}", "Public Key:".cyan().bold(), public_key);
    println!();
    Ok(())
}

#[cfg(test)]
mod set_tests {
    use super::{MasterWalletSetCmd, set_master_wallet};
    use clap::{Args, Command, FromArgMatches};
    use common::app_config::AppConfig;

    fn set_cmd(args: &[&str]) -> MasterWalletSetCmd {
        let mut argv = vec!["set"];
        argv.extend_from_slice(args);
        let matches = MasterWalletSetCmd::augment_args(Command::new("set"))
            .try_get_matches_from(argv)
            .expect("parse");
        MasterWalletSetCmd::from_arg_matches(&matches).expect("args")
    }

    /// A config as `config generate` writes it (no master wallet), with one
    /// unrelated wallet so a replacement can be shown to keep the rest.
    fn generated_config() -> AppConfig {
        serde_json::from_value(serde_json::json!({
            "nodes": {},
            "wallets": {"op": {"key": {"name": "op-key"}, "version": "V3R2",
                               "subwallet_id": 7, "workchain": -1}},
            "pools": {},
            "bindings": {},
            "chain_rpc": {"urls": ["http://127.0.0.1:3301/"]},
            "http": {},
            "master_wallet": null,
        }))
        .expect("config")
    }

    fn master(config: &AppConfig) -> serde_json::Value {
        serde_json::to_value(&config.master_wallet).expect("master wallet")
    }

    #[test]
    fn set_writes_the_named_wallet_on_both_workchains() {
        for (args, workchain) in
            [(&["-s", "m", "-v", "V4R2"][..], 0), (&["-s", "m", "-v", "V4R2", "-w", "-1"][..], -1)]
        {
            let config =
                set_master_wallet(&generated_config(), set_cmd(args).wallet_config(), false)
                    .expect("first configuration");
            assert_eq!(
                master(&config),
                serde_json::json!({"key": {"name": "m"}, "version": "V4R2",
                                   "subwallet_id": 42, "workchain": workchain}),
                "{args:?}"
            );
        }
    }

    #[test]
    fn an_existing_master_wallet_is_replaced_only_with_force() {
        let first = set_master_wallet(
            &generated_config(),
            set_cmd(&["-s", "old", "-v", "V3R2"]).wallet_config(),
            false,
        )
        .expect("first configuration");
        let before = serde_json::to_value(&first).expect("config");

        let replacement = set_cmd(&["-s", "new", "-v", "V4R2", "-i", "9", "--force"]);
        let error = set_master_wallet(&first, replacement.wallet_config(), false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("--force"), "unexpected refusal: {error}");
        assert_eq!(
            serde_json::to_value(&first).expect("config"),
            before,
            "refusal changes nothing"
        );

        let replaced = set_master_wallet(&first, replacement.wallet_config(), replacement.force)
            .expect("replacement with --force");
        assert_eq!(
            master(&replaced),
            serde_json::json!({"key": {"name": "new"}, "version": "V4R2",
                               "subwallet_id": 9, "workchain": 0})
        );
        let mut rest_before = before;
        let mut rest_after = serde_json::to_value(&replaced).expect("config");
        rest_before["master_wallet"] = serde_json::Value::Null;
        rest_after["master_wallet"] = serde_json::Value::Null;
        assert_eq!(rest_after, rest_before, "only the master wallet changes");
    }
}
