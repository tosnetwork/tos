/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use anyhow::Context;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::{
    client_json_rpc::ClientJsonRpc,
    data_models::{AccountState, GetWalletInformationRes},
};
use colored::Colorize;
use common::{
    app_config::{AppConfig, WalletConfig},
    task_cancellation::CancellationCtx,
    vault_signer::VaultSigner,
};
use contracts::{WalletContract, contract_provider};
use secrets_vault::{
    errors::error::VaultError, types::secret::Secret, vault::SecretVault,
    vault_builder::SecretVaultBuilder,
};
use std::{collections::HashMap, path::Path, sync::Arc};

const POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(2);
pub const SEND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);
pub const DEPLOY_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);

/// clap value parser for a flag that takes an account address. The flag also allows
/// hyphen values, because a raw masterchain address starts with `-1:`; this parser
/// is what keeps a following option (`--to --bounce`) from being taken as the
/// address. Accepts the raw `wc:hex` and the user-friendly form, ignoring surrounding
/// whitespace; returns the trimmed text.
pub(crate) fn address_arg(value: &str) -> Result<String, String> {
    use std::str::FromStr;
    // Surrounding whitespace was trimmed by the commands that read these values
    // before; trim before validating so a quoted value keeps working.
    let value = value.trim();
    MsgAddressInt::from_str(value).map(|_| value.to_owned()).map_err(|error| {
        format!("'{value}' is not an account address ({error}); expected wc:hex or the user-friendly form")
    })
}

pub fn warn_missing_secret(secret_name: &str) {
    println!("\n{} {}", "[WARNING]".yellow().bold(), "Vault secret is missing".yellow(),);
    println!(
        "  {} Secret '{}' does not exist in vault",
        "Reason:".yellow().bold(),
        secret_name.yellow()
    );
    println!(
        "  {} {}",
        "Note:".yellow().bold(),
        format!("Create it with `tosctl key add --name {secret_name}`").yellow().italic()
    );
}

pub fn warn_chain_rpc_unavailable(error: &anyhow::Error, note: &str) {
    println!("\n{} {}", "[WARNING]".yellow().bold(), "Failed to connect to chain RPC".yellow(),);
    println!("  {} {}", "Reason:".yellow().bold(), error.root_cause().to_string());
    println!("  {} {}", "Note:".yellow().bold(), note.yellow().italic());
}

pub fn save_config(config: &AppConfig, path: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    secrets_vault::private_file::write_private_atomic(path, json.as_bytes())?;
    Ok(())
}

pub async fn load_config_vault(
    config_path: &Path,
) -> anyhow::Result<(AppConfig, Arc<SecretVault>)> {
    let config = AppConfig::load(config_path)?;
    let vault = SecretVaultBuilder::from_env().await?;

    Ok((config, vault))
}

/// The network's GLOBALID (ConfigParam 19). Attestation and settlement
/// signatures name it, so a signature made for one network does not verify on
/// another that runs the same contract at the same address.
pub async fn network_global_id(rpc_client: &ClientJsonRpc) -> anyhow::Result<i32> {
    match rpc_client.get_config_param(19).await? {
        chain_block::ConfigParamEnum::ConfigParam19(value) => Ok(value as i32),
        _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
    }
}

/// Refuses an instance deployed from a release other than the one this tosctl
/// builds, before anything decodes its state or signs for it: an earlier
/// release's getters and signing domains differ, so its state would be
/// misread and a signature made here would not be one it accepts.
pub async fn require_supported_contract(
    rpc_client: &ClientJsonRpc,
    address: &chain_block::MsgAddressInt,
    contract: contracts::VersionedContract,
) -> anyhow::Result<()> {
    let info = rpc_client.get_address_information(address).await?;
    contract
        .require_supported_code_boc(info.code.as_deref())
        .map_err(|e| anyhow::anyhow!("{address}: {e}"))
}

pub async fn check_chain_rpc_connection(rpc_client: &ClientJsonRpc) -> anyhow::Result<()> {
    rpc_client.get_config_param(1).await.map(|_| ())
}

pub async fn try_create_rpc_client(config: &AppConfig) -> anyhow::Result<Arc<ClientJsonRpc>> {
    let client = ClientJsonRpc::connect_many(
        config.chain_rpc.resolved_endpoints(),
        config.chain_rpc.api_key.clone(),
    )?;
    check_chain_rpc_connection(&client).await.map(|_| Arc::new(client))
}

pub async fn load_config_vault_rpc_client(
    config_path: &Path,
) -> anyhow::Result<(AppConfig, Arc<SecretVault>, Arc<ClientJsonRpc>)> {
    let (config, vault) = load_config_vault(config_path).await?;
    let rpc_client = Arc::new(
        ClientJsonRpc::connect_many(
            config.chain_rpc.resolved_endpoints(),
            config.chain_rpc.api_key.clone(),
        )
        .context("ClientJsonRpc")?,
    );

    Ok((config, vault, rpc_client))
}

pub async fn load_config_vault_rpc_client_fd(
    fd: i32,
    format: &str,
) -> anyhow::Result<(AppConfig, Arc<SecretVault>, Arc<ClientJsonRpc>)> {
    let config = AppConfig::load_fd(fd, format)?;
    let vault = SecretVaultBuilder::from_env().await?;
    let rpc_client = Arc::new(
        ClientJsonRpc::connect_many(
            config.chain_rpc.resolved_endpoints(),
            config.chain_rpc.api_key.clone(),
        )
        .context("ClientJsonRpc")?,
    );
    Ok((config, vault, rpc_client))
}

pub async fn wallet_address(
    wallet_cfg: &WalletConfig,
    vault: Arc<SecretVault>,
) -> anyhow::Result<(MsgAddressInt, Secret)> {
    let secret = wallet_cfg.key.read_secret(Some(vault)).await?;
    let keypair = secret.as_keypair()?;

    let pub_key = keypair
        .public_key()
        .await?
        .ok_or_else(|| anyhow::anyhow!(VaultError::empty_public_key("Empty public key")))?;

    let address = calculate_wallet_address(wallet_cfg, &pub_key).context("calculate_address")?;

    Ok((address, secret))
}

pub async fn wallet_info(
    rpc_client: Arc<ClientJsonRpc>,
    wallet_cfg: &WalletConfig,
    vault: Arc<SecretVault>,
) -> anyhow::Result<(MsgAddressInt, GetWalletInformationRes, Secret)> {
    let (wallet_address, secret) = wallet_address(wallet_cfg, vault).await?;
    let wallet_info = rpc_client.get_wallet_information(&wallet_address).await?;

    Ok((wallet_address, wallet_info, secret))
}

pub fn calculate_wallet_address(
    wallet_cfg: &WalletConfig,
    pub_key: &[u8],
) -> anyhow::Result<MsgAddressInt> {
    WalletContract::calculate_address(
        wallet_cfg.version,
        wallet_cfg.workchain,
        wallet_cfg.subwallet_id,
        pub_key,
    )
}

pub fn get_wallet_config<'a>(
    name: &str,
    wallets: &'a HashMap<String, WalletConfig>,
    master_wallet: Option<&'a WalletConfig>,
) -> anyhow::Result<&'a WalletConfig> {
    let config = if name == "master_wallet" { master_wallet } else { wallets.get(name) };
    config.ok_or_else(|| anyhow::anyhow!("Wallet not found '{}'", name))
}

pub async fn make_wallet(
    rpc_client: Arc<ClientJsonRpc>,
    wallet_cfg: &WalletConfig,
    secret: Secret,
    label: &str,
) -> anyhow::Result<WalletContract> {
    let wallet_signer = VaultSigner::new(secret)
        .await
        .with_context(|| format!("[{label}] create wallet signer"))?;

    // The wallet binds the network identity into every signature, so it is
    // read from the chain this client talks to rather than from local config.
    let global_id = rpc_client
        .get_global_id()
        .await
        .with_context(|| format!("[{label}] read network global_id"))?;

    let wallet = WalletContract::new(
        Box::new(wallet_signer),
        wallet_cfg.version,
        wallet_cfg.subwallet_id,
        wallet_cfg.workchain,
        global_id,
        contract_provider!(rpc_client.clone()),
    )
    .await
    .with_context(|| format!("[{label}] create wallet"))?;

    Ok(wallet)
}

async fn poll_until(
    cancellation_ctx: &CancellationCtx,
    max_wait: tokio::time::Duration,
    timeout_msg: &str,
    mut check: impl AsyncFnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let poll = async {
        loop {
            if cancellation_ctx.is_cancelled() {
                anyhow::bail!("Task cancelled");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
            if check().await? {
                return Ok(());
            }
        }
    };

    tokio::time::timeout(max_wait, poll).await.map_err(|_| anyhow::anyhow!("{timeout_msg}"))?
}

pub async fn wait_for_deploy(
    rpc_client: Arc<ClientJsonRpc>,
    address: &MsgAddressInt,
    cancellation_ctx: &CancellationCtx,
    verbose: bool,
    max_wait: tokio::time::Duration,
) -> anyhow::Result<()> {
    poll_until(cancellation_ctx, max_wait, "Timeout waiting for contract deployment", async || {
        if verbose {
            println!("\n{}: {}...", "Wait for deploy".bold(), address);
        }
        let info = rpc_client.get_address_information(address).await?;
        let deployed = info.state == AccountState::Active;
        if deployed && verbose {
            println!("\n{}: {}", "Deployed".bold(), address);
        }
        Ok(deployed)
    })
    .await
}

pub async fn wait_for_seqno_change(
    rpc_client: Arc<ClientJsonRpc>,
    address: &MsgAddressInt,
    initial_seqno: Option<u32>,
    cancellation_ctx: &CancellationCtx,
    max_wait: tokio::time::Duration,
) -> anyhow::Result<()> {
    poll_until(cancellation_ctx, max_wait, "Transaction timeout expired", async || {
        let info = rpc_client.get_wallet_information(address).await?;
        Ok(info.seqno != initial_seqno)
    })
    .await
}

#[cfg(all(test, unix))]
mod tests {
    use super::save_config;
    use common::app_config::{AppConfig, ChainRpcConfig, HttpConfig};
    use std::{
        collections::HashMap,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn minimal_config() -> AppConfig {
        AppConfig {
            nodes: HashMap::new(),
            wallets: HashMap::new(),
            agent_wallets: HashMap::new(),
            agent_tasks: HashMap::new(),
            capability_registries: HashMap::new(),
            service_actors: HashMap::new(),
            disputes: HashMap::new(),
            proof_attestations: HashMap::new(),
            pools: HashMap::new(),
            bindings: HashMap::new(),
            chain_rpc: ChainRpcConfig::default(),
            elections: None,
            voting: None,
            http: HttpConfig::default(),
            master_wallet: None,
            tick_interval: 40,
            indexer_retention_blocks: 0,
            log: None,
            bookmarks: HashMap::new(),
            alerts: Default::default(),
            proof_verifier: None,
        }
    }

    /// Configuration may hold inline keys, so it is saved owner-only and never
    /// through a link planted at the target.
    #[test]
    fn save_config_is_private_and_refuses_a_linked_target() {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("tosctl-config.json");
        save_config(&minimal_config(), &path).expect("save config");
        let meta = std::fs::symlink_metadata(&path).expect("config metadata");
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"unchanged").expect("seed victim");
        std::fs::remove_file(&path).expect("remove config");
        symlink(&victim, &path).expect("link config");
        assert!(save_config(&minimal_config(), &path).is_err());
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"unchanged");
    }
}
