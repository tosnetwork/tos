/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use adnl::client::AdnlClientConfig;
use anyhow::Context;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::{
    client_json_rpc::ClientJsonRpc,
    data_models::{AccountState, GetWalletInformationRes},
};
use colored::Colorize;
use common::{
    app_config::{AdnlConfig, AppConfig, KeyConfig, WalletConfig},
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

/// The configured node a single-node command talks to: the one `name` gives,
/// or else the first by name, so the choice never depends on map order.
pub(crate) fn select_node<'a>(
    config: &'a AppConfig,
    name: Option<&str>,
) -> anyhow::Result<(&'a String, &'a AdnlConfig)> {
    match name {
        Some(name) => config
            .nodes
            .get_key_value(name)
            .ok_or_else(|| anyhow::anyhow!("Node '{name}' is not configured")),
        None => config
            .nodes
            .iter()
            .min_by(|(a, _), (b, _)| a.cmp(b))
            .ok_or_else(|| anyhow::anyhow!("No nodes configured")),
    }
}

fn node_keys_in_vault(node: &AdnlConfig) -> bool {
    matches!(node.server_key, KeyConfig::VaultKey { .. })
        || matches!(node.client_key, KeyConfig::VaultKey { .. })
}

/// Control-connection settings for a node. Without an open `vault`, the vault
/// is opened from the environment, and only when one of the node's keys is
/// stored there: a node configured with inline keys needs no vault at all.
pub(crate) async fn node_adnl_config(
    node: &AdnlConfig,
    vault: Option<Arc<SecretVault>>,
) -> anyhow::Result<AdnlClientConfig> {
    node_adnl_config_from(node, vault, None).await
}

/// [`node_adnl_config`] with the vault location given explicitly instead of
/// read from `VAULT_URL`.
async fn node_adnl_config_from(
    node: &AdnlConfig,
    vault: Option<Arc<SecretVault>>,
    vault_url: Option<&str>,
) -> anyhow::Result<AdnlClientConfig> {
    let vault = match vault {
        Some(vault) => Some(vault),
        None if node_keys_in_vault(node) => {
            Some(SecretVaultBuilder::from_url_or_env(vault_url).await?.ok_or_else(|| {
                anyhow::anyhow!(
                    "the node's control keys are stored in the vault, but VAULT_URL is not set"
                )
            })?)
        }
        None => None,
    };
    node.to_node_adnl_config(vault).await
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

/// A file vault in a private temporary directory, for tests that need keys
/// stored the way an operator stores them.
#[cfg(all(test, unix))]
pub(crate) mod test_vault {
    use secrets_vault::{
        types::{algorithm::Algorithm, secret_id::SecretId, secret_spec::SecretSpec},
        vault::SecretVault,
        vault_builder::SecretVaultBuilder,
    };
    use std::{os::unix::fs::PermissionsExt, sync::Arc};

    /// A closed vault file: it is locked while open, so it is opened only
    /// where a test needs it.
    pub(crate) struct TestVault {
        pub(crate) url: String,
        _dir: tempfile::TempDir,
    }

    /// A vault holding one Ed25519 key per `(name, extractable)` pair.
    pub(crate) async fn with_ed25519_keys(keys: &[(&str, bool)]) -> TestVault {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("tempdir");
        let url = format!(
            "file://{}?master_key={}",
            dir.path().join("vault.json").display(),
            "11".repeat(32)
        );
        let test_vault = TestVault { url, _dir: dir };
        let vault = test_vault.open().await;
        for (name, extractable) in keys {
            let spec = SecretSpec::new(Algorithm::Ed25519).extractable(*extractable);
            vault.generate_secret(&spec, &SecretId::new(*name)).await.expect("generate key");
        }
        vault.flush().await.expect("flush test vault");
        test_vault
    }

    impl TestVault {
        pub(crate) async fn open(&self) -> Arc<SecretVault> {
            SecretVaultBuilder::from_url(&self.url).await.expect("open test vault")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{node_adnl_config_from, save_config, select_node, test_vault};
    use common::app_config::{
        AdnlConfig, AppConfig, ChainRpcConfig, HttpConfig, KeyConfig, TimeoutVariant,
    };
    use std::{
        collections::HashMap,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn vault_node(client_secret: &str) -> AdnlConfig {
        AdnlConfig {
            server_address: "127.0.0.1:1".to_string(),
            server_key: KeyConfig::PublicKey { type_id: 1209251014, pub_key: vec![7; 32] },
            client_key: KeyConfig::VaultKey { name: client_secret.to_string() },
            timeouts: TimeoutVariant::Single(1),
        }
    }

    /// A node added with `config node add` keeps its control client key in the
    /// vault. The helper every single-node command uses must open the vault for
    /// it even when the caller has none open.
    #[tokio::test]
    async fn node_control_config_opens_the_vault_for_a_vault_key() {
        let vault = test_vault::with_ed25519_keys(&[("console", true)]).await;
        let node = vault_node("console");

        node_adnl_config_from(&node, None, Some(&vault.url))
            .await
            .expect("a vault-held extractable key yields a control config");
    }

    /// The vault can only hand out an extractable key; a non-extractable one
    /// is refused with the key's name and the command that fixes it.
    #[tokio::test]
    async fn node_control_config_names_the_fix_for_a_non_extractable_key() {
        let vault = test_vault::with_ed25519_keys(&[("sealed", false)]).await;
        let node = vault_node("sealed");

        let error = node_adnl_config_from(&node, None, Some(&vault.url))
            .await
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(
            error.contains("'sealed'")
                && error.contains("tosctl key import --name sealed --extractable"),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn select_node_is_by_name_and_never_by_map_order() {
        let mut config = minimal_config();
        assert!(select_node(&config, None).is_err());
        for name in ["n3", "n1", "n2"] {
            config.nodes.insert(name.to_string(), vault_node(name));
        }
        for _ in 0..8 {
            assert_eq!(select_node(&config, None).expect("first").0, "n1");
        }
        assert_eq!(select_node(&config, Some("n2")).expect("named").0, "n2");
        assert!(select_node(&config, Some("missing")).is_err());
    }

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
