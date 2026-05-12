/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/*
 * `tosctl jvm-wallet` / `tosctl jw` — wc=3 single-owner Ed25519 wallet
 * subcommand. Mirrors the wc=0 `tosctl wallet` flow but speaks the JVM
 * address-derivation + JvmArgs/JvmCallDescriptor ABI from
 * `contracts::jvm_wallet` instead of TVM seqno + V3R2/V4R2/V5R1 wallet
 * code cells.
 *
 * Subcommands shipped working in this round:
 *   * create  — generate Ed25519 keypair under `jvm-wallet-{name}` in
 *               the vault, store deployer/salt/class in tosctl-config.json,
 *               derive and cache the wc=3 address.
 *   * address — print the wallet's deterministic wc=3 address.
 *   * info    — `jvm_getContractState` view of owner key / nonce / init
 *               flag (best-effort; falls back to a clear error if the
 *               validator can't supply the accountStateBoc).
 *
 * Subcommands stubbed with a clear `bail!()` and a roadmap note:
 *   * deploy  — emits an `action_create_account` from a sender wallet.
 *               The wc=3 source-workchain admission gate at
 *               `crypto/block/transaction.cpp:2812` (addr_std int8
 *               range) plus the per-account capability flag at
 *               `transaction.cpp:2807` means this only works from
 *               another wc=3 wallet. For the very first wc=3 wallet,
 *               point users at the genesis-seeding Fift word
 *               (`jvm-zerostate-from-alloc`) instead of building a
 *               half-working cross-workchain path here.
 *   * execute — sends a signed-payload internal message from this
 *               wallet. Requires a separately-funded wc=3 routing
 *               account because the CLI process itself cannot mint
 *               messages with `src.wc=3`; we'd need to call into a
 *               proxy contract that already exists. Stub for now.
 */
use super::utils::load_config_vault_rpc_client;
use anyhow::{Context, Result};
use chain_block::{
    Cell, ExternalInboundMessageHeader, Message, MsgAddressExt, MsgAddressInt,
    SliceData, Serializable, write_boc,
};
use chain_rpc_client::v2::jvm::JvmContractStateView;
use colored::Colorize;
use common::{
    app_config::{JvmDeployerConfig, JvmWalletConfig},
    vault_signer::VaultSigner,
};
use contracts::{
    build_wallet_single_transfer_payload,
    jvm_codec::{
        encode_jvm_contract_account_state, encode_jvm_state_init_cell,
        JvmContractAccountState,
    },
    jvm_deployer::JvmDeployerContract,
    jvm_wallet::JvmWalletContract,
    U256,
};
use secrets_vault::vault::SecretVault;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

#[derive(clap::Args, Clone)]
#[command(about = "Manage wc=3 JVM wallets")]
pub struct JvmWalletCmd {
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
    action: JvmWalletAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum JvmWalletAction {
    /// Create a new wc=3 JVM wallet (vault keypair + config entry).
    Create(JvmWalletCreateCmd),
    /// Print the derived wc=3 address of a wallet.
    Address(JvmWalletAddressCmd),
    /// Deploy this wallet to wc=3 via a registered Deployer.
    Deploy(JvmWalletDeployCmd),
    /// Sign + send a single transfer from this wallet (stub — see
    /// docs).
    Execute(JvmWalletExecuteCmd),
    /// Fetch + decode the wallet's on-chain state (owner key, nonce,
    /// init flag).
    Info(JvmWalletInfoCmd),
    /// Register an existing on-chain Deployer under a CLI name (binds
    /// to a vault secret + salt + class file).
    RegisterDeployer(JvmDeployerRegisterCmd),
    /// Print the derived wc=3 address of a registered Deployer.
    DeployerAddress(JvmDeployerAddressCmd),
    /// Print summary info for a registered Deployer (address +
    /// best-effort on-chain state lookup).
    DeployerInfo(JvmDeployerInfoCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a new wc=3 JVM wallet")]
pub struct JvmWalletCreateCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    /// 32-byte hex salt. When omitted, sha256(name) is used as a
    /// deterministic default — re-running `create` for the same name
    /// without `--salt` will land on the same wc=3 address.
    #[arg(long = "salt", help = "32-byte hex salt (default: sha256(name))")]
    salt: Option<String>,
    /// 32-byte hex deployer account-id. Defaults to all-zero, which
    /// mirrors the "genesis deployer" sentinel used by the C++ side
    /// in `parse_jvm_deploy_contract_request` when the `salt` field
    /// is absent.
    #[arg(long = "deployer", help = "32-byte hex deployer (default: all-zero)")]
    deployer: Option<String>,
    /// Path to the compiled `Wallet.class` file. Optional — when
    /// omitted the wallet is created without a class blob (suitable
    /// for address derivation only; `deploy` will refuse until
    /// `--class-file` is supplied via `tosctl jw create` or set via
    /// `--class-file` on the deploy command).
    #[arg(long = "class-file", help = "Path to compiled Wallet.class bytes")]
    class_file: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Print the derived wc=3 address of a wallet")]
pub struct JvmWalletAddressCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy a wc=3 JVM wallet via a registered Deployer")]
pub struct JvmWalletDeployCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name (target)")]
    name: String,
    /// Name of a registered Deployer to route the deploy through.
    /// The Deployer must already be active on-chain (e.g. seeded at
    /// genesis via `jvm-zerostate-from-alloc`).
    #[arg(long = "via", help = "Registered Deployer config name")]
    via: String,
    /// Tomis attached to the action_create_account (covers storage
    /// stake + init call gas).
    #[arg(long = "balance", default_value = "1000000000")]
    balance: u128,
    /// 32-byte hex stdlib_hash committed into the target wallet's
    /// JVAC.  MUST match ConfigParam 85 on the live chain; otherwise
    /// the engine rejects the first call with `sk_bad_state`.  Default
    /// is all-zeros, which matches `JvmConfig::default_activation()`
    /// for testnet/local-net workflows.  Pass the real value for
    /// mainnet deploys.
    #[arg(long = "stdlib-hash", help = "32-byte hex stdlib_hash from ConfigParam 85")]
    stdlib_hash: Option<String>,
    /// Opt-in to deploying with an all-zero stdlib_hash.  Required
    /// when `--stdlib-hash` is omitted and the resulting wallet would
    /// be rejected by any chain whose ConfigParam 85 carries a
    /// non-zero hash (i.e. every mainnet-like network).  Use this on
    /// localnet / unit-test chains only.
    #[arg(long = "allow-zero-stdlib-hash",
          help = "Permit the all-zero default (testnet only)")]
    allow_zero_stdlib_hash: bool,
    /// Deployer nonce.  When omitted, the CLI fetches the current
    /// value from on-chain storage via `jvm_getContractState`.
    #[arg(long = "nonce", help = "Deployer replay-counter (defaults to chain-fetched)")]
    nonce: Option<u64>,
    /// When set, build all the artifacts (signed deploy descriptor +
    /// ext-msg BOC) and print them, but do NOT call send_boc.  Useful
    /// for inspection / offline composition.
    #[arg(long = "dry-run", help = "Skip send_boc; print artifacts only")]
    dry_run: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Register an existing on-chain Deployer in the CLI config")]
pub struct JvmDeployerRegisterCmd {
    #[arg(short = 'n', long = "name", help = "Deployer config name")]
    name: String,
    /// Vault secret name that holds the Deployer's Ed25519 keypair.
    /// Typically populated out-of-band (e.g. imported from the genesis
    /// ceremony) via `tosctl wallet import` against the same vault.
    #[arg(long = "vault-secret", help = "Vault secret name")]
    vault_secret: String,
    /// 32-byte hex salt.  Defaults to sha256(name).
    #[arg(long = "salt", help = "32-byte hex salt (default: sha256(name))")]
    salt: Option<String>,
    /// 32-byte hex deployer-of-deployers account-id.  Defaults to
    /// all-zero ("kJvmGenesisDeployer" sentinel) since genesis-seeded
    /// Deployers use that.
    #[arg(long = "deployer", help = "32-byte hex deployer (default: all-zero)")]
    deployer: Option<String>,
    /// Path to the compiled `Deployer.class` bytes.  Required —
    /// without this the CLI cannot derive the Deployer's wc=3 address.
    #[arg(long = "class-file", help = "Path to compiled Deployer.class bytes")]
    class_file: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Print the derived wc=3 address of a registered Deployer")]
pub struct JvmDeployerAddressCmd {
    #[arg(short = 'n', long = "name", help = "Deployer config name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Print summary info for a registered Deployer")]
pub struct JvmDeployerInfoCmd {
    #[arg(short = 'n', long = "name", help = "Deployer config name")]
    name: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Sign + send a single transfer from a wc=3 JVM wallet")]
pub struct JvmWalletExecuteCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    /// Destination address in `wc:hex32` form.
    #[arg(long = "to", help = "Destination address (wc:hex32)")]
    to: String,
    /// Transfer amount in Tomis.
    #[arg(long = "amount", help = "Amount in Tomis")]
    amount: u128,
    /// Optional message body bytes, hex-encoded.
    #[arg(long = "body", help = "Internal message body (hex)")]
    body: Option<String>,
    /// Nonce to use. When absent, the CLI calls `jvm_getContractState`
    /// to fetch the current value from on-chain storage.
    #[arg(long = "nonce", help = "Replay-protection nonce (defaults to chain-fetched)")]
    nonce: Option<u64>,
    /// When set, build all the artifacts (signed execute() descriptor +
    /// ext-msg BOC) and print them, but do NOT call send_boc.
    #[arg(long = "dry-run", help = "Skip send_boc; print artifacts only")]
    dry_run: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Fetch + decode the wallet's on-chain state")]
pub struct JvmWalletInfoCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
}

impl JvmWalletCmd {
    pub async fn run(&self) -> Result<()> {
        match &self.action {
            JvmWalletAction::Create(cmd) => cmd.run(&self.config).await,
            JvmWalletAction::Address(cmd) => cmd.run(&self.config).await,
            JvmWalletAction::Deploy(cmd) => cmd.run(&self.config).await,
            JvmWalletAction::Execute(cmd) => cmd.run(&self.config).await,
            JvmWalletAction::Info(cmd) => cmd.run(&self.config).await,
            JvmWalletAction::RegisterDeployer(cmd) => {
                cmd.run(&self.config).await
            }
            JvmWalletAction::DeployerAddress(cmd) => {
                cmd.run(&self.config).await
            }
            JvmWalletAction::DeployerInfo(cmd) => {
                cmd.run(&self.config).await
            }
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn parse_hex32(input: &str, label: &str) -> Result<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed)
        .with_context(|| format!("Invalid hex {label}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn default_salt_for(name: &str) -> [u8; 32] {
    let digest = Sha256::digest(name.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

async fn load_jvm_wallet(
    name: &str,
    cfg: &JvmWalletConfig,
    vault: Arc<SecretVault>,
) -> Result<JvmWalletContract> {
    let secret = cfg
        .key
        .read_secret(Some(vault))
        .await
        .with_context(|| format!("Read keypair for jvm-wallet '{name}'"))?;
    let signer = VaultSigner::new(secret)
        .await
        .with_context(|| format!("Build VaultSigner for jvm-wallet '{name}'"))?;

    let deployer = parse_hex32(&cfg.deployer_hex, "deployer_hex")?;
    let salt = parse_hex32(&cfg.salt_hex, "salt_hex")?;
    let class_bytes = match &cfg.class_bytes_hex {
        Some(hex_str) => hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
            .context("Invalid class_bytes_hex")?,
        None => Vec::new(),
    };

    JvmWalletContract::new(Box::new(signer), deployer, salt, class_bytes)
        .await
        .with_context(|| format!("Build JvmWalletContract for '{name}'"))
}

async fn load_jvm_deployer(
    name: &str,
    cfg: &JvmDeployerConfig,
    vault: Arc<SecretVault>,
) -> Result<JvmDeployerContract> {
    let secret = cfg
        .key
        .read_secret(Some(vault))
        .await
        .with_context(|| format!("Read keypair for jvm-deployer '{name}'"))?;
    let signer = VaultSigner::new(secret).await.with_context(|| {
        format!("Build VaultSigner for jvm-deployer '{name}'")
    })?;

    let deployer = parse_hex32(&cfg.deployer_hex, "deployer_hex")?;
    let salt = parse_hex32(&cfg.salt_hex, "salt_hex")?;
    let class_bytes =
        hex::decode(cfg.class_bytes_hex.strip_prefix("0x").unwrap_or(&cfg.class_bytes_hex))
            .context("Invalid class_bytes_hex on deployer")?;

    JvmDeployerContract::new(Box::new(signer), deployer, salt, class_bytes)
        .await
        .with_context(|| format!("Build JvmDeployerContract for '{name}'"))
}

/// Parse the on-chain Deployer nonce from a `jvm_getContractState`
/// response.  Reads the slot at `keccak256("Deployer.nonce")` and
/// interprets the value as a big-endian Uint256.  Returns 0 when the
/// slot is absent (uninitialized Deployer).
fn parse_wallet_nonce(view: &JvmContractStateView) -> Result<u64> {
    parse_nonce_slot(view, b"Wallet.nonce")
}

fn parse_deployer_nonce(view: &JvmContractStateView) -> Result<u64> {
    parse_nonce_slot(view, b"Deployer.nonce")
}

fn parse_nonce_slot(
    view: &JvmContractStateView,
    slot_name: &[u8],
) -> Result<u64> {
    let slot_key_hex =
        hex::encode(chain_block::keccak256_digest(slot_name));

    let Some(slots) = &view.storage_slots else {
        return Ok(0);
    };
    for slot in slots {
        let normalized_key =
            slot.key.strip_prefix("0x").unwrap_or(&slot.key).to_ascii_lowercase();
        if normalized_key == slot_key_hex {
            let value_hex = slot.value.strip_prefix("0x").unwrap_or(&slot.value);
            let bytes =
                hex::decode(value_hex).context("Invalid hex in nonce slot value")?;
            if bytes.is_empty() {
                return Ok(0);
            }
            // Treat trailing 8 bytes as u64 BE; Uint256 fits in u64 for any
            // realistic nonce.
            let mut buf = [0u8; 8];
            let take = bytes.len().min(8);
            buf[8 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
            return Ok(u64::from_be_bytes(buf));
        }
    }
    Ok(0)
}

/// Build a wc=3 internal-message body Cell — used as the activating
/// init() call body on the target wallet.  We wrap an already-built
/// `JvmCallDescriptor` Cell so the host runtime's first-activation
/// dispatch route runs `Wallet.init(ownerPubKey)`.
fn cell_to_boc(cell: &Cell) -> Result<Vec<u8>> {
    write_boc(cell).context("Serialize cell to BOC")
}

/// Build an external-in message body wrapping `body_cell`, addressed
/// to `(dst_wc, dst_addr)`.  Returns the serialized BOC.
fn build_ext_in_message(
    dst_wc: i32,
    dst_addr: [u8; 32],
    body_cell: Cell,
) -> Result<Vec<u8>> {
    let dst = MsgAddressInt::with_standart(None, dst_wc as i8, dst_addr.into())
        .context("Build MsgAddressInt for ext-msg dst")?;
    let header = ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, dst);
    let body_slice = SliceData::load_cell(body_cell)
        .context("Load body cell into slice")?;
    let msg = Message::with_ext_in_header_and_body(header, body_slice);
    let msg_cell = msg
        .serialize()
        .context("Serialize ext-in message to cell")?;
    write_boc(&msg_cell).context("Serialize ext-in message BOC")
}

// ─── Subcommand impls ───────────────────────────────────────────────

impl JvmWalletCreateCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) =
            super::utils::load_config_vault(path).await?;

        if config.jvm_wallets.contains_key(&self.name) {
            anyhow::bail!(
                "JVM wallet '{}' already exists in config",
                self.name
            );
        }

        // Generate Ed25519 keypair in the vault under jvm-wallet-{name}.
        let secret_name = format!("jvm-wallet-{}", self.name);
        let spec = secrets_vault::types::secret_spec::SecretSpec::new(
            secrets_vault::types::algorithm::Algorithm::Ed25519,
        )
        .extractable(false);
        let secret_id = secret_name.as_str().into();
        vault.generate_secret(&spec, &secret_id).await?;
        vault.flush().await?;

        // Resolve salt / deployer / class_bytes.
        let salt_bytes: [u8; 32] = match &self.salt {
            Some(s) => parse_hex32(s, "--salt")?,
            None => default_salt_for(&self.name),
        };
        let deployer_bytes: [u8; 32] = match &self.deployer {
            Some(d) => parse_hex32(d, "--deployer")?,
            None => [0u8; 32],
        };
        let class_bytes_hex = match &self.class_file {
            Some(p) => {
                let bytes = std::fs::read(p)
                    .with_context(|| format!("Read class file {p}"))?;
                Some(hex::encode(bytes))
            }
            None => None,
        };
        let class_bytes_vec = match &class_bytes_hex {
            Some(h) => hex::decode(h).context("decode class bytes")?,
            None => Vec::new(),
        };

        // Build the signer + wallet helper purely to derive the address
        // we want to cache in the config.
        let secret = vault.get(&secret_id).await?;
        let signer = VaultSigner::new(secret).await?;
        let wallet = JvmWalletContract::new(
            Box::new(signer),
            deployer_bytes,
            salt_bytes,
            class_bytes_vec,
        )
        .await
        .context("Derive wc=3 wallet address")?;

        let address_hex = hex::encode(wallet.calculate_address());

        let entry = JvmWalletConfig {
            key: common::app_config::KeyConfig::VaultKey {
                name: secret_name.clone(),
            },
            deployer_hex: hex::encode(deployer_bytes),
            salt_hex: hex::encode(salt_bytes),
            class_bytes_hex,
            address_hex: Some(address_hex.clone()),
        };
        config.jvm_wallets.insert(self.name.clone(), entry);
        super::utils::save_config(&config, path)?;

        println!(
            "\n{} JVM wallet '{}' created\n",
            "OK".green().bold(),
            self.name
        );
        println!("  wc=3 address: {}", address_hex);
        println!("  salt:         {}", hex::encode(salt_bytes));
        println!("  deployer:     {}", hex::encode(deployer_bytes));
        println!("  vault key:    {}", secret_name);
        println!();
        Ok(())
    }
}

impl JvmWalletAddressCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = super::utils::load_config_vault(path).await?;

        let cfg = config
            .jvm_wallets
            .get(&self.name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "JVM wallet '{}' not found in config",
                    self.name
                )
            })?;

        // If a cached address is present, prefer it; otherwise rederive.
        let addr = match &cfg.address_hex {
            Some(a) => a.clone(),
            None => {
                let wallet =
                    load_jvm_wallet(&self.name, cfg, vault.clone()).await?;
                hex::encode(wallet.calculate_address())
            }
        };

        println!("3:{}", addr);
        Ok(())
    }
}

impl JvmWalletInfoCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) =
            load_config_vault_rpc_client(path).await?;

        let cfg = config
            .jvm_wallets
            .get(&self.name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "JVM wallet '{}' not found in config",
                    self.name
                )
            })?;

        let wallet = load_jvm_wallet(&self.name, cfg, vault.clone()).await?;
        let address_hex = hex::encode(wallet.calculate_address());

        println!(
            "\n{} JVM wallet '{}' info\n",
            "OK".green().bold(),
            self.name
        );
        println!("  wc=3 address: {}", address_hex);
        println!("  owner pubkey: {}", hex::encode(wallet.owner_pubkey()));
        println!("  class hash:   {}", hex::encode(wallet.class_hash()));
        println!(
            "  manifest:     {}",
            hex::encode(wallet.manifest_root_hash())
        );

        // Try a best-effort jvm_getContractState. The current RPC
        // requires the caller to supply `accountStateBoc` because the
        // server-side falls back to "empty" when it cannot read live
        // state — and we don't have an obvious way to materialize that
        // BOC from the CLI today. If the call succeeds without one
        // (newer server with live-state lookup), surface what we get.
        let state_call = rpc_client
            .jvm_get_contract_state(address_hex.clone(), None)
            .await;
        match state_call {
            Ok(view) => print_state_view(&view),
            Err(e) => {
                println!(
                    "\n  {} {}",
                    "WARN".yellow(),
                    "jvm_getContractState unavailable — wallet may not be deployed yet"
                );
                println!("  reason: {}", e.root_cause());
            }
        }
        println!();
        Ok(())
    }
}

fn print_state_view(view: &JvmContractStateView) {
    if let Some(class_name) = &view.class_name {
        println!("  class name:   {}", class_name);
    }
    if let Some(slots) = &view.storage_slots {
        println!("\n  storage slots:");
        for slot in slots {
            println!(
                "    key={}  value={}",
                slot.key,
                truncated(&slot.value, 64)
            );
        }
        if view.storage_truncated {
            println!("  (storage truncated; ask validator for full dump)");
        }
    }
}

fn truncated(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…({} bytes elided)", &s[..max], s.len() - max)
    }
}

impl JvmWalletDeployCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) =
            load_config_vault_rpc_client(path).await?;

        // 1. Load target wallet config + signer.
        let target_cfg = config.jvm_wallets.get(&self.name).ok_or_else(|| {
            anyhow::anyhow!("JVM wallet '{}' not found in config", self.name)
        })?;
        let target_class_bytes_hex = target_cfg
            .class_bytes_hex
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "JVM wallet '{}' has no class_bytes_hex — re-run \
                     `jw create` with `--class-file <Wallet.class>`",
                    self.name
                )
            })?;
        let target_class_bytes = hex::decode(
            target_class_bytes_hex.strip_prefix("0x").unwrap_or(target_class_bytes_hex),
        )
        .context("Decode target wallet class_bytes_hex")?;
        let target_wallet =
            load_jvm_wallet(&self.name, target_cfg, vault.clone()).await?;
        let target_addr = target_wallet.calculate_address();

        // 2. Load Deployer config + signer.
        let deployer_cfg = config.jvm_deployers.get(&self.via).ok_or_else(|| {
            anyhow::anyhow!(
                "Deployer '{}' not found in config — register one with \
                 `jw register-deployer`",
                self.via
            )
        })?;
        let deployer =
            load_jvm_deployer(&self.via, deployer_cfg, vault.clone()).await?;
        let deployer_addr = deployer.calculate_address();

        // 3. Build the target wallet's JVAC (consensus state cell).
        let stdlib_hash = match &self.stdlib_hash {
            Some(s) => parse_hex32(s, "--stdlib-hash")?,
            None => {
                if !self.allow_zero_stdlib_hash && !self.dry_run {
                    anyhow::bail!(
                        "--stdlib-hash not provided and \
                         --allow-zero-stdlib-hash not set.  Deploying \
                         with an all-zero stdlib_hash produces a wallet \
                         that any chain whose ConfigParam 85 carries a \
                         non-zero stdlib_hash will reject on first call \
                         with sk_bad_state.  Pass the real 32-byte hash \
                         (from `tosctl get-config 85` or the genesis \
                         ceremony output) or pass --allow-zero-stdlib-hash \
                         on localnet."
                    );
                }
                [0u8; 32]
            }
        };
        let target_deployer = parse_hex32(&target_cfg.deployer_hex, "target deployer_hex")?;
        let target_salt = parse_hex32(&target_cfg.salt_hex, "target salt_hex")?;
        // Rebuild the same init_args cell that target_wallet's address
        // derivation used (Bytes32 ownerPubKey).
        let init_args_cell = contracts::jvm_codec::encode_jvm_args(
            &contracts::jvm_codec::JvmArgs::new(vec![
                contracts::jvm_codec::JvmTypedArg::bytes32(
                    *target_wallet.owner_pubkey(),
                ),
            ]),
        )
        .context("encode target wallet init_args")?;
        let address_commit = contracts::jvm_codec::compute_jvm_address_commit(
            &target_deployer,
            &target_salt,
            &init_args_cell,
        );

        let state = JvmContractAccountState {
            stdlib_hash,
            deployer: target_deployer,
            address_commit,
            class_bytes: target_class_bytes.clone(),
            storage_root: None,
            manifest_root: Some(target_wallet.manifest_cell().clone()),
        };
        let jvac_cell = encode_jvm_contract_account_state(&state)
            .context("encode target JVAC")?;
        let state_init_cell = encode_jvm_state_init_cell(jvac_cell)
            .context("encode target StateInit")?;
        let state_init_boc = cell_to_boc(&state_init_cell)?;

        // 4. Init call descriptor — becomes the activating message body
        // for the new wallet account.
        let init_call_cell = target_wallet
            .encode_init_call()
            .context("encode init() call descriptor")?;
        let init_body_boc = cell_to_boc(&init_call_cell)?;

        // 5. Determine Deployer nonce (chain-fetch or override).
        let deployer_addr_hex = hex::encode(deployer_addr);
        let nonce_u64 = match self.nonce {
            Some(n) => n,
            None => {
                let view = rpc_client
                    .jvm_get_contract_state(deployer_addr_hex.clone(), None)
                    .await
                    .context(
                        "jvm_getContractState(deployer) — pass --nonce to skip"
                    )?;
                parse_deployer_nonce(&view)?
            }
        };
        let nonce = U256::from_u64(nonce_u64);
        let value = U256::from_u64(self.balance as u64);

        // 6. Sign + encode the Deployer.deploy(...) call.
        let signature = deployer
            .sign_deploy(
                nonce,
                &target_addr,
                &state_init_boc,
                value,
                &init_body_boc,
            )
            .await
            .context("Sign deploy digest")?;
        let deploy_call_cell = deployer
            .encode_deploy_call(
                nonce,
                &target_addr,
                &state_init_boc,
                value,
                &init_body_boc,
                &signature,
            )
            .context("Encode deploy() call descriptor")?;

        // 7. Wrap as external-in message to the Deployer's wc=3
        // account.  The validator's wc=3 admission accepts external
        // inbound for already-active accounts (the Deployer is
        // genesis-seeded in the canonical workflow).
        let ext_msg_boc =
            build_ext_in_message(3, deployer_addr, deploy_call_cell)?;

        println!(
            "\n{} prepared deploy artifacts\n",
            "OK".green().bold()
        );
        println!("  target wallet:     3:{}", hex::encode(target_addr));
        println!("  via deployer:      3:{}", deployer_addr_hex);
        println!("  deployer nonce:    {}", nonce_u64);
        println!("  initial balance:   {}", self.balance);
        println!(
            "  state_init BOC:    {} bytes",
            state_init_boc.len()
        );
        println!(
            "  init body BOC:     {} bytes",
            init_body_boc.len()
        );
        println!("  ext-msg BOC:       {} bytes", ext_msg_boc.len());
        println!();

        if self.dry_run {
            println!(
                "  {}: --dry-run set; not sending. ext-msg BOC hex below:",
                "DRY".yellow().bold()
            );
            println!("  0x{}", hex::encode(&ext_msg_boc));
            return Ok(());
        }

        // 8. Send via RPC.
        rpc_client
            .send_boc(&ext_msg_boc)
            .await
            .context("send_boc to wc=3 Deployer")?;
        println!(
            "  {} ext-msg submitted; target wallet will materialize \
             in the next block",
            "SENT".green().bold()
        );
        Ok(())
    }
}

impl JvmDeployerRegisterCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (mut config, vault) = super::utils::load_config_vault(path).await?;

        if config.jvm_deployers.contains_key(&self.name) {
            anyhow::bail!(
                "Deployer '{}' already exists in config",
                self.name
            );
        }

        // Verify the vault secret resolves to an Ed25519 keypair before
        // we commit a config entry.
        let secret_id = self.vault_secret.as_str().into();
        let secret = vault.get(&secret_id).await.with_context(|| {
            format!(
                "Vault secret '{}' not found — import it first via \
                 `tosctl wallet import`",
                self.vault_secret
            )
        })?;
        let signer = VaultSigner::new(secret).await?;

        let salt: [u8; 32] = match &self.salt {
            Some(s) => parse_hex32(s, "--salt")?,
            None => default_salt_for(&self.name),
        };
        let deployer: [u8; 32] = match &self.deployer {
            Some(d) => parse_hex32(d, "--deployer")?,
            None => [0u8; 32],
        };
        let class_bytes = std::fs::read(&self.class_file).with_context(|| {
            format!("Read Deployer class file {}", self.class_file)
        })?;

        let deployer_contract = JvmDeployerContract::new(
            Box::new(signer),
            deployer,
            salt,
            class_bytes.clone(),
        )
        .await
        .context("Derive Deployer wc=3 address")?;
        let address_hex = hex::encode(deployer_contract.calculate_address());

        let class_size = class_bytes.len();
        let entry = JvmDeployerConfig {
            key: common::app_config::KeyConfig::VaultKey {
                name: self.vault_secret.clone(),
            },
            deployer_hex: hex::encode(deployer),
            salt_hex: hex::encode(salt),
            class_bytes_hex: hex::encode(class_bytes),
            address_hex: Some(address_hex.clone()),
        };
        config.jvm_deployers.insert(self.name.clone(), entry);
        super::utils::save_config(&config, path)?;

        println!(
            "\n{} Deployer '{}' registered\n",
            "OK".green().bold(),
            self.name
        );
        println!("  wc=3 address: {}", address_hex);
        println!("  salt:         {}", hex::encode(salt));
        println!("  deployer:     {}", hex::encode(deployer));
        println!("  vault key:    {}", self.vault_secret);
        println!("  class size:   {} bytes", class_size);
        println!();
        Ok(())
    }
}

impl JvmDeployerAddressCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault) = super::utils::load_config_vault(path).await?;

        let cfg = config.jvm_deployers.get(&self.name).ok_or_else(|| {
            anyhow::anyhow!("Deployer '{}' not found in config", self.name)
        })?;
        let addr = match &cfg.address_hex {
            Some(a) => a.clone(),
            None => {
                let dep =
                    load_jvm_deployer(&self.name, cfg, vault.clone()).await?;
                hex::encode(dep.calculate_address())
            }
        };
        println!("3:{}", addr);
        Ok(())
    }
}

impl JvmDeployerInfoCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) =
            load_config_vault_rpc_client(path).await?;

        let cfg = config.jvm_deployers.get(&self.name).ok_or_else(|| {
            anyhow::anyhow!("Deployer '{}' not found in config", self.name)
        })?;
        let deployer =
            load_jvm_deployer(&self.name, cfg, vault.clone()).await?;
        let address_hex = hex::encode(deployer.calculate_address());

        println!(
            "\n{} Deployer '{}' info\n",
            "OK".green().bold(),
            self.name
        );
        println!("  wc=3 address: {}", address_hex);
        println!("  owner pubkey: {}", hex::encode(deployer.owner_pubkey()));
        println!("  class hash:   {}", hex::encode(deployer.class_hash()));
        println!(
            "  manifest:     {}",
            hex::encode(deployer.manifest_root_hash())
        );

        match rpc_client
            .jvm_get_contract_state(address_hex.clone(), None)
            .await
        {
            Ok(view) => match parse_deployer_nonce(&view) {
                Ok(n) => println!("  on-chain nonce: {}", n),
                Err(_) => {}
            },
            Err(e) => println!(
                "\n  {} jvm_getContractState unavailable — Deployer may not \
                 be deployed yet ({})",
                "WARN".yellow(),
                e.root_cause()
            ),
        }
        println!();
        Ok(())
    }
}

impl JvmWalletExecuteCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault, rpc_client) =
            load_config_vault_rpc_client(path).await?;

        let cfg = config
            .jvm_wallets
            .get(&self.name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "JVM wallet '{}' not found in config",
                    self.name
                )
            })?;

        let wallet = load_jvm_wallet(&self.name, cfg, vault.clone()).await?;
        let (dest_wc, dest_addr) = parse_address(&self.to)?;
        let body_bytes = match &self.body {
            Some(b) => hex::decode(b.strip_prefix("0x").unwrap_or(b))
                .context("--body must be hex")?,
            None => Vec::new(),
        };

        let payload = build_wallet_single_transfer_payload(
            dest_wc,
            &dest_addr,
            self.amount,
            &body_bytes,
        )?;

        // Determine the wallet's current nonce: explicit override > chain
        // fetch.  A wallet that has never sent before returns 0.
        let wallet_addr = wallet.calculate_address();
        let wallet_addr_hex = hex::encode(wallet_addr);
        let nonce_value = match self.nonce {
            Some(n) => n,
            None => {
                let view = rpc_client
                    .jvm_get_contract_state(wallet_addr_hex.clone(), None)
                    .await
                    .context(
                        "jvm_getContractState(wallet) — pass --nonce to skip",
                    )?;
                parse_wallet_nonce(&view)?
            }
        };
        let nonce = U256::from_u64(nonce_value);

        let signature = wallet.sign_execute(nonce, &payload).await?;
        let call_descriptor: Cell = wallet
            .encode_execute_call(nonce, &payload, &signature)
            .context("encode execute call descriptor")?;

        // Wrap as ext-in-msg to the wallet's own wc=3 address.  This is
        // the same shape Phase H.4's `jw deploy` uses for the Deployer.
        let ext_msg_boc =
            build_ext_in_message(3, wallet_addr, call_descriptor)?;

        println!(
            "\n{} prepared execute() artifacts\n",
            "OK".green().bold()
        );
        println!("  wallet:          3:{}", wallet_addr_hex);
        println!("  destination:     {}:{}", dest_wc, hex::encode(dest_addr));
        println!("  amount:          {}", self.amount);
        println!("  nonce:           {}", nonce_value);
        println!("  payload size:    {} bytes", payload.len());
        println!("  ext-msg BOC:     {} bytes", ext_msg_boc.len());
        println!();

        if self.dry_run {
            println!(
                "  {}: --dry-run set; not sending. ext-msg BOC hex below:",
                "DRY".yellow().bold()
            );
            println!("  0x{}", hex::encode(&ext_msg_boc));
            return Ok(());
        }

        rpc_client
            .send_boc(&ext_msg_boc)
            .await
            .context("send_boc to wc=3 wallet")?;
        println!(
            "  {} ext-msg submitted; nonce will advance to {} on commit",
            "SENT".green().bold(),
            nonce_value + 1
        );
        Ok(())
    }
}

/// Parse a `wc:hex32` address string into `(wc, [u8;32])`. Accepts
/// either `3:abc…` or `-1:abc…` shapes; the hex part must be 64 chars.
fn parse_address(input: &str) -> Result<(i32, [u8; 32])> {
    let (wc_str, addr_str) = input
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("address must be `wc:hex32`"))?;
    let wc: i32 = wc_str
        .parse()
        .with_context(|| format!("invalid workchain id {wc_str}"))?;
    let addr = parse_hex32(addr_str, "address account-id")?;
    Ok((wc, addr))
}
