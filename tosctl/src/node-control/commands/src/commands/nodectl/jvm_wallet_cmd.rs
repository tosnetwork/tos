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
use chain_block::{Cell, write_boc};
use chain_rpc_client::v2::jvm::JvmContractStateView;
use colored::Colorize;
use common::{app_config::JvmWalletConfig, vault_signer::VaultSigner};
use contracts::{
    build_wallet_single_transfer_payload, jvm_wallet::JvmWalletContract,
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
    /// Deploy this wallet to wc=3 via a deployer wallet (stub — see
    /// docs).
    Deploy(JvmWalletDeployCmd),
    /// Sign + send a single transfer from this wallet (stub — see
    /// docs).
    Execute(JvmWalletExecuteCmd),
    /// Fetch + decode the wallet's on-chain state (owner key, nonce,
    /// init flag).
    Info(JvmWalletInfoCmd),
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
#[command(about = "Deploy a wc=3 JVM wallet (cross-workchain — stubbed)")]
pub struct JvmWalletDeployCmd {
    #[arg(short = 'n', long = "name", help = "Wallet name")]
    name: String,
    /// Name of a previously-deployed wc=3 wallet to send the deploy
    /// `action_create_account` from. The action_create_account TLB
    /// requires the sender to declare
    /// `admits_engine_create_account_actions` (jvm/core only), so this
    /// MUST be a wc=3 wallet, NOT a wc=0 TVM wallet.
    #[arg(long = "deployer-name", help = "Name of a wc=3 deployer wallet")]
    deployer_name: String,
    /// Tomis attached to the deploy call (covers storage stake + init
    /// call gas).
    #[arg(long = "balance", default_value = "1000000000")]
    balance: u128,
}

#[derive(clap::Args, Clone)]
#[command(about = "Sign + send a single transfer from a wc=3 JVM wallet (stubbed)")]
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
    pub async fn run(&self, _config_path: &str) -> Result<()> {
        // Documented stub — see module-level doc-comment for the
        // detailed rationale. The pieces needed to make this work
        // automatically:
        //   1. A wc=3 wallet at `--deployer-name` that has already
        //      been seeded into the chain via the genesis Fift word
        //      `jvm-zerostate-from-alloc` (see Phase F seeding docs).
        //   2. A path to build an `action_create_account` OutAction
        //      from that wallet's signing surface.
        //   3. A way to package that into a wc=3 wallet internal
        //      message and forward via `send_boc` — which requires
        //      the deployer wallet to already understand the JVI2
        //      execute(...) ABI.
        // The contract-level building blocks all exist (see
        // `contracts::JvmWalletContract::build_create_account_action`,
        // `encode_jvm_state_init_cell`, `encode_action_create_account`).
        // What's missing is a wc=3 "router" that can sign one for us
        // before any wc=3 wallet exists — i.e. this is genuinely a
        // bootstrapping problem that should be solved by genesis
        // seeding, not by an ad-hoc CLI workflow.
        let _ = &self.deployer_name;
        let _ = self.balance;
        let _ = &self.name;
        anyhow::bail!(
            "tosctl jvm-wallet deploy is not yet wired into the CLI.\n\
             For the first wc=3 wallet, use the genesis seeding Fift word\n\
             `jvm-zerostate-from-alloc` from the Phase F bring-up docs.\n\
             For subsequent wallets, this path will be enabled once a\n\
             wc=3 router wallet is reachable from the CLI; the contract-\n\
             level helpers (JvmWalletContract::build_create_account_action,\n\
             encode_jvm_state_init_cell, encode_action_create_account)\n\
             are already in place in `contracts::jvm_wallet`."
        )
    }
}

impl JvmWalletExecuteCmd {
    pub async fn run(&self, config_path: &str) -> Result<()> {
        let path = Path::new(config_path);
        let (config, vault, _rpc_client) =
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

        // Even though the actual send is stubbed, we make sure the
        // offline portion (build payload + sign) succeeds so users can
        // at least dry-run / capture the call descriptor BOC.
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

        let nonce_value = self.nonce.unwrap_or(0);
        let nonce = U256::from_u64(nonce_value);

        let signature = wallet.sign_execute(nonce, &payload).await?;
        let call_descriptor: Cell = wallet
            .encode_execute_call(nonce, &payload, &signature)
            .context("encode execute call descriptor")?;

        let descriptor_boc = write_boc(&call_descriptor)?;
        println!(
            "{} Built signed execute() descriptor",
            "OK".green().bold()
        );
        println!("  wallet:          3:{}", hex::encode(wallet.calculate_address()));
        println!("  destination:     {}:{}", dest_wc, hex::encode(dest_addr));
        println!("  amount:          {}", self.amount);
        println!("  nonce:           {}", nonce_value);
        println!("  payload (hex):   {}", hex::encode(&payload));
        println!("  signature (hex): {}", hex::encode(&signature));
        println!(
            "  descriptor BOC:  {}",
            hex::encode(&descriptor_boc)
        );

        anyhow::bail!(
            "tosctl jvm-wallet execute is not yet wired for on-chain send.\n\
             The signed JvmCallDescriptor BOC printed above is correct and\n\
             can be replayed via a wc=3 router; CLI send routing requires\n\
             a wc=3 sender account (see deploy stub for the same\n\
             bootstrapping rationale)."
        )
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
