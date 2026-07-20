/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use super::agent_cmd::{confirm, parse_required_hash, send_wallet_message, validate_tos_amount};
use super::output_format::OutputFormat;
use super::utils::{
    get_wallet_config, load_config_vault_rpc_client, make_wallet, save_config,
    try_create_rpc_client, wallet_info,
};
use anyhow::Context;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::data_models::AccountState;
use clap::ValueEnum;
use colored::Colorize;
use common::app_config::{KeyConfig, ProofAttestationConfig};
use contracts::{ProofAttestationContract, ProofAttestationData, ProofAttestationInit};
use secrets_vault::vault::SecretVault;
use std::{path::Path, sync::Arc};

const PROOF_ATTESTATION_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const PROOF_ATTESTATION_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent attestation` -- Proof Attestation operations.
#[derive(clap::Args, Clone)]
#[command(about = "Proof Attestation (ed25519 signature adapter) operations")]
pub struct ProofAttestationCmd {
    #[command(subcommand)]
    action: ProofAttestationAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ProofAttestationAction {
    /// Deploy a Proof Attestation actor
    Deploy(ProofAttestationDeployCmd),
    /// List locally tracked Proof Attestation records
    Ls(ProofAttestationLsCmd),
    /// Show Proof Attestation state by address or local record name
    Show(ProofAttestationShowCmd),
    /// Send a Proof Attestation lifecycle message
    Send(ProofAttestationSendCmd),
}

impl ProofAttestationCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            ProofAttestationAction::Deploy(cmd) => cmd.run(config_path).await,
            ProofAttestationAction::Ls(cmd) => cmd.run(config_path).await,
            ProofAttestationAction::Show(cmd) => cmd.run(config_path).await,
            ProofAttestationAction::Send(cmd) => cmd.run(config_path).await,
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy a Proof Attestation actor")]
pub struct ProofAttestationDeployCmd {
    #[arg(long, help = "Local record name; defaults to attestation-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Owner address; must match the funding wallet")]
    owner: String,
    #[arg(
        long,
        conflicts_with = "signer_vault_key",
        help = "32-byte ed25519 public key expected to sign attestations"
    )]
    public_key: Option<String>,
    #[arg(
        long,
        conflicts_with = "public_key",
        help = "Vault key name to derive the public key from, instead of --public-key"
    )]
    signer_vault_key: Option<String>,
    #[arg(long, help = "32-byte reference to what this attestation is about")]
    subject_hash: String,
    #[arg(long, help = "Funding wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0.05, help = "Message value funding the deploy, in TOS")]
    amount: f64,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(long)]
    yes: bool,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked Proof Attestation records")]
pub struct ProofAttestationLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show Proof Attestation state by address or local record name")]
pub struct ProofAttestationShowCmd {
    #[arg(long, conflicts_with = "name", help = "Proof Attestation address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent attestation ls`")]
    name: Option<String>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum ProofAttestationOperation {
    Attest,
    RotateKey,
    Revoke,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send a Proof Attestation lifecycle message")]
pub struct ProofAttestationSendCmd {
    #[arg(long, value_enum)]
    operation: ProofAttestationOperation,
    #[arg(long, conflicts_with = "name", help = "Proof Attestation address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent attestation ls`")]
    name: Option<String>,
    #[arg(long, help = "Funding wallet name or master_wallet (attest is permissionless on-chain, \
                         but still needs a wallet to pay for the message)")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "Hash being attested to, for attest")]
    attested_hash: Option<String>,
    #[arg(long, conflicts_with = "signer_vault_key", help = "Precomputed 64-byte ed25519 \
                                                              signature over --attested-hash, hex, \
                                                              for attest")]
    signature: Option<String>,
    #[arg(long, conflicts_with = "signature", help = "Vault key name to sign --attested-hash \
                                                       with locally, instead of --signature")]
    signer_vault_key: Option<String>,
    #[arg(long, conflicts_with = "new_signer_vault_key", help = "New public key for rotate-key")]
    new_public_key: Option<String>,
    #[arg(
        long,
        conflicts_with = "new_public_key",
        help = "Vault key name to derive the new public key from, for rotate-key"
    )]
    new_signer_vault_key: Option<String>,
    #[arg(long, default_value_t = 0.01, help = "Message value in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

/// Resolve the attestation address from an explicit `--address` or a stored `--name` record.
fn resolve_attestation_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .proof_attestations
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!("Attestation record '{}' not found; see `agent attestation ls`", name)
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid Proof Attestation address")
}

/// Derive an ed25519 public key from a named vault secret.
async fn public_key_from_vault(name: &str, vault: Arc<SecretVault>) -> anyhow::Result<[u8; 32]> {
    let secret = KeyConfig::VaultKey { name: name.to_owned() }.read_secret(Some(vault)).await?;
    let keypair = secret.as_keypair()?;
    let raw = keypair
        .public_key()
        .await?
        .ok_or_else(|| anyhow::anyhow!("vault key '{}' has no public key", name))?;
    raw.try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))
}

async fn resolve_public_key(
    public_key: &Option<String>,
    signer_vault_key: &Option<String>,
    vault: Arc<SecretVault>,
) -> anyhow::Result<[u8; 32]> {
    match (public_key, signer_vault_key) {
        (Some(hex), None) => parse_required_hash("public-key", &Some(hex.clone())),
        (None, Some(name)) => public_key_from_vault(name, vault).await,
        _ => anyhow::bail!("provide exactly one of --public-key or --signer-vault-key"),
    }
}

/// Sign the 32-byte `attested_hash` directly with the named vault key,
/// matching `CHKSIGNU`'s convention (the same one `AgentAccountContract`'s
/// controller-signed actions already use: sign the raw hash, not a
/// re-hashed or length-prefixed encoding of it).
async fn sign_with_vault_key(
    name: &str,
    attested_hash: &[u8; 32],
    vault: Arc<SecretVault>,
) -> anyhow::Result<[u8; 64]> {
    let secret = KeyConfig::VaultKey { name: name.to_owned() }.read_secret(Some(vault)).await?;
    let keypair = secret.as_keypair()?;
    let raw = keypair.sign(attested_hash).await?;
    raw.try_into().map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))
}

impl ProofAttestationDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let owner = self.owner.parse::<MsgAddressInt>().context("invalid owner address")?;
        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let public_key =
            resolve_public_key(&self.public_key, &self.signer_vault_key, vault.clone()).await?;
        let init = ProofAttestationInit {
            owner: owner.clone(),
            public_key,
            subject_hash: parse_required_hash("subject-hash", &Some(self.subject_hash.clone()))?,
        };
        let address = ProofAttestationContract::calculate_address(self.workchain, &init)?;
        let state_init = ProofAttestationContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("attestation-{}", &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.proof_attestations.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "Attestation record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .proof_attestations
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!(
                "Proof Attestation address {} is already tracked as '{}'",
                address,
                existing_name
            );
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != owner {
            anyhow::bail!("owner address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if amount_nanotos == 0
            || payer_info.balance < amount_nanotos.saturating_add(PROOF_ATTESTATION_DEPLOY_GAS)
        {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Proof Attestation deployment?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), payer_cfg, payer_secret, &self.from).await?;
        let body = chain_block::BuilderData::new().into_cell()?;
        super::agent_cmd::send_wallet_message_with_state_init(
            &wallet,
            rpc_client,
            address.clone(),
            amount_nanotos,
            body,
            payer_info.seqno,
            &payer_address,
            state_init,
        )
        .await?;
        config.proof_attestations.insert(
            record_name.clone(),
            ProofAttestationConfig {
                address: address.to_string(),
                owner: owner.to_string(),
                public_key: hex::encode(init.public_key),
                subject_hash: hex::encode(init.subject_hash),
                created_at: Some(common::time_format::now()),
            },
        );
        save_config(&config, path)?;
        if self.format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({
                    "name": record_name,
                    "address": address.to_string(),
                    "status": "submitted",
                    "owner": owner.to_string(),
                    "public_key": hex::encode(public_key),
                })
            );
        } else {
            println!(
                "{} Proof Attestation '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ProofAttestationDataView {
    address: String,
    owner: String,
    public_key: String,
    revoked: bool,
    has_attestation: bool,
    attested_at: u64,
    subject_hash: String,
    attested_hash: String,
}

fn data_view(address: &MsgAddressInt, data: ProofAttestationData) -> ProofAttestationDataView {
    ProofAttestationDataView {
        address: address.to_string(),
        owner: data.owner.to_string(),
        public_key: hex::encode(data.public_key),
        revoked: data.revoked,
        has_attestation: data.has_attestation,
        attested_at: data.attested_at,
        subject_hash: hex::encode(data.subject_hash),
        attested_hash: hex::encode(data.attested_hash),
    }
}

impl ProofAttestationShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_attestation_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack =
            provider.get_method(address.to_string(), "get_proof_attestation_data", vec![]).await?;
        let data = ProofAttestationContract::decode_data(&stack)?;
        let view = data_view(&address, data);
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&view)?);
        } else {
            println!("Proof Attestation: {}", view.address);
            println!("Owner: {}", view.owner);
            println!("Public key: {}", view.public_key);
            println!("Revoked: {}", view.revoked);
            println!("Has attestation: {}", view.has_attestation);
            if view.has_attestation {
                println!("Attested hash: {}", view.attested_hash);
                println!("Attested at: {}", view.attested_at);
            }
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ProofAttestationRecordView {
    name: String,
    address: String,
    owner: String,
    public_key: String,
    subject_hash: String,
    created_at: Option<u64>,
}

impl ProofAttestationLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let mut records: Vec<ProofAttestationRecordView> = config
            .proof_attestations
            .iter()
            .map(|(name, entry)| ProofAttestationRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                owner: entry.owner.clone(),
                public_key: entry.public_key.clone(),
                subject_hash: entry.subject_hash.clone(),
                created_at: entry.created_at,
            })
            .collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No Proof Attestation records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:    {}\n  Owner:      {}\n  Public key: {}",
                record.name.bold(),
                record.address,
                record.owner,
                record.public_key,
            );
        }
        Ok(())
    }
}

impl ProofAttestationSendCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_attestation_address(&config, &self.address, &self.name)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault.clone()).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }

        let body = match self.operation {
            ProofAttestationOperation::Attest => {
                let attested_hash =
                    parse_required_hash("attested-hash", &self.attested_hash)?;
                let signature = match (&self.signature, &self.signer_vault_key) {
                    (Some(hex), None) => parse_signature(hex)?,
                    (None, Some(name)) => {
                        sign_with_vault_key(name, &attested_hash, vault.clone()).await?
                    }
                    _ => anyhow::bail!("provide exactly one of --signature or --signer-vault-key"),
                };
                ProofAttestationContract::attest(self.query_id, attested_hash, &signature)?
            }
            ProofAttestationOperation::RotateKey => {
                let new_public_key = resolve_public_key(
                    &self.new_public_key,
                    &self.new_signer_vault_key,
                    vault.clone(),
                )
                .await?;
                ProofAttestationContract::rotate_key(self.query_id, new_public_key)?
            }
            ProofAttestationOperation::Revoke => ProofAttestationContract::revoke(self.query_id)?,
        };

        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(PROOF_ATTESTATION_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm Proof Attestation message?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), wallet_config, owner_secret, &self.from).await?;
        send_wallet_message(
            &wallet,
            rpc_client,
            destination.clone(),
            amount_nanotos,
            body,
            true,
            owner_info.seqno,
            &owner_address,
        )
        .await?;
        println!(
            "{} Proof Attestation {} message submitted to {}",
            "OK".green().bold(),
            self.operation.to_possible_value().unwrap().get_name(),
            destination
        );
        Ok(())
    }
}

fn parse_signature(hex_str: &str) -> anyhow::Result<[u8; 64]> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed).context("--signature must be a 64-byte hex string")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("--signature must be exactly 64 bytes"))
}
