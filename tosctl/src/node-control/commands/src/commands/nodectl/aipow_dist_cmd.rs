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
use colored::Colorize;
use common::app_config::AipowDistributorConfig;
use contracts::aipow_merkle::{ScoreEntry, inclusion_proof, score_root};
use contracts::{
    AIPOW_COMMITMENT_STATUS_FINAL, AipowCommitmentContract, AipowDistributorContract,
    AipowDistributorData, AipowDistributorInit, AipowMaturation,
};
use std::path::Path;

const DIST_DEPLOY_GAS: u64 = 1_000_000; // 0.001 TOS
const DIST_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent aipow-dist` -- AIPoW reward distributor operations.
#[derive(clap::Args, Clone)]
#[command(about = "AIPoW reward distributor operations")]
pub struct AipowDistCmd {
    #[command(subcommand)]
    action: AipowDistAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AipowDistAction {
    /// Deploy a distributor over a finalized epoch score root
    Deploy(AipowDistDeployCmd),
    /// List locally tracked distributor records
    Ls(AipowDistLsCmd),
    /// Show distributor state by address or local record name
    Show(AipowDistShowCmd),
    /// Claim a beneficiary's pro-rata share with a merkle inclusion proof
    Claim(AipowDistClaimCmd),
    /// Operator-only: forfeit a claim's unmatured remainder (fraud slashing)
    Forfeit(AipowDistForfeitCmd),
}

impl AipowDistCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AipowDistAction::Deploy(cmd) => cmd.run(config_path).await,
            AipowDistAction::Ls(cmd) => cmd.run(config_path).await,
            AipowDistAction::Show(cmd) => cmd.run(config_path).await,
            AipowDistAction::Claim(cmd) => cmd.run(config_path).await,
            AipowDistAction::Forfeit(cmd) => cmd.run(config_path).await,
        }
    }
}

/// One scored identity as published by the scorer: a 32-byte identity hex
/// and its final score.
#[derive(serde::Deserialize)]
struct EntryJson {
    identity: String,
    score: u128,
}

/// Parse an entries file into merkle score entries. The file is a JSON
/// array of `{ "identity": "<64 hex>", "score": <u128> }`.
fn load_entries(path: &str) -> anyhow::Result<Vec<ScoreEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read entries file {path}"))?;
    let raw: Vec<EntryJson> = serde_json::from_str(&text)
        .context("entries file must be a JSON array of {identity, score}")?;
    raw.into_iter()
        .map(|e| {
            let identity = parse_required_hash("identity", &Some(e.identity))?;
            Ok(ScoreEntry { identity, score: e.score })
        })
        .collect()
}

/// The pro-rata denominator: the sum of all entry scores, checked.
fn total_score(entries: &[ScoreEntry]) -> anyhow::Result<u128> {
    let mut total: u128 = 0;
    for entry in entries {
        total = total
            .checked_add(entry.score)
            .ok_or_else(|| anyhow::anyhow!("total score overflows u128"))?;
    }
    Ok(total)
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy a distributor over a finalized epoch score root")]
pub struct AipowDistDeployCmd {
    #[arg(long, help = "Local record name; defaults to aipow-dist-<epoch>-<address prefix>")]
    name: Option<String>,
    #[arg(long, help = "Operator address; must match the funding wallet")]
    operator: String,
    #[arg(long, help = "AIPoW epoch number this distributor serves")]
    epoch: u64,
    #[arg(
        long,
        help = "JSON entries file (the scorer's identity/score list); the score root and total score are computed from it"
    )]
    entries_file: String,
    #[arg(long, help = "Nominal epoch pool in TOS this slice records against")]
    pool: f64,
    #[arg(
        long,
        conflicts_with = "commitment_ref",
        help = "Finalized score-commitment address to bind to; it is queried and must be final with a matching root, total score, and epoch, and its account id becomes the commitment reference"
    )]
    commitment: Option<String>,
    #[arg(
        long,
        help = "32-byte reference to the finalized score commitment (hex); the raw, unverified alternative to --commitment"
    )]
    commitment_ref: Option<String>,
    #[arg(
        long,
        help = "Optional 32-byte score root (hex) to require the entries file to match, as a guard against the wrong file"
    )]
    expect_score_root: Option<String>,
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

impl AipowDistDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        validate_tos_amount("pool", self.pool)?;
        let operator =
            self.operator.parse::<MsgAddressInt>().context("invalid operator address")?;
        let entries = load_entries(&self.entries_file)?;
        if entries.is_empty() {
            anyhow::bail!("entries file is empty");
        }
        let root = score_root(&entries).context("computing score root from entries")?;
        if let Some(expected) = &self.expect_score_root {
            let expected = parse_required_hash("expect-score-root", &Some(expected.clone()))?;
            if root != expected {
                anyhow::bail!(
                    "entries file score root {} does not match --expect-score-root {}",
                    hex::encode(root),
                    hex::encode(expected)
                );
            }
        }
        let total = total_score(&entries)?;
        let pool_nanotos = common::chain_utils::tos_to_nanotos(self.pool);

        let path = Path::new(config_path);
        let (mut config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;

        // Bind the distributor to a finalized commitment. With --commitment,
        // the commitment is queried and must be final with a root, total
        // score, and epoch that match this deployment; its account id then
        // becomes the reference, so the binding is provable rather than a
        // free operator-supplied hash. --commitment-ref keeps the raw path.
        let commitment_ref = match (&self.commitment, &self.commitment_ref) {
            (Some(addr_raw), None) => {
                let commitment_addr =
                    addr_raw.parse::<MsgAddressInt>().context("invalid commitment address")?;
                let provider = contracts::contract_provider!(rpc_client.clone());
                let stack = provider
                    .get_method(commitment_addr.to_string(), "get_aipow_commitment_data", vec![])
                    .await?;
                let commitment = AipowCommitmentContract::decode_data(&stack)?;
                if commitment.status != AIPOW_COMMITMENT_STATUS_FINAL {
                    anyhow::bail!(
                        "commitment {} is not final (status {}); a distributor may only be deployed over a finalized root",
                        commitment_addr,
                        commitment.status
                    );
                }
                if commitment.score_root != root {
                    anyhow::bail!(
                        "commitment root {} does not match the entries-file root {}",
                        hex::encode(commitment.score_root),
                        hex::encode(root)
                    );
                }
                if commitment.total_score != total {
                    anyhow::bail!(
                        "commitment total_score {} does not match the entries-file total {}",
                        commitment.total_score,
                        total
                    );
                }
                if commitment.epoch != self.epoch {
                    anyhow::bail!(
                        "commitment epoch {} does not match --epoch {}",
                        commitment.epoch,
                        self.epoch
                    );
                }
                let bytes = commitment_addr.address().get_bytestring(0);
                bytes.try_into().map_err(|_| {
                    anyhow::anyhow!("commitment address is not a 256-bit account id")
                })?
            }
            (None, Some(raw)) => parse_required_hash("commitment-ref", &Some(raw.clone()))?,
            _ => anyhow::bail!("provide exactly one of --commitment or --commitment-ref"),
        };

        let init = AipowDistributorInit {
            operator: operator.clone(),
            epoch: self.epoch,
            // Scored identities are paid on the basechain where agent wallets
            // live; the maturation curve uses the methodology v0 snapshot. Phase
            // C surfaces both as governance/CLI parameters.
            earner_workchain: 0,
            total_score: total,
            pool: pool_nanotos,
            maturation: AipowMaturation::methodology_v0(),
            score_root: root,
            commitment_ref,
        };
        let address = AipowDistributorContract::calculate_address(self.workchain, &init)?;
        let state_init = AipowDistributorContract::build_state_init(&init)?;
        let record_name = self.name.clone().unwrap_or_else(|| {
            let hex = address.to_string();
            let hash = hex.rsplit(':').next().unwrap_or(&hex);
            format!("aipow-dist-{}-{}", self.epoch, &hash[..hash.len().min(8)])
        });
        if let Some(existing) = config.aipow_distributors.get(&record_name) {
            if existing.address != address.to_string() {
                anyhow::bail!(
                    "distributor record '{}' already exists for address {}",
                    record_name,
                    existing.address
                );
            }
        }
        if let Some((existing_name, _)) = config
            .aipow_distributors
            .iter()
            .find(|(name, entry)| *name != &record_name && entry.address == address.to_string())
        {
            anyhow::bail!(
                "distributor address {} is already tracked as '{}'",
                address,
                existing_name
            );
        }
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_address != operator {
            anyhow::bail!("operator address must match funding wallet address");
        }
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if amount_nanotos == 0
            || payer_info.balance < amount_nanotos.saturating_add(DIST_DEPLOY_GAS)
        {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW distributor deployment?")? {
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
        config.aipow_distributors.insert(
            record_name.clone(),
            AipowDistributorConfig {
                address: address.to_string(),
                operator: operator.to_string(),
                epoch: self.epoch,
                total_score: total.to_string(),
                pool: pool_nanotos,
                score_root: hex::encode(root),
                commitment_ref: hex::encode(init.commitment_ref),
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
                    "epoch": self.epoch,
                    "score_root": hex::encode(root),
                    "total_score": total.to_string(),
                })
            );
        } else {
            println!(
                "{} AIPoW distributor '{}' deployed at {}",
                "OK".green().bold(),
                record_name,
                address
            );
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "List locally tracked distributor records")]
pub struct AipowDistLsCmd {
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(serde::Serialize)]
struct DistRecordView {
    name: String,
    address: String,
    operator: String,
    epoch: u64,
    total_score: String,
    created_at: Option<u64>,
}

impl AipowDistLsCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let mut records: Vec<DistRecordView> = config
            .aipow_distributors
            .iter()
            .map(|(name, entry)| DistRecordView {
                name: name.clone(),
                address: entry.address.clone(),
                operator: entry.operator.clone(),
                epoch: entry.epoch,
                total_score: entry.total_score.clone(),
                created_at: entry.created_at,
            })
            .collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        if self.format == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&records)?);
            return Ok(());
        }
        if records.is_empty() {
            println!("No AIPoW distributor records configured");
            return Ok(());
        }
        for record in &records {
            println!(
                "{}\n  Address:  {}\n  Operator: {}\n  Epoch:    {}",
                record.name.bold(),
                record.address,
                record.operator,
                record.epoch,
            );
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Show distributor state by address or local record name")]
pub struct AipowDistShowCmd {
    #[arg(long, conflicts_with = "name", help = "Distributor address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent aipow-dist ls`")]
    name: Option<String>,
    #[arg(long, help = "Optional identity (hex) to also report the claim and matured amount for")]
    identity: Option<String>,
    #[arg(long, help = "Unix time to evaluate maturation at; defaults to now")]
    at_time: Option<u64>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

fn resolve_dist_address(
    config: &common::app_config::AppConfig,
    address: &Option<String>,
    name: &Option<String>,
) -> anyhow::Result<MsgAddressInt> {
    let raw = match (address, name) {
        (Some(address), None) => address.clone(),
        (None, Some(name)) => config
            .aipow_distributors
            .get(name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "distributor record '{}' not found; see `agent aipow-dist ls`",
                    name
                )
            })?
            .address
            .clone(),
        _ => anyhow::bail!("provide exactly one of --address or --name"),
    };
    raw.parse::<MsgAddressInt>().context("invalid distributor address")
}

#[derive(serde::Serialize)]
struct DistDataView {
    address: String,
    operator: String,
    epoch: u64,
    total_score: String,
    pool: u64,
    claimed_count: u32,
    claimed_score: String,
    score_root: String,
    commitment_ref: String,
}

fn data_view(address: &MsgAddressInt, data: AipowDistributorData) -> DistDataView {
    DistDataView {
        address: address.to_string(),
        operator: data.operator.to_string(),
        epoch: data.epoch,
        total_score: data.total_score.to_string(),
        pool: data.pool,
        claimed_count: data.claimed_count,
        claimed_score: data.claimed_score.to_string(),
        score_root: hex::encode(data.score_root),
        commitment_ref: hex::encode(data.commitment_ref),
    }
}

impl AipowDistShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let address = resolve_dist_address(&config, &self.address, &self.name)?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client);
        let stack =
            provider.get_method(address.to_string(), "get_aipow_distributor_data", vec![]).await?;
        let data = AipowDistributorContract::decode_data(&stack)?;
        let view = data_view(&address, data);

        // Optionally report a single beneficiary's claim + matured amount.
        let claim_view = if let Some(identity_hex) = &self.identity {
            let identity = parse_required_hash("identity", &Some(identity_hex.clone()))?;
            let arg = vec![contracts::stack_utils::bytes_to_stack_entry(&identity)];
            let claim_stack =
                provider.get_method(address.to_string(), "get_claim", arg.clone()).await?;
            let claim = AipowDistributorContract::decode_claim(&claim_stack)?;
            let at = self.at_time.unwrap_or_else(common::time_format::now);
            let mut matured_arg = arg;
            matured_arg.push(contracts::stack_utils::i64_to_stack_entry(at as i64));
            let matured_stack =
                provider.get_method(address.to_string(), "get_matured", matured_arg).await?;
            let matured = AipowDistributorContract::decode_matured(&matured_stack)?;
            claim.map(|c| ClaimView {
                identity: identity_hex.clone(),
                amount: c.amount,
                claimed_at: c.claimed_at,
                forfeited: c.forfeited,
                forfeit_at: c.forfeit_at,
                matured_at: at,
                matured: matured.unwrap_or(0),
            })
        } else {
            None
        };

        if self.format == OutputFormat::Json {
            let mut out = serde_json::to_value(&view)?;
            if let Some(claim) = &claim_view {
                out["claim"] = serde_json::to_value(claim)?;
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!("AIPoW distributor: {}", view.address);
            println!("Operator: {}", view.operator);
            println!("Epoch:    {}", view.epoch);
            println!("Total score: {}", view.total_score);
            println!("Pool (nanotos): {}", view.pool);
            println!("Claimed count:  {}", view.claimed_count);
            println!("Claimed score:  {}", view.claimed_score);
            println!("Score root: {}", view.score_root);
            match &claim_view {
                Some(c) => {
                    println!("Claim [{}]:", c.identity);
                    println!("  Amount (nanotos):  {}", c.amount);
                    println!("  Forfeited: {}", c.forfeited);
                    println!("  Matured at {} (nanotos): {}", c.matured_at, c.matured);
                }
                None if self.identity.is_some() => println!("No claim for that identity"),
                None => {}
            }
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ClaimView {
    identity: String,
    amount: u64,
    claimed_at: u64,
    forfeited: bool,
    forfeit_at: u64,
    matured_at: u64,
    matured: u64,
}

#[derive(clap::Args, Clone)]
#[command(about = "Claim a beneficiary's pro-rata share with a merkle inclusion proof")]
pub struct AipowDistClaimCmd {
    #[arg(long, conflicts_with = "name", help = "Distributor address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent aipow-dist ls`")]
    name: Option<String>,
    #[arg(
        long,
        help = "JSON entries file (the scorer's identity/score list); the inclusion proof is built from it"
    )]
    entries_file: String,
    #[arg(long, help = "32-byte identity to claim for (hex)")]
    identity: String,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(
        long,
        default_value_t = 0.1,
        help = "Message value in TOS; must clear the contract's minimum claim value (0.05 TOS) so the claim funds its own gas and storage rent"
    )]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

impl AipowDistClaimCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_dist_address(&config, &self.address, &self.name)?;
        let identity = parse_required_hash("identity", &Some(self.identity.clone()))?;
        let entries = load_entries(&self.entries_file)?;
        let entry = entries
            .iter()
            .find(|e| e.identity == identity)
            .ok_or_else(|| anyhow::anyhow!("identity is not present in the entries file"))?;
        let score = entry.score;
        let root = score_root(&entries).context("computing score root from entries")?;
        let proof = inclusion_proof(&entries, &identity).context("building inclusion proof")?;

        // Guard against the wrong entries file: the computed root must match
        // the distributor's on-chain root, or the claim would be rejected
        // anyway.
        let provider = contracts::contract_provider!(rpc_client.clone());
        let stack = provider
            .get_method(destination.to_string(), "get_aipow_distributor_data", vec![])
            .await?;
        let onchain = AipowDistributorContract::decode_data(&stack)?;
        if onchain.score_root != root {
            anyhow::bail!(
                "entries file score root {} does not match the distributor's on-chain root {}",
                hex::encode(root),
                hex::encode(onchain.score_root)
            );
        }

        let body = AipowDistributorContract::claim(self.query_id, identity, score, &proof)?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if amount_nanotos < contracts::AIPOW_MIN_CLAIM_VALUE {
            anyhow::bail!(
                "--amount must be at least the contract's minimum claim value ({} nanotos)",
                contracts::AIPOW_MIN_CLAIM_VALUE
            );
        }
        if owner_info.balance < amount_nanotos.saturating_add(DIST_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW distributor claim?")? {
            return Ok(());
        }
        let wallet =
            make_wallet(rpc_client.clone(), wallet_config, owner_secret, &self.from).await?;
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
            "{} AIPoW distributor claim submitted to {} for identity {}",
            "OK".green().bold(),
            destination,
            hex::encode(identity)
        );
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Operator-only: forfeit a claim's unmatured remainder")]
pub struct AipowDistForfeitCmd {
    #[arg(long, conflicts_with = "name", help = "Distributor address")]
    address: Option<String>,
    #[arg(long, help = "Local record name from `agent aipow-dist ls`")]
    name: Option<String>,
    #[arg(long, help = "32-byte identity whose claim to forfeit (hex)")]
    identity: String,
    #[arg(long, help = "Operator signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, default_value_t = 0.05, help = "Message value in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

impl AipowDistForfeitCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let destination = resolve_dist_address(&config, &self.address, &self.name)?;
        let identity = parse_required_hash("identity", &Some(self.identity.clone()))?;
        let wallet_config =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(rpc_client.clone(), wallet_config, vault).await?;
        if owner_info.account_state != AccountState::Active {
            anyhow::bail!("signing wallet is not active");
        }
        let body = AipowDistributorContract::forfeit(self.query_id, identity)?;
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);
        if owner_info.balance < amount_nanotos.saturating_add(DIST_ACTION_GAS) {
            anyhow::bail!("signing wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW distributor forfeit?")? {
            return Ok(());
        }
        let wallet =
            make_wallet(rpc_client.clone(), wallet_config, owner_secret, &self.from).await?;
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
            "{} AIPoW distributor forfeit submitted to {} for identity {}",
            "OK".green().bold(),
            destination,
            hex::encode(identity)
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_score_sums_and_detects_overflow() {
        let entries = vec![
            ScoreEntry { identity: [1; 32], score: 100 },
            ScoreEntry { identity: [2; 32], score: 200 },
        ];
        assert_eq!(total_score(&entries).unwrap(), 300);
        let big = vec![
            ScoreEntry { identity: [1; 32], score: u128::MAX },
            ScoreEntry { identity: [2; 32], score: 1 },
        ];
        assert!(total_score(&big).is_err());
    }

    #[test]
    fn load_entries_parses_and_rejects_bad_hex() {
        let dir = std::env::temp_dir().join(format!("aipow-dist-entries-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.json");
        std::fs::write(&good, format!(r#"[{{"identity":"{}","score":500}}]"#, "ab".repeat(32)))
            .unwrap();
        let entries = load_entries(good.to_str().unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity, [0xAB; 32]);
        assert_eq!(entries[0].score, 500);

        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"[{"identity":"zz","score":1}]"#).unwrap();
        assert!(load_entries(bad.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
