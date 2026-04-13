/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Governance voting commands
#[derive(clap::Args, Clone)]
#[command(about = "Manage governance voting")]
pub struct VoteCmd {
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
    action: VoteAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteAction {
    /// Manage config-proposal offers
    Offer(VoteOfferCmd),
    /// Manage complaints
    Complaint(VoteComplaintCmd),
    /// Manage validator elections
    Election(VoteElectionCmd),
}

// ── Offer ────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage config-proposal offers")]
pub struct VoteOfferCmd {
    #[command(subcommand)]
    action: VoteOfferAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteOfferAction {
    /// List active config-proposal offers
    Ls(VoteOfferLsCmd),
    /// Show diff for a config-proposal offer
    Diff(VoteOfferDiffCmd),
    /// Cast vote on one or more offers
    Cast(VoteOfferCastCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List active config-proposal offers")]
pub struct VoteOfferLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show diff for a config-proposal offer")]
pub struct VoteOfferDiffCmd {
    #[arg(long, help = "Proposal hash (hex)")]
    hash: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Cast vote on one or more offers")]
pub struct VoteOfferCastCmd {
    /// Proposal hash (hex) to vote on. If omitted, lists proposals and prompts.
    #[arg(long)]
    hash: Option<String>,
}

// ── Complaint ────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage complaints")]
pub struct VoteComplaintCmd {
    #[command(subcommand)]
    action: VoteComplaintAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteComplaintAction {
    /// List active complaints
    Ls(VoteComplaintLsCmd),
    /// Cast complaint vote
    Cast(VoteComplaintCastCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List active complaints")]
pub struct VoteComplaintLsCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Cast complaint vote")]
pub struct VoteComplaintCastCmd {
    /// Election ID of the past election containing the complaint
    #[arg(long)]
    election_id: u32,
    /// Complaint hash (hex, 64 chars / 32 bytes)
    #[arg(long)]
    complaint_hash: String,
}

// ── Election ─────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage validator elections")]
pub struct VoteElectionCmd {
    #[command(subcommand)]
    action: VoteElectionAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteElectionAction {
    /// List election entries
    Ls(VoteElectionLsCmd),
    /// Enter election
    Cast(VoteElectionCastCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List election entries")]
pub struct VoteElectionLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Enter election")]
pub struct VoteElectionCastCmd {
    /// Dry-run mode: query election status without actually casting a vote
    #[arg(long, default_value = "false")]
    dry_run: bool,
    /// Max factor for election bid (1.0 to 3.0)
    #[arg(long, default_value = "3.0")]
    max_factor: f32,
    /// Stake amount in TOS (whole units). If omitted, uses the minimum stake from elector.
    #[arg(long)]
    stake: Option<u64>,
    /// Wallet name from config to use for sending the bid. Defaults to first node's wallet.
    #[arg(long)]
    wallet: Option<String>,
}

// ── run() dispatch ───────────────────────────────────────────────────

impl VoteCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            VoteAction::Offer(cmd) => cmd.run(&self.config).await,
            VoteAction::Complaint(cmd) => cmd.run(&self.config).await,
            VoteAction::Election(cmd) => cmd.run(&self.config).await,
        }
    }

    /// Shortcut entry point for `tosctl ol` (vote offer ls).
    pub async fn run_offer_ls_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = VoteOfferLsCmd {
            format: super::output_format::OutputFormat::Table,
        };
        cmd.run(&config_path).await
    }

    /// Shortcut entry point for `tosctl el` (vote election ls).
    pub async fn run_election_ls_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = VoteElectionLsCmd {
            format: super::output_format::OutputFormat::Table,
        };
        cmd.run(&config_path).await
    }
}

impl VoteOfferCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteOfferAction::Ls(cmd) => cmd.run(config_path).await,
            VoteOfferAction::Diff(cmd) => cmd.run(config_path).await,
            VoteOfferAction::Cast(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteOfferLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::time_format::format_ts;
        use contracts::{ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, contract_provider_from};
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        if self.format != super::output_format::OutputFormat::Json {
            println!("\n{}", "Querying config contract for proposals...".cyan());
        }

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposals = wrapper.list_proposals().await?;

        if proposals.is_empty() {
            if self.format == super::output_format::OutputFormat::Json {
                println!("[]");
            } else {
                println!("\n{}\n", "No active config proposals.".yellow());
            }
            return Ok(());
        }

        if self.format == super::output_format::OutputFormat::Json {
            let views: Vec<serde_json::Value> = proposals.iter().map(|p| {
                serde_json::json!({
                    "param_id": p.param.id,
                    "is_critical": p.is_critical,
                    "expires": format_ts(p.expires as u64),
                    "voters": p.voters.len(),
                    "weight_remaining": p.weight_remaining,
                    "hash": hex::encode(p.hash),
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&views)?);
        } else {
            println!();
            println!("{}", "Config Proposals".bold());
            println!("{}", "\u{2500}".repeat(80));
            println!(
                "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
                "#".bold(),
                "Param".bold(),
                "Critical".bold(),
                "Expires".bold(),
                "Voters".bold(),
                "Weight Remaining".bold(),
            );
            println!("  {}", "\u{2500}".repeat(76));

            for (i, p) in proposals.iter().enumerate() {
                let critical = if p.is_critical { "Yes" } else { "No" };
                let expires = format_ts(p.expires as u64);
                println!(
                    "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
                    i + 1,
                    p.param.id,
                    critical,
                    expires,
                    p.voters.len(),
                    p.weight_remaining,
                );
            }

            println!();
        }
        Ok(())
    }
}

impl VoteOfferDiffCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::time_format::format_ts;
        use contracts::{ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, contract_provider_from};
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let hash_bytes_vec = hex::decode(self.hash.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid hex hash: {}", e))?;
        if hash_bytes_vec.len() != 32 {
            anyhow::bail!("Proposal hash must be 32 bytes (64 hex chars), got {}", hash_bytes_vec.len());
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash_bytes_vec);

        println!("\n{}", "Querying config contract for proposal...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposal = wrapper.get_proposal(hash_bytes).await?;

        match proposal {
            None => {
                println!("\n{}\n", "Proposal not found.".yellow());
            }
            Some(p) => {
                println!();
                println!("{}", "Proposal Details".bold());
                println!("{}", "\u{2500}".repeat(60));
                println!("  {:<20} {}", "Hash:".bold(), self.hash);
                println!("  {:<20} {}", "Param ID:".bold(), p.param.id);
                println!(
                    "  {:<20} {}",
                    "Critical:".bold(),
                    if p.is_critical { "Yes".red().to_string() } else { "No".green().to_string() }
                );
                println!("  {:<20} {}", "Expires:".bold(), format_ts(p.expires as u64));
                println!("  {:<20} {}", "Voters:".bold(), p.voters.len());
                println!("  {:<20} {}", "Weight remaining:".bold(), p.weight_remaining);
                println!("  {:<20} {}", "Rounds remaining:".bold(), p.rounds_remaining);
                println!("  {:<20} W={} / L={}", "Wins / Losses:".bold(), p.wins, p.losses);
                println!();
                if p.param.cell.is_some() {
                    println!("  {}", "New cell value: present (param has a proposed value)".green());
                } else {
                    println!("  {}", "New cell value: none (param deletion or reset)".yellow());
                }
                if let Some(h) = p.param.hash {
                    println!("  {:<20} {}", "Param hash:".bold(), hex::encode(h));
                }
                println!();
            }
        }

        Ok(())
    }
}

impl VoteOfferCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{load_config_vault_rpc_client, make_wallet, wallet_info};
        use anyhow::Context;
        use colored::Colorize;
        use common::time_format::format_ts;
        use contracts::{
            ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, SmartContract,
            Wallet, config_contract, contract_provider_from,
        };
        use control_client::{
            client_adnl::ControlClientAdnl,
            client_api::{ClientAPI, SignRq},
            config_params::parse_config_param_34,
        };
        use std::path::Path;
        use std::sync::Arc;
        use chain_block::write_boc;

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        println!("\n{}", "Querying config contract for proposals...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposals = wrapper.list_proposals().await?;

        if proposals.is_empty() {
            println!("\n{}\n", "No active proposals to vote on.".yellow());
            return Ok(());
        }

        // Determine which proposal to vote on
        let target_hash: Option<[u8; 32]> = if let Some(ref hash_str) = self.hash {
            let hash_bytes_vec = hex::decode(hash_str.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("Invalid hex hash: {}", e))?;
            if hash_bytes_vec.len() != 32 {
                anyhow::bail!(
                    "Proposal hash must be 32 bytes (64 hex chars), got {}",
                    hash_bytes_vec.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash_bytes_vec);
            Some(arr)
        } else {
            None
        };

        // Display proposals
        println!();
        println!("{}", "Active Config Proposals".bold());
        println!("{}", "\u{2500}".repeat(80));
        println!(
            "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
            "#".bold(),
            "Param".bold(),
            "Critical".bold(),
            "Expires".bold(),
            "Voters".bold(),
            "Hash (first 16 hex)".bold(),
        );
        println!("  {}", "\u{2500}".repeat(76));

        for (i, p) in proposals.iter().enumerate() {
            let critical = if p.is_critical { "Yes" } else { "No" };
            let expires = format_ts(p.expires as u64);
            let hash_short = hex::encode(&p.hash[..8]);
            println!(
                "  {:<4} {:<8} {:<11} {:<22} {:<9} {}...",
                i + 1,
                p.param.id,
                critical,
                expires,
                p.voters.len(),
                hash_short,
            );
        }
        println!();

        // Find the target proposal
        let proposal = if let Some(ref target) = target_hash {
            proposals.iter().find(|p| p.hash == *target)
        } else {
            // If only one proposal, use it; otherwise require --hash
            if proposals.len() == 1 {
                Some(&proposals[0])
            } else {
                println!(
                    "  {}",
                    "Multiple proposals found. Use --hash to specify which one to vote on."
                        .yellow()
                );
                println!();
                return Ok(());
            }
        };

        let proposal = match proposal {
            Some(p) => p,
            None => {
                println!(
                    "  {}",
                    "Proposal with specified hash not found among active proposals.".yellow()
                );
                println!();
                return Ok(());
            }
        };

        println!(
            "  Target proposal: param {} (hash={})",
            proposal.param.id,
            hex::encode(proposal.hash)
        );

        // --- Connect to node via ADNL control ---
        println!("\n{}", "Connecting to validator node...".cyan());
        let (node_name, node_cfg) = config
            .nodes
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await.context("Failed to connect to validator node via ADNL")?;
        println!("  {} Connected to node '{}'", "OK".green().bold(), node_name);

        // --- Get current validator set (config param 34) ---
        println!("{}", "Fetching current validator set...".cyan());
        let vset_bytes = client.get_config_param(34).await.context("get config param 34")?;
        let vset = parse_config_param_34(&vset_bytes)?;

        // --- Get validator config to find our key ---
        let validator_config = client.get_validator_config().await.context("get_validator_config")?;

        // Search through recent validator keys to find one in the current vset
        let mut validators_sorted = validator_config.validators.clone();
        validators_sorted.sort_by_key(|v| v.election_date);

        let mut found_idx: Option<u16> = None;
        let mut found_key_id: Option<Vec<u8>> = None;

        // Check the last 3 election keys (same strategy as voting_task.rs)
        let check_count = validators_sorted.len().min(3);
        for validator in validators_sorted.iter().rev().take(check_count) {
            let public_key = match client.export_key_pub(&validator.id).await {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let mut key = [0u8; 32];
            if public_key.len() >= 32 {
                key.copy_from_slice(&public_key[..32]);
            } else {
                continue;
            }
            // Search for this public key in the current validator set
            if let Some(idx) = vset
                .list()
                .iter()
                .position(|item| item.public_key.as_slice() == &key)
            {
                found_idx = Some(idx as u16);
                found_key_id = Some(validator.id.clone());
                println!(
                    "  {} Found validator at index {} (pubkey={})",
                    "OK".green().bold(),
                    idx,
                    hex::encode(&key)
                );
                break;
            }
        }

        let validator_idx = found_idx.ok_or_else(|| {
            anyhow::anyhow!(
                "This node is not in the current validator set (config param 34). \
                 Only active validators can vote on config proposals."
            )
        })?;
        let key_id = found_key_id.unwrap();

        // Check if we already voted
        if proposal.voters.contains(&validator_idx) {
            println!(
                "\n{} Already voted for this proposal (validator index {}).",
                "OK".green().bold(),
                validator_idx
            );
            println!();
            return Ok(());
        }

        // --- Build and sign the vote ---
        println!("{}", "Signing vote...".cyan());
        let unsigned_body = config_contract::messages::unsigned_vote(validator_idx, &proposal.hash)?;

        let signature = client
            .sign(&SignRq {
                key_hash: key_id,
                data: unsigned_body.data().to_vec(),
            })
            .await
            .context("sign vote")?;
        println!("  {} Vote signed", "OK".green().bold());

        // Build the signed vote message body
        let query_id = 0u64;
        let vote_body =
            config_contract::messages::signed_vote(query_id, &unsigned_body, &signature)?;

        // --- Send via wallet ---
        println!("{}", "Sending vote transaction...".cyan());
        let wallet_name = node_name;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (_wallet_address, _wallet_info_res, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;

        let config_addr = wrapper.address();
        let send_value = 1_000_000_000u64; // 1 TOS for gas
        let msg_cell = wallet.message(config_addr, send_value, vote_body).await?;
        let boc = write_boc(&msg_cell)?;
        client.send_boc(&boc).await.context("send vote BOC")?;

        println!(
            "\n{} Vote cast successfully!",
            "OK".green().bold()
        );
        println!("  Proposal hash:    {}", hex::encode(proposal.hash));
        println!("  Param ID:         {}", proposal.param.id);
        println!("  Validator index:  {}", validator_idx);
        println!();
        println!(
            "  {}",
            "Use 'tosctl vote offer ls' to verify your vote is recorded."
                .dimmed()
        );
        println!();

        Ok(())
    }
}

impl VoteComplaintCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteComplaintAction::Ls(cmd) => cmd.run(config_path).await,
            VoteComplaintAction::Cast(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteComplaintLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::chain_utils::display_tons;
        use common::time_format::format_ts;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        println!("\n{}", "Querying elector for past elections (complaint data)...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let past = elector.past_elections().await?;

        if past.is_empty() {
            println!("\n{}\n", "No past elections found.".yellow());
            return Ok(());
        }

        println!();
        println!("{}", "Past Elections (Complaint Context)".bold());
        println!("{}", "\u{2500}".repeat(80));
        println!(
            "  {:<4} {:<14} {:<22} {:<16} {:<8} {}",
            "#".bold(),
            "Election ID".bold(),
            "Unfreeze At".bold(),
            "Total Stake".bold(),
            "Frozen".bold(),
            "Banned".bold(),
        );
        println!("  {}", "\u{2500}".repeat(76));

        for (i, election) in past.iter().enumerate() {
            let banned_count = election
                .frozen_map
                .values()
                .filter(|f| f.banned)
                .count();
            println!(
                "  {:<4} {:<14} {:<22} {:<16} {:<8} {}",
                i + 1,
                election.election_id,
                format_ts(election.unfreeze_at),
                display_tons(election.total_stake),
                election.frozen_map.len(),
                banned_count,
            );
        }

        // Show banned validators if any exist
        let has_banned = past.iter().any(|e| e.frozen_map.values().any(|f| f.banned));
        if has_banned {
            println!();
            println!("  {}", "Banned Validators".bold().red());
            println!("  {}", "\u{2500}".repeat(76));
            for election in &past {
                for (pubkey, frozen) in &election.frozen_map {
                    if frozen.banned {
                        let pubkey_hex: String =
                            pubkey.iter().map(|b| format!("{:02x}", b)).collect();
                        let wallet_hex: String = frozen
                            .wallet_addr
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect();
                        println!(
                            "  Election {}: pubkey={}... wallet={}... stake={} TOS",
                            election.election_id,
                            &pubkey_hex[..16],
                            &wallet_hex[..16],
                            display_tons(frozen.stake),
                        );
                    }
                }
            }
        }

        println!();
        println!(
            "  {}",
            "Note: Complaints are submitted against validators in past elections.".dimmed()
        );
        println!(
            "  {}",
            "Banned validators have already been penalized.".dimmed()
        );
        println!();

        Ok(())
    }
}

impl VoteComplaintCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{load_config_vault_rpc_client, make_wallet, wallet_info};
        use anyhow::Context;
        use colored::Colorize;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, SmartContract,
            Wallet, elector, contract_provider_from,
        };
        use control_client::{
            client_adnl::ControlClientAdnl,
            client_api::{ClientAPI, SignRq},
            config_params::parse_config_param_34,
        };
        use std::path::Path;
        use std::sync::Arc;
        use chain_block::write_boc;

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        // Parse and validate complaint hash
        let hash_hex = self.complaint_hash.trim().trim_start_matches("0x");
        let hash_bytes_vec = hex::decode(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hex complaint hash: {}", e))?;
        if hash_bytes_vec.len() != 32 {
            anyhow::bail!(
                "Complaint hash must be 32 bytes (64 hex chars), got {}",
                hash_bytes_vec.len()
            );
        }
        let mut complaint_hash = [0u8; 32];
        complaint_hash.copy_from_slice(&hash_bytes_vec);

        println!("\n{}", "Complaint Voting".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  Election ID:      {}", self.election_id);
        println!("  Complaint hash:   {}", hex::encode(complaint_hash));

        // Verify the election exists in past elections
        println!("\n{}", "Querying elector for past elections...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let past = elector.past_elections().await?;
        let target_election = past
            .iter()
            .find(|e| e.election_id == self.election_id as u64);

        if target_election.is_none() {
            let election_ids: Vec<String> = past.iter().map(|e| e.election_id.to_string()).collect();
            anyhow::bail!(
                "Election ID {} not found in past elections. Available: [{}]",
                self.election_id,
                election_ids.join(", ")
            );
        }
        println!(
            "  {} Election {} found in past elections",
            "OK".green().bold(),
            self.election_id
        );

        // --- Connect to node via ADNL control ---
        println!("\n{}", "Connecting to validator node...".cyan());
        let (node_name, node_cfg) = config
            .nodes
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await.context("Failed to connect to validator node via ADNL")?;
        println!("  {} Connected to node '{}'", "OK".green().bold(), node_name);

        // --- Get current validator set (config param 34) ---
        println!("{}", "Fetching current validator set...".cyan());
        let vset_bytes = client.get_config_param(34).await.context("get config param 34")?;
        let vset = parse_config_param_34(&vset_bytes)?;

        // --- Get validator config to find our key ---
        let validator_config = client.get_validator_config().await.context("get_validator_config")?;

        // Search through recent validator keys to find one in the current vset
        let mut validators_sorted = validator_config.validators.clone();
        validators_sorted.sort_by_key(|v| v.election_date);

        let mut found_idx: Option<u16> = None;
        let mut found_key_id: Option<Vec<u8>> = None;

        // Check the last 3 election keys (same strategy as offer voting)
        let check_count = validators_sorted.len().min(3);
        for validator in validators_sorted.iter().rev().take(check_count) {
            let public_key = match client.export_key_pub(&validator.id).await {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let mut key = [0u8; 32];
            if public_key.len() >= 32 {
                key.copy_from_slice(&public_key[..32]);
            } else {
                continue;
            }
            // Search for this public key in the current validator set
            if let Some(idx) = vset
                .list()
                .iter()
                .position(|item| item.public_key.as_slice() == &key)
            {
                found_idx = Some(idx as u16);
                found_key_id = Some(validator.id.clone());
                println!(
                    "  {} Found validator at index {} (pubkey={})",
                    "OK".green().bold(),
                    idx,
                    hex::encode(&key)
                );
                break;
            }
        }

        let validator_idx = found_idx.ok_or_else(|| {
            anyhow::anyhow!(
                "This node is not in the current validator set (config param 34). \
                 Only active validators can vote on complaints."
            )
        })?;
        let key_id = found_key_id.unwrap();

        // --- Build and sign the complaint vote ---
        println!("{}", "Signing complaint vote...".cyan());
        let unsigned_body = elector::messages::unsigned_complaint_vote(
            validator_idx,
            self.election_id,
            &complaint_hash,
        )?;

        let signature = client
            .sign(&SignRq {
                key_hash: key_id,
                data: unsigned_body.data().to_vec(),
            })
            .await
            .context("sign complaint vote")?;
        println!("  {} Complaint vote signed", "OK".green().bold());

        // Build the signed complaint vote message body.
        // Query ID follows the same convention as complaint-vote-signed.fif:
        //   now << 32 | (complaint_hash % (1 << 32))
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // complaint_hash interpreted as big-endian 256-bit number, take low 32 bits
        let hash_low32 = u32::from_be_bytes([
            complaint_hash[28],
            complaint_hash[29],
            complaint_hash[30],
            complaint_hash[31],
        ]);
        let query_id = (now << 32) | (hash_low32 as u64 % (1u64 << 32));

        let vote_body =
            elector::messages::signed_complaint_vote(query_id, &unsigned_body, &signature)?;

        // --- Send via wallet ---
        println!("{}", "Sending complaint vote transaction...".cyan());
        let wallet_name = node_name;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (_wallet_address, _wallet_info_res, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;

        let elector_addr = elector.address();
        let send_value = 1_000_000_000u64; // 1 TOS for gas
        let msg_cell = wallet.message(elector_addr, send_value, vote_body).await?;
        let boc = write_boc(&msg_cell)?;
        client.send_boc(&boc).await.context("send complaint vote BOC")?;

        println!(
            "\n{} Complaint vote cast successfully!",
            "OK".green().bold()
        );
        println!("  Election ID:      {}", self.election_id);
        println!("  Complaint hash:   {}", hex::encode(complaint_hash));
        println!("  Validator index:  {}", validator_idx);
        println!();
        println!(
            "  {}",
            "Use 'tosctl vote complaint ls' to verify complaint status."
                .dimmed()
        );
        println!();

        Ok(())
    }
}

impl VoteElectionCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteElectionAction::Ls(cmd) => cmd.run(config_path).await,
            VoteElectionAction::Cast(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteElectionLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::chain_utils::display_tons;
        use contracts::{DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, contract_provider_from};
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        if self.format != super::output_format::OutputFormat::Json {
            println!("\n{}", "Querying elector for election participants...".cyan());
        }

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let info = elector.elections_info().await?;

        if info.participants.is_empty() {
            if self.format == super::output_format::OutputFormat::Json {
                let obj = serde_json::json!({
                    "election_id": info.election_id,
                    "participants": [],
                });
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                println!("\n{}\n", "No election participants found.".yellow());
            }
            return Ok(());
        }

        if self.format == super::output_format::OutputFormat::Json {
            let participants: Vec<serde_json::Value> = info.participants.iter().map(|p| {
                let pubkey_hex: String =
                    p.pub_key.iter().map(|b| format!("{:02x}", b)).collect();
                serde_json::json!({
                    "public_key": pubkey_hex,
                    "stake": display_tons(p.stake),
                    "max_factor": p.max_factor,
                })
            }).collect();
            let obj = serde_json::json!({
                "election_id": info.election_id,
                "elect_close": info.elect_close,
                "total_stake": display_tons(info.total_stake),
                "min_stake": display_tons(info.min_stake),
                "participants": participants,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!("{}", "Election Participants".bold());
            println!("{}", "\u{2500}".repeat(90));
            println!("  {:<8} {}", "Election:".bold(), info.election_id);
            println!("  {:<8} {}", "Closes:".bold(), info.elect_close);
            println!("  {:<8} {} TOS", "Total:".bold(), display_tons(info.total_stake));
            println!("  {:<8} {} TOS", "Min:".bold(), display_tons(info.min_stake));
            println!();
            println!(
                "  {:<4} {:<66} {:<16} {}",
                "#".bold(),
                "Public Key (hex)".bold(),
                "Stake (TOS)".bold(),
                "Max Factor".bold(),
            );
            println!("  {}", "\u{2500}".repeat(96));

            for (i, p) in info.participants.iter().enumerate() {
                let pubkey_hex: String =
                    p.pub_key.iter().map(|b| format!("{:02x}", b)).collect();
                let pubkey_display = if pubkey_hex.len() > 64 {
                    pubkey_hex[..64].to_string()
                } else {
                    format!("{:<64}", pubkey_hex)
                };
                println!(
                    "  {:<4} {:<66} {:<16} {}",
                    i + 1,
                    pubkey_display,
                    display_tons(p.stake),
                    p.max_factor,
                );
            }

            println!();
        }
        Ok(())
    }
}

impl VoteElectionCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{load_config_vault_rpc_client, make_wallet, wallet_info};
        use anyhow::Context;
        use colored::Colorize;
        use common::chain_utils::display_tons;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, SmartContract,
            Wallet, contract_provider_from, nominator,
        };
        use control_client::{
            client_adnl::ControlClientAdnl,
            client_api::{
                AddAdnlAddressRq, AddValidatorAdnlAddrRq, AddValidatorPermKeyRq,
                AddValidatorTempKeyRq, ClientAPI, SignRq,
            },
            config_params::parse_config_param_15,
        };
        use std::path::Path;
        use std::sync::Arc;
        use chain_block::{UnixTime, write_boc};

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        println!("\n{}", "Querying elector for active election...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let election_id = elector.get_active_election_id().await?;

        if election_id == 0 {
            println!("\n{}\n", "No active election".yellow());
            return Ok(());
        }

        println!(
            "\n{} Active election ID: {}",
            "OK".green().bold(),
            election_id.to_string().white().bold()
        );

        let elections_info = elector.elections_info().await?;
        println!("  Total stake:    {} TOS", display_tons(elections_info.total_stake));
        println!("  Participants:   {}", elections_info.participants.len());
        println!("  Min stake:      {} TOS", display_tons(elections_info.min_stake));
        println!("  Closes at:      {}", elections_info.elect_close);

        if self.dry_run {
            println!(
                "\n{}",
                "Dry-run mode: no bid was submitted. Remove --dry-run to participate."
                    .yellow()
                    .italic()
            );
            println!();
            return Ok(());
        }

        // Validate max_factor
        if !(1.0..=3.0).contains(&self.max_factor) {
            anyhow::bail!("--max-factor must be between 1.0 and 3.0, got {}", self.max_factor);
        }

        // --- Connect to node via ADNL control ---
        println!("\n{}", "Connecting to validator node...".cyan());
        let (node_name, node_cfg) = config
            .nodes
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await.context("Failed to connect to validator node via ADNL")?;
        println!("  {} Connected to node '{}'", "OK".green().bold(), node_name);

        // --- Get config param 15 for timing ---
        let cfg15_bytes = client.get_config_param(15).await.context("get config param 15")?;
        let cfg15 = parse_config_param_15(&cfg15_bytes)?;
        let key_expire_at = election_id + cfg15.validators_elected_for as u64 + 300; // 5 min lag

        // --- Generate validator key pair ---
        println!("{}", "Generating validator key pair...".cyan());
        let key_hash = client.generate_key_pair().await.context("generate_key_pair")?;
        println!(
            "  {} Key hash: {}",
            "OK".green().bold(),
            hex::encode(&key_hash)
        );

        // Register permanent key
        client
            .add_validator_perm_key(&AddValidatorPermKeyRq {
                key_hash: key_hash.clone(),
                election_date: election_id as i32,
                expire_at: key_expire_at as i32,
            })
            .await
            .context("add_validator_perm_key")?;
        println!("  {} Permanent key registered", "OK".green().bold());

        // Register temp key (same as perm key for simplicity)
        client
            .add_validator_temp_key(&AddValidatorTempKeyRq {
                perm_key_hash: key_hash.clone(),
                key_hash: key_hash.clone(),
                expire_at: key_expire_at as i32,
            })
            .await
            .context("add_validator_temp_key")?;
        println!("  {} Temp key registered", "OK".green().bold());

        // Export public key
        let pub_key = client.export_key_pub(&key_hash).await.context("export_key_pub")?;
        println!(
            "  {} Public key: {}",
            "OK".green().bold(),
            hex::encode(&pub_key)
        );

        // --- Generate ADNL address ---
        println!("{}", "Generating ADNL address...".cyan());
        let adnl_key_hash = client.generate_key_pair().await.context("generate ADNL key pair")?;
        client
            .add_adnl_address(&AddAdnlAddressRq {
                key_hash: adnl_key_hash.clone(),
                category: 0,
            })
            .await
            .context("add_adnl_address")?;
        client
            .add_validator_adnl_addr(&AddValidatorAdnlAddrRq {
                perm_key_hash: key_hash.clone(),
                key_hash: adnl_key_hash.clone(),
                expire_at: key_expire_at as i32,
            })
            .await
            .context("add_validator_adnl_addr")?;
        println!(
            "  {} ADNL address: {}",
            "OK".green().bold(),
            hex::encode(&adnl_key_hash)
        );

        // --- Determine wallet and stake ---
        let wallet_name = self.wallet.as_deref().unwrap_or(node_name);
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (wallet_address, _wallet_info_res, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;
        let wallet_addr_bytes = wallet_address.address().clone().storage().to_vec();

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;

        // Calculate stake in nanotons
        let stake_nanotons: u64 = if let Some(stake_tos) = self.stake {
            stake_tos * 1_000_000_000
        } else {
            // Use minimum stake from the elector if available, otherwise fail
            if elections_info.min_stake > 0 {
                elections_info.min_stake
            } else {
                anyhow::bail!(
                    "Could not determine minimum stake. Please specify --stake explicitly."
                );
            }
        };

        let max_factor_u32 = (self.max_factor * 65536.0) as u32;

        println!("\n{}", "Building election bid...".cyan());
        println!("  Election ID:  {}", election_id);
        println!("  Stake:        {} TOS", display_tons(stake_nanotons));
        println!("  Max factor:   {}", self.max_factor);
        println!("  Wallet:       {}", wallet_address);

        // --- Sign the election bid data ---
        // Build data to sign (same format as validator-elect-req.fif / runner.rs)
        let mut data_to_sign = 0x654C5074u32.to_be_bytes().to_vec();
        data_to_sign.extend_from_slice(&(election_id as u32).to_be_bytes());
        data_to_sign.extend_from_slice(&max_factor_u32.to_be_bytes());
        data_to_sign.extend_from_slice(&wallet_addr_bytes);
        data_to_sign.extend_from_slice(&adnl_key_hash);

        let signature = client
            .sign(&SignRq {
                key_hash: key_hash.clone(),
                data: data_to_sign,
            })
            .await
            .context("sign election bid")?;
        println!("  {} Bid signed", "OK".green().bold());

        // --- Build the stake message payload ---
        let payload = nominator::new_stake(&nominator::NewStakeParams {
            query_id: UnixTime::now(),
            stake_amount: stake_nanotons,
            validator_pubkey: pub_key.as_slice(),
            stake_at: election_id as u32,
            max_factor: max_factor_u32,
            adnl_addr: adnl_key_hash.as_slice(),
            signature: signature.as_slice(),
        })?;

        // --- Send the bid via wallet ---
        println!("{}", "Sending election bid...".cyan());
        let elector_addr = elector.address();
        let send_value = stake_nanotons + 1_000_000_000; // stake + elector fee
        let msg_cell = wallet.message(elector_addr, send_value, payload).await?;
        let boc = write_boc(&msg_cell)?;
        client.send_boc(&boc).await.context("send election bid BOC")?;

        println!(
            "\n{} Election bid submitted successfully!",
            "OK".green().bold()
        );
        println!("  Election ID:  {}", election_id);
        println!("  Stake:        {} TOS", display_tons(stake_nanotons));
        println!("  Public key:   {}", hex::encode(&pub_key));
        println!("  ADNL addr:    {}", hex::encode(&adnl_key_hash));
        println!();
        println!(
            "  {}",
            "Use 'tosctl vote election ls' to verify your bid appears in participants."
                .dimmed()
        );
        println!();

        Ok(())
    }
}
