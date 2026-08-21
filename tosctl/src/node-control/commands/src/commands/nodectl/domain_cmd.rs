/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `tosctl domain` -- `.tos` naming operations: normalization, resolution
//! with explicit provenance, item inspection, and the inherited auction /
//! renewal / release / record lifecycle.
//!
//! Authority boundary: everything here is a projection of finalized chain
//! state. Resolution through a single JSON-RPC endpoint is labelled
//! `evaluated` (DNS.md §8.1) -- the get-method ran against a named state,
//! with no cryptographic proof of that state.

use super::agent_cmd::{confirm, send_wallet_message, validate_tos_amount};
use super::utils::{get_wallet_config, load_config_vault_rpc_client, make_wallet, wallet_info};
use anyhow::{Context, bail, ensure};
use chain_block::{Cell, ConfigParamEnum, MsgAddressInt};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use common::app_config::AppConfig;
use common::chain_utils::{display_tos, tos_to_nanotos};
use common::tvm_stack_parser::TvmStackParser;
use contracts::dns::{
    self, AuctionInfo, CollectionConfig, DnsRecord, DomainState, HopOutcome, MAX_RESOLVER_HOPS,
};
use contracts::{ContractProvider, contract_provider};
use std::path::Path;
use std::sync::Arc;

const DOMAIN_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS margin kept in the wallet

/// `.tos` naming operations
#[derive(clap::Args, Clone)]
#[command(about = "`.tos` domain operations")]
pub struct DomainCmd {
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
    action: DomainAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum DomainAction {
    /// Canonicalize a name and report contract-rule and UI-policy findings (offline)
    Normalize(DomainNormalizeCmd),
    /// Resolve a name through the on-chain resolver chain with provenance
    Resolve(DomainResolveCmd),
    /// Derive a Domain Item address and report its lifecycle state
    Inspect(DomainInspectCmd),
    /// Start a registration auction by bidding on a new label
    Register(DomainRegisterCmd),
    /// Bid in a running auction
    Bid(DomainBidCmd),
    /// Renew a leased name (refreshes the 366-day clock)
    Renew(DomainRenewCmd),
    /// Finalize an ended auction from any wallet
    Finish(DomainFinishCmd),
    /// Release an overdue name and start its re-auction
    Release(DomainReleaseCmd),
    /// Transfer an owned name
    Transfer(DomainTransferCmd),
    /// Set or delete DNS records on an owned name
    #[command(subcommand)]
    Record(DomainRecordAction),
    /// Delegate a subtree: set the dns_next_resolver record
    Delegate(DomainDelegateCmd),
}

impl DomainCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            DomainAction::Normalize(cmd) => cmd.run(),
            DomainAction::Resolve(cmd) => cmd.run(&self.config).await,
            DomainAction::Inspect(cmd) => cmd.run(&self.config).await,
            DomainAction::Register(cmd) => cmd.run(&self.config).await,
            DomainAction::Bid(cmd) => cmd.run(&self.config).await,
            DomainAction::Renew(cmd) => cmd.run(&self.config).await,
            DomainAction::Finish(cmd) => cmd.run(&self.config).await,
            DomainAction::Release(cmd) => cmd.run(&self.config).await,
            DomainAction::Transfer(cmd) => cmd.run(&self.config).await,
            DomainAction::Record(cmd) => cmd.run(&self.config).await,
            DomainAction::Delegate(cmd) => cmd.run(&self.config).await,
        }
    }
}

// ─── Shared argument bundles ───────────────────────────────────────────────

/// Locating one Domain Item under a deployed Collection. With the pinned
/// item-code hash and depth, the address is derived locally and any server
/// answer naming a different item is rejected (DNS.md §5.2); without them,
/// the Collection's `get_nft_address_by_index` answer is used UNVERIFIED.
#[derive(clap::Args, Clone)]
pub struct ItemLocator {
    #[arg(long, allow_hyphen_values = true, help = "Deployed .tos Collection address")]
    collection: String,
    #[arg(long, help = "Pinned Domain Item code cell hash (hex) for local derivation")]
    item_code_hash: Option<String>,
    #[arg(long, help = "Depth of the pinned item code cell", requires = "item_code_hash")]
    item_code_depth: Option<u16>,
}

impl ItemLocator {
    fn collection_address(&self) -> anyhow::Result<MsgAddressInt> {
        self.collection.parse::<MsgAddressInt>().context("invalid --collection address")
    }

    async fn item_address(
        &self,
        provider: &dyn ContractProvider,
        label: &str,
    ) -> anyhow::Result<MsgAddressInt> {
        let collection = self.collection_address()?;
        if let Some(hash_hex) = &self.item_code_hash {
            let depth = self
                .item_code_depth
                .ok_or_else(|| anyhow::anyhow!("--item-code-depth is required"))?;
            let config = CollectionConfig {
                collection,
                item_code_hash: parse_hash32("item-code-hash", hash_hex)?,
                item_code_depth: depth,
                item_workchain: 0,
            };
            return dns::derive_item_address(&config, label);
        }
        println!(
            "{} item address taken from the Collection (unverified); pass \
             --item-code-hash/--item-code-depth to derive and verify it locally",
            "WARN".yellow().bold()
        );
        let index = dns::label_slice_hash(label)?;
        let stack = vec![contracts::stack_utils::bytes_to_stack_entry(&index)];
        let parser =
            provider.get_method(collection.to_string(), "get_nft_address_by_index", stack).await?;
        let mut slice = parser.slice(0)?;
        Ok(chain_block::Deserializable::construct_from(&mut slice)?)
    }
}

// ─── normalize ─────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Canonicalize a name (offline)")]
pub struct DomainNormalizeCmd {
    #[arg(help = "Human-typed name, e.g. alice.tos")]
    name: String,
}

impl DomainNormalizeCmd {
    fn run(&self) -> anyhow::Result<()> {
        let canonical = dns::canonicalize_name(&self.name)?;
        let encoded = dns::encode_name(&canonical.name)?;
        println!("canonical name: {}", canonical.name);
        if canonical.case_folded {
            println!(
                "{} input was case-folded; registration and signed uses must reject \
                 non-canonical input instead of repairing it",
                "WARN".yellow().bold()
            );
        }
        println!("encoded length: {} bytes (bound {})", encoded.len(), dns::MAX_ENCODED_BYTES);
        for label in &canonical.labels {
            if label == dns::TOS_SUFFIX && canonical.labels.len() > 1 {
                continue;
            }
            match dns::label_contract_error(label) {
                Some(err) => {
                    println!("label '{label}': {} {err}", "NOT REGISTRABLE:".red().bold())
                }
                None => {
                    let warnings = dns::label_ui_warnings(label);
                    if warnings.is_empty() {
                        println!("label '{label}': registrable");
                    } else {
                        println!(
                            "label '{label}': registrable, UI warnings: {}",
                            warnings.join("; ")
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

// ─── resolve ───────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Resolve a name with explicit provenance")]
pub struct DomainResolveCmd {
    #[arg(help = "Name to resolve, e.g. alice.tos")]
    name: String,
    #[arg(
        long,
        help = "Category name (hashed), 0x-prefixed 32-byte hex, or 'all' (default: all records)"
    )]
    category: Option<String>,
    #[arg(
        long,
        allow_hyphen_values = true,
        help = "Root resolver address (default: ConfigParam 4)"
    )]
    root: Option<String>,
}

impl DomainResolveCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client.clone());

        let canonical = dns::canonicalize_name(&self.name)?;
        let (category_label, category) = parse_category(self.category.as_deref())?;
        let (root, root_source) = match &self.root {
            Some(addr) => {
                (addr.parse::<MsgAddressInt>().context("invalid --root address")?, "--root flag")
            }
            None => (dns_root_from_chain(&rpc_client).await?, "ConfigParam 4"),
        };

        let mut query = dns::encode_name(&canonical.name)?;
        let mut resolver = root.clone();
        let mut hops_left = MAX_RESOLVER_HOPS;
        let mut resolver_path: Vec<String> = Vec::new();
        let outcome = loop {
            resolver_path.push(resolver.to_string());
            let stack = dns::dnsresolve_stack(&query, &category)?;
            let parser =
                provider.get_method(resolver.to_string(), "dnsresolve", stack).await.with_context(
                    || format!("dnsresolve on {resolver} (hop {})", resolver_path.len()),
                )?;
            let hop = dns::decode_dnsresolve(&parser)?;
            match dns::validate_hop(&query, &hop, hops_left)? {
                HopOutcome::Continue { next_resolver, remaining } => {
                    resolver = next_resolver;
                    query = remaining;
                    hops_left -= 1;
                }
                terminal => break terminal,
            }
        };

        println!("canonical name: {}", canonical.name);
        println!("category:       {category_label} (0x{})", hex::encode(category));
        match outcome {
            HopOutcome::NotFound => println!("result:         {}", "not found".yellow()),
            HopOutcome::Terminal(None) => println!("result:         {}", "not found".yellow()),
            HopOutcome::Terminal(Some(value)) => {
                if category == dns::CATEGORY_ALL {
                    println!(
                        "result:         record dictionary cell (repr hash {})",
                        hex::encode(value.repr_hash().as_slice())
                    );
                } else {
                    match dns::parse_record_for_category(&value, &category) {
                        Ok(record) => println!("result:         {}", display_record(&record)),
                        Err(err) => println!(
                            "result:         {} record cell {} rejected: {err}",
                            "FAIL-CLOSED:".red().bold(),
                            hex::encode(value.repr_hash().as_slice())
                        ),
                    }
                }
            }
            HopOutcome::Continue { .. } => unreachable!("loop breaks only on terminal outcomes"),
        }
        println!("root resolver:  {root} (from {root_source})");
        println!("resolver path:  {}", resolver_path.join(" -> "));
        println!("hops used:      {} of {}", resolver_path.len(), MAX_RESOLVER_HOPS);
        // A single JSON-RPC endpoint executed the get-methods without state
        // proofs; do not present this as proved or quorum-agreed (DNS.md §8.1).
        println!("provenance:     evaluated");
        Ok(())
    }
}

// ─── inspect ───────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Derive a Domain Item address and report its lifecycle")]
pub struct DomainInspectCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
}

impl DomainInspectCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client.clone());
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        println!("name:            {}", self.name);
        println!("item address:    {item}");

        let auction = match read_auction_info(provider.as_ref(), &item).await {
            Ok(auction) => auction,
            Err(err) => {
                println!("state:           {}", "not deployed".yellow());
                println!("(get_auction_info failed: {err:#}; the name was never registered, or");
                println!(" the item is frozen/uninitialized -- treat it as unregistered)");
                return Ok(());
            }
        };
        let last_fill_up_time = read_last_fill_up_time(provider.as_ref(), &item).await?;
        let now = unix_now()?;
        let lifecycle = dns::classify_domain(auction.as_ref(), last_fill_up_time, now);

        if let Some(auction) = &auction {
            println!("auction ends:    {}", auction.auction_end_time);
            println!(
                "max bid:         {} TOS{}",
                auction.max_bid_amount as f64 / dns::ONE_TOS as f64,
                auction.max_bid_address.as_ref().map(|a| format!(" from {a}")).unwrap_or_default()
            );
            if let Ok(min) = dns::minimum_next_bid(auction.max_bid_amount) {
                println!("minimum raise:   {} TOS", min as f64 / dns::ONE_TOS as f64);
            }
        }
        println!("last fill-up:    {last_fill_up_time}");
        if let Some(deadline) = lifecycle.renewal_deadline {
            println!("renewal deadline: {deadline}");
        }
        println!("state:           {}", lifecycle.state.as_str());
        println!("detail:          {}", lifecycle.detail);
        if !lifecycle.safe_to_resolve {
            println!(
                "{} records of this name must NOT be trusted in its current state",
                "WARN".yellow().bold()
            );
        }
        Ok(())
    }
}

// ─── register ──────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Start a registration auction for a new label")]
pub struct DomainRegisterCmd {
    #[arg(help = "Label to register (without .tos)")]
    label: String,
    #[arg(long, allow_hyphen_values = true, help = "Deployed .tos Collection address")]
    collection: String,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, help = "First bid attached to the registration, in TOS")]
    amount: f64,
    #[arg(
        long,
        help = "Deployed auction_start_time; when set, the bid is checked against the \
                current minimum price locally before sending"
    )]
    auction_start_time: Option<i64>,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainRegisterCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        if let Some(err) = dns::label_contract_error(&self.label) {
            bail!("label is not registrable: {err}");
        }
        for warning in dns::label_ui_warnings(&self.label) {
            println!("{} {warning}", "WARN".yellow().bold());
        }
        let amount = tos_to_nanotos(self.amount);
        if let Some(start) = self.auction_start_time {
            let now = unix_now()?;
            ensure!(now > start, "the .tos auction has not launched yet (starts at {start})");
            let min = dns::min_price(self.label.len(), now, start)?;
            ensure!(
                u128::from(amount) >= min,
                "bid of {} is below the current minimum price {} TOS",
                display_tos(amount),
                min as f64 / dns::ONE_TOS as f64
            );
        } else {
            println!(
                "{} no --auction-start-time given; the minimum-price check is skipped and \
                 an underpriced registration will bounce on-chain",
                "WARN".yellow().bold()
            );
        }
        let collection =
            self.collection.parse::<MsgAddressInt>().context("invalid --collection address")?;
        let body = dns::register_body(&self.label)?;
        send_domain_message(
            config_path,
            &self.from,
            collection,
            amount,
            body,
            self.yes,
            &format!("Register '{}' with a {} first bid?", self.label, display_tos(amount)),
        )
        .await
    }
}

// ─── bid ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Bid in a running auction")]
pub struct DomainBidCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, help = "Bid amount, in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

impl DomainBidCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        let auction = read_auction_info(provider.as_ref(), &item)
            .await
            .context("cannot read the auction state; is the name registered?")?;
        let Some(auction) = auction else {
            bail!(
                "no auction is running on {}; an empty transfer to a leased name is a renewal \
                 top-up -- use `domain renew`",
                self.name
            );
        };
        let now = unix_now()?;
        ensure!(
            now <= auction.auction_end_time,
            "the auction ended at {}; use `domain finish` to finalize it",
            auction.auction_end_time
        );
        let amount = tos_to_nanotos(self.amount);
        let min = dns::minimum_next_bid(auction.max_bid_amount)?;
        ensure!(
            u128::from(amount) >= min,
            "bid of {} is below the 105% threshold: the current bid is {} TOS, so the minimum \
             accepted bid is {} TOS",
            display_tos(amount),
            auction.max_bid_amount as f64 / dns::ONE_TOS as f64,
            min as f64 / dns::ONE_TOS as f64
        );
        let end = dns::prolonged_end_time(auction.auction_end_time, now);
        if end != auction.auction_end_time {
            println!("anti-sniping: this bid extends the auction to {end}");
        }
        let body = dns::bid_body()?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            amount,
            body,
            self.yes,
            &format!("Bid {} on '{}'?", display_tos(amount), self.name),
        )
        .await
    }
}

// ─── renew / finish / release ──────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Renew a leased name (refreshes the 366-day clock)")]
pub struct DomainRenewCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0.05, help = "Top-up value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainRenewCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        if let Ok(Some(_)) = read_auction_info(provider.as_ref(), &item).await {
            bail!("an auction is running on {}; there is nothing to renew", self.name);
        }
        let body = dns::fill_up_body(self.query_id)?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            tos_to_nanotos(self.amount),
            body,
            self.yes,
            &format!(
                "Renew '{}' with a {} top-up?",
                self.name,
                display_tos(tos_to_nanotos(self.amount))
            ),
        )
        .await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Finalize an ended auction from any wallet")]
pub struct DomainFinishCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 0.05, help = "Message value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainFinishCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        let auction = read_auction_info(provider.as_ref(), &item).await?;
        let Some(auction) = auction else {
            bail!("no auction to finalize on {}", self.name);
        };
        let now = unix_now()?;
        ensure!(
            now > auction.auction_end_time,
            "the auction is still running until {}",
            auction.auction_end_time
        );
        // get_static_data is the one inherited permissionless finalizer and
        // does NOT refresh last_fill_up_time (DNS.md §6.4)
        let body = dns::finish_auction_body(self.query_id)?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            tos_to_nanotos(self.amount),
            body,
            self.yes,
            &format!("Finalize the ended auction on '{}'?", self.name),
        )
        .await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Release an overdue name and start its re-auction")]
pub struct DomainReleaseCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, help = "First bid of the re-auction (must cover the minimum price), in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainReleaseCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        let auction = read_auction_info(provider.as_ref(), &item).await?;
        let last_fill_up_time = read_last_fill_up_time(provider.as_ref(), &item).await?;
        let lifecycle = dns::classify_domain(auction.as_ref(), last_fill_up_time, unix_now()?);
        ensure!(
            lifecycle.state == DomainState::Releasable,
            "'{}' is not releasable: {} ({})",
            self.name,
            lifecycle.state.as_str(),
            lifecycle.detail
        );
        let body = dns::release_body(self.query_id)?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            tos_to_nanotos(self.amount),
            body,
            self.yes,
            &format!(
                "Release '{}' and open a seven-day re-auction with your {} as first bid?",
                self.name,
                display_tos(tos_to_nanotos(self.amount))
            ),
        )
        .await
    }
}

// ─── transfer ──────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Transfer an owned name")]
pub struct DomainTransferCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet (must own the name)")]
    from: String,
    #[arg(long, allow_hyphen_values = true, help = "New owner address")]
    new_owner: String,
    #[arg(long, default_value_t = 0.05, help = "Message value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainTransferCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        if let Ok(Some(_)) = read_auction_info(provider.as_ref(), &item).await {
            bail!("an auction is running on {}; the contract refuses transfers", self.name);
        }
        let new_owner =
            self.new_owner.parse::<MsgAddressInt>().context("invalid --new-owner address")?;
        let (wallet, owner_address, seqno, rpc_client) =
            load_signer(config_path, &self.from).await?;
        let body = dns::transfer_body(&new_owner, &owner_address, 0, self.query_id)?;
        if !self.yes
            && !confirm(&format!("Transfer '{}' to {new_owner}? This is irreversible.", self.name))?
        {
            return Ok(());
        }
        send_wallet_message(
            &wallet,
            rpc_client,
            item,
            tos_to_nanotos(self.amount),
            body,
            true,
            seqno,
            &owner_address,
        )
        .await?;
        println!("{} transfer of '{}' submitted", "OK".green().bold(), self.name);
        Ok(())
    }
}

// ─── record set / delete, delegate ─────────────────────────────────────────

#[derive(Clone, clap::ValueEnum)]
enum RecordValueType {
    /// dns_smc_address (wallet/agent/capability/messenger categories)
    Smc,
    /// dns_next_resolver (subtree delegation)
    NextResolver,
    /// dns_adnl_address (site category)
    Adnl,
    /// dns_storage_address (storage category)
    Storage,
}

#[derive(clap::Subcommand, Clone)]
pub enum DomainRecordAction {
    /// Set one record category
    Set(DomainRecordSetCmd),
    /// Delete one record category
    Delete(DomainRecordDeleteCmd),
}

impl DomainRecordAction {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match self {
            DomainRecordAction::Set(cmd) => cmd.run(config_path).await,
            DomainRecordAction::Delete(cmd) => cmd.run(config_path).await,
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Set one DNS record category")]
pub struct DomainRecordSetCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet (must own the name)")]
    from: String,
    #[arg(long, help = "Category name (hashed) or 0x-prefixed 32-byte hex")]
    category: String,
    #[arg(long, value_enum, help = "Record type to store")]
    r#type: RecordValueType,
    #[arg(
        long,
        allow_hyphen_values = true,
        help = "Address (smc/next-resolver) or 32-byte hex (adnl/storage)"
    )]
    value: String,
    #[arg(long, default_value_t = 0.05, help = "Message value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainRecordSetCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let (_, category) = parse_category(Some(&self.category))?;
        ensure!(category != dns::CATEGORY_ALL, "category zero is a query wildcard, not a record");
        let record = match self.r#type {
            RecordValueType::Smc => dns::make_smc_address_record(
                &self.value.parse::<MsgAddressInt>().context("invalid --value address")?,
            )?,
            RecordValueType::NextResolver => dns::make_next_resolver_record(
                &self.value.parse::<MsgAddressInt>().context("invalid --value address")?,
            )?,
            RecordValueType::Adnl => {
                dns::make_adnl_address_record(&parse_hash32("value", &self.value)?)?
            }
            RecordValueType::Storage => {
                dns::make_storage_address_record(&parse_hash32("value", &self.value)?)?
            }
        };
        // refuse a record the strict category table would fail closed on
        if let Some(expected) = dns::expected_record_tag(&category) {
            let record = dns::parse_record(&record)?;
            ensure!(
                record.tag() == expected,
                "record type 0x{:04x} does not match the 0x{expected:04x} this category \
                 requires; resolvers will fail closed on it",
                record.tag()
            );
        }
        send_record_change(config_path, self, Some(record), &category).await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Delete one DNS record category")]
pub struct DomainRecordDeleteCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet (must own the name)")]
    from: String,
    #[arg(long, help = "Category name (hashed) or 0x-prefixed 32-byte hex")]
    category: String,
    #[arg(long, default_value_t = 0.05, help = "Message value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainRecordDeleteCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let (_, category) = parse_category(Some(&self.category))?;
        ensure!(category != dns::CATEGORY_ALL, "category zero is a query wildcard, not a record");
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        let body = dns::change_record_body(&category, None, self.query_id)?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            tos_to_nanotos(self.amount),
            body,
            self.yes,
            &format!("Delete record category 0x{} on '{}'?", hex::encode(category), self.name),
        )
        .await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Delegate a subtree: set the dns_next_resolver record")]
pub struct DomainDelegateCmd {
    #[arg(help = "Second-level name, e.g. alice.tos")]
    name: String,
    #[command(flatten)]
    locator: ItemLocator,
    #[arg(long, help = "Signing wallet name or master_wallet (must own the name)")]
    from: String,
    #[arg(long, allow_hyphen_values = true, help = "Resolver contract to delegate the subtree to")]
    resolver: String,
    #[arg(long, default_value_t = 0.05, help = "Message value, in TOS")]
    amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
}

impl DomainDelegateCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let resolver =
            self.resolver.parse::<MsgAddressInt>().context("invalid --resolver address")?;
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client);
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;
        let category = dns::category_hash("dns_next_resolver");
        let record = dns::make_next_resolver_record(&resolver)?;
        let body = dns::change_record_body(&category, Some(record), self.query_id)?;
        send_domain_message(
            config_path,
            &self.from,
            item,
            tos_to_nanotos(self.amount),
            body,
            self.yes,
            &format!("Delegate the subtree of '{}' to {resolver}?", self.name),
        )
        .await
    }
}

async fn send_record_change(
    config_path: &str,
    cmd: &DomainRecordSetCmd,
    record: Option<Cell>,
    category: &[u8; 32],
) -> anyhow::Result<()> {
    let rpc_client = connect_rpc(config_path)?;
    let provider = contract_provider!(rpc_client);
    let label = dns::second_level_label(&cmd.name)?;
    let item = cmd.locator.item_address(provider.as_ref(), &label).await?;
    let body = dns::change_record_body(category, record, cmd.query_id)?;
    send_domain_message(
        config_path,
        &cmd.from,
        item,
        tos_to_nanotos(cmd.amount),
        body,
        cmd.yes,
        &format!("Set record category 0x{} on '{}'?", hex::encode(category), cmd.name),
    )
    .await
}

// ─── shared plumbing ───────────────────────────────────────────────────────

fn connect_rpc(config_path: &str) -> anyhow::Result<Arc<ClientJsonRpc>> {
    let config = AppConfig::load(Path::new(config_path))
        .map_err(|e| anyhow::anyhow!("Failed to open config file: {e}"))?;
    Ok(Arc::new(ClientJsonRpc::connect_many(
        config.chain_rpc.resolved_endpoints(),
        config.chain_rpc.api_key.clone(),
    )?))
}

type Signer = (contracts::wallet::WalletContract, MsgAddressInt, Option<u32>, Arc<ClientJsonRpc>);

async fn load_signer(config_path: &str, from: &str) -> anyhow::Result<Signer> {
    let path = Path::new(config_path);
    let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
    let wallet_config = get_wallet_config(from, &config.wallets, config.master_wallet.as_ref())?;
    let (owner_address, owner_info, owner_secret) =
        wallet_info(rpc_client.clone(), wallet_config, vault).await?;
    if owner_info.account_state != AccountState::Active {
        bail!("signing wallet is not active");
    }
    let wallet = make_wallet(rpc_client.clone(), wallet_config, owner_secret, from).await?;
    Ok((wallet, owner_address, owner_info.seqno, rpc_client))
}

async fn send_domain_message(
    config_path: &str,
    from: &str,
    destination: MsgAddressInt,
    amount: u64,
    body: Cell,
    yes: bool,
    prompt: &str,
) -> anyhow::Result<()> {
    let path = Path::new(config_path);
    let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
    let wallet_config = get_wallet_config(from, &config.wallets, config.master_wallet.as_ref())?;
    let (owner_address, owner_info, owner_secret) =
        wallet_info(rpc_client.clone(), wallet_config, vault).await?;
    if owner_info.account_state != AccountState::Active {
        bail!("signing wallet is not active");
    }
    if owner_info.balance < amount.saturating_add(DOMAIN_ACTION_GAS) {
        bail!(
            "signing wallet has insufficient balance: {} < {} + gas",
            display_tos(owner_info.balance),
            display_tos(amount)
        );
    }
    println!("to:     {destination}");
    println!("value:  {}", display_tos(amount));
    if !yes && !confirm(prompt)? {
        return Ok(());
    }
    let wallet = make_wallet(rpc_client.clone(), wallet_config, owner_secret, from).await?;
    send_wallet_message(
        &wallet,
        rpc_client,
        destination,
        amount,
        body,
        true,
        owner_info.seqno,
        &owner_address,
    )
    .await?;
    println!("{} message submitted", "OK".green().bold());
    Ok(())
}

async fn dns_root_from_chain(rpc_client: &ClientJsonRpc) -> anyhow::Result<MsgAddressInt> {
    match rpc_client.get_config_param(4).await {
        Ok(ConfigParamEnum::ConfigParam4(param)) => {
            // the DNS root always lives in the masterchain
            Ok(MsgAddressInt::with_standart(None, -1, param.dns_root_addr)?)
        }
        Ok(_) => bail!("ConfigParam 4 has an unexpected shape"),
        Err(e) => bail!(
            "ConfigParam 4 (dns_root_addr) is not set on this network; `.tos` is not \
             activated and clients fail closed ({e})"
        ),
    }
}

/// `get_auction_info` -> `(slice max_bid_address, int max_bid_amount, int
/// auction_end_time)`; `auction_end_time == 0` means no auction.
async fn read_auction_info(
    provider: &dyn ContractProvider,
    item: &MsgAddressInt,
) -> anyhow::Result<Option<AuctionInfo>> {
    let parser = provider.get_method(item.to_string(), "get_auction_info", vec![]).await?;
    let auction_end_time = parser.i64(2)?;
    if auction_end_time == 0 {
        return Ok(None);
    }
    let max_bid_amount = parse_u128(&parser, 1)?;
    let mut slice = parser.slice(0)?;
    let max_bid_address = chain_block::Deserializable::construct_from(&mut slice).ok();
    Ok(Some(AuctionInfo { max_bid_address, max_bid_amount, auction_end_time }))
}

async fn read_last_fill_up_time(
    provider: &dyn ContractProvider,
    item: &MsgAddressInt,
) -> anyhow::Result<i64> {
    let parser = provider.get_method(item.to_string(), "get_last_fill_up_time", vec![]).await?;
    parser.i64(0)
}

fn parse_u128(parser: &TvmStackParser, index: usize) -> anyhow::Result<u128> {
    let decimal = parser.decimal_string(index)?;
    if let Some(hex_str) = decimal.strip_prefix("0x") {
        u128::from_str_radix(hex_str, 16).context("parse u128 from hex")
    } else {
        decimal.parse::<u128>().context("parse u128 from decimal")
    }
}

fn parse_hash32(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).with_context(|| format!("{name} must be 32-byte hex"))?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("{name} must be exactly 32 bytes"))
}

/// Category argument: `all`/`0` -> the whole dictionary, 0x-hex -> raw
/// 32-byte category, anything else -> `sha256(name)`.
fn parse_category(arg: Option<&str>) -> anyhow::Result<(String, [u8; 32])> {
    match arg {
        None => Ok(("all".to_owned(), dns::CATEGORY_ALL)),
        Some("all") | Some("0") => Ok(("all".to_owned(), dns::CATEGORY_ALL)),
        Some(hex_str) if hex_str.starts_with("0x") => {
            Ok((hex_str.to_owned(), parse_hash32("category", hex_str)?))
        }
        Some(name) => Ok((name.to_owned(), dns::category_hash(name))),
    }
}

fn display_record(record: &DnsRecord) -> String {
    match record {
        DnsRecord::SmcAddress { address } => format!("dns_smc_address {address}"),
        DnsRecord::NextResolver { resolver } => format!("dns_next_resolver {resolver}"),
        DnsRecord::AdnlAddress { adnl } => format!("dns_adnl_address {}", hex::encode(adnl)),
        DnsRecord::StorageAddress { bag_id } => {
            format!("dns_storage_address {}", hex::encode(bag_id))
        }
        DnsRecord::Text => "dns_text (presentation-only)".to_owned(),
    }
}

fn unix_now() -> anyhow::Result<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before the Unix epoch")?;
    i64::try_from(now.as_secs()).context("system clock out of range")
}

#[cfg(test)]
mod domain_cli_tests {
    use super::*;
    use clap::{Args, Command, FromArgMatches};

    #[test]
    fn parses_resolve_with_category_and_root() {
        let command = DomainResolveCmd::augment_args(Command::new("resolve"));
        let matches = command
            .try_get_matches_from([
                "resolve",
                "alice.tos",
                "--category",
                "wallet",
                "--root",
                "-1:8894ba5b65878886259e0695213d0b8f6ca659c735dd3275379c88c9759aeb76",
            ])
            .expect("resolve flags must parse");
        let parsed = DomainResolveCmd::from_arg_matches(&matches).expect("parsed resolve args");
        assert_eq!(parsed.name, "alice.tos");
        assert_eq!(parsed.category.as_deref(), Some("wallet"));
        assert!(parsed.root.is_some());
    }

    #[test]
    fn parses_bid_with_locator() {
        let command = DomainBidCmd::augment_args(Command::new("bid"));
        let matches = command
            .try_get_matches_from([
                "bid",
                "alice.tos",
                "--collection",
                "0:9af984dec57312139ca31cf499aaeb8fddd7f323442fd7ea41fd4bc68025a27f",
                "--item-code-hash",
                "501f3036d7b892f6b35113addb8f0c271d9e50b581199600b9baf6b04e2de8fb",
                "--item-code-depth",
                "11",
                "--from",
                "master_wallet",
                "--amount",
                "1050",
                "--yes",
            ])
            .expect("bid flags must parse");
        let parsed = DomainBidCmd::from_arg_matches(&matches).expect("parsed bid args");
        assert_eq!(parsed.locator.item_code_depth, Some(11));
        assert!(parsed.yes);
    }

    #[test]
    fn item_code_depth_requires_hash() {
        let command = DomainBidCmd::augment_args(Command::new("bid"));
        let result = command.try_get_matches_from([
            "bid",
            "alice.tos",
            "--collection",
            "0:9af984dec57312139ca31cf499aaeb8fddd7f323442fd7ea41fd4bc68025a27f",
            "--item-code-depth",
            "11",
            "--from",
            "master_wallet",
            "--amount",
            "1",
        ]);
        assert!(result.is_err(), "--item-code-depth without --item-code-hash must fail");
    }

    #[test]
    fn parses_record_set() {
        let command = DomainRecordSetCmd::augment_args(Command::new("set"));
        let matches = command
            .try_get_matches_from([
                "set",
                "alice.tos",
                "--collection",
                "0:9af984dec57312139ca31cf499aaeb8fddd7f323442fd7ea41fd4bc68025a27f",
                "--from",
                "master_wallet",
                "--category",
                "wallet",
                "--type",
                "smc",
                "--value",
                "0:1111111111111111111111111111111111111111111111111111111111111111",
            ])
            .expect("record set flags must parse");
        let parsed = DomainRecordSetCmd::from_arg_matches(&matches).expect("parsed record set");
        assert_eq!(parsed.category, "wallet");
        assert_eq!(parsed.query_id, 0);
    }

    #[test]
    fn category_argument_forms() {
        let (label, cat) = parse_category(None).expect("default");
        assert_eq!(label, "all");
        assert_eq!(cat, dns::CATEGORY_ALL);
        let (_, cat) = parse_category(Some("dns_next_resolver")).expect("named");
        assert_eq!(cat, dns::category_hash("dns_next_resolver"));
        let hex_form = format!("0x{}", hex::encode(cat));
        let (_, cat2) = parse_category(Some(&hex_form)).expect("hex");
        assert_eq!(cat, cat2);
        assert!(parse_category(Some("0xzz")).is_err());
    }
}
