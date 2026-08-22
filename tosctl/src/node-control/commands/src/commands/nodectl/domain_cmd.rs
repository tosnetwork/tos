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

use super::agent_cmd::{
    build_wallet_message_boc, confirm, send_wallet_message, validate_tos_amount,
};
use super::output_format::OutputFormat;
use super::utils::{get_wallet_config, load_config_vault_rpc_client, make_wallet, wallet_info};
use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use chain_block::{Cell, ConfigParamEnum, MsgAddressInt};
use chain_rpc_client::v2::RPCStackEntry;
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::{AccountState, BlockIdExt, RunGetMethodParams};
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
    #[arg(short, long, default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
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
        let mut hop_blocks: Vec<Option<BlockIdExt>> = Vec::new();
        let outcome = loop {
            resolver_path.push(resolver.to_string());
            let (parser, block) = dnsresolve_with_block(&rpc_client, &resolver, &query, &category)
                .await
                .with_context(|| {
                    format!("dnsresolve on {resolver} (hop {})", resolver_path.len())
                })?;
            hop_blocks.push(block);
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

        // For a second-level name the terminal answer comes from the Domain
        // Item the Collection delegated to; fetch its lifecycle so no §8
        // field is left for the caller to assemble.
        let is_terminal = !matches!(outcome, HopOutcome::NotFound);
        let item_address = if canonical.labels.len() == 2 && is_terminal {
            resolver_path.last().cloned()
        } else {
            None
        };
        let (item, item_unavailable_reason) = match &item_address {
            Some(addr) => match read_item_report(provider.as_ref(), addr).await {
                Ok(report) => (Some(report), None),
                Err(err) => (None, Some(format!("item state not readable: {err:#}"))),
            },
            None => (None, Some("no single Domain Item answers this query".to_owned())),
        };

        let report = build_resolve_report(ResolveInputs {
            canonical_name: canonical.name.clone(),
            category_label,
            category,
            outcome: &outcome,
            root: root.to_string(),
            root_source: root_source.to_owned(),
            resolver_path,
            hop_blocks,
            item_address,
            item,
            item_unavailable_reason,
            resolved_at_unix: unix_now()?,
        })?;

        if matches!(self.format, OutputFormat::Json) {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        println!("canonical name: {}", report.canonical_name);
        println!("category:       {} ({})", report.category_hash_label(), report.category_hash);
        match report.result.as_str() {
            "not_found" => println!("result:         {}", "not found".yellow()),
            "record_rejected" => println!(
                "result:         {} {}",
                "FAIL-CLOSED:".red().bold(),
                report.reject_reason.as_deref().unwrap_or("record rejected")
            ),
            _ => println!(
                "result:         {}",
                report.record_value.as_deref().unwrap_or("record dictionary")
            ),
        }
        println!("root resolver:  {} (from {})", report.root_resolver_address, report.root_source);
        println!("resolver path:  {}", report.resolver_path.join(" -> "));
        println!("hops used:      {} of {}", report.hops_used, report.max_hops);
        match (&report.first_hop_block, &report.last_hop_block) {
            (Some(first), Some(last)) => {
                println!("first hop ran at block: {}", block_label(first));
                println!("last hop ran at block:  {}", block_label(last));
                if !report.blocks_consistent {
                    println!(
                        "{} the hops ran against different blocks: a plain JSON-RPC \
                         caller cannot pin a checkpoint; re-run or use a proving client",
                        "WARN".yellow().bold()
                    );
                }
            }
            _ => println!("blocks:         not reported by the endpoint"),
        }
        if let Some(item) = &report.item {
            print_item_report(item);
        } else if let Some(reason) = &report.item_unavailable_reason {
            println!("item state:     {reason}");
        }
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
    #[arg(short, long, default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
}

impl DomainInspectCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let rpc_client = connect_rpc(config_path)?;
        let provider = contract_provider!(rpc_client.clone());
        let label = dns::second_level_label(&self.name)?;
        let item = self.locator.item_address(provider.as_ref(), &label).await?;

        let (item_report, item_unavailable_reason) =
            match read_item_report(provider.as_ref(), &item.to_string()).await {
                Ok(report) => (Some(report), None),
                Err(err) => (
                    None,
                    Some(format!(
                        "get_auction_info failed: {err:#}; the name was never registered, or \
                         the item is frozen/uninitialized -- treat it as unregistered"
                    )),
                ),
            };
        let report = InspectReport {
            name: self.name.clone(),
            domain_item_address: item.to_string(),
            item: item_report,
            item_unavailable_reason,
            resolved_at_unix: unix_now()?,
            provenance_class: "evaluated".to_owned(),
        };

        if matches!(self.format, OutputFormat::Json) {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        println!("name:            {}", report.name);
        println!("item address:    {}", report.domain_item_address);
        match &report.item {
            Some(item) => print_item_report(item),
            None => {
                println!("state:           {}", "not deployed".yellow());
                if let Some(reason) = &report.item_unavailable_reason {
                    println!("({reason})");
                }
            }
        }
        println!("provenance:      evaluated");
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(
        long,
        default_value_t = 0.0,
        help = "TOS forwarded to the new owner inside the ownership-assigned notification \
                (must be below the message value)"
    )]
    forward_amount: f64,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long)]
    yes: bool,
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
}

impl DomainTransferCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        validate_tos_amount("forward-amount", self.forward_amount)?;
        let amount = tos_to_nanotos(self.amount);
        let forward_amount = tos_to_nanotos(self.forward_amount);
        ensure!(
            forward_amount < amount,
            "--forward-amount ({}) must be below the message value ({}); the contract \
             needs the difference for fees",
            display_tos(forward_amount),
            display_tos(amount)
        );
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
        let body = dns::transfer_body(&new_owner, &owner_address, forward_amount, self.query_id)?;
        if !self.yes
            && !confirm(&format!("Transfer '{}' to {new_owner}? This is irreversible.", self.name))?
        {
            return Ok(());
        }
        if self.build_only {
            let body_hash = hex::encode(body.repr_hash().as_slice());
            let msg_boc =
                build_wallet_message_boc(&wallet, item.clone(), amount, body, true, seqno).await?;
            println!(
                "{}",
                prepared_send_json(&self.from, &owner_address, &item, amount, &body_hash, &msg_boc)
            );
            return Ok(());
        }
        send_wallet_message(&wallet, rpc_client, item, amount, body, true, seqno, &owner_address)
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
    #[arg(long, help = "Build and sign only; print prepared-send JSON instead of broadcasting")]
    build_only: bool,
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
            self.build_only,
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
        cmd.build_only,
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
    build_only: bool,
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
    if build_only {
        let body_hash = hex::encode(body.repr_hash().as_slice());
        let msg_boc = build_wallet_message_boc(
            &wallet,
            destination.clone(),
            amount,
            body,
            true,
            owner_info.seqno,
        )
        .await?;
        println!(
            "{}",
            prepared_send_json(from, &owner_address, &destination, amount, &body_hash, &msg_boc)
        );
        return Ok(());
    }
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

/// The same prepared-send envelope `wallet send --build-only` emits, so
/// `wallet broadcast-prepared --message-boc <base64>` accepts it unchanged.
fn prepared_send_json(
    from: &str,
    payer: &MsgAddressInt,
    destination: &MsgAddressInt,
    amount: u64,
    body_hash: &str,
    msg_boc: &[u8],
) -> String {
    serde_json::json!({
        "version": "tosctl.wallet-prepared-send.v1",
        "message_boc_base64": base64::engine::general_purpose::STANDARD.encode(msg_boc),
        "wallet": from,
        "payer": payer.to_string(),
        "destination": destination.to_string(),
        "amount_nanotos": amount,
        "body_hash": body_hash,
        "state_init_hash": serde_json::Value::Null,
    })
    .to_string()
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

// ─── structured §8 result (DNS.md) ─────────────────────────────────────────

/// The full structured resolution result of DNS.md §8, so no field is left
/// for the caller to assemble. `provenance_class` is always `evaluated`
/// here: a single JSON-RPC endpoint executed the get-methods without state
/// proofs (§8.1).
#[derive(serde::Serialize)]
struct ResolveReport {
    canonical_name: String,
    category_name: Option<String>,
    category_hash: String,
    /// "found" | "not_found" | "record_dictionary" | "record_rejected"
    result: String,
    record_type: Option<String>,
    record_value: Option<String>,
    reject_reason: Option<String>,
    root_resolver_address: String,
    root_source: String,
    resolver_path: Vec<String>,
    hops_used: usize,
    max_hops: i64,
    first_hop_block: Option<BlockIdExt>,
    last_hop_block: Option<BlockIdExt>,
    /// false when hops ran against different blocks -- an unpinned JSON-RPC
    /// caller cannot rule that out, and must not present the result as
    /// evaluated against one checkpoint when this is false
    blocks_consistent: bool,
    domain_item_address: Option<String>,
    item: Option<ItemReport>,
    item_unavailable_reason: Option<String>,
    /// wall clock at assembly time -- NOT chain time
    resolved_at_unix: i64,
    provenance_class: String,
}

impl ResolveReport {
    fn category_hash_label(&self) -> &str {
        self.category_name.as_deref().unwrap_or("raw")
    }
}

#[derive(serde::Serialize)]
struct InspectReport {
    name: String,
    domain_item_address: String,
    item: Option<ItemReport>,
    item_unavailable_reason: Option<String>,
    /// wall clock at assembly time -- NOT chain time
    resolved_at_unix: i64,
    provenance_class: String,
}

#[derive(serde::Serialize)]
struct ItemReport {
    auction_active: bool,
    max_bidder: Option<String>,
    max_bid_nanotos: Option<u128>,
    auction_end_time: Option<i64>,
    last_fill_up_time: i64,
    renewal_deadline: Option<i64>,
    lifecycle_state: String,
    safe_to_resolve: bool,
    lifecycle_detail: String,
}

struct ResolveInputs<'a> {
    canonical_name: String,
    category_label: String,
    category: [u8; 32],
    outcome: &'a HopOutcome,
    root: String,
    root_source: String,
    resolver_path: Vec<String>,
    hop_blocks: Vec<Option<BlockIdExt>>,
    item_address: Option<String>,
    item: Option<ItemReport>,
    item_unavailable_reason: Option<String>,
    resolved_at_unix: i64,
}

fn build_resolve_report(inputs: ResolveInputs<'_>) -> anyhow::Result<ResolveReport> {
    let (result, record_type, record_value, reject_reason) = match inputs.outcome {
        HopOutcome::NotFound | HopOutcome::Terminal(None) => ("not_found", None, None, None),
        HopOutcome::Terminal(Some(value)) => {
            if inputs.category == dns::CATEGORY_ALL {
                (
                    "record_dictionary",
                    None,
                    Some(format!(
                        "record dictionary cell (repr hash {})",
                        hex::encode(value.repr_hash().as_slice())
                    )),
                    None,
                )
            } else {
                match dns::parse_record_for_category(value, &inputs.category) {
                    Ok(record) => (
                        "found",
                        Some(record_type_name(&record).to_owned()),
                        Some(display_record(&record)),
                        None,
                    ),
                    Err(err) => (
                        "record_rejected",
                        None,
                        None,
                        Some(format!(
                            "record cell {} rejected: {err}",
                            hex::encode(value.repr_hash().as_slice())
                        )),
                    ),
                }
            }
        }
        HopOutcome::Continue { .. } => bail!("resolution ended on a non-terminal outcome"),
    };
    let first_hop_block = inputs.hop_blocks.first().cloned().flatten();
    let last_hop_block = inputs.hop_blocks.last().cloned().flatten();
    let blocks_consistent = match (&first_hop_block, &last_hop_block) {
        (Some(a), Some(b)) => {
            a.workchain == b.workchain
                && a.shard == b.shard
                && a.seqno == b.seqno
                && a.root_hash == b.root_hash
        }
        _ => false,
    };
    let category_name = known_category_name(&inputs.category).map(str::to_owned).or_else(|| {
        (!inputs.category_label.starts_with("0x")).then(|| inputs.category_label.clone())
    });
    Ok(ResolveReport {
        canonical_name: inputs.canonical_name,
        category_name,
        category_hash: format!("0x{}", hex::encode(inputs.category)),
        result: result.to_owned(),
        record_type,
        record_value,
        reject_reason,
        root_resolver_address: inputs.root,
        root_source: inputs.root_source,
        hops_used: inputs.resolver_path.len(),
        max_hops: MAX_RESOLVER_HOPS,
        resolver_path: inputs.resolver_path,
        first_hop_block,
        last_hop_block,
        blocks_consistent,
        domain_item_address: inputs.item_address,
        item: inputs.item,
        item_unavailable_reason: inputs.item_unavailable_reason,
        resolved_at_unix: inputs.resolved_at_unix,
        provenance_class: "evaluated".to_owned(),
    })
}

fn build_item_report(auction: Option<AuctionInfo>, last_fill_up_time: i64, now: i64) -> ItemReport {
    let lifecycle = dns::classify_domain(auction.as_ref(), last_fill_up_time, now);
    ItemReport {
        auction_active: auction.is_some(),
        max_bidder: auction
            .as_ref()
            .and_then(|a| a.max_bid_address.as_ref().map(|addr| addr.to_string())),
        max_bid_nanotos: auction.as_ref().map(|a| a.max_bid_amount),
        auction_end_time: auction.as_ref().map(|a| a.auction_end_time),
        last_fill_up_time,
        renewal_deadline: lifecycle.renewal_deadline,
        lifecycle_state: lifecycle.state.as_str().to_owned(),
        safe_to_resolve: lifecycle.safe_to_resolve,
        lifecycle_detail: lifecycle.detail.to_owned(),
    }
}

async fn read_item_report(
    provider: &dyn ContractProvider,
    item_address: &str,
) -> anyhow::Result<ItemReport> {
    let item = item_address.parse::<MsgAddressInt>().context("invalid item address")?;
    let auction = read_auction_info(provider, &item).await?;
    let last_fill_up_time = read_last_fill_up_time(provider, &item).await?;
    Ok(build_item_report(auction, last_fill_up_time, unix_now()?))
}

fn print_item_report(item: &ItemReport) {
    if let Some(end) = item.auction_end_time {
        println!("auction ends:    {end}");
        if let Some(bid) = item.max_bid_nanotos {
            println!(
                "max bid:         {} TOS{}",
                bid as f64 / dns::ONE_TOS as f64,
                item.max_bidder.as_ref().map(|a| format!(" from {a}")).unwrap_or_default()
            );
            if let Ok(min) = dns::minimum_next_bid(bid) {
                println!("minimum raise:   {} TOS", min as f64 / dns::ONE_TOS as f64);
            }
        }
    }
    println!("last fill-up:    {}", item.last_fill_up_time);
    if let Some(deadline) = item.renewal_deadline {
        println!("renewal deadline: {deadline}");
    }
    println!("state:           {}", item.lifecycle_state);
    println!("detail:          {}", item.lifecycle_detail);
    if !item.safe_to_resolve {
        println!(
            "{} records of this name must NOT be trusted in its current state",
            "WARN".yellow().bold()
        );
    }
}

/// One dnsresolve get-method call surfacing the block it ran against.
/// `ContractProvider::get_method` discards the response's `block_id`, so the
/// resolve loop talks to the RPC layer directly with the same conversions.
async fn dnsresolve_with_block(
    rpc_client: &ClientJsonRpc,
    resolver: &MsgAddressInt,
    query: &[u8],
    category: &[u8; 32],
) -> anyhow::Result<(TvmStackParser, Option<BlockIdExt>)> {
    let stack = dns::dnsresolve_stack(query, category)?;
    let result = rpc_client
        .run_get_method(&RunGetMethodParams {
            address: resolver.to_string(),
            method_id: "dnsresolve".to_owned(),
            stack: Some(stack.into_iter().map(RPCStackEntry::from).collect::<Vec<_>>()),
            seqno: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("dnsresolve error: {e}"))?;
    ensure!(result.exit_code == 0, "dnsresolve error: exit_code={}", result.exit_code);
    let block = result.block_id;
    // the JSON-RPC server serializes the TVM stack top-first; decoders
    // expect bottom-first (same convention as ContractProviderImpl)
    Ok((
        TvmStackParser::new(result.stack.into_iter().rev().map(Into::into).collect::<Vec<_>>()),
        block,
    ))
}

fn block_label(block: &BlockIdExt) -> String {
    format!("({},{:016x},{})", block.workchain, block.shard, block.seqno)
}

fn known_category_name(category: &[u8; 32]) -> Option<&'static str> {
    const KNOWN: [&str; 8] = [
        "dns_next_resolver",
        "site",
        "wallet",
        "agent",
        "capability",
        "messenger",
        "storage",
        "text",
    ];
    if *category == dns::CATEGORY_ALL {
        return Some("all");
    }
    KNOWN.into_iter().find(|name| dns::category_hash(name) == *category)
}

fn record_type_name(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::SmcAddress { .. } => "dns_smc_address",
        DnsRecord::NextResolver { .. } => "dns_next_resolver",
        DnsRecord::AdnlAddress { .. } => "dns_adnl_address",
        DnsRecord::StorageAddress { .. } => "dns_storage_address",
        DnsRecord::Text => "dns_text",
    }
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
                "-1:280e2d46c2bea67664609ad2df6db55ef92dd257ff5b16c3317eed59fa649a32",
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
                "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a",
                "--item-code-hash",
                "e469483aa8a8e5018f46cdd9c374b60153025847a6d4997692cfdd9b15be1d78",
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
            "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a",
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
                "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a",
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
    fn parses_build_only_and_forward_amount() {
        let command = DomainTransferCmd::augment_args(Command::new("transfer"));
        let matches = command
            .try_get_matches_from([
                "transfer",
                "alice.tos",
                "--collection",
                "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a",
                "--from",
                "master_wallet",
                "--new-owner",
                "0:1111111111111111111111111111111111111111111111111111111111111111",
                "--forward-amount",
                "0.01",
                "--build-only",
                "--yes",
            ])
            .expect("transfer flags must parse");
        let parsed = DomainTransferCmd::from_arg_matches(&matches).expect("parsed transfer");
        assert!(parsed.build_only);
        assert!((parsed.forward_amount - 0.01).abs() < f64::EPSILON);

        let command = DomainRegisterCmd::augment_args(Command::new("register"));
        let matches = command
            .try_get_matches_from([
                "register",
                "alice",
                "--collection",
                "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a",
                "--from",
                "master_wallet",
                "--amount",
                "500",
                "--build-only",
            ])
            .expect("register flags must parse");
        let parsed = DomainRegisterCmd::from_arg_matches(&matches).expect("parsed register");
        assert!(parsed.build_only);
    }

    #[test]
    fn parses_resolve_json_format() {
        let command = DomainResolveCmd::augment_args(Command::new("resolve"));
        let matches = command
            .try_get_matches_from(["resolve", "alice.tos", "--format", "json"])
            .expect("resolve --format json must parse");
        let parsed = DomainResolveCmd::from_arg_matches(&matches).expect("parsed resolve");
        assert!(matches!(parsed.format, OutputFormat::Json));
    }

    #[test]
    fn prepared_send_json_shape() {
        let payer: MsgAddressInt =
            "0:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .expect("payer address");
        let dest: MsgAddressInt =
            "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a"
                .parse()
                .expect("dest address");
        let json = prepared_send_json("boss", &payer, &dest, 42, "aa55", &[1, 2, 3]);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["version"], "tosctl.wallet-prepared-send.v1");
        assert_eq!(value["wallet"], "boss");
        assert_eq!(value["amount_nanotos"], 42);
        assert_eq!(value["body_hash"], "aa55");
        assert!(value["state_init_hash"].is_null());
        let boc = value["message_boc_base64"].as_str().expect("boc field");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(boc).expect("base64"),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn resolve_report_carries_every_section_8_field() {
        let record = dns::make_smc_address_record(
            &"0:2222222222222222222222222222222222222222222222222222222222222222"
                .parse()
                .expect("record address"),
        )
        .expect("record cell");
        let outcome = HopOutcome::Terminal(Some(record));
        let item = build_item_report(
            Some(AuctionInfo {
                max_bid_address: None,
                max_bid_amount: 1_000_000_000,
                auction_end_time: 2_000,
            }),
            1_000,
            1_500,
        );
        let report = build_resolve_report(ResolveInputs {
            canonical_name: "alice.tos".to_owned(),
            category_label: "wallet".to_owned(),
            category: dns::category_hash("wallet"),
            outcome: &outcome,
            root: "-1:00".to_owned(),
            root_source: "ConfigParam 4".to_owned(),
            resolver_path: vec!["-1:00".to_owned(), "0:aa".to_owned()],
            hop_blocks: vec![None, None],
            item_address: Some("0:aa".to_owned()),
            item: Some(item),
            item_unavailable_reason: None,
            resolved_at_unix: 1_700_000_000,
        })
        .expect("report");
        let value = serde_json::to_value(&report).expect("serializable");
        for field in [
            "canonical_name",
            "category_name",
            "category_hash",
            "result",
            "record_type",
            "record_value",
            "root_resolver_address",
            "resolver_path",
            "hops_used",
            "max_hops",
            "first_hop_block",
            "last_hop_block",
            "blocks_consistent",
            "domain_item_address",
            "item",
            "resolved_at_unix",
            "provenance_class",
        ] {
            assert!(value.get(field).is_some(), "missing §8 field {field}");
        }
        assert_eq!(value["result"], "found");
        assert_eq!(value["record_type"], "dns_smc_address");
        assert_eq!(value["category_name"], "wallet");
        assert_eq!(value["provenance_class"], "evaluated");
        assert_eq!(value["hops_used"], 2);
        // no block ids -> must NOT claim consistency
        assert_eq!(value["blocks_consistent"], false);
        let item = &value["item"];
        assert_eq!(item["auction_active"], true);
        assert_eq!(item["lifecycle_state"], "auction");
        assert_eq!(item["safe_to_resolve"], false);
        assert_eq!(item["max_bid_nanotos"], 1_000_000_000u64);
    }

    #[test]
    fn item_report_lifecycle_fields() {
        let leased = build_item_report(None, 1_000, 2_000);
        assert!(!leased.auction_active);
        assert_eq!(leased.lifecycle_state, "leased");
        assert!(leased.safe_to_resolve);
        assert_eq!(leased.renewal_deadline, Some(1_000 + 31_622_400));

        let releasable = build_item_report(None, 1_000, 1_000 + 31_622_401);
        assert_eq!(releasable.lifecycle_state, "releasable");
        assert!(!releasable.safe_to_resolve);
    }

    #[test]
    fn known_category_names_round_trip() {
        assert_eq!(known_category_name(&dns::CATEGORY_ALL), Some("all"));
        assert_eq!(known_category_name(&dns::category_hash("wallet")), Some("wallet"));
        assert_eq!(known_category_name(&[0x5c; 32]), None);
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
