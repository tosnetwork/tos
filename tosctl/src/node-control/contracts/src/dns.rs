/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Transport-free protocol core for the `.tos` naming system.
//!
//! Mirrors the on-chain contracts under `crypto/smartcont/dns/func` and the
//! reference client library in `domains/packages/protocol`, byte-for-byte
//! where determinism matters (name encoding, item index, item address) and
//! integer-exact where economics matter (minimum price, 105% bid threshold,
//! auction durations, 366-day release).
//!
//! Authority boundary: a `.tos` name is an alias and discovery hint. Nothing
//! here creates identity, authorization, or payment authority; finalized TOS
//! chain state is the only authority.

use anyhow::{Context, bail, ensure};
use chain_block::{
    BuilderData, Cell, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, SliceData,
    write_boc,
};
use sha2::{Digest, Sha256};
use tl_api::tos::tvm::StackEntry;

use crate::stack_utils::bytes_to_stack_entry;
use common::tvm_stack_parser::TvmStackParser;

// ─── Name rules (Collection `check_domain_string` + length checks) ─────────

/// Collection: `len > 3 * 8`.
pub const MIN_LABEL_BYTES: usize = 4;
/// Collection: `len <= 126 * 8`.
pub const MAX_LABEL_BYTES: usize = 126;
/// `dnsresolve` slice bound (1023-bit cell).
pub const MAX_ENCODED_BYTES: usize = 127;
/// Encoded length is always dotted length + 1.
pub const MAX_DOTTED_BYTES: usize = MAX_ENCODED_BYTES - 1;
pub const TOS_SUFFIX: &str = "tos";

// ─── Inherited contract ABI ────────────────────────────────────────────────

pub const OP_TRANSFER: u32 = 0x5fcc3d14;
pub const OP_GET_STATIC_DATA: u32 = 0x2fcb26a2;
pub const OP_EDIT_CONTENT: u32 = 0x1a0b9d51;
pub const OP_CHANGE_DNS_RECORD: u32 = 0x4eb1f0f9;
pub const OP_DNS_BALANCE_RELEASE: u32 = 0x4ed14b65;
pub const OP_FILL_UP: u32 = 0x370fec51;
pub const OP_OUTBID_NOTIFICATION: u32 = 0x557cea20;

/// DNSRecord TL-B tags (crypto/block/block.tlb).
pub const TAG_DNS_TEXT: u16 = 0x1eda;
pub const TAG_DNS_NEXT_RESOLVER: u16 = 0xba93;
pub const TAG_DNS_ADNL_ADDRESS: u16 = 0xad01;
pub const TAG_DNS_SMC_ADDRESS: u16 = 0x9fd3;
pub const TAG_DNS_STORAGE_ADDRESS: u16 = 0x7473;

// ─── Auction / renewal constants (dns-utils.fc, nft-item.fc) ───────────────

pub const ONE_MONTH: i64 = 2_592_000; // 30 days
pub const ONE_YEAR: i64 = 31_622_400; // 366 days
pub const AUCTION_START_DURATION: i64 = 604_800; // 7 days
pub const AUCTION_END_DURATION: i64 = 3_600; // 1 hour
pub const AUCTION_PROLONGATION: i64 = 3_600; // 1 hour
pub const ONE_TOS: u128 = 1_000_000_000;
/// `min_tons_for_storage()` in nft-item.fc.
pub const MIN_STORAGE_RESERVE: u128 = ONE_TOS;

/// Uniform resolver hop budget shared by every TOS client (DNS.md §8).
pub const MAX_RESOLVER_HOPS: i64 = 8;

// ─── Label and name validation ─────────────────────────────────────────────

/// The exact on-chain registration rule. `None` when the label registers.
pub fn label_contract_error(label: &str) -> Option<String> {
    let bytes = label.as_bytes();
    if bytes.len() < MIN_LABEL_BYTES {
        return Some(format!(
            "label is {} bytes; the contract requires at least {}",
            bytes.len(),
            MIN_LABEL_BYTES
        ));
    }
    if bytes.len() > MAX_LABEL_BYTES {
        return Some(format!(
            "label is {} bytes; the contract allows at most {}",
            bytes.len(),
            MAX_LABEL_BYTES
        ));
    }
    for (i, &c) in bytes.iter().enumerate() {
        let is_digit = c.is_ascii_digit();
        let is_lower = c.is_ascii_lowercase();
        let is_hyphen = c == b'-';
        if is_hyphen {
            if i == 0 || i == bytes.len() - 1 {
                return Some("leading and trailing hyphens are rejected by the contract".into());
            }
            continue;
        }
        if !is_digit && !is_lower {
            return Some(format!("byte {i} (0x{c:02x}) is outside lowercase [a-z0-9-]"));
        }
    }
    None
}

/// Contract-valid but risky: registrar UIs warn (never block resolution).
pub fn label_ui_warnings(label: &str) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if label.len() > 63 {
        warnings.push("longer than the 63-byte Internet DNS label convention");
    }
    if label.starts_with("xn--") {
        warnings.push("xn-- punycode prefix: potential homograph");
    }
    if label.contains("--") {
        warnings.push("consecutive hyphens");
    }
    warnings
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalName {
    /// lowercase dotted name without trailing dot, e.g. "alice.tos"
    pub name: String,
    pub labels: Vec<String>,
    /// true when lowercasing changed the input (lookup-only repair)
    pub case_folded: bool,
}

/// Canonicalize a human-typed name for LOOKUP. Registration and every signed
/// or durable use must reject non-canonical input instead of repairing it.
pub fn canonicalize_name(input: &str) -> anyhow::Result<CanonicalName> {
    let trimmed = input.trim();
    ensure!(!trimmed.is_empty(), "empty name");
    // encode_name("x.") yields a leading NUL — a different query, not an
    // alternative spelling. Reject rather than silently strip.
    ensure!(!trimmed.ends_with('.'), "trailing dot is rejected; \".tos\" names have no root dot");
    for ch in trimmed.chars() {
        let code = ch as u32;
        if code <= 0x20 || code >= 0x7f || ch == '/' || ch == ':' {
            bail!("forbidden character {ch:?} in name");
        }
    }
    let lower = trimmed.to_lowercase();
    let labels: Vec<String> = lower.split('.').map(str::to_owned).collect();
    ensure!(labels.iter().all(|l| !l.is_empty()), "empty label");
    ensure!(
        lower.len() <= MAX_DOTTED_BYTES,
        "name is {} bytes; at most {} resolve",
        lower.len(),
        MAX_DOTTED_BYTES
    );
    Ok(CanonicalName { case_folded: lower != trimmed, name: lower, labels })
}

/// Internal reverse zero-delimited encoding:
/// `"translate.alice.tos"` -> `"tos\0alice\0translate\0"`.
pub fn encode_name(name: &str) -> anyhow::Result<Vec<u8>> {
    let canonical = canonicalize_name(name)?;
    let mut out = Vec::with_capacity(canonical.name.len() + 1);
    for label in canonical.labels.iter().rev() {
        out.extend_from_slice(label.as_bytes());
        out.push(0);
    }
    ensure!(
        out.len() <= MAX_ENCODED_BYTES,
        "encoded name is {} bytes; at most {} fit a cell",
        out.len(),
        MAX_ENCODED_BYTES
    );
    Ok(out)
}

pub fn decode_name(encoded: &[u8]) -> anyhow::Result<String> {
    ensure!(
        !encoded.is_empty() && encoded[encoded.len() - 1] == 0,
        "encoded name must end with a zero byte"
    );
    let mut labels: Vec<&str> = Vec::new();
    let mut start = 0usize;
    for (i, &b) in encoded.iter().enumerate() {
        if b == 0 {
            ensure!(i != start, "empty component in encoded name");
            let label = std::str::from_utf8(&encoded[start..i])
                .context("encoded component is not UTF-8")?;
            labels.insert(0, label);
            start = i + 1;
        }
    }
    Ok(labels.join("."))
}

/// Split `"label.tos"`, validate the suffix, return the second-level label.
pub fn second_level_label(name: &str) -> anyhow::Result<String> {
    let canonical = canonicalize_name(name)?;
    ensure!(
        canonical.labels.len() == 2 && canonical.labels[1] == TOS_SUFFIX,
        "expected a second-level .{TOS_SUFFIX} name"
    );
    Ok(canonical.labels[0].clone())
}

// ─── Categories ────────────────────────────────────────────────────────────

/// Category zero requests the complete record dictionary.
pub const CATEGORY_ALL: [u8; 32] = [0u8; 32];

pub fn category_hash(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}

/// Category names pinned in TOS code or frozen by the TIP corpus, with the
/// record type each category is REQUIRED to carry (DNS.md §7).
pub const KNOWN_CATEGORIES: [(&str, u16); 8] = [
    ("dns_next_resolver", TAG_DNS_NEXT_RESOLVER),
    ("site", TAG_DNS_ADNL_ADDRESS),
    ("wallet", TAG_DNS_SMC_ADDRESS),
    ("agent", TAG_DNS_SMC_ADDRESS),
    ("capability", TAG_DNS_SMC_ADDRESS),
    ("messenger", TAG_DNS_SMC_ADDRESS),
    ("storage", TAG_DNS_STORAGE_ADDRESS),
    ("text", TAG_DNS_TEXT),
];

/// Strict category-to-record-type table: the TL-B tag a record under this
/// category must carry, or `None` for a category outside the known table.
pub fn expected_record_tag(category: &[u8; 32]) -> Option<u16> {
    KNOWN_CATEGORIES.iter().find(|(name, _)| &category_hash(name) == category).map(|&(_, tag)| tag)
}

// ─── Domain Item identity ──────────────────────────────────────────────────

/// `slice_hash(label)`: TVM `HASHSU`, the representation hash of the refless
/// byte-aligned cell holding the label — NOT plain `sha256(label)`.
pub fn label_slice_hash(label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = label.as_bytes();
    ensure!(bytes.len() <= MAX_ENCODED_BYTES, "label too long for a single cell");
    let mut repr = Vec::with_capacity(2 + bytes.len());
    repr.push(0); // d1: no refs, level 0
    let d2 = bytes.len().checked_mul(2).context("label length overflow")?;
    repr.push(u8::try_from(d2).context("label length overflow")?); // byte-aligned d2
    repr.extend_from_slice(bytes);
    Ok(Sha256::digest(&repr).into())
}

/// Deployment configuration for deterministic item-address derivation. The
/// network tuple is deliberately NOT an input: mainnet/testnet separation
/// comes from the collection address itself.
#[derive(Debug, Clone)]
pub struct CollectionConfig {
    /// deployed `.tos` Collection address (deployment configuration)
    pub collection: MsgAddressInt,
    /// pinned Domain Item code cell hash (reproducible-build record)
    pub item_code_hash: [u8; 32],
    /// depth of the pinned item code cell
    pub item_code_depth: u16,
    /// workchain items are deployed in; the contracts pin workchain 0
    pub item_workchain: i32,
}

/// Item data cell exactly as nft-collection.fc builds it:
/// `uint256(index) ++ MsgAddressInt(collection)`.
pub fn item_data_cell(index: &[u8; 32], collection: &MsgAddressInt) -> anyhow::Result<Cell> {
    let mut data = BuilderData::new();
    data.append_u256(index)?;
    collection.write_to(&mut data)?;
    Ok(data.into_cell()?)
}

/// Derive the Domain Item address locally. Clients reject any collection
/// response, next-resolver record, indexer row, or gateway result naming a
/// different item (DNS.md §5.2).
pub fn derive_item_address(
    config: &CollectionConfig,
    label: &str,
) -> anyhow::Result<MsgAddressInt> {
    if let Some(err) = label_contract_error(label) {
        bail!("invalid label: {err}");
    }
    let index = label_slice_hash(label)?;
    let data = item_data_cell(&index, &config.collection)?;
    ensure!(data.references_count() == 0, "item data cell must be refless");
    let data_hash = data.repr_hash();
    let data_depth = data.depth(0);

    // StateInit = b{00110} ^code ^data; the code cell is pinned by hash and
    // depth only, so compute the representation hash manually:
    // sha256(d1 ‖ d2 ‖ data-with-completion-tag ‖ ref depths ‖ ref hashes).
    let mut repr = Vec::with_capacity(3 + 4 + 64);
    repr.push(0x02); // d1: two refs, level 0
    repr.push(0x01); // d2 for 5 data bits
    repr.push(0b0011_0100); // 00110 + completion tag 1 + padding
    repr.extend_from_slice(&config.item_code_depth.to_be_bytes());
    repr.extend_from_slice(&data_depth.to_be_bytes());
    repr.extend_from_slice(&config.item_code_hash);
    repr.extend_from_slice(data_hash.as_slice());
    let hash: [u8; 32] = Sha256::digest(&repr).into();
    Ok(MsgAddressInt::with_params(config.item_workchain, hash)?)
}

// ─── Auction, renewal, and release arithmetic ──────────────────────────────

/// `get_min_price_config`: (start, end) whole-token tiers by label byte length.
pub fn min_price_tiers(label_byte_length: usize) -> (u128, u128) {
    match label_byte_length {
        4 => (1000, 100),
        5 => (500, 50),
        6 => (400, 40),
        7 => (300, 30),
        8 => (200, 20),
        9 => (100, 10),
        10 => (50, 5),
        _ => (10, 1),
    }
}

/// `get_min_price`: tier start decayed by 10% per elapsed 30-day month with
/// floor division each step, flat at the end tier after 21 months. Nano
/// units. Before launch the undecayed start tier applies (the Collection
/// separately refuses registration until launch).
pub fn min_price(
    label_byte_length: usize,
    now_unix: i64,
    auction_start_time: i64,
) -> anyhow::Result<u128> {
    let (start_tokens, end_tokens) = min_price_tiers(label_byte_length);
    let mut price = start_tokens.checked_mul(ONE_TOS).context("min price overflow")?;
    let end = end_tokens.checked_mul(ONE_TOS).context("min price overflow")?;
    let months = now_unix.saturating_sub(auction_start_time).div_euclid(ONE_MONTH);
    if months > 21 {
        return Ok(end);
    }
    for _ in 0..months.max(0) {
        price = price.checked_mul(90).context("min price overflow")? / 100;
    }
    Ok(price)
}

/// First-auction duration: seven days falling to one hour in twelve 30-day
/// steps after launch. Only the registration auction ramps; a release
/// re-auction is always seven days.
pub fn initial_auction_duration(now_unix: i64, auction_start_time: i64) -> anyhow::Result<i64> {
    ensure!(now_unix > auction_start_time, "auction has not launched (Collection error 199)");
    let months = ((now_unix - auction_start_time) / ONE_MONTH).min(12);
    Ok(AUCTION_START_DURATION - (AUCTION_START_DURATION - AUCTION_END_DURATION) * months / 12)
}

/// `muldiv(max_bid, 105, 100)`: the inclusive minimum for a replacement bid.
pub fn minimum_next_bid(current_max_bid: u128) -> anyhow::Result<u128> {
    Ok(current_max_bid.checked_mul(105).context("bid overflow")? / 100)
}

/// Anti-sniping: a bid always leaves at least one hour on the clock.
pub fn prolonged_end_time(auction_end_time: i64, now_unix: i64) -> i64 {
    let delta = AUCTION_PROLONGATION - (auction_end_time - now_unix);
    if delta > 0 { auction_end_time + delta } else { auction_end_time }
}

/// Outbid refund actually sent: min(previous max bid, balance minus the
/// storage reserve). A client must not assume the refund always equals the
/// previous bid.
pub fn outbid_refund(previous_max_bid: u128, item_balance: u128) -> u128 {
    let cap = item_balance.saturating_sub(MIN_STORAGE_RESERVE);
    previous_max_bid.min(cap)
}

#[derive(Debug, Clone)]
pub struct AuctionInfo {
    pub max_bid_address: Option<MsgAddressInt>,
    pub max_bid_amount: u128,
    pub auction_end_time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Auction,
    AuctionEndedUnfinalized,
    Leased,
    Releasable,
}

impl DomainState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainState::Auction => "auction",
            DomainState::AuctionEndedUnfinalized => "auction-ended-unfinalized",
            DomainState::Leased => "leased",
            DomainState::Releasable => "releasable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainLifecycle {
    pub state: DomainState,
    /// true only when records may be trusted by security-sensitive consumers
    pub safe_to_resolve: bool,
    pub renewal_deadline: Option<i64>,
    pub detail: &'static str,
}

/// Fail-closed lifecycle interpretation (DNS.md §6.5): the raw item retains
/// records while overdue or under auction, so clients must derive the state
/// from `get_auction_info()` and `get_last_fill_up_time()` and refuse stale
/// records. The renewal clock runs from the LAST BID of the winning auction:
/// every accepted bid refreshes `last_fill_up_time` and finalization
/// preserves it.
pub fn classify_domain(
    auction: Option<&AuctionInfo>,
    last_fill_up_time: i64,
    now_unix: i64,
) -> DomainLifecycle {
    if let Some(auction) = auction {
        if now_unix > auction.auction_end_time {
            return DomainLifecycle {
                state: DomainState::AuctionEndedUnfinalized,
                safe_to_resolve: false,
                renewal_deadline: None,
                detail: "auction ended but no finalizing transaction has executed; \
                         ownership is not yet assigned on-chain",
            };
        }
        return DomainLifecycle {
            state: DomainState::Auction,
            safe_to_resolve: false,
            renewal_deadline: None,
            detail: "auction in progress; any records belong to a previous lease",
        };
    }
    let deadline = last_fill_up_time.saturating_add(ONE_YEAR);
    if now_unix.saturating_sub(last_fill_up_time) > ONE_YEAR {
        return DomainLifecycle {
            state: DomainState::Releasable,
            safe_to_resolve: false,
            renewal_deadline: Some(deadline),
            detail: "renewal deadline passed; anyone may release and re-auction this name",
        };
    }
    DomainLifecycle {
        state: DomainState::Leased,
        safe_to_resolve: true,
        renewal_deadline: Some(deadline),
        detail: "active lease",
    }
}

// ─── Message-body builders (inherited ABI) ─────────────────────────────────

/// Registration: an op-0 text comment whose body is the plaintext label,
/// sent to the COLLECTION with at least `min_price` attached. Long labels
/// continue in a single-ref chain, exactly as `read_domain_from_comment`
/// reads them back.
pub fn register_body(label: &str) -> anyhow::Result<Cell> {
    if let Some(err) = label_contract_error(label) {
        bail!("invalid label: {err}");
    }
    let bytes = label.as_bytes();
    // 123 bytes fit beside the 32-bit op in a 1023-bit cell
    const HEAD_CAPACITY: usize = (1023 - 32) / 8;
    let head_len = bytes.len().min(HEAD_CAPACITY);
    let mut head = BuilderData::new();
    head.append_u32(0)?;
    head.append_raw(&bytes[..head_len], head_len * 8)?;
    if bytes.len() > HEAD_CAPACITY {
        let tail = &bytes[HEAD_CAPACITY..];
        let mut rest = BuilderData::new();
        rest.append_raw(tail, tail.len() * 8)?;
        head.checked_append_reference(rest.into_cell()?)?;
    }
    Ok(head.into_cell()?)
}

/// A bid, or an owner renewal top-up: an empty body sent to the DOMAIN ITEM.
pub fn bid_body() -> anyhow::Result<Cell> {
    Ok(BuilderData::new().into_cell()?)
}

/// Explicit renewal top-up (`op::fill_up`): refreshes `last_fill_up_time`.
pub fn fill_up_body(query_id: u64) -> anyhow::Result<Cell> {
    message(OP_FILL_UP, query_id, |_| Ok(()))
}

/// Finalize a completed auction from any address: `get_static_data` is the
/// one inherited operation with a query_id, no sender check, and no side
/// effect beyond a report — and it does NOT refresh `last_fill_up_time`
/// (DNS.md §6.4).
pub fn finish_auction_body(query_id: u64) -> anyhow::Result<Cell> {
    message(OP_GET_STATIC_DATA, query_id, |_| Ok(()))
}

/// Set (value present) or delete (value absent) one record category.
pub fn change_record_body(
    category: &[u8; 32],
    value: Option<Cell>,
    query_id: u64,
) -> anyhow::Result<Cell> {
    message(OP_CHANGE_DNS_RECORD, query_id, |body| {
        body.append_u256(category)?;
        if let Some(value) = value {
            body.checked_append_reference(value)?;
        }
        Ok(())
    })
}

/// Standard NFT transfer (owner only; refused while an auction is active).
pub fn transfer_body(
    new_owner: &MsgAddressInt,
    response_to: &MsgAddressInt,
    forward_amount: u64,
    query_id: u64,
) -> anyhow::Result<Cell> {
    message(OP_TRANSFER, query_id, |body| {
        new_owner.write_to(body)?;
        response_to.write_to(body)?;
        body.append_bit_zero()?; // no custom payload
        Coins::new(forward_amount).write_to(body)?;
        Ok(())
    })
}

/// Release an overdue name (anyone; requires value >= current minimum
/// price). Starts a seven-day auction with the caller as first bidder.
pub fn release_body(query_id: u64) -> anyhow::Result<Cell> {
    message(OP_DNS_BALANCE_RELEASE, query_id, |_| Ok(()))
}

fn message<F>(opcode: u32, query_id: u64, append: F) -> anyhow::Result<Cell>
where
    F: FnOnce(&mut BuilderData) -> anyhow::Result<()>,
{
    let mut body = BuilderData::new();
    body.append_u32(opcode)?.append_u64(query_id)?;
    append(&mut body)?;
    Ok(body.into_cell()?)
}

// ─── DNSRecord codecs ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    SmcAddress {
        address: MsgAddressInt,
    },
    NextResolver {
        resolver: MsgAddressInt,
    },
    AdnlAddress {
        adnl: [u8; 32],
    },
    StorageAddress {
        bag_id: [u8; 32],
    },
    /// chunked Text payload: presentation-only, never authoritative
    Text,
}

impl DnsRecord {
    pub fn tag(&self) -> u16 {
        match self {
            DnsRecord::SmcAddress { .. } => TAG_DNS_SMC_ADDRESS,
            DnsRecord::NextResolver { .. } => TAG_DNS_NEXT_RESOLVER,
            DnsRecord::AdnlAddress { .. } => TAG_DNS_ADNL_ADDRESS,
            DnsRecord::StorageAddress { .. } => TAG_DNS_STORAGE_ADDRESS,
            DnsRecord::Text => TAG_DNS_TEXT,
        }
    }
}

pub fn make_smc_address_record(address: &MsgAddressInt) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u16(TAG_DNS_SMC_ADDRESS)?;
    address.write_to(&mut b)?;
    b.append_u8(0)?; // flags: no capability list
    Ok(b.into_cell()?)
}

pub fn make_next_resolver_record(resolver: &MsgAddressInt) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u16(TAG_DNS_NEXT_RESOLVER)?;
    resolver.write_to(&mut b)?;
    Ok(b.into_cell()?)
}

pub fn make_adnl_address_record(adnl: &[u8; 32]) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u16(TAG_DNS_ADNL_ADDRESS)?;
    b.append_raw(adnl, 256)?;
    b.append_u8(0)?; // flags: no protocol list
    Ok(b.into_cell()?)
}

pub fn make_storage_address_record(bag_id: &[u8; 32]) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u16(TAG_DNS_STORAGE_ADDRESS)?;
    b.append_raw(bag_id, 256)?;
    Ok(b.into_cell()?)
}

/// Decode one DNSRecord cell, failing closed on unknown tags.
pub fn parse_record(cell: &Cell) -> anyhow::Result<DnsRecord> {
    let mut s = SliceData::load_cell(cell.clone())?;
    ensure!(s.remaining_bits() >= 16, "record too short for a TL-B tag");
    let tag = s.get_next_u16()?;
    match tag {
        TAG_DNS_SMC_ADDRESS => {
            let address = MsgAddressInt::construct_from(&mut s)?;
            read_flag_list(&mut s)?;
            require_exhausted(&s)?;
            Ok(DnsRecord::SmcAddress { address })
        }
        TAG_DNS_NEXT_RESOLVER => {
            let resolver = MsgAddressInt::construct_from(&mut s)?;
            require_exhausted(&s)?;
            Ok(DnsRecord::NextResolver { resolver })
        }
        TAG_DNS_ADNL_ADDRESS => {
            let adnl = next_hash(&mut s)?;
            read_flag_list(&mut s)?;
            require_exhausted(&s)?;
            Ok(DnsRecord::AdnlAddress { adnl })
        }
        TAG_DNS_STORAGE_ADDRESS => {
            let bag_id = next_hash(&mut s)?;
            require_exhausted(&s)?;
            Ok(DnsRecord::StorageAddress { bag_id })
        }
        TAG_DNS_TEXT => Ok(DnsRecord::Text),
        _ => bail!("unknown DNSRecord tag 0x{tag:04x}: failing closed"),
    }
}

/// Decode a record for a specific requested category, enforcing the strict
/// category-to-record-type table. Fails on any mismatch or unknown category.
pub fn parse_record_for_category(cell: &Cell, category: &[u8; 32]) -> anyhow::Result<DnsRecord> {
    let record = parse_record(cell)?;
    let expected = expected_record_tag(category).context("unknown category: failing closed")?;
    ensure!(
        record.tag() == expected,
        "record tag 0x{:04x} does not match the 0x{:04x} required by this category",
        record.tag(),
        expected
    );
    Ok(record)
}

fn next_hash(s: &mut SliceData) -> anyhow::Result<[u8; 32]> {
    let bytes = s.get_next_bytes(32)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn read_flag_list(s: &mut SliceData) -> anyhow::Result<()> {
    let flags = s.get_next_byte()?;
    ensure!(flags <= 1, "invalid record flags");
    if flags & 1 == 1 {
        // capability/protocol list present: tolerated but not interpreted
        while s.remaining_bits() > 0 {
            s.get_next_bit()?;
        }
    }
    Ok(())
}

fn require_exhausted(s: &SliceData) -> anyhow::Result<()> {
    ensure!(s.remaining_bits() == 0, "trailing data after DNSRecord: failing closed");
    Ok(())
}

// ─── dnsresolve plumbing ───────────────────────────────────────────────────

/// Stack-entry helper for slice arguments: the JSON-RPC server deserializes
/// a slice entry from a single-cell BOC.
pub fn slice_stack_entry(cell: &Cell) -> anyhow::Result<StackEntry> {
    let bytes = write_boc(cell)?;
    Ok(StackEntry::Tvm_StackEntrySlice(tl_api::tos::tvm::stackentry::StackEntrySlice {
        slice: tl_api::tos::tvm::slice::Slice { bytes },
    }))
}

/// Arguments for `dnsresolve(slice subdomain, int category)`.
pub fn dnsresolve_stack(
    encoded_name: &[u8],
    category: &[u8; 32],
) -> anyhow::Result<Vec<StackEntry>> {
    ensure!(
        !encoded_name.is_empty() && encoded_name.len() <= MAX_ENCODED_BYTES,
        "encoded name must be 1..={MAX_ENCODED_BYTES} bytes"
    );
    let mut b = BuilderData::new();
    b.append_raw(encoded_name, encoded_name.len() * 8)?;
    Ok(vec![slice_stack_entry(&b.into_cell()?)?, bytes_to_stack_entry(category)])
}

/// One `(int used_bits, cell|null value)` dnsresolve answer.
#[derive(Debug, Clone)]
pub struct HopResult {
    pub used_bits: i64,
    pub value: Option<Cell>,
}

/// Decode a dnsresolve get-method result (bottom-first parser order).
pub fn decode_dnsresolve(parser: &TvmStackParser) -> anyhow::Result<HopResult> {
    Ok(HopResult { used_bits: parser.i64(0)?, value: parser.cell_opt(1)? })
}

#[derive(Debug, Clone)]
pub enum HopOutcome {
    NotFound,
    Terminal(Option<Cell>),
    Continue { next_resolver: MsgAddressInt, remaining: Vec<u8> },
}

/// Validate one dnsresolve answer for the encoded query (DNS.md §5.5, §8).
/// Every check fails closed; exhausting the hop budget is a DISTINCT error,
/// never "not found".
pub fn validate_hop(query: &[u8], hop: &HopResult, hops_left: i64) -> anyhow::Result<HopOutcome> {
    if hop.used_bits <= 0 {
        return Ok(HopOutcome::NotFound);
    }
    ensure!(hop.used_bits % 8 == 0, "consumed-bit count {} is not byte aligned", hop.used_bits);
    let query_bits = i64::try_from(query.len()).context("query too long")? * 8;
    ensure!(
        hop.used_bits <= query_bits,
        "resolver claims {} bits of a {}-bit query",
        hop.used_bits,
        query_bits
    );
    let pos = usize::try_from(hop.used_bits / 8).context("invalid consumed-bit count")?;
    if pos == query.len() {
        return Ok(HopOutcome::Terminal(hop.value.clone()));
    }
    // partial resolution: must stop at a component boundary
    ensure!(query[pos - 1] == 0 || query[pos] == 0, "domain split not at a component boundary");
    let Some(value) = &hop.value else {
        return Ok(HopOutcome::NotFound);
    };
    let record = parse_record(value)?;
    let DnsRecord::NextResolver { resolver } = record else {
        bail!(
            "partially resolved answer carries tag 0x{:04x}, not dns_next_resolver: failing closed",
            record.tag()
        );
    };
    ensure!(
        hops_left > 1,
        "resolver hop limit ({MAX_RESOLVER_HOPS}) exhausted; next resolver would be {resolver}"
    );
    Ok(HopOutcome::Continue { next_resolver: resolver, remaining: query[pos..].to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(wc: i32, byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, wc as i8, [byte; 32].into()).expect("addr")
    }

    fn parse_addr(s: &str) -> MsgAddressInt {
        s.parse::<MsgAddressInt>().expect("address")
    }

    // ── vectors.json ground truth (gen-vectors.fif, auction_start_time
    //    1798761600, TIP-1) ───────────────────────────────────────────────
    const VECTOR_COLLECTION: &str =
        "0:cec242160fa821bc402586947649f25d4a0c1b02808d1dce93c893e98061bb8a";
    const VECTOR_ITEM_CODE_HASH: &str =
        "e469483aa8a8e5018f46cdd9c374b60153025847a6d4997692cfdd9b15be1d78";
    const VECTOR_ITEM_CODE_DEPTH: u16 = 11;
    const VECTOR_ALICE_SLICE_HASH: &str =
        "56121e387810a23e51711d37fbb3241ee8ea09af40a72d0a1b37985af8af1d08";
    const VECTOR_ALICE_PLAIN_SHA256: &str =
        "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90";
    const VECTOR_ALICE_ITEM_DATA_HASH: &str =
        "0890ab4aa0a01f85fc143cfd4749815e7e60d0c962e22e006db8938264bd469a";
    const VECTOR_ALICE_ITEM_ADDRESS: &str =
        "0:d1a8a3d62880a1afb40186d7dc67e5072eb2740b094bd3d407e703bf3a26674d";
    const VECTOR_CATEGORY_NEXT_RESOLVER: &str =
        "19f02441ee588fdb26ee24b2568dd035c3c9206e11ab979be62e55558a1d17ff";
    const AUCTION_START: i64 = 1_798_761_600;

    fn vector_config() -> CollectionConfig {
        CollectionConfig {
            collection: parse_addr(VECTOR_COLLECTION),
            item_code_hash: hex32(VECTOR_ITEM_CODE_HASH),
            item_code_depth: VECTOR_ITEM_CODE_DEPTH,
            item_workchain: 0,
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn slice_hash_matches_fift_and_differs_from_plain_sha256() {
        let got = label_slice_hash("alice").expect("hash");
        assert_eq!(hex::encode(got), VECTOR_ALICE_SLICE_HASH);
        let plain: [u8; 32] = Sha256::digest(b"alice").into();
        assert_eq!(hex::encode(plain), VECTOR_ALICE_PLAIN_SHA256);
        assert_ne!(got, plain, "HASHSU must differ from plain sha256");
    }

    #[test]
    fn item_data_cell_matches_fift() {
        let index = label_slice_hash("alice").expect("hash");
        let data = item_data_cell(&index, &parse_addr(VECTOR_COLLECTION)).expect("data");
        assert_eq!(hex::encode(data.repr_hash().as_slice()), VECTOR_ALICE_ITEM_DATA_HASH);
        assert_eq!(data.depth(0), 0);
    }

    #[test]
    fn item_address_matches_fift_byte_for_byte() {
        let derived = derive_item_address(&vector_config(), "alice").expect("derive");
        assert_eq!(derived, parse_addr(VECTOR_ALICE_ITEM_ADDRESS));
    }

    #[test]
    fn item_address_rejects_invalid_label() {
        assert!(derive_item_address(&vector_config(), "-alice").is_err());
        assert!(derive_item_address(&vector_config(), "bob").is_err());
    }

    #[test]
    fn category_hash_matches_pinned_vector() {
        assert_eq!(hex::encode(category_hash("dns_next_resolver")), VECTOR_CATEGORY_NEXT_RESOLVER);
        assert_eq!(
            expected_record_tag(&category_hash("dns_next_resolver")),
            Some(TAG_DNS_NEXT_RESOLVER)
        );
        assert_eq!(expected_record_tag(&category_hash("wallet")), Some(TAG_DNS_SMC_ADDRESS));
        assert_eq!(expected_record_tag(&[0x77; 32]), None);
    }

    // ── name rules ────────────────────────────────────────────────────────

    #[test]
    fn label_rule_negatives() {
        assert!(label_contract_error("alice").is_none());
        assert!(label_contract_error("ab-cd").is_none());
        assert!(label_contract_error("bob").is_some(), "3 bytes too short");
        assert!(label_contract_error("-alice").is_some(), "leading hyphen");
        assert!(label_contract_error("alice-").is_some(), "trailing hyphen");
        assert!(label_contract_error("aLice").is_some(), "uppercase");
        assert!(label_contract_error("ali_ce").is_some(), "underscore");
        assert!(label_contract_error(&"a".repeat(126)).is_none());
        assert!(label_contract_error(&"a".repeat(127)).is_some());
        // contract-valid, UI-warned
        assert!(label_contract_error("xn--alice").is_none());
        assert!(!label_ui_warnings("xn--alice").is_empty());
        assert!(!label_ui_warnings("a--b").is_empty());
        assert!(label_ui_warnings("alice").is_empty());
    }

    #[test]
    fn encoding_and_boundaries() {
        assert_eq!(encode_name("translate.alice.tos").expect("encode"), b"tos\0alice\0translate\0");
        assert_eq!(decode_name(b"tos\0alice\0translate\0").expect("decode"), "translate.alice.tos");
        // 126 dotted bytes encode to exactly 127
        let name126 = format!("{}cd.tos", "ab.".repeat(40));
        assert_eq!(name126.len(), 126);
        assert_eq!(encode_name(&name126).expect("encode").len(), 127);
        // 127 dotted bytes are over the bound
        let name127 = format!("{}cde.tos", "ab.".repeat(40));
        assert_eq!(name127.len(), 127);
        assert!(canonicalize_name(&name127).is_err());
        // rejections
        assert!(canonicalize_name("alice.tos.").is_err(), "trailing dot");
        assert!(canonicalize_name("alice..tos").is_err(), "empty label");
        assert!(canonicalize_name("").is_err());
        assert!(canonicalize_name("al ice.tos").is_err());
        assert!(canonicalize_name("alice:tos").is_err());
        // case folding is reported
        assert!(canonicalize_name("Alice.tos").expect("canonical").case_folded);
        assert_eq!(second_level_label("alice.tos").expect("sll"), "alice");
        assert!(second_level_label("a.alice.tos").is_err());
        assert!(second_level_label("alice.ton").is_err());
    }

    // ── auction arithmetic ────────────────────────────────────────────────

    #[test]
    fn min_price_tiers_and_decay() {
        let t = AUCTION_START + 1;
        assert_eq!(min_price(4, t, AUCTION_START).expect("p"), 1000 * ONE_TOS);
        assert_eq!(min_price(5, t, AUCTION_START).expect("p"), 500 * ONE_TOS);
        assert_eq!(min_price(11, t, AUCTION_START).expect("p"), 10 * ONE_TOS);
        // one month: single 90/100 floor step
        assert_eq!(
            min_price(4, AUCTION_START + ONE_MONTH, AUCTION_START).expect("p"),
            900 * ONE_TOS
        );
        // 22 months: flat end tier
        assert_eq!(
            min_price(4, AUCTION_START + 22 * ONE_MONTH, AUCTION_START).expect("p"),
            100 * ONE_TOS
        );
        // pre-launch: undecayed start tier
        assert_eq!(min_price(4, AUCTION_START - 5, AUCTION_START).expect("p"), 1000 * ONE_TOS);
    }

    #[test]
    fn bid_threshold_exact_boundary() {
        let min = minimum_next_bid(1000 * ONE_TOS).expect("bid");
        assert_eq!(min, 1050 * ONE_TOS);
        // floor division on an odd amount
        assert_eq!(minimum_next_bid(1).expect("bid"), 1);
        assert_eq!(minimum_next_bid(100).expect("bid"), 105);
        // acceptance is inclusive: a bid exactly at min wins
        assert!(min >= minimum_next_bid(1000 * ONE_TOS).expect("bid"));
    }

    #[test]
    fn auction_duration_ramp() {
        let start = AUCTION_START;
        assert!(initial_auction_duration(start, start).is_err(), "not launched");
        assert_eq!(initial_auction_duration(start + 1, start).expect("d"), 604_800);
        assert_eq!(
            initial_auction_duration(start + ONE_MONTH, start).expect("d"),
            604_800 - (604_800 - 3_600) / 12
        );
        assert_eq!(initial_auction_duration(start + 12 * ONE_MONTH, start).expect("d"), 3_600);
        assert_eq!(initial_auction_duration(start + 40 * ONE_MONTH, start).expect("d"), 3_600);
    }

    #[test]
    fn prolongation_and_refund() {
        assert_eq!(prolonged_end_time(10_000, 1_000), 10_000, "over an hour left");
        assert_eq!(prolonged_end_time(1_000, 900), 900 + 3_600, "sniping window");
        assert_eq!(outbid_refund(5 * ONE_TOS, 10 * ONE_TOS), 5 * ONE_TOS);
        assert_eq!(outbid_refund(10 * ONE_TOS, 10 * ONE_TOS), 9 * ONE_TOS, "reserve cap");
        assert_eq!(outbid_refund(10 * ONE_TOS, ONE_TOS / 2), 0);
    }

    #[test]
    fn lifecycle_classification_table() {
        let auction =
            AuctionInfo { max_bid_address: None, max_bid_amount: 0, auction_end_time: 2_000 };
        let live = classify_domain(Some(&auction), 0, 1_500);
        assert_eq!(live.state, DomainState::Auction);
        assert!(!live.safe_to_resolve);
        let ended = classify_domain(Some(&auction), 0, 2_001);
        assert_eq!(ended.state, DomainState::AuctionEndedUnfinalized);
        assert!(!ended.safe_to_resolve);
        let leased = classify_domain(None, 1_000, 1_000 + ONE_YEAR);
        assert_eq!(leased.state, DomainState::Leased);
        assert!(leased.safe_to_resolve);
        assert_eq!(leased.renewal_deadline, Some(1_000 + ONE_YEAR));
        let overdue = classify_domain(None, 1_000, 1_001 + ONE_YEAR);
        assert_eq!(overdue.state, DomainState::Releasable);
        assert!(!overdue.safe_to_resolve);
    }

    // ── message bodies ────────────────────────────────────────────────────

    #[test]
    fn register_body_layout() {
        let cell = register_body("alice").expect("body");
        let mut s = SliceData::load_cell(cell).expect("slice");
        assert_eq!(s.get_next_u32().expect("op"), 0);
        assert_eq!(s.get_next_bytes(5).expect("label"), b"alice");
        assert_eq!(s.remaining_bits(), 0);
        assert_eq!(s.remaining_references(), 0);
        // long label: 123-byte head + single-ref continuation
        let label = "a".repeat(126);
        let cell = register_body(&label).expect("body");
        let mut s = SliceData::load_cell(cell).expect("slice");
        assert_eq!(s.get_next_u32().expect("op"), 0);
        assert_eq!(s.get_next_bytes(123).expect("head"), label.as_bytes()[..123]);
        assert_eq!(s.remaining_references(), 1);
        let rest = s.checked_drain_reference().expect("ref");
        let mut rest = SliceData::load_cell(rest).expect("slice");
        assert_eq!(rest.get_next_bytes(3).expect("tail"), label.as_bytes()[123..]);
        assert!(register_body("aLice").is_err());
    }

    #[test]
    fn operation_bodies() {
        let mut s = SliceData::load_cell(finish_auction_body(7).expect("body")).expect("s");
        assert_eq!(s.get_next_u32().expect("op"), OP_GET_STATIC_DATA);
        assert_eq!(s.get_next_u64().expect("qid"), 7);
        let mut s = SliceData::load_cell(fill_up_body(1).expect("body")).expect("s");
        assert_eq!(s.get_next_u32().expect("op"), OP_FILL_UP);
        let mut s = SliceData::load_cell(release_body(0).expect("body")).expect("s");
        assert_eq!(s.get_next_u32().expect("op"), OP_DNS_BALANCE_RELEASE);
        assert_eq!(bid_body().expect("body").bit_length(), 0);

        let cat = category_hash("wallet");
        let value = make_smc_address_record(&addr(0, 0x11)).expect("record");
        let set = change_record_body(&cat, Some(value), 3).expect("body");
        let mut s = SliceData::load_cell(set).expect("s");
        assert_eq!(s.get_next_u32().expect("op"), OP_CHANGE_DNS_RECORD);
        assert_eq!(s.get_next_u64().expect("qid"), 3);
        assert_eq!(s.get_next_bytes(32).expect("cat"), cat);
        assert_eq!(s.remaining_references(), 1);
        let del = change_record_body(&cat, None, 3).expect("body");
        let s = SliceData::load_cell(del).expect("s");
        assert_eq!(s.remaining_references(), 0);

        let t = transfer_body(&addr(0, 0x22), &addr(0, 0x33), 5, 9).expect("body");
        let mut s = SliceData::load_cell(t).expect("s");
        assert_eq!(s.get_next_u32().expect("op"), OP_TRANSFER);
        assert_eq!(s.get_next_u64().expect("qid"), 9);
        assert_eq!(MsgAddressInt::construct_from(&mut s).expect("owner"), addr(0, 0x22));
        assert_eq!(MsgAddressInt::construct_from(&mut s).expect("resp"), addr(0, 0x33));
        assert!(!s.get_next_bit().expect("payload bit"));
        assert_eq!(Coins::construct_from(&mut s).expect("fwd").as_u128(), 5);
        assert_eq!(s.remaining_bits(), 0);
    }

    // ── record codecs ─────────────────────────────────────────────────────

    #[test]
    fn record_round_trips_and_fail_closed() {
        let a = addr(-1, 0x44);
        let rec = parse_record(&make_smc_address_record(&a).expect("mk")).expect("parse");
        assert_eq!(rec, DnsRecord::SmcAddress { address: a.clone() });
        let rec = parse_record(&make_next_resolver_record(&a).expect("mk")).expect("parse");
        assert_eq!(rec, DnsRecord::NextResolver { resolver: a.clone() });
        let rec = parse_record(&make_adnl_address_record(&[0x55; 32]).expect("mk")).expect("parse");
        assert_eq!(rec, DnsRecord::AdnlAddress { adnl: [0x55; 32] });
        let rec =
            parse_record(&make_storage_address_record(&[0x66; 32]).expect("mk")).expect("parse");
        assert_eq!(rec, DnsRecord::StorageAddress { bag_id: [0x66; 32] });

        // unknown tag fails closed
        let mut b = BuilderData::new();
        b.append_u16(0xbeef).expect("tag");
        assert!(parse_record(&b.into_cell().expect("cell")).is_err());
        // trailing data fails closed
        let mut b = BuilderData::new();
        b.append_u16(TAG_DNS_NEXT_RESOLVER).expect("tag");
        addr(0, 1).write_to(&mut b).expect("addr");
        b.append_u8(0xff).expect("junk");
        assert!(parse_record(&b.into_cell().expect("cell")).is_err());
        // strict category table
        let wallet_cat = category_hash("wallet");
        let smc = make_smc_address_record(&a).expect("mk");
        assert!(parse_record_for_category(&smc, &wallet_cat).is_ok());
        let nr = make_next_resolver_record(&a).expect("mk");
        assert!(parse_record_for_category(&nr, &wallet_cat).is_err());
        assert!(parse_record_for_category(&smc, &[0x99; 32]).is_err(), "unknown category");
    }

    // ── hop validation ────────────────────────────────────────────────────

    fn hop(used_bits: i64, value: Option<Cell>) -> HopResult {
        HopResult { used_bits, value }
    }

    #[test]
    fn hop_validation_cases() {
        let query = encode_name("alice.tos").expect("encode"); // "tos\0alice\0", 10 bytes
        let next = make_next_resolver_record(&addr(0, 0x10)).expect("mk");

        // not found
        assert!(matches!(
            validate_hop(&query, &hop(0, None), 8).expect("ok"),
            HopOutcome::NotFound
        ));
        // misaligned
        assert!(validate_hop(&query, &hop(13, None), 8).is_err());
        // over-claim
        assert!(validate_hop(&query, &hop(88, None), 8).is_err());
        // terminal
        assert!(matches!(
            validate_hop(&query, &hop(80, Some(next.clone())), 1).expect("ok"),
            HopOutcome::Terminal(Some(_))
        ));
        // split not at a component boundary ("to|s\0alice\0")
        assert!(validate_hop(&query, &hop(16, Some(next.clone())), 8).is_err());
        // valid partial after "tos\0" continues with the remaining suffix
        match validate_hop(&query, &hop(32, Some(next.clone())), 8).expect("ok") {
            HopOutcome::Continue { next_resolver, remaining } => {
                assert_eq!(next_resolver, addr(0, 0x10));
                assert_eq!(remaining, b"alice\0");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        // partial with a non-next-resolver record fails closed
        let smc = make_smc_address_record(&addr(0, 0x11)).expect("mk");
        assert!(validate_hop(&query, &hop(32, Some(smc)), 8).is_err());
        // partial with no value is not found
        assert!(matches!(
            validate_hop(&query, &hop(32, None), 8).expect("ok"),
            HopOutcome::NotFound
        ));
        // hop exhaustion is a DISTINCT error, never "not found"
        let err = validate_hop(&query, &hop(32, Some(next)), 1).expect_err("must be an error");
        assert!(err.to_string().contains("hop limit"), "distinct hop-limit error: {err}");
    }

    #[test]
    fn dnsresolve_stack_shape() {
        let query = encode_name("alice.tos").expect("encode");
        let stack = dnsresolve_stack(&query, &CATEGORY_ALL).expect("stack");
        assert_eq!(stack.len(), 2);
        assert!(matches!(stack[0], StackEntry::Tvm_StackEntrySlice(_)));
        assert!(matches!(stack[1], StackEntry::Tvm_StackEntryNumber(_)));
        assert!(dnsresolve_stack(&[], &CATEGORY_ALL).is_err());
    }
}
