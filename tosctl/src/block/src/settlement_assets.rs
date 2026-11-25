/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! ConfigParam 84: the recognized settlement assets.
//!
//! ```text
//! settlement_asset_origin$_ kind:uint8 bridge_address:bits256
//!   source_chain_id:uint32 source_token:bits160 = SettlementAssetOriginV1;
//! settlement_asset_v1#01 status:uint8 decimals:uint8
//!   minter_code_hash:bits256 wallet_code_hash:bits256
//!   max_liability_per_actor:Coins
//!   origin:^SettlementAssetOriginV1 = SettlementAssetV1;
//! settlement_assets_v1#01 assets:(HashmapE 256 SettlementAssetV1) = SettlementAssets;
//! _ SettlementAssets = ConfigParam 84;
//! ```
//!
//! The schema fixes only the shape. This module also refuses every status and
//! origin kind the schema does not define, a zero liability cap, any trailing bit
//! or reference, and an exotic cell anywhere in the value. The whole-value
//! decoder and the builder also refuse more than [`SETTLEMENT_ASSETS_MAX_ENTRIES`]
//! entries. Two readers are provided:
//!
//! * [`SettlementAssets`] decodes the whole value and refuses it when any entry is
//!   malformed. Display and proposal building use it.
//! * [`read_pinned_settlement_assets`] decodes only the entries a client pins and
//!   ignores the contents of every other entry and their number. Settlement
//!   clients use it. It still refuses a value the node could not have installed:
//!   one with an exotic cell or over the node's validation budget.

use crate::{
    error, fail, BuilderData, Cell, CellType, Coins, Deserializable, HashmapE, HashmapType,
    IBitstring, Result, Serializable, SliceData, UInt256,
};
use std::collections::BTreeMap;

/// The configuration parameter that holds the recognized settlement assets.
pub const SETTLEMENT_ASSETS_CONFIG_PARAM: u32 = 84;
/// The `settlement_assets_v1` constructor tag.
pub const SETTLEMENT_ASSETS_TAG: u8 = 0x01;
/// The `settlement_asset_v1` constructor tag.
pub const SETTLEMENT_ASSET_TAG: u8 = 0x01;
/// `max_liability_per_actor` meaning "no cap": the largest `Coins` value, 2^120 - 1.
pub const NO_LIABILITY_CAP: Coins = Coins::MAX;
/// kind:uint8 bridge_address:bits256 source_chain_id:uint32 source_token:bits160.
const ORIGIN_BITS: usize = 8 + 256 + 32 + 160;
/// The dictionary key: a workchain-0 account id.
const KEY_BITS: usize = 256;
/// The most entries a ConfigParam 84 value may hold. The network recognizes one or
/// two assets; 16 leaves headroom and keeps the value far inside the node's
/// validation budget.
pub const SETTLEMENT_ASSETS_MAX_ENTRIES: usize = 16;
/// The cell budget the node validates every configuration parameter against
/// (`check_one_config_param` in crypto/block/block.cpp: `validate_ref(1024, ..)`).
/// A value over it matches its schema yet fails validation when installed, and
/// the collator then refuses to install the new configuration.
pub const CONFIG_PARAM_VALIDATION_CELLS: usize = 1024;

/// The cells the node's `validate_ref` visits for a value whose every reference is
/// typed (as in every ConfigParam 84 value): each reference is a visit, so a cell
/// reached twice counts twice. Returns `None` as soon as `limit` is exceeded.
/// For a schema that leaves a reference untyped this over-counts, never
/// under-counts, so refusing above the budget never admits a value the node
/// would refuse.
pub fn validation_cell_visits(cell: &Cell, limit: usize) -> Option<usize> {
    let mut visits = 0usize;
    let mut pending = vec![cell.clone()];
    while let Some(next) = pending.pop() {
        visits = visits.checked_add(1)?;
        if visits > limit {
            return None;
        }
        for index in 0..next.references_count() {
            pending.push(next.reference(index).ok()?);
        }
    }
    Some(visits)
}

/// Refuses a value with more cell visits than [`CONFIG_PARAM_VALIDATION_CELLS`].
pub fn check_config_param_budget(param: u32, cell: &Cell) -> Result<()> {
    if validation_cell_visits(cell, CONFIG_PARAM_VALIDATION_CELLS).is_none() {
        fail!(
            "ConfigParam {param}: the value needs more than {CONFIG_PARAM_VALIDATION_CELLS} cells \
             of validation; the node would refuse to install it"
        )
    }
    Ok(())
}

/// Every cell of the value must be ordinary at level 0: the node's schema check
/// refuses an exotic cell anywhere in a configuration parameter.
fn all_ordinary(cell: &Cell) -> Result<()> {
    let mut pending = vec![cell.clone()];
    let mut visits = 0usize;
    while let Some(next) = pending.pop() {
        visits += 1;
        if visits > CONFIG_PARAM_VALIDATION_CELLS {
            fail!("ConfigParam 84: the value exceeds the node's validation budget")
        }
        if next.cell_type() != CellType::Ordinary || next.level() != 0 {
            fail!("ConfigParam 84: the value holds a cell that is not ordinary")
        }
        for index in 0..next.references_count() {
            pending.push(next.reference(index)?);
        }
    }
    Ok(())
}

/// Whether a token actor may admit new calls in the asset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum SettlementAssetStatus {
    /// 1: admission open.
    #[default]
    Active,
    /// 2: admission suspended network-wide; payouts are unaffected.
    AdmissionSuspended,
    /// 3: retired; clients refuse new deployments and quotes.
    Retired,
}

impl SettlementAssetStatus {
    pub const fn code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::AdmissionSuspended => 2,
            Self::Retired => 3,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Active),
            2 => Ok(Self::AdmissionSuspended),
            3 => Ok(Self::Retired),
            other => fail!("ConfigParam 84: unknown settlement asset status {other}"),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::AdmissionSuspended => "admission_suspended",
            Self::Retired => "retired",
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "active" => Ok(Self::Active),
            "admission_suspended" => Ok(Self::AdmissionSuspended),
            "retired" => Ok(Self::Retired),
            other => fail!("ConfigParam 84: unknown settlement asset status {other:?}"),
        }
    }
}

/// Where an asset's master comes from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum SettlementAssetOriginKind {
    /// 1: a minter created by the TOS token bridge.
    #[default]
    TokenBridge,
    /// 2: reserved for native issuance; no verification rule exists for it yet.
    NativeIssuance,
}

impl SettlementAssetOriginKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::TokenBridge => 1,
            Self::NativeIssuance => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::TokenBridge),
            2 => Ok(Self::NativeIssuance),
            other => fail!("ConfigParam 84: unknown settlement asset origin kind {other}"),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::TokenBridge => "token_bridge",
            Self::NativeIssuance => "native_issuance",
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "token_bridge" => Ok(Self::TokenBridge),
            "native_issuance" => Ok(Self::NativeIssuance),
            other => fail!("ConfigParam 84: unknown settlement asset origin kind {other:?}"),
        }
    }
}

/// `SettlementAssetOriginV1`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SettlementAssetOrigin {
    pub kind: SettlementAssetOriginKind,
    /// Masterchain account id of the bridge that created the minter.
    pub bridge_address: UInt256,
    /// The minter content's `chain_id`.
    pub source_chain_id: u32,
    /// The minter content's `token_address` (160 bits).
    pub source_token: [u8; 20],
}

impl Serializable for SettlementAssetOrigin {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u8(self.kind.code())?;
        self.bridge_address.write_to(cell)?;
        cell.append_u32(self.source_chain_id)?;
        cell.append_raw(&self.source_token, 160)?;
        Ok(())
    }
}

impl SettlementAssetOrigin {
    /// Decodes the origin cell exactly: an ordinary cell of 456 bits and no reference.
    pub fn from_cell(cell: Cell) -> Result<Self> {
        let mut slice = ordinary_slice(cell, "origin")?;
        if slice.remaining_bits() != ORIGIN_BITS || slice.remaining_references() != 0 {
            fail!("ConfigParam 84: the origin cell must hold exactly {ORIGIN_BITS} bits and no reference")
        }
        let kind = SettlementAssetOriginKind::from_code(slice.get_next_byte()?)?;
        let bridge_address = slice.get_next_hash()?;
        let source_chain_id = slice.get_next_u32()?;
        let mut source_token = [0u8; 20];
        slice.get_next_bytes_to_slice(&mut source_token)?;
        Ok(Self { kind, bridge_address, source_chain_id, source_token })
    }
}

/// `SettlementAssetV1`, one recognized asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementAsset {
    pub status: SettlementAssetStatus,
    /// Decimals of the atomic unit; equals the minter content's decimals.
    pub decimals: u8,
    /// Code hash of the master account.
    pub minter_code_hash: UInt256,
    /// `cell_hash` of the wallet code the minter derives wallets with.
    pub wallet_code_hash: UInt256,
    /// The largest token liability one actor may hold; non-zero. [`NO_LIABILITY_CAP`]
    /// means no cap.
    pub max_liability_per_actor: Coins,
    pub origin: SettlementAssetOrigin,
}

impl Default for SettlementAsset {
    fn default() -> Self {
        Self {
            status: SettlementAssetStatus::Active,
            decimals: 0,
            minter_code_hash: UInt256::default(),
            wallet_code_hash: UInt256::default(),
            max_liability_per_actor: NO_LIABILITY_CAP,
            origin: SettlementAssetOrigin::default(),
        }
    }
}

impl SettlementAsset {
    /// Whether the record states no liability cap.
    pub fn is_uncapped(&self) -> bool {
        self.max_liability_per_actor == NO_LIABILITY_CAP
    }

    /// Refuses a record this module could not decode back to itself.
    pub fn check(&self) -> Result<()> {
        if self.max_liability_per_actor.is_zero() {
            fail!("ConfigParam 84: max_liability_per_actor must be non-zero (no cap is 2^120 - 1)")
        }
        Ok(())
    }

    /// Decodes one dictionary value exactly: the record must use every bit and its
    /// one reference, and nothing may follow.
    pub fn from_leaf(mut slice: SliceData) -> Result<Self> {
        let tag = slice.get_next_byte()?;
        if tag != SETTLEMENT_ASSET_TAG {
            fail!("ConfigParam 84: unknown settlement asset tag {tag:#04x}")
        }
        let status = SettlementAssetStatus::from_code(slice.get_next_byte()?)?;
        let decimals = slice.get_next_byte()?;
        let minter_code_hash = slice.get_next_hash()?;
        let wallet_code_hash = slice.get_next_hash()?;
        // Coins refuses a non-minimal length itself.
        let max_liability_per_actor = Coins::construct_from(&mut slice)?;
        if max_liability_per_actor.is_zero() {
            fail!("ConfigParam 84: max_liability_per_actor must be non-zero (no cap is 2^120 - 1)")
        }
        if slice.remaining_bits() != 0 || slice.remaining_references() != 1 {
            fail!("ConfigParam 84: a settlement asset record carries trailing data")
        }
        let origin = SettlementAssetOrigin::from_cell(slice.checked_drain_reference()?)?;
        Ok(Self {
            status,
            decimals,
            minter_code_hash,
            wallet_code_hash,
            max_liability_per_actor,
            origin,
        })
    }
}

impl Serializable for SettlementAsset {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.check()?;
        cell.append_u8(SETTLEMENT_ASSET_TAG)?;
        cell.append_u8(self.status.code())?;
        cell.append_u8(self.decimals)?;
        self.minter_code_hash.write_to(cell)?;
        self.wallet_code_hash.write_to(cell)?;
        self.max_liability_per_actor.write_to(cell)?;
        cell.checked_append_reference(self.origin.serialize()?)?;
        Ok(())
    }
}

/// `SettlementAssets`, the whole value of ConfigParam 84, keyed by master account id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SettlementAssets {
    pub assets: BTreeMap<UInt256, SettlementAsset>,
}

impl SettlementAssets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, master: &UInt256) -> Option<&SettlementAsset> {
        self.assets.get(master)
    }

    /// Adds an entry, refusing a master that is already listed.
    pub fn insert(&mut self, master: UInt256, asset: SettlementAsset) -> Result<()> {
        asset.check()?;
        if self.assets.len() >= SETTLEMENT_ASSETS_MAX_ENTRIES {
            fail!("ConfigParam 84: at most {SETTLEMENT_ASSETS_MAX_ENTRIES} assets may be listed")
        }
        if self.assets.contains_key(&master) {
            fail!("ConfigParam 84: master {master:x} is listed twice")
        }
        self.assets.insert(master, asset);
        Ok(())
    }

    /// The value as the configuration stores it.
    pub fn to_cell(&self) -> Result<Cell> {
        self.serialize()
    }

    /// Decodes a whole value and refuses it if anything in it is malformed.
    pub fn from_cell(cell: Cell) -> Result<Self> {
        let (_, dictionary) = open_value(cell)?;
        let mut assets = BTreeMap::new();
        if dictionary.len()? > SETTLEMENT_ASSETS_MAX_ENTRIES {
            fail!("ConfigParam 84: more than {SETTLEMENT_ASSETS_MAX_ENTRIES} assets are listed")
        }
        let mut failure = None;
        dictionary.iterate_slices(|mut key, value| {
            let master = key.get_next_hash()?;
            match SettlementAsset::from_leaf(value) {
                Ok(asset) => {
                    assets.insert(master, asset);
                    Ok(true)
                }
                Err(err) => {
                    failure = Some(error!("ConfigParam 84 entry {master:x}: {err}"));
                    Ok(false)
                }
            }
        })?;
        if let Some(err) = failure {
            return Err(err);
        }
        Ok(Self { assets })
    }
}

impl Serializable for SettlementAssets {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        let mut dictionary = HashmapE::with_bit_len(KEY_BITS);
        for (master, asset) in &self.assets {
            let value = asset.write_to_new_cell()?;
            dictionary
                .set_builder(SliceData::from_raw(master.as_slice().to_vec(), KEY_BITS), &value)?;
        }
        cell.append_u8(SETTLEMENT_ASSETS_TAG)?;
        dictionary.write_hashmap_data(cell)?;
        Ok(())
    }
}

impl Deserializable for SettlementAssets {
    fn construct_from(slice: &mut SliceData) -> Result<Self> {
        // The value is a whole cell: decode it from its own cell so that trailing
        // data is refused, then consume the slice the caller handed in.
        let cell = slice.clone().into_cell()?;
        let value = Self::from_cell(cell)?;
        *slice = SliceData::default();
        Ok(value)
    }

    fn construct_from_cell(cell: Cell) -> Result<Self> {
        Self::from_cell(cell)
    }
}

/// One pinned master and what ConfigParam 84 says about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedSettlementAsset {
    pub master: UInt256,
    /// `None` when the configuration does not list the master.
    pub asset: Option<SettlementAsset>,
}

/// Reads only the masters a client pins. Every other entry is ignored, however it
/// is encoded, and more entries than pins is never an error. A pinned entry is
/// decoded exactly and refused if malformed. The value itself must still carry
/// the `settlement_assets_v1` tag and nothing after the dictionary root, hold
/// only ordinary cells and fit the node's validation budget.
pub fn read_pinned_settlement_assets(
    value: Cell,
    pins: &[UInt256],
) -> Result<Vec<PinnedSettlementAsset>> {
    let (_, dictionary) = open_value(value)?;
    let mut result = Vec::with_capacity(pins.len());
    for (index, master) in pins.iter().enumerate() {
        if pins[..index].contains(master) {
            fail!("ConfigParam 84: master {master:x} is pinned twice")
        }
        let key = SliceData::from_raw(master.as_slice().to_vec(), KEY_BITS);
        let asset = match dictionary.get(key)? {
            Some(leaf) => Some(
                SettlementAsset::from_leaf(leaf)
                    .map_err(|err| error!("ConfigParam 84 entry {master:x}: {err}"))?,
            ),
            None => None,
        };
        result.push(PinnedSettlementAsset { master: master.clone(), asset });
    }
    Ok(result)
}

fn ordinary_slice(cell: Cell, what: &str) -> Result<SliceData> {
    if cell.cell_type() != CellType::Ordinary || cell.level() != 0 {
        fail!("ConfigParam 84: the {what} is not an ordinary cell")
    }
    SliceData::load_cell(cell)
}

/// The tag, then `HashmapE 256` and nothing else.
fn open_value(cell: Cell) -> Result<(u8, HashmapE)> {
    all_ordinary(&cell)?;
    let mut slice = ordinary_slice(cell, "value")?;
    let tag = slice.get_next_byte()?;
    if tag != SETTLEMENT_ASSETS_TAG {
        fail!("ConfigParam 84: unknown settlement assets tag {tag:#04x}")
    }
    let mut dictionary = HashmapE::with_bit_len(KEY_BITS);
    dictionary.read_hashmap_data(&mut slice)?;
    if slice.remaining_bits() != 0 || slice.remaining_references() != 0 {
        fail!("ConfigParam 84: the value carries trailing data")
    }
    if let Some(root) = dictionary.data() {
        if root.cell_type() != CellType::Ordinary {
            fail!("ConfigParam 84: the dictionary root is not an ordinary cell")
        }
    }
    Ok((tag, dictionary))
}
