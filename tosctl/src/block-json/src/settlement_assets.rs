/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! JSON form of ConfigParam 84 (recognized settlement assets).
//!
//! The decoder ([`settlement_assets_to_json`]) and the proposal value builder
//! ([`settlement_assets_from_json`]) use one shape, so a decoded value can be
//! edited and built back:
//!
//! ```json
//! {"assets": [{
//!   "master": "<64 hex: workchain-0 account id>",
//!   "status": "active | admission_suspended | retired",
//!   "decimals": 6,
//!   "minter_code_hash": "<64 hex>",
//!   "wallet_code_hash": "<64 hex>",
//!   "max_liability_per_actor": "<decimal, non-zero; 1329227995784915872903807060280344575 is no cap>",
//!   "uncapped": false,
//!   "origin": {"kind": "token_bridge | native_issuance", "bridge_address": "<64 hex>",
//!              "source_chain_id": 1, "source_token": "<40 hex>"}
//! }]}
//! ```
//!
//! The builder refuses unknown or missing fields, a repeated master, and an
//! `uncapped` flag (optional on input) that disagrees with the amount.

use chain_block::{
    error, fail, Coins, Result, SettlementAsset, SettlementAssetOrigin, SettlementAssetOriginKind,
    SettlementAssetStatus, SettlementAssets, UInt256, NO_LIABILITY_CAP,
};
use serde_json::{json, Map, Value};

#[cfg(test)]
#[path = "tests/test_settlement_assets.rs"]
mod tests;

fn hex32(value: &UInt256) -> String {
    hex::encode(value.as_slice())
}

/// The decoded value as JSON, entries in ascending master order.
pub fn settlement_assets_to_json(value: &SettlementAssets) -> Value {
    let assets: Vec<Value> = value
        .assets
        .iter()
        .map(|(master, asset)| {
            json!({
                "master": hex32(master),
                "status": asset.status.name(),
                "decimals": asset.decimals,
                "minter_code_hash": hex32(&asset.minter_code_hash),
                "wallet_code_hash": hex32(&asset.wallet_code_hash),
                "max_liability_per_actor": asset.max_liability_per_actor.inner().to_string(),
                "uncapped": asset.is_uncapped(),
                "origin": {
                    "kind": asset.origin.kind.name(),
                    "bridge_address": hex32(&asset.origin.bridge_address),
                    "source_chain_id": asset.origin.source_chain_id,
                    "source_token": hex::encode(asset.origin.source_token),
                },
            })
        })
        .collect();
    json!({ "assets": assets })
}

/// A JSON value parsed so that a repeated object key is an error instead of the
/// last occurrence silently winning.
struct Strict(Value);

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_u64<E>(self, v: u64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_f64<E>(self, v: f64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_str<E>(self, v: &str) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }
    fn visit_unit<E>(self) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Strict(Value::Array(items)))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut access: A,
    ) -> std::result::Result<Strict, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(serde::de::Error::custom(format!("duplicate field {key:?}")));
            }
            let Strict(value) = access.next_value()?;
            map.insert(key, value);
        }
        Ok(Strict(Value::Object(map)))
    }
}

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

/// Parses JSON text, refusing a repeated key anywhere in it.
pub fn parse_json_strict(text: &str) -> Result<Value> {
    let Strict(value) = serde_json::from_str(text).map_err(|err| error!("JSON: {err}"))?;
    Ok(value)
}

/// Parses a builder spec, refusing a repeated key anywhere in it.
pub fn parse_settlement_assets_spec(text: &str) -> Result<Value> {
    parse_json_strict(text).map_err(|err| error!("ConfigParam 84 spec: {err}"))
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| error!("{what} must be a JSON object"))
}

fn exact_keys(
    map: &Map<String, Value>,
    what: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<()> {
    for key in map.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            fail!("{what}: unknown field {key:?}")
        }
    }
    for key in required {
        if !map.contains_key(*key) {
            fail!("{what}: missing field {key:?}")
        }
    }
    Ok(())
}

fn field<'a>(map: &'a Map<String, Value>, what: &str, key: &str) -> Result<&'a Value> {
    map.get(key).ok_or_else(|| error!("{what}: missing field {key:?}"))
}

fn string<'a>(map: &'a Map<String, Value>, what: &str, key: &str) -> Result<&'a str> {
    field(map, what, key)?.as_str().ok_or_else(|| error!("{what}: {key} must be a string"))
}

fn fixed_hex<const N: usize>(map: &Map<String, Value>, what: &str, key: &str) -> Result<[u8; N]> {
    let text = string(map, what, key)?;
    if text.len() != 2 * N
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        fail!("{what}: {key} must be {} lowercase hex digits", 2 * N)
    }
    let bytes = hex::decode(text).map_err(|err| error!("{what}: {key}: {err}"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn unsigned(map: &Map<String, Value>, what: &str, key: &str, max: u64) -> Result<u64> {
    let value = field(map, what, key)?
        .as_u64()
        .ok_or_else(|| error!("{what}: {key} must be a non-negative integer"))?;
    if value > max {
        fail!("{what}: {key} {value} exceeds {max}")
    }
    Ok(value)
}

fn liability(map: &Map<String, Value>, what: &str) -> Result<Coins> {
    let text = string(map, what, "max_liability_per_actor")?;
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        fail!("{what}: max_liability_per_actor must be a canonical decimal string")
    }
    let amount: u128 =
        text.parse().map_err(|_| error!("{what}: max_liability_per_actor exceeds 2^120 - 1"))?;
    let coins = Coins::try_from(amount)
        .map_err(|_| error!("{what}: max_liability_per_actor exceeds 2^120 - 1"))?;
    if coins.is_zero() {
        fail!("{what}: max_liability_per_actor must be non-zero (no cap is 2^120 - 1)")
    }
    if let Some(flag) = map.get("uncapped") {
        let flag = flag.as_bool().ok_or_else(|| error!("{what}: uncapped must be a boolean"))?;
        if flag != (coins == NO_LIABILITY_CAP) {
            fail!("{what}: uncapped is {flag} but max_liability_per_actor says otherwise")
        }
    }
    Ok(coins)
}

fn origin(value: &Value, what: &str) -> Result<SettlementAssetOrigin> {
    let what = format!("{what}.origin");
    let map = object(value, &what)?;
    exact_keys(map, &what, &["kind", "bridge_address", "source_chain_id", "source_token"], &[])?;
    Ok(SettlementAssetOrigin {
        kind: SettlementAssetOriginKind::from_name(string(map, &what, "kind")?)?,
        bridge_address: UInt256::from(fixed_hex::<32>(map, &what, "bridge_address")?),
        source_chain_id: unsigned(map, &what, "source_chain_id", u32::MAX as u64)? as u32,
        source_token: fixed_hex::<20>(map, &what, "source_token")?,
    })
}

/// Builds a ConfigParam 84 value from its JSON form, refusing anything the
/// decoder would not reproduce.
pub fn settlement_assets_from_json(value: &Value) -> Result<SettlementAssets> {
    let top = object(value, "ConfigParam 84")?;
    exact_keys(top, "ConfigParam 84", &["assets"], &[])?;
    let list =
        top["assets"].as_array().ok_or_else(|| error!("ConfigParam 84: assets must be a list"))?;
    let mut assets = SettlementAssets::new();
    for (index, entry) in list.iter().enumerate() {
        let what = format!("ConfigParam 84 assets[{index}]");
        let map = object(entry, &what)?;
        exact_keys(
            map,
            &what,
            &[
                "master",
                "status",
                "decimals",
                "minter_code_hash",
                "wallet_code_hash",
                "max_liability_per_actor",
                "origin",
            ],
            &["uncapped"],
        )?;
        let master = UInt256::from(fixed_hex::<32>(map, &what, "master")?);
        let asset = SettlementAsset {
            status: SettlementAssetStatus::from_name(string(map, &what, "status")?)?,
            decimals: unsigned(map, &what, "decimals", u8::MAX as u64)? as u8,
            minter_code_hash: UInt256::from(fixed_hex::<32>(map, &what, "minter_code_hash")?),
            wallet_code_hash: UInt256::from(fixed_hex::<32>(map, &what, "wallet_code_hash")?),
            max_liability_per_actor: liability(map, &what)?,
            origin: origin(field(map, &what, "origin")?, &what)?,
        };
        assets.insert(master, asset).map_err(|err| error!("{what}: {err}"))?;
    }
    Ok(assets)
}
