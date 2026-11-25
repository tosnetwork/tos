/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The ConfigParam 84 vector shared with the node's typed JSON-RPC view.
//!
//! `test/fixtures/configparam-84-v1.json` holds one valid value built by the
//! proposal value builder, its decoded form in both the `tosctl` and the
//! JSON-RPC shape, and one value per malformation the decoders refuse. The C++
//! test `JsonRpcExplorer.settlement_assets_vector` reads the same file, so the
//! builder and both decoders are held to the same bytes.
//!
//! Regenerate with `TOS_WRITE_CONFIGPARAM84_FIXTURE=1`; otherwise the file must
//! equal what this test builds.

use super::*;
use crate::{serialize_config, serialize_known_config_param, SerializationMode};
use chain_block::{
    base64_encode, read_pinned_settlement_assets, read_single_root_boc, write_boc, BuilderData,
    Cell, CellType, ConfigParamEnum, Deserializable, HashmapE, HashmapType, IBitstring, SliceData,
    UInt256,
};
use chain_block::{
    check_config_param_budget, validation_cell_visits, CONFIG_PARAM_VALIDATION_CELLS,
    SETTLEMENT_ASSETS_MAX_ENTRIES,
};
use serde_json::{json, Value};

const MASTER_A: [u8; 32] = [0xa1; 32];
const MASTER_B: [u8; 32] = [0xb2; 32];

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../test/fixtures/configparam-84-v1.json")
}

fn spec() -> Value {
    json!({"assets": [
        {
            "master": hex::encode(MASTER_A),
            "status": "active",
            "decimals": 6,
            "minter_code_hash": "11".repeat(32),
            "wallet_code_hash": "22".repeat(32),
            "max_liability_per_actor": "1000000000",
            "origin": {
                "kind": "token_bridge",
                "bridge_address": "33".repeat(32),
                "source_chain_id": 1,
                "source_token": "44".repeat(20)
            }
        },
        {
            "master": hex::encode(MASTER_B),
            "status": "retired",
            "decimals": 18,
            "minter_code_hash": "55".repeat(32),
            "wallet_code_hash": "66".repeat(32),
            "max_liability_per_actor": NO_LIABILITY_CAP.inner().to_string(),
            "uncapped": true,
            "origin": {
                "kind": "native_issuance",
                "bridge_address": "00".repeat(32),
                "source_chain_id": 0,
                "source_token": "00".repeat(20)
            }
        }
    ]})
}

/// The `decoded.value` the node's `getConfigParam` view prints for `value`,
/// written out independently of the C++ code that prints it.
fn json_rpc_view(value: &SettlementAssets) -> String {
    let assets: Vec<Value> = value
        .assets
        .iter()
        .map(|(master, asset)| {
            json!({
                "master": format!("0:{}", hex::encode(master.as_slice())),
                "status": asset.status.name(),
                "decimals": asset.decimals,
                "minter_code_hash": base64_encode(asset.minter_code_hash.as_slice()),
                "wallet_code_hash": base64_encode(asset.wallet_code_hash.as_slice()),
                "max_liability_per_actor": asset.max_liability_per_actor.inner().to_string(),
                "uncapped": asset.is_uncapped(),
                "origin": {
                    "kind": asset.origin.kind.name(),
                    "bridge_address": format!("-1:{}", hex::encode(asset.origin.bridge_address.as_slice())),
                    "source_chain_id": asset.origin.source_chain_id,
                    "source_token": hex::encode(asset.origin.source_token),
                },
            })
        })
        .collect();
    json!({"kind": "settlement_assets_v1", "assets": assets}).to_string()
}

fn cell(fill: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    fill(&mut b);
    b.into_cell().unwrap()
}

fn origin_cell(kind: u8, extra_bits: i32, extra_ref: bool) -> Cell {
    cell(|b| {
        b.append_u8(kind).unwrap();
        b.append_raw(&[0x33; 32], 256).unwrap();
        b.append_u32(1).unwrap();
        if extra_bits < 0 {
            b.append_raw(&[0x44; 20], 159).unwrap();
        } else {
            b.append_raw(&[0x44; 20], 160).unwrap();
            b.append_bits(0, extra_bits as usize).unwrap();
        }
        if extra_ref {
            b.checked_append_reference(Cell::default()).unwrap();
        }
    })
}

#[derive(Clone)]
struct Record {
    tag: u8,
    status: u8,
    /// Raw Coins: the 4-bit length, then the bytes.
    coins: (usize, Vec<u8>),
    origin: Option<Cell>,
    extra_bits: usize,
    extra_ref: bool,
}

impl Record {
    fn good() -> Self {
        Self {
            tag: 0x01,
            status: 1,
            coins: (4, 1_000_000_000u32.to_be_bytes().to_vec()),
            origin: Some(origin_cell(1, 0, false)),
            extra_bits: 0,
            extra_ref: false,
        }
    }

    fn leaf(&self) -> BuilderData {
        let mut b = BuilderData::new();
        b.append_u8(self.tag).unwrap();
        b.append_u8(self.status).unwrap();
        b.append_u8(6).unwrap();
        b.append_raw(&[0x11; 32], 256).unwrap();
        b.append_raw(&[0x22; 32], 256).unwrap();
        b.append_bits(self.coins.0, 4).unwrap();
        b.append_raw(&self.coins.1, self.coins.1.len() * 8).unwrap();
        b.append_bits(0, self.extra_bits).unwrap();
        if let Some(origin) = &self.origin {
            b.checked_append_reference(origin.clone()).unwrap();
        }
        if self.extra_ref {
            b.checked_append_reference(Cell::default()).unwrap();
        }
        b
    }
}

/// A value holding `record` under MASTER_A.
fn value_with(record: &Record, tag: u8, extra_bit: bool, extra_ref: bool) -> Cell {
    let mut dict = HashmapE::with_bit_len(256);
    dict.set_builder(SliceData::from_raw(MASTER_A.to_vec(), 256), &record.leaf()).unwrap();
    cell(|b| {
        b.append_u8(tag).unwrap();
        dict.write_hashmap_data(b).unwrap();
        if extra_bit {
            b.append_bit_zero().unwrap();
        }
        if extra_ref {
            b.checked_append_reference(Cell::default()).unwrap();
        }
    })
}

fn malformed() -> Vec<(&'static str, Cell)> {
    let good = Record::good();
    let with = |change: &dyn Fn(&mut Record)| {
        let mut r = good.clone();
        change(&mut r);
        value_with(&r, 0x01, false, false)
    };
    vec![
        ("value_tag", value_with(&good, 0x02, false, false)),
        ("value_trailing_bit", value_with(&good, 0x01, true, false)),
        ("value_trailing_ref", value_with(&good, 0x01, false, true)),
        ("record_tag", with(&|r| r.tag = 0x02)),
        ("status_zero", with(&|r| r.status = 0)),
        ("status_four", with(&|r| r.status = 4)),
        ("cap_zero", with(&|r| r.coins = (0, vec![]))),
        ("cap_nonminimal", with(&|r| r.coins = (2, vec![0x00, 0x05]))),
        ("record_trailing_bit", with(&|r| r.extra_bits = 1)),
        ("record_extra_ref", with(&|r| r.extra_ref = true)),
        ("record_no_origin", with(&|r| r.origin = None)),
        ("origin_short", with(&|r| r.origin = Some(origin_cell(1, -1, false)))),
        ("origin_long", with(&|r| r.origin = Some(origin_cell(1, 1, false)))),
        ("origin_ref", with(&|r| r.origin = Some(origin_cell(1, 0, true)))),
        ("origin_kind_zero", with(&|r| r.origin = Some(origin_cell(0, 0, false)))),
        ("origin_kind_three", with(&|r| r.origin = Some(origin_cell(3, 0, false)))),
    ]
}

fn built() -> (SettlementAssets, Cell) {
    let assets = settlement_assets_from_json(&spec()).unwrap();
    let cell = assets.to_cell().unwrap();
    (assets, cell)
}

fn fixture() -> Value {
    let (assets, value) = built();
    let cases: Vec<Value> = malformed()
        .into_iter()
        .map(|(name, cell)| json!({"name": name, "boc": base64_encode(write_boc(&cell).unwrap())}))
        .collect();
    json!({
        "schema": "configparam-84-vector-v1",
        "param": 84,
        "spec": spec(),
        "boc": base64_encode(write_boc(&value).unwrap()),
        "tosctl": settlement_assets_to_json(&assets),
        "json_rpc_value": json_rpc_view(&assets),
        "malformed": cases,
    })
}

#[test]
fn the_shared_vector_is_what_the_builder_and_decoders_produce() {
    let expected = serde_json::to_string_pretty(&fixture()).unwrap() + "\n";
    let path = fixture_path();
    if std::env::var_os("TOS_WRITE_CONFIGPARAM84_FIXTURE").is_some() {
        std::fs::write(&path, &expected).unwrap();
    }
    let stored = std::fs::read_to_string(&path).unwrap();
    assert_eq!(stored, expected, "regenerate with TOS_WRITE_CONFIGPARAM84_FIXTURE=1");
}

#[test]
fn the_builder_round_trips_through_the_decoder() {
    let (assets, value) = built();
    let decoded = SettlementAssets::construct_from_cell(value.clone()).unwrap();
    assert_eq!(decoded, assets);
    assert_eq!(settlement_assets_from_json(&settlement_assets_to_json(&decoded)).unwrap(), assets);
    // Through the configuration-parameter path tosctl decodes with.
    let json = serialize_known_config_param(84, value.clone(), SerializationMode::Standart)
        .unwrap()
        .unwrap();
    assert_eq!(json, settlement_assets_to_json(&assets));
    let ConfigParamEnum::ConfigParam84(param) =
        ConfigParamEnum::construct_from_cell_and_number(value.clone(), 84).unwrap()
    else {
        panic!("ConfigParam 84 decodes as its own type")
    };
    let mut builder = BuilderData::new();
    ConfigParamEnum::ConfigParam84(param).write_to_cell(&mut builder).unwrap();
    assert_eq!(builder.into_cell().unwrap().reference(0).unwrap(), value);
    let entry = decoded.get(&UInt256::from(MASTER_B)).unwrap();
    assert!(entry.is_uncapped());
    assert_eq!(entry.max_liability_per_actor, NO_LIABILITY_CAP);
    assert!(!decoded.get(&UInt256::from(MASTER_A)).unwrap().is_uncapped());
}

#[test]
fn an_empty_list_is_a_valid_value() {
    let empty = settlement_assets_from_json(&json!({"assets": []})).unwrap();
    let cell = empty.to_cell().unwrap();
    assert_eq!(cell.bit_length(), 9);
    assert_eq!(SettlementAssets::construct_from_cell(cell).unwrap(), empty);
}

#[test]
fn every_malformed_value_is_refused_by_the_decoder() {
    for (name, cell) in malformed() {
        assert!(
            SettlementAssets::construct_from_cell(cell.clone()).is_err(),
            "{name} was accepted"
        );
        assert!(
            ConfigParamEnum::construct_from_cell_and_number(cell.clone(), 84).is_err(),
            "{name} was accepted as ConfigParam 84"
        );
        assert!(
            serialize_known_config_param(84, cell, SerializationMode::Standart).is_err(),
            "{name} was decoded for display"
        );
    }
    // The valid record these cases mutate is itself accepted.
    let good = value_with(&Record::good(), 0x01, false, false);
    assert!(SettlementAssets::construct_from_cell(good).is_ok());
}

#[test]
fn an_exotic_value_is_refused() {
    let mut library = BuilderData::new();
    library.set_type(CellType::LibraryReference);
    library.append_u8(2).unwrap();
    library.append_raw(&[0u8; 32], 256).unwrap();
    let library = library.into_cell().unwrap();
    assert!(SettlementAssets::construct_from_cell(library).is_err());
}

#[test]
fn a_whole_configuration_with_a_malformed_value_still_serializes() {
    // The schema admits a zero cap, so a configuration can hold one; showing it
    // raw must not fail the rest of the configuration.
    let (_, bad) = malformed().into_iter().find(|(name, _)| *name == "cap_zero").unwrap();
    let mut params = chain_block::ConfigParams::default();
    params.set_config(ConfigParamEnum::ConfigParamAny(84, bad)).unwrap();
    let mut map = serde_json::Map::new();
    serialize_config(&mut map, &params, SerializationMode::Standart).unwrap();
    assert!(map["config"].get("p84").is_none());
    assert_eq!(map["unknown_config"][0]["number"], 84);
}

#[test]
fn the_builder_refuses_what_the_decoder_would_not_reproduce() {
    let mutate = |path: &[&str], value: Value| {
        let mut spec = spec();
        let mut node = &mut spec["assets"][0];
        for key in &path[..path.len() - 1] {
            node = &mut node[*key];
        }
        node[path[path.len() - 1]] = value;
        spec
    };
    let refused = [
        ("zero cap", mutate(&["max_liability_per_actor"], json!("0"))),
        (
            "cap above 2^120 - 1",
            mutate(&["max_liability_per_actor"], json!("1329227995784915872903807060280344576")),
        ),
        ("cap with a leading zero", mutate(&["max_liability_per_actor"], json!("01"))),
        ("cap as a number", mutate(&["max_liability_per_actor"], json!(5))),
        ("uncapped flag that disagrees", mutate(&["uncapped"], json!(true))),
        ("unknown status", mutate(&["status"], json!("paused"))),
        ("decimals above 255", mutate(&["decimals"], json!(256))),
        ("short master", mutate(&["master"], json!("ab"))),
        ("uppercase hash", mutate(&["minter_code_hash"], json!("AB".repeat(32)))),
        ("unknown origin kind", mutate(&["origin", "kind"], json!("custodial"))),
        ("chain id above uint32", mutate(&["origin", "source_chain_id"], json!(4294967296u64))),
        ("short source token", mutate(&["origin", "source_token"], json!("44".repeat(19)))),
        ("unknown field", mutate(&["ticker"], json!("USDC"))),
        ("unknown origin field", mutate(&["origin", "ticker"], json!("USDC"))),
    ];
    for (name, spec) in refused {
        assert!(settlement_assets_from_json(&spec).is_err(), "{name} was built");
    }
    let mut missing = spec();
    missing["assets"][0].as_object_mut().unwrap().remove("decimals");
    assert!(settlement_assets_from_json(&missing).is_err(), "a missing field was built");
    let mut twice = spec();
    let first = twice["assets"][0].clone();
    twice["assets"].as_array_mut().unwrap().push(first);
    assert!(settlement_assets_from_json(&twice).is_err(), "a repeated master was built");
    assert!(settlement_assets_from_json(&json!({"assets": [], "extra": 1})).is_err());
    assert!(settlement_assets_from_json(&json!({})).is_err());
}

#[test]
fn a_client_reads_only_the_entries_it_pins() {
    // One good entry and one malformed entry under another master.
    let mut dict = HashmapE::with_bit_len(256);
    dict.set_builder(SliceData::from_raw(MASTER_A.to_vec(), 256), &Record::good().leaf()).unwrap();
    let mut bad = Record::good();
    bad.status = 9;
    dict.set_builder(SliceData::from_raw(MASTER_B.to_vec(), 256), &bad.leaf()).unwrap();
    let value = cell(|b| {
        b.append_u8(0x01).unwrap();
        dict.write_hashmap_data(b).unwrap();
    });
    // The whole-value decoder refuses it ...
    assert!(SettlementAssets::construct_from_cell(value.clone()).is_err());
    // ... a client pinning only MASTER_A ignores the other entry ...
    let a = UInt256::from(MASTER_A);
    let read = read_pinned_settlement_assets(value.clone(), &[a.clone()]).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].asset.as_ref().unwrap().decimals, 6);
    // ... a pinned master that is not listed is absent, not an error ...
    let c = UInt256::from([0xc3; 32]);
    let read = read_pinned_settlement_assets(value.clone(), &[c.clone(), a.clone()]).unwrap();
    assert!(read[0].asset.is_none() && read[1].asset.is_some());
    // ... and pinning the malformed entry refuses it.
    assert!(read_pinned_settlement_assets(value.clone(), &[UInt256::from(MASTER_B)]).is_err());
    assert!(
        read_pinned_settlement_assets(value.clone(), &[a.clone(), a]).is_err(),
        "a repeated pin"
    );
    // The value's own tag and trailing data are still checked.
    for name in ["value_tag", "value_trailing_bit", "value_trailing_ref"] {
        let (_, bad) = malformed().into_iter().find(|(n, _)| *n == name).unwrap();
        assert!(read_pinned_settlement_assets(bad, &[c.clone()]).is_err(), "{name}");
    }
}

#[test]
fn the_fixture_bocs_decode_from_bytes() {
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap();
    let bytes = chain_block::base64_decode(stored["boc"].as_str().unwrap()).unwrap();
    let value = read_single_root_boc(bytes).unwrap();
    let decoded = SettlementAssets::construct_from_cell(value).unwrap();
    assert_eq!(settlement_assets_to_json(&decoded), stored["tosctl"]);
    for case in stored["malformed"].as_array().unwrap() {
        let bytes = chain_block::base64_decode(case["boc"].as_str().unwrap()).unwrap();
        let cell = read_single_root_boc(bytes).unwrap();
        assert!(SettlementAssets::construct_from_cell(cell).is_err(), "{}", case["name"]);
    }
}

/// A value of `entries` well-formed records under distinct keys, built as the
/// node sees it rather than through the builder.
fn value_of(entries: usize) -> Cell {
    let mut dict = HashmapE::with_bit_len(256);
    for i in 0..entries {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&(i as u32).to_be_bytes());
        dict.set_builder(SliceData::from_raw(key.to_vec(), 256), &Record::good().leaf()).unwrap();
    }
    cell(|b| {
        b.append_u8(0x01).unwrap();
        dict.write_hashmap_data(b).unwrap();
    })
}

#[test]
fn the_entry_cap_admits_sixteen_and_refuses_seventeen() {
    assert_eq!(SETTLEMENT_ASSETS_MAX_ENTRIES, 16);
    let at_cap = SettlementAssets::construct_from_cell(value_of(16)).unwrap();
    assert_eq!(at_cap.assets.len(), 16);
    let over = SettlementAssets::construct_from_cell(value_of(17)).unwrap_err().to_string();
    assert!(over.contains("more than 16"), "{over}");
    // The builder stops at the cap as well.
    let mut built = at_cap.clone();
    let extra = built.assets.values().next().unwrap().clone();
    let refused = built.insert(UInt256::from([0xee; 32]), extra).unwrap_err().to_string();
    assert!(refused.contains("at most 16"), "{refused}");
    let mut spec = json!({"assets": []});
    let entry = spec_entry();
    for i in 0..17u8 {
        let mut e = entry.clone();
        e["master"] = json!(hex::encode([i; 32]));
        spec["assets"].as_array_mut().unwrap().push(e);
    }
    assert!(settlement_assets_from_json(&spec).is_err());
    // A client reading its pin does not count the other entries.
    let mut pin = [0u8; 32];
    pin[31] = 3;
    let read = read_pinned_settlement_assets(value_of(17), &[UInt256::from(pin)]).unwrap();
    assert!(read[0].asset.is_some());
}

fn spec_entry() -> Value {
    spec()["assets"][0].clone()
}

#[test]
fn the_validation_budget_is_the_nodes() {
    // The node's boundary: 341 entries take 1023 cells, 342 take 1026
    // (JsonRpcExplorer.settlement_assets_entry_cap_and_node_budget checks the
    // same values against validate_ref).
    assert_eq!(CONFIG_PARAM_VALIDATION_CELLS, 1024);
    assert_eq!(validation_cell_visits(&value_of(341), 1024), Some(1023));
    assert_eq!(validation_cell_visits(&value_of(342), 1024), None);
    assert_eq!(validation_cell_visits(&value_of(16), 1024), Some(48));
    assert!(check_config_param_budget(84, &value_of(341)).is_ok());
    assert!(check_config_param_budget(84, &value_of(342)).is_err());
    // A value the node could not install is refused even by the pinned reader.
    assert!(read_pinned_settlement_assets(value_of(342), &[UInt256::from([0u8; 32])]).is_err());
}

#[test]
fn an_exotic_interior_cell_is_refused() {
    let mut library = BuilderData::new();
    library.set_type(CellType::LibraryReference);
    library.append_u8(2).unwrap();
    library.append_raw(&[0u8; 32], 256).unwrap();
    let library = library.into_cell().unwrap();
    let value = cell(|b| {
        b.append_u8(0x01).unwrap();
        b.append_bit_one().unwrap();
        b.checked_append_reference(library.clone()).unwrap();
    });
    let refused = SettlementAssets::construct_from_cell(value.clone()).unwrap_err().to_string();
    assert!(refused.contains("not ordinary"), "{refused}");
    let pinned = read_pinned_settlement_assets(value, &[UInt256::from([0u8; 32])]).unwrap_err();
    assert!(pinned.to_string().contains("not ordinary"), "{pinned}");
}

#[test]
fn a_spec_with_a_repeated_field_is_refused() {
    let good = serde_json::to_string(&spec()).unwrap();
    assert!(parse_settlement_assets_spec(&good).is_ok());
    let twice = good.replacen("\"decimals\":6", "\"decimals\":6,\"decimals\":18", 1);
    assert_ne!(twice, good);
    let err = parse_settlement_assets_spec(&twice).unwrap_err().to_string();
    assert!(err.contains("duplicate field"), "{err}");
    let nested =
        good.replacen("\"source_chain_id\":1", "\"source_chain_id\":1,\"source_chain_id\":56", 1);
    assert_ne!(nested, good);
    assert!(parse_settlement_assets_spec(&nested).is_err());
    assert!(parse_settlement_assets_spec("{\"assets\":[],\"assets\":[]}").is_err());
}
