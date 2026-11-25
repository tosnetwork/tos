/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! ConfigParam 84 records checked against a minter the bridge really created.
//!
//! The reader re-derives the master's address from the record and the master's
//! account state (contracts::settlement_assets). Here the master is the minter
//! this bridge deployed during a real mint, so the derivation is held to the
//! bridge's own `calculate_minter_address`, and every field a vote could get
//! wrong is shown to be refused.

use chain_block::{
    Cell, ConfigParamEnum, Deserializable, SettlementAsset, SettlementAssetOrigin,
    SettlementAssetOriginKind, SettlementAssetStatus, SettlementAssets, TokenBridgeParams, UInt256,
    read_pinned_settlement_assets,
};
use contracts::settlement_assets::{MasterEvidence, bridge_config_param, verify_settlement_asset};

use crate::harness::*;

struct Recognized {
    master: UInt256,
    asset: SettlementAsset,
    code: Cell,
    data: Cell,
    bridge_params: TokenBridgeParams,
    bridge_data: Cell,
}

/// A deployed minter, its record as a vote would write it, and the evidence a
/// reader fetches for it.
fn recognized() -> Recognized {
    let mut net = Net::new();
    net.swap(1_000);
    let minter = net.minter();
    let account = net.bc.get_account(&minter).expect("the mint deployed the minter");
    let code = account.get_code().expect("the minter has code");
    let data = account.get_data().expect("the minter has data");
    let bridge_data = net
        .bc
        .get_account(&net.bridge)
        .expect("the bridge is deployed")
        .get_data()
        .expect("the bridge has data");
    let param = match net.bc.config_params().config(CONFIG_PARAM).expect("lookup") {
        Some(ConfigParamEnum::ConfigParam79(params)) => params,
        Some(ConfigParamEnum::ConfigParamAny(_, cell)) => {
            TokenBridgeParams::construct_from_cell(cell).expect("bridge parameters")
        }
        other => panic!("ConfigParam {CONFIG_PARAM} is {other:?}"),
    };
    let asset = SettlementAsset {
        status: SettlementAssetStatus::Active,
        decimals: 18,
        minter_code_hash: codes().minter.repr_hash(),
        wallet_code_hash: codes().wallet.repr_hash(),
        max_liability_per_actor: chain_block::NO_LIABILITY_CAP,
        origin: SettlementAssetOrigin {
            kind: SettlementAssetOriginKind::TokenBridge,
            bridge_address: UInt256::from_slice(&account_hash(&net.bridge)),
            source_chain_id: CHAIN_ID,
            source_token: [0x5a; 20],
        },
    };
    Recognized {
        master: UInt256::from_slice(&account_hash(&minter)),
        asset,
        code,
        data,
        bridge_params: param,
        bridge_data,
    }
}

fn verify(r: &Recognized) -> anyhow::Result<()> {
    verify_settlement_asset(
        &r.master,
        &r.asset,
        &MasterEvidence {
            code: &r.code,
            data: &r.data,
            bridge_params: &r.bridge_params,
            bridge_data: &r.bridge_data,
        },
    )
}

#[test]
fn a_minter_the_bridge_created_verifies_from_its_record() {
    let r = recognized();
    assert_eq!(bridge_config_param(CHAIN_ID), Some(CONFIG_PARAM));
    verify(&r).expect("the record of a bridge-created minter verifies");
    // The same record through the value a vote installs and a client's pinned read.
    let mut assets = SettlementAssets::new();
    assets.insert(r.master.clone(), r.asset.clone()).expect("one entry");
    let pinned =
        read_pinned_settlement_assets(assets.to_cell().expect("value"), &[r.master.clone()])
            .expect("the pinned read");
    let listed = pinned[0].asset.as_ref().expect("listed");
    verify_settlement_asset(
        &r.master,
        listed,
        &MasterEvidence {
            code: &r.code,
            data: &r.data,
            bridge_params: &r.bridge_params,
            bridge_data: &r.bridge_data,
        },
    )
    .expect("the read-back record verifies");
}

#[test]
fn every_wrong_field_of_a_record_is_refused() {
    let refused = |name: &str, change: &dyn Fn(&mut Recognized)| {
        let mut r = recognized();
        change(&mut r);
        assert!(verify(&r).is_err(), "{name} verified");
    };
    refused("another master", &|r| r.master = UInt256::from([0x77; 32]));
    refused("other decimals", &|r| r.asset.decimals = 6);
    refused("another token", &|r| r.asset.origin.source_token = [0x5b; 20]);
    refused("another source chain", &|r| r.asset.origin.source_chain_id = 56);
    refused("a chain without a bridge", &|r| r.asset.origin.source_chain_id = 5);
    refused("another bridge", &|r| r.asset.origin.bridge_address = UInt256::from([0x66; 32]));
    refused("another wallet code", &|r| r.asset.wallet_code_hash = codes().bridge.repr_hash());
    refused("another minter code", &|r| r.asset.minter_code_hash = codes().wallet.repr_hash());
    refused("native issuance", &|r| {
        r.asset.origin.kind = SettlementAssetOriginKind::NativeIssuance
    });
    refused("code that is not the minter's", &|r| r.code = codes().wallet.clone());
    refused("a minter with foreign code recorded as such", &|r| {
        r.code = codes().wallet.clone();
        r.asset.minter_code_hash = codes().wallet.repr_hash();
    });
    refused("bridge storage that does not parse", &|r| r.bridge_data = Cell::default());
    refused("another account's storage as the bridge's", &|r| r.bridge_data = r.data.clone());
    refused("data that is not a minter's", &|r| {
        r.data = cell(|b| {
            b.checked_append_reference(Cell::default()).unwrap();
        })
    });
    refused("a bridge parameter naming another bridge", &|r| {
        r.bridge_params.bridge_address = UInt256::from([0x66; 32]).into()
    });
}
