// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
use chain_block::{read_single_root_boc, write_boc, BuilderData};
use serde_json::Value;
use shielded_pool_mobile::{
    pool::{decode_pool_state, MAX_BOC_CELLS, MAX_BOC_DEPTH},
    Error, MAX_REQUEST_BYTES,
};

const GENESIS: &[u8] =
    include_bytes!("../../../artifacts/shielded-pool/deployments/epoch4-v16/data.boc");

#[test]
fn frozen_state_decodes_with_hash_and_lossless_amounts() {
    let state = decode_pool_state(GENESIS).unwrap();
    let state: Value = serde_json::from_slice(&state).unwrap();
    assert_eq!(
        state["data_hash"],
        "50ba96d38f3e0e474737a1946973f7ba528775a246bbe9b8d02a97a0425d6b4f"
    );
    assert_eq!(state["withdrawal_fee"], "20000000");
    assert_eq!(state["last_anchor_epoch"], "4294967295");
    assert_eq!(state["native_liability"], "0");
    assert_eq!(state["nullifier_next_index"], "1");
    assert_eq!(state["denominations"][3], "1000000000000");
    assert!(state.get("verified").is_none());
}

#[test]
fn malformed_and_unbounded_bocs_are_not_state_observations() {
    assert_eq!(decode_pool_state(&[]), Err(Error::InvalidInput));
    assert_eq!(decode_pool_state(&vec![0; MAX_REQUEST_BYTES + 1]), Err(Error::Limit));
    let empty = write_boc(&BuilderData::new().into_cell().unwrap()).unwrap();
    assert_eq!(decode_pool_state(&empty), Err(Error::InvalidInput));
    for size in [1, 6, GENESIS.len() - 1] {
        assert_eq!(decode_pool_state(&GENESIS[..size]), Err(Error::InvalidInput));
    }
    let mut trailing = GENESIS.to_vec();
    trailing.push(0);
    assert_eq!(decode_pool_state(&trailing), Err(Error::InvalidInput));
    let mut huge = vec![0xb5, 0xee, 0x9c, 0x72, 4, 1];
    huge.extend_from_slice(&((MAX_BOC_CELLS + 1) as u32).to_be_bytes());
    huge.extend_from_slice(&1u32.to_be_bytes());
    huge.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(decode_pool_state(&huge), Err(Error::Limit));
}

#[test]
fn deep_frontier_is_rejected_before_layout_decode() {
    let root = read_single_root_boc(GENESIS).unwrap();
    let mut frontier = BuilderData::new().into_cell().unwrap();
    for _ in 0..=MAX_BOC_DEPTH {
        let mut node = BuilderData::new();
        node.checked_append_reference(frontier).unwrap();
        frontier = node.into_cell().unwrap();
    }
    let mut changed = BuilderData::from_cell(&root).unwrap();
    changed.replace_reference_cell(0, frontier);
    let boc = write_boc(&changed.into_cell().unwrap()).unwrap();
    // The existing pool layout parser intentionally ignores the frontier:
    // only this adapter's depth guard should reject this otherwise parseable state.
    assert!(shielded_pool_codec::PoolState::parse(&read_single_root_boc(&boc).unwrap()).is_ok());
    assert_eq!(decode_pool_state(&boc), Err(Error::InvalidInput));
}

#[test]
fn cell_limit_rejects_a_valid_shallow_boc() {
    use chain_block::IBitstring;
    for (leaves, rejected) in [(16384usize, false), (32768usize, true)] {
        let mut level = Vec::with_capacity(leaves);
        for index in 0..leaves {
            let mut leaf = BuilderData::new();
            leaf.append_u64(index as u64).unwrap();
            level.push(leaf.into_cell().unwrap());
        }
        while level.len() > 1 {
            level = level
                .chunks(4)
                .map(|children| {
                    let mut node = BuilderData::new();
                    for child in children {
                        node.checked_append_reference(child.clone()).unwrap();
                    }
                    node.into_cell().unwrap()
                })
                .collect();
        }
        let mut state = BuilderData::from_cell(&read_single_root_boc(GENESIS).unwrap()).unwrap();
        state.replace_reference_cell(0, level.pop().unwrap());
        let boc = write_boc(&state.into_cell().unwrap()).unwrap();
        assert!(boc.len() < MAX_REQUEST_BYTES);
        // Both are valid, shallow single-root state BOCs; the cell count is
        // the only reason the larger one must not be decoded by the adapter.
        assert!(shielded_pool_codec::PoolState::parse(&read_single_root_boc(&boc).unwrap()).is_ok());
        if rejected {
            assert_eq!(decode_pool_state(&boc), Err(Error::Limit));
        } else {
            assert!(decode_pool_state(&boc).is_ok());
        }
    }
}
