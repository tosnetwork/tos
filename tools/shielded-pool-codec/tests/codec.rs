// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use chain_block::{read_single_root_boc, SliceData};
use shielded_pool_codec::{DepositBody, PoolState, MAX_COINS, OP_DEPOSIT, OUTPUT_DATA_BYTES};

#[test]
fn frozen_deployment_state_keeps_its_existing_layout() {
    let bytes = include_bytes!("../../../artifacts/shielded-pool/deployments/epoch4-v16/data.boc");
    let state = PoolState::parse(&read_single_root_boc(bytes).unwrap()).unwrap();
    assert_eq!(state.commitment_next_index, 0);
    assert_eq!(state.nullifier_next_index, 1);
    assert_eq!(state.last_anchor_epoch, u32::MAX);
    assert_eq!(state.native_liability, 0);
    assert_eq!(state.reserve_floor, 50_000_000_000);
    assert_eq!(state.config.withdrawal_fee, 20_000_000);
    assert_eq!(
        state.config.denominations,
        vec![1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000]
    );
    assert_eq!(state.verifying_key.len(), 1248);
    assert!(state.anchors.recent.is_empty() && state.anchors.epoch.is_empty());
}

#[test]
fn deposit_wire_roundtrip_preserves_unsigned_widths() {
    let deposit = DepositBody {
        query_id: u64::MAX,
        amount: MAX_COINS,
        owner_commitment: [0x42; 32],
        output_data: vec![0x71; OUTPUT_DATA_BYTES],
    };
    let mut slice = SliceData::load_cell(deposit.build().unwrap()).unwrap();
    assert_eq!(slice.get_next_int(32).unwrap(), u64::from(OP_DEPOSIT));
    assert_eq!(DepositBody::parse(&mut slice).unwrap(), deposit);
    for amount in [0, MAX_COINS + 1] {
        assert!(DepositBody { amount, ..deposit.clone() }.build().is_err());
    }
    for size in [0, OUTPUT_DATA_BYTES - 1, OUTPUT_DATA_BYTES + 1] {
        assert!(DepositBody { output_data: vec![0; size], ..deposit.clone() }.build().is_err());
    }
}
