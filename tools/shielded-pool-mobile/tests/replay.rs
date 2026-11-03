// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::unwrap_used)]
mod common;
use chain_block::{read_single_root_boc, ConfigParamEnum, Deserializable, Transaction};
use serde_json::Value;
use shielded_pool_codec::{compute_fee, PoolState, BOUNCE_GAS_CEILING};
use shielded_pool_mobile::{
    replay::{Head, Replay},
    Error,
};

fn setup() -> (Value, Head, PoolState, u128) {
    let f = common::linked_fixture();
    let entry = f["transactions"].as_array().unwrap().last().unwrap();
    let tx = Transaction::construct_from_cell(
        read_single_root_boc(hex::decode(entry["boc"].as_str().unwrap()).unwrap()).unwrap(),
    )
    .unwrap();
    let head = Head {
        account_id: hex::decode(&f["pool_address"].as_str().unwrap()[2..])
            .unwrap()
            .try_into()
            .unwrap(),
        last_hash: hex::decode(entry["hash"].as_str().unwrap()).unwrap().try_into().unwrap(),
        last_lt: tx.logical_time(),
        account_root: *tx.read_state_update().unwrap().new_hash.as_array(),
        shard_time: tx.now(),
    };
    let state = PoolState::parse(
        &read_single_root_boc(hex::decode(f["account_data"].as_str().unwrap()).unwrap()).unwrap(),
    )
    .unwrap();
    let gas = read_single_root_boc(hex::decode(f["gas_prices_param21"].as_str().unwrap()).unwrap())
        .unwrap();
    let ConfigParamEnum::ConfigParam21(prices) =
        ConfigParamEnum::construct_from_cell_and_number(gas, 21).unwrap()
    else {
        unreachable!()
    };
    let charge = compute_fee(&prices, BOUNCE_GAS_CEILING).unwrap();
    (f, head, state, charge)
}
fn push_all(replay: &mut Replay, f: &Value) {
    for e in f["transactions"].as_array().unwrap() {
        replay.push(&hex::decode(e["boc"].as_str().unwrap()).unwrap()).unwrap();
    }
}
#[test]
fn replays_deposits_spends_and_recovery_to_the_exact_pool_checkpoint() {
    let (f, head, state, charge) = setup();
    let mut replay = Replay::new(head, &state, charge).unwrap();
    push_all(&mut replay, &f);
    let ledger = replay.finish().unwrap();
    assert_eq!(ledger.checkpoint().native_liability, state.native_liability);
    assert_eq!(ledger.nullifiers().len(), 4);
    assert!(!ledger.outputs().is_empty());
    assert!(ledger.pending_recoveries().iter().any(|p| p.consumed));
}
#[test]
fn all_six_checkpoint_mismatches_reject_the_entire_result() {
    let (f, head, state, charge) = setup();
    for i in 0..6 {
        let mut wrong = state.clone();
        match i {
            0 => wrong.commitment_root = [0; 32],
            1 => wrong.commitment_next_index += 1,
            2 => wrong.reserved_recovery_leaves += 1,
            3 => wrong.nullifier_root = [0; 32],
            4 => wrong.nullifier_next_index += 1,
            _ => wrong.native_liability = wrong.native_liability.checked_add(1).unwrap(),
        }
        let mut replay = Replay::new(head.clone(), &wrong, charge).unwrap();
        push_all(&mut replay, &f);
        assert_eq!(replay.finish().err(), Some(Error::InvalidInput), "checkpoint field {i}");
    }
}
#[test]
fn truncated_history_or_wrong_proven_head_cannot_finish() {
    let (f, head, state, charge) = setup();
    let mut truncated = Replay::new(head.clone(), &state, charge).unwrap();
    for e in &f["transactions"].as_array().unwrap()[..8] {
        truncated.push(&hex::decode(e["boc"].as_str().unwrap()).unwrap()).unwrap();
    }
    assert!(matches!(truncated.finish(), Err(Error::InvalidInput)));
    for i in 0..3 {
        let mut wrong = head.clone();
        match i {
            0 => wrong.last_hash = [1; 32],
            1 => wrong.last_lt += 1,
            _ => wrong.account_root = [1; 32],
        }
        let mut replay = Replay::new(wrong, &state, charge).unwrap();
        push_all(&mut replay, &f);
        assert_eq!(replay.finish().err(), Some(Error::InvalidInput), "head field {i}");
    }
}
#[test]
fn skipped_reordered_foreign_or_failed_pushes_poison_the_replay() {
    let (f, head, state, charge) = setup();
    let entries = f["transactions"].as_array().unwrap();
    for indices in [vec![1], vec![0, 2], vec![0, 1, 1], vec![0, 2, 1]] {
        let mut replay = Replay::new(head.clone(), &state, charge).unwrap();
        let mut refused = false;
        for i in indices {
            if replay.push(&hex::decode(entries[i]["boc"].as_str().unwrap()).unwrap()).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused);
        assert_eq!(
            replay.push(&hex::decode(entries[0]["boc"].as_str().unwrap()).unwrap()),
            Err(Error::InvalidInput)
        );
        assert!(matches!(replay.finish(), Err(Error::InvalidInput)));
    }
    let mut foreign = head;
    foreign.account_id = [1; 32];
    let mut replay = Replay::new(foreign, &state, charge).unwrap();
    assert_eq!(
        replay.push(&hex::decode(entries[0]["boc"].as_str().unwrap()).unwrap()),
        Err(Error::InvalidInput)
    );
    assert!(matches!(replay.finish(), Err(Error::InvalidInput)));
}
#[test]
fn wrong_recovery_pricing_never_becomes_a_balance() {
    let (f, head, state, charge) = setup();
    let mut replay = Replay::new(head, &state, charge.checked_add(1).unwrap()).unwrap();
    push_all(&mut replay, &f);
    assert!(matches!(replay.finish(), Err(Error::InvalidInput)));
}

#[test]
fn each_forward_link_binding_is_checked_independently() {
    use chain_block::{write_boc, HashUpdate, Serializable, UInt256};
    let (f, head, state, charge) = setup();
    let first = hex::decode(f["transactions"][0]["boc"].as_str().unwrap()).unwrap();
    let second = hex::decode(f["transactions"][1]["boc"].as_str().unwrap()).unwrap();
    let first_tx = Transaction::construct_from_cell(read_single_root_boc(&first).unwrap()).unwrap();
    for i in 0..5 {
        let mut tx =
            Transaction::construct_from_cell(read_single_root_boc(&second).unwrap()).unwrap();
        match i {
            0 => tx.set_prev_trans_hash(UInt256::from([1; 32])),
            1 => tx.set_prev_trans_lt(first_tx.logical_time() + 1),
            2 => tx
                .write_state_update(&HashUpdate::with_hashes(
                    UInt256::from([1; 32]),
                    tx.read_state_update().unwrap().new_hash,
                ))
                .unwrap(),
            3 => tx.set_now(first_tx.now() - 1),
            _ => tx.set_logical_time(first_tx.logical_time()),
        }
        let mut replay = Replay::new(head.clone(), &state, charge).unwrap();
        replay.push(&first).unwrap();
        assert_eq!(
            replay.push(&write_boc(&tx.serialize().unwrap()).unwrap()),
            Err(Error::InvalidInput),
            "binding {i}"
        );
    }
    let mut zero = first_tx.clone();
    zero.set_logical_time(0);
    let mut replay = Replay::new(head.clone(), &state, charge).unwrap();
    assert_eq!(
        replay.push(&write_boc(&zero.serialize().unwrap()).unwrap()),
        Err(Error::InvalidInput)
    );
    for i in 0..3 {
        let mut changed = head.clone();
        match i {
            0 => changed.account_id = [1; 32],
            1 => changed.shard_time = 0,
            _ => changed.last_lt = first_tx.logical_time() - 1,
        }
        let mut replay = Replay::new(changed, &state, charge).unwrap();
        assert_eq!(replay.push(&first), Err(Error::InvalidInput), "head binding {i}");
    }
}

fn no_op_template() -> Transaction {
    use chain_block::{HashUpdate, TransactionDescr, UInt256};
    let f = common::fixture();
    let mut tx = Transaction::construct_from_cell(
        read_single_root_boc(hex::decode(f["transactions"][0]["boc"].as_str().unwrap()).unwrap())
            .unwrap(),
    )
    .unwrap();
    tx.write_in_msg(None).unwrap();
    tx.write_description(&TransactionDescr::default()).unwrap();
    tx.write_state_update(&HashUpdate::with_hashes(UInt256::default(), UInt256::default()))
        .unwrap();
    tx.set_now(0);
    tx
}

#[test]
fn transaction_budget_stops_valid_small_links_and_discards_state() {
    use chain_block::{write_boc, Serializable, UInt256};
    use shielded_pool_mobile::replay::MAX_HISTORY_TRANSACTIONS;
    let (_, mut head, state, charge) = setup();
    head.last_lt = u64::MAX;
    let mut replay = Replay::new(head, &state, charge).unwrap();
    let mut tx = no_op_template();
    let mut prev = UInt256::default();
    for i in 1..=MAX_HISTORY_TRANSACTIONS + 1 {
        tx.set_logical_time(i as u64);
        tx.set_prev_trans_lt((i - 1) as u64);
        tx.set_prev_trans_hash(prev);
        let root = tx.serialize().unwrap();
        prev = root.repr_hash();
        let boc = write_boc(&root).unwrap();
        assert!(boc.len() < 256);
        let result = replay.push(&boc);
        if i <= MAX_HISTORY_TRANSACTIONS {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(Error::Limit));
        }
    }
    assert!(matches!(replay.finish(), Err(Error::InvalidInput)));
}

#[test]
fn aggregate_byte_budget_stops_valid_large_links() {
    use chain_block::{
        write_boc, BuilderData, IBitstring, Message, Serializable, SliceData, UInt256,
    };
    use shielded_pool_mobile::replay::MAX_HISTORY_BYTES;
    let (_, mut head, state, charge) = setup();
    head.last_lt = u64::MAX;
    let mut replay = Replay::new(head, &state, charge).unwrap();
    let mut level = Vec::new();
    for i in 0..8192u64 {
        let mut b = BuilderData::new();
        b.append_u64(i).unwrap();
        b.append_raw(&[0; 64], 512).unwrap();
        level.push(b.into_cell().unwrap());
    }
    while level.len() > 1 {
        level = level
            .chunks(4)
            .map(|children| {
                let mut b = BuilderData::new();
                for c in children {
                    b.checked_append_reference(c.clone()).unwrap();
                }
                b.into_cell().unwrap()
            })
            .collect();
    }
    let mut message = Message::default();
    message.set_body(SliceData::load_cell(level.pop().unwrap()).unwrap());
    let mut tx = no_op_template();
    tx.write_in_msg(Some(&message)).unwrap();
    let mut prev = UInt256::default();
    let mut total = 0usize;
    let mut reached = false;
    for i in 1..100u64 {
        tx.set_logical_time(i);
        tx.set_prev_trans_lt(i - 1);
        tx.set_prev_trans_hash(prev);
        let root = tx.serialize().unwrap();
        prev = root.repr_hash();
        let boc = write_boc(&root).unwrap();
        assert!(boc.len() > 500000);
        total += boc.len();
        if total <= MAX_HISTORY_BYTES {
            assert_eq!(replay.push(&boc), Ok(()));
        } else {
            assert_eq!(replay.push(&boc), Err(Error::Limit));
            reached = true;
            break;
        }
    }
    assert!(reached, "did not reach aggregate byte budget");
    assert!(matches!(replay.finish(), Err(Error::InvalidInput)));
}

#[test]
fn empty_history_requires_a_consistent_head_and_genesis_checkpoint() {
    let (_, mut head, state, charge) = setup();
    head.last_lt = 0;
    assert!(matches!(Replay::new(head.clone(), &state, charge), Err(Error::InvalidInput)));
    head.last_hash = [0; 32];
    assert!(matches!(
        Replay::new(head.clone(), &state, charge).unwrap().finish(),
        Err(Error::InvalidInput)
    ));
    let genesis = PoolState::parse(
        &read_single_root_boc(include_bytes!(
            "../../../artifacts/shielded-pool/deployments/epoch4-v16/data.boc"
        ))
        .unwrap(),
    )
    .unwrap();
    let ledger = Replay::new(head, &genesis, charge).unwrap().finish().unwrap();
    assert_eq!(ledger.checkpoint().native_liability, 0);
    assert!(ledger.outputs().is_empty());
}
