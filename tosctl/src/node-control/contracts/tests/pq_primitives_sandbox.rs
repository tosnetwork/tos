/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What the post-quantum primitives cost inside a contract, measured before the elector
//! and the configuration contract are built around them.
//!
//! Two numbers decide whether the frozen design is affordable: deriving a key identity
//! from a 1312-byte key, and validating a whole elected set of them. Both are done in the
//! contract rather than trusted from a caller, so both are paid for on every registration
//! and every installation, and neither had ever been run.
//!
//! The derivation is checked against the same formula the node uses, so the probe is not
//! merely cheap but correct: a contract that derives a different identity would produce
//! validator sets every node refuses.

use chain_block::{
    Cell, MsgAddressInt, PqConsensusKey, Serializable, StateInit, UInt256, ValidatorDescr,
    ValidatorSet, derive_consensus_key_id,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;
/// From the zerostate's masterchain gas prices: an ordinary transaction may spend a
/// million gas, and a special account -- which the configuration contract is -- may spend
/// seventy. The set-validation work belongs to that account, so it is measured against
/// the budget that account actually has.
const ORDINARY_GAS_LIMIT: i64 = 1_000_000;
const SPECIAL_ACCOUNT_GAS_LIMIT: i64 = 70_000_000;
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;

/// The probe. Nothing here is elector or configuration logic: it is the two operations
/// those contracts will perform, isolated so their cost is attributable.
fn probe_code() -> Cell {
    let src = std::env::temp_dir().join("tos_pq_primitives_probe.fc");
    std::fs::write(
        &src,
        r#"
;; A stored key is a length in its own cell and a reference to the chunk chain, so the
;; length is read and checked before anything is hashed, and the chain alone is hashed.
;;
;; Prepending the domain and the algorithm in a head cell gives exactly
;;   SHA-256("TOS-PQ-CONSENSUS-KEY-v1" || u16_le(algorithm_id) || key bytes)
;; because the result does not depend on where the chain's chunk boundaries fall.
int derive_key_id(int algorithm_id, cell public_key) method_id {
  slice stored = public_key.begin_parse();
  int length = stored~load_uint(32);
  throw_unless(47, length == 1312);
  cell chain = stored~load_ref();
  stored.end_parse();
  int little_endian = ((algorithm_id & 0xff) << 8) | ((algorithm_id >> 8) & 0xff);
  return begin_cell()
    .store_slice("TOS-PQ-CONSENSUS-KEY-v1")
    .store_uint(little_endian, 16)
    .store_ref(chain)
  .end_cell().snake_string_hash();
}

;; Walk an elected set, read every post-quantum descriptor, and derive every key identity
;; from the key it carries. This is the work a configuration contract must do before it
;; installs a set, which is where its cost has to be affordable.
int validate_set(cell vset) method_id {
  slice cs = vset.begin_parse();
  throw_unless(40, cs~load_uint(8) == 0x12);
  cs~skip_bits(32 + 32);
  int total = cs~load_uint(16);
  cs~skip_bits(16 + 64);
  cell dict = cs~load_dict();
  int checked = 0;
  int index = -1;
  do {
    (index, slice descr, int found) = dict.idict_get_next?(16, index);
    if (found) {
      throw_unless(41, descr~load_uint(8) == 0xb3);
      int validator_id = descr~load_uint(256);
      int algorithm_id = descr~load_uint(16);
      int key_id = descr~load_uint(256);
      cell public_key = descr~load_ref();
      int weight = descr~load_uint(64);
      int adnl = descr~load_uint(256);
      throw_if(42, validator_id == 0);
      throw_if(43, adnl == 0);
      throw_if(44, weight == 0);
      throw_unless(45, key_id == derive_key_id(algorithm_id, public_key));
      checked += 1;
    }
  } until (~ found);
  throw_unless(46, checked == total);
  return checked;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("probe source");
    compile_func_with_stdlib(&[src]).expect("the probe compiles")
}

fn deploy(chain: &mut Blockchain) -> MsgAddressInt {
    let state = StateInit::with_code_and_data(probe_code(), Cell::default());
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("probe-funder", 1_000 * TOS).expect("funding");
    chain
        .send_message(
            MessageBuilder::internal(deployer.address(), &address, 100 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();
    address
}

/// A key as a descriptor stores it: the production encoder, not a second implementation
/// of the same shape.
fn stored_key(bytes: &[u8]) -> Cell {
    chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
        .expect("a key of admitted length")
}

/// Distinct keys, because a measurement over one repeated key would be a measurement of
/// the cell cache rather than of the work.
fn key_bytes(index: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(MLDSA44_PUBLIC_KEY_BYTES);
    let mut block = chain_block::sha256_digest(format!("pq-probe-{index}").as_bytes());
    while key.len() < MLDSA44_PUBLIC_KEY_BYTES {
        key.extend_from_slice(&block);
        block = chain_block::sha256_digest(block);
    }
    key.truncate(MLDSA44_PUBLIC_KEY_BYTES);
    key
}

fn validator_set(count: usize) -> Cell {
    let mut list = Vec::with_capacity(count);
    for index in 0..count {
        let key = key_bytes(index);
        let key_id = derive_consensus_key_id(1, &key);
        list.push(ValidatorDescr::with_pq_params(
            UInt256::from(chain_block::sha256_digest(format!("validator-{index}").as_bytes())),
            PqConsensusKey { algorithm_id: 1, key_id, public_key: key },
            1,
            UInt256::from(chain_block::sha256_digest(format!("adnl-{index}").as_bytes())),
        ));
    }
    ValidatorSet::new(100, 200, count as u16, list)
        .expect("a set the node would accept")
        .serialize()
        .expect("serialised set")
}

#[test]
fn the_contract_derives_the_same_key_identity_as_the_node() {
    let mut chain =
        Blockchain::with_global_version(16).expect("a chain at the post-quantum version");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    for index in 0..4 {
        let key = key_bytes(index);
        let result = chain
            .run_get_method(
                &probe,
                "derive_key_id",
                vec![StackItem::int(1), StackItem::Cell(stored_key(&key))],
            )
            .expect("the probe answers");
        assert_eq!(result.exit_code, 0, "derive_key_id failed: {}", result.exit_code);
        let derived =
            result.stack.last().expect("a key identity").as_integer().expect("an integer");
        let expected = derive_consensus_key_id(1, &key);
        assert_eq!(
            derived.to_string(),
            IntegerData::from_unsigned_bytes_be(expected.as_slice()).to_string(),
            "the contract derived a different key identity than the node does"
        );
        if index == 0 {
            eprintln!(
                "key-id derivation over {MLDSA44_PUBLIC_KEY_BYTES} bytes: {} gas",
                result.gas_used
            );
        }
    }
}

#[test]
fn the_algorithm_number_enters_the_identity_as_two_little_endian_bytes() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);
    let key = key_bytes(0);

    let one = chain
        .run_get_method(
            &probe,
            "derive_key_id",
            vec![StackItem::int(1), StackItem::Cell(stored_key(&key))],
        )
        .expect("the probe answers");
    let two_fifty_six = chain
        .run_get_method(
            &probe,
            "derive_key_id",
            vec![StackItem::int(256), StackItem::Cell(stored_key(&key))],
        )
        .expect("the probe answers");

    // 1 and 256 are the same two bytes in the other order. A derivation that wrote them
    // big-endian would give the same identity to both, which is the mistake this checks.
    assert_ne!(
        one.stack.last().expect("an identity").as_integer().expect("an integer").to_string(),
        two_fifty_six
            .stack
            .last()
            .expect("an identity")
            .as_integer()
            .expect("an integer")
            .to_string(),
        "algorithm 1 and algorithm 256 produced the same key identity"
    );
    assert_eq!(
        two_fifty_six
            .stack
            .last()
            .expect("an identity")
            .as_integer()
            .expect("an integer")
            .to_string(),
        IntegerData::from_unsigned_bytes_be(derive_consensus_key_id(256, &key).as_slice())
            .to_string(),
        "the contract disagrees with the node about algorithm 256"
    );
}

#[test]
fn validating_an_elected_set_is_affordable_at_the_sizes_the_configuration_allows() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let mut per_validator = Vec::new();
    for count in [21usize, 100, 400] {
        let result = chain
            .run_get_method_with_gas(
                &probe,
                "validate_set",
                vec![StackItem::Cell(validator_set(count))],
                SPECIAL_ACCOUNT_GAS_LIMIT,
            )
            .expect("the probe answers");
        assert_eq!(result.exit_code, 0, "validate_set failed at {count}: {}", result.exit_code);
        let checked: usize = result
            .stack
            .last()
            .expect("a count")
            .as_integer()
            .expect("an integer")
            .to_string()
            .parse()
            .expect("a count");
        assert_eq!(checked, count, "the probe skipped descriptors");
        eprintln!(
            "validating {count} post-quantum descriptors: {} gas ({} per validator)",
            result.gas_used,
            result.gas_used / count as i64
        );
        per_validator.push(result.gas_used / count as i64);
    }

    // The cost has to be linear in the number of validators. A super-linear one would
    // make the largest allowed set the one that cannot be installed, which is the failure
    // this measurement exists to rule out.
    let (smallest, largest) = (per_validator[0], per_validator[2]);
    assert!(
        largest <= smallest * 2,
        "per-validator cost grew from {smallest} to {largest} gas between 21 and 400 validators"
    );

    // The number that decides the design: the largest set the configuration allows must
    // be validatable inside the budget the account that installs it is given.
    let largest_set = per_validator[2] * 400;
    assert!(
        largest_set < SPECIAL_ACCOUNT_GAS_LIMIT,
        "validating the largest allowed set costs {largest_set} gas, over the {SPECIAL_ACCOUNT_GAS_LIMIT} a special account may spend"
    );
    eprintln!(
        "largest allowed set: {largest_set} gas, {}% of a special account's budget, {}x an ordinary transaction's",
        largest_set * 100 / SPECIAL_ACCOUNT_GAS_LIMIT,
        largest_set / ORDINARY_GAS_LIMIT
    );
}
