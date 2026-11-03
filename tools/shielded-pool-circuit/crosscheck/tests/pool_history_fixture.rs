/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The pool's own transaction history, as a client replaying it is handed it.
//!
//! A client that rebuilds the pool's state from its transactions has to
//! classify each one -- a deployment, a deposit, a transfer, a withdrawal
//! with its payout, a recovery bounce, a reserve top-up -- and apply the ones
//! that changed state. Its tests cannot run this prover, so this test runs
//! the real contract through one history that holds every kind, and writes
//! the transactions down together with the pool's final state cell and the
//! gas prices they ran under. The committed copy is what the client's
//! replay is checked against.
//!
//! Set `SHIELDED_POOL_HISTORY_FIXTURE` to a path to rewrite the fixture.
//! Without it the test still runs the history and checks its shape.

mod support;

use chain_block::{Cell, Deserializable, Serializable, TrComputePhase, TransactionDescr};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::imt;
use shielded_pool_circuit_crosscheck::pool::{Pool, DENOMINATION, WITHDRAWAL_FEE};
use shielded_pool_circuit_crosscheck::transact::Anchor;
use support::{
    deploy_destination, deposit_notes, execution_domain, prove_withdrawal, ProvedWithdrawal,
    ACCEPTER, REFUSER,
};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn boc_hex(cell: &Cell) -> String {
    hex(&chain_block::write_boc(cell).expect("a BOC"))
}

/// The kind a client is expected to classify a transaction as, from what
/// this test knows it sent.
fn kind(sent: &str) -> serde_json::Value {
    serde_json::Value::String(sent.to_owned())
}

#[test]
fn the_pools_history_replays_to_its_state() {
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let mut nullifiers = imt::State::genesis();
    let mut pool = Pool::deploy().expect("deploy the pool");
    let refuser = deploy_destination(&mut pool.bc, "refuser", REFUSER);
    let accepter = deploy_destination(&mut pool.bc, "accepter", ACCEPTER);
    let domain = execution_domain(&pool);

    // Four denominations in, so two withdrawals each have two notes to spend.
    let (held, root) = deposit_notes(&mut pool, &mut frontier, &[0x41, 0x42, 0x43, 0x44]);
    let mut expected = vec![
        (kind("no-state-change"), None),
        (kind("deposit"), None),
        (kind("deposit"), None),
        (kind("deposit"), None),
        (kind("deposit"), None),
    ];

    // A reserve top-up changes no pool state a client tracks.
    pool.send(TOS, Pool::topup_body(7).expect("a top-up body"))
        .expect("the top-up")
        .expect_success();
    expected.push((kind("no-state-change"), None));

    // A withdrawal the recipient refuses: the payout bounces and the pool
    // recovers the returned value into a note.
    let refused = prove_withdrawal(ProvedWithdrawal {
        pool: &pool,
        domain,
        frontier: &frontier,
        root,
        anchor: Anchor::Current,
        inputs: [&held[0], &held[1]],
        amount: DENOMINATION,
        recipient: &refuser,
        intent_nonce: 0x1001,
        recovery_owner_commitment: Fr::from(0x5eed_0001u64),
        nullifiers: &mut nullifiers,
    });
    let result = pool.send(COMPUTE_FEE * 4, refused).expect("the refused withdrawal");
    assert_eq!(result.transaction_count(), 3, "in, payout out, bounce back");
    expected.push((kind("transact"), Some((refuser.to_string(), u128::from(DENOMINATION)))));
    expected.push((kind("bounce"), None));

    // A withdrawal the recipient takes, proved against the root the first one
    // anchored before it changed anything: the prover's tree is still the one
    // after the deposits.
    let (recent, _) = pool.anchor_rings().expect("the anchor rings");
    let root_bytes = shielded_pool_circuit_crosscheck::pool::be(root);
    let slot = recent
        .iter()
        .find(|entry| entry.root == root_bytes)
        .map(|entry| u32::try_from(entry.slot).expect("a slot"))
        .expect("the deposits' root is anchored in the recent ring");
    let accepted = prove_withdrawal(ProvedWithdrawal {
        pool: &pool,
        domain,
        frontier: &frontier,
        root,
        anchor: Anchor::Recent(slot),
        inputs: [&held[2], &held[3]],
        amount: DENOMINATION,
        recipient: &accepter,
        intent_nonce: 0x1002,
        recovery_owner_commitment: Fr::from(0x5eed_0002u64),
        nullifiers: &mut nullifiers,
    });
    let result = pool.send(COMPUTE_FEE * 4, accepted).expect("the accepted withdrawal");
    assert_eq!(result.transaction_count(), 2, "in and payout out, nothing back");
    expected.push((kind("transact"), Some((accepter.to_string(), u128::from(DENOMINATION)))));

    // --- the history, as the chain holds it --------------------------------
    let history = pool.history();
    assert_eq!(history.len(), expected.len(), "one pool transaction per step");
    let mut transactions = Vec::new();
    let mut previous_lt = 0u64;
    for (transaction, (kind, payout)) in history.iter().zip(&expected) {
        let TransactionDescr::Ordinary(description) =
            transaction.read_description().expect("a description")
        else {
            panic!("a pool transaction that is not ordinary")
        };
        let TrComputePhase::Vm(vm) = &description.compute_ph else {
            panic!("a pool transaction whose compute phase was skipped")
        };
        assert!(vm.success && !description.aborted, "every step of this history was applied");
        assert!(transaction.logical_time() > previous_lt, "the history is in time order");
        previous_lt = transaction.logical_time();
        let cell = transaction.serialize().expect("serialize the transaction");
        transactions.push(serde_json::json!({
            "lt": transaction.logical_time(),
            "hash": hex(cell.repr_hash().as_slice()),
            "kind": kind,
            "payout": payout.as_ref().map(|(recipient, value)| serde_json::json!({
                "recipient": recipient,
                "value": value.to_string(),
            })),
            "boc": boc_hex(&cell),
        }));
    }

    let account = pool.bc.get_account(&pool.addr).expect("the pool's account");
    let data = account.get_data().expect("the pool's data");
    let code_hash = account.get_code_hash().expect("the pool's code hash");
    let key = 21u32.write_to_bitstring().expect("a config key");
    let gas_prices = pool
        .bc
        .config_params()
        .config_params
        .get(key)
        .expect("read the config")
        .expect("config parameter 21")
        .reference(0)
        .expect("the parameter cell");

    let fixture = serde_json::json!({
        "schema": "shielded-pool-history-fixture-v1",
        "description": "The pool's own transactions, oldest first, from one sandbox run of the \
                        real contract with development proofs: deployment, four deposits, a \
                        reserve top-up, a withdrawal whose payout was refused and bounced into a \
                        recovery note, and a withdrawal whose payout was taken. `account_data` \
                        is the pool's state cell after the last one and `gas_prices_param21` \
                        the gas prices every step ran under.",
        "pool_address": pool.addr.to_string(),
        "code_hash": hex(code_hash.as_slice()),
        "denomination": DENOMINATION.to_string(),
        "withdrawal_fee": WITHDRAWAL_FEE.to_string(),
        "gas_prices_param21": boc_hex(&gas_prices),
        "account_data": boc_hex(&data),
        "transactions": transactions,
    });

    if let Some(path) = std::env::var_os("SHIELDED_POOL_HISTORY_FIXTURE") {
        let text = serde_json::to_string_pretty(&fixture).expect("serialize the fixture");
        std::fs::write(&path, text + "\n").expect("write the fixture");
        eprintln!("wrote {}", std::path::Path::new(&path).display());
    }

    // The committed copy has the same shape as a fresh run, so a client's test
    // against it is a test against what this history produces.
    let committed: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/pool-history-development.json"))
            .expect("the committed fixture parses");
    let committed_kinds: Vec<&str> = committed["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .map(|entry| entry["kind"].as_str().expect("a kind"))
        .collect();
    let fresh_kinds: Vec<&str> =
        expected.iter().map(|(k, _)| k.as_str().expect("a kind")).collect();
    assert_eq!(committed_kinds, fresh_kinds, "the committed history has another shape");
    for entry in committed["transactions"].as_array().expect("transactions") {
        let bytes: Vec<u8> = (0..entry["boc"].as_str().expect("boc").len() / 2)
            .map(|i| u8::from_str_radix(&entry["boc"].as_str().expect("boc")[i * 2..i * 2 + 2], 16))
            .collect::<Result<_, _>>()
            .expect("hex");
        let cell = chain_block::read_single_root_boc(bytes).expect("a committed transaction BOC");
        assert_eq!(hex(cell.repr_hash().as_slice()), entry["hash"], "a committed hash");
        let transaction =
            chain_block::Transaction::construct_from_cell(cell).expect("a transaction");
        assert_eq!(transaction.logical_time(), entry["lt"].as_u64().expect("lt"));
        assert_eq!(
            hex(&transaction.account_id().get_bytestring(0)),
            committed["pool_address"].as_str().expect("address")[2..],
            "a committed transaction of another account"
        );
    }
}
