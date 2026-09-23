/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The two gates at the top of the shielded pool's safety list, run in the VM:
//!
//! * P0-0, deposit binding: the note that lands in the tree is computed by the
//!   contract from the principal it actually admitted, never taken from the
//!   depositor. Otherwise depositing 1 buys a note worth 100.
//! * P0-1, backing: the contract never calls `ACCEPT`, so a message can only buy
//!   the gas its own value pays for and can never spend the pool's balance on
//!   its behalf; the principal credited to liability is never eaten by gas; and
//!   after every transaction the balance still covers liability plus the reserve.
//!
//! The hash is a PLACEHOLDER (`cell_hash`). Nothing here depends on which hash
//! is used, so nothing here says anything about gas per transfer. It says
//! whether the money-handling rules hold, which is the thing that has to be
//! true before any of the expensive parts are worth building.
//!
//! Each assertion below was chosen so that a specific mutation of the contract
//! turns it red; the mutations are listed at the bottom and are meant to be run.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit, TrComputePhase,
};
use tos_sandbox::{Blockchain, GetMethodResult, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
/// What a deposit must carry beyond its principal to pay for its own execution.
/// The contract refuses anything less rather than reaching for the pool's balance.
const GAS_BUDGET: u64 = 50_000_000;
const RESERVE_FLOOR: u64 = TOS;
const OP_DEPOSIT: u32 = 1;
/// This chain's ConfigParam 21, as the VM applies it: a flat 667 for the first
/// hundred gas, then 436,907 per 65,536 gas with the division rounded up.
const fn compute_fee(gas: u64) -> u64 {
    const FLAT_LIMIT: u64 = 100;
    const FLAT_PRICE: u64 = 667;
    const GAS_PRICE: u64 = 436_907;
    if gas <= FLAT_LIMIT {
        FLAT_PRICE
    } else {
        FLAT_PRICE + ((gas - FLAT_LIMIT) * GAS_PRICE).div_ceil(65_536)
    }
}

/// A message value that is above the threshold below which the executor skips
/// the compute phase outright, and below what the deposit path costs to run.
///
/// Derived from the price rather than written down, because it has now been
/// wrong twice for the same reason: it was 400,000 while gas cost 400 nanotos,
/// stopped starving anything when the price was aligned to TON's 66.66, was
/// re-derived to 66,667, and stopped starving anything again when the price
/// was cut tenfold. A value that buys a thousand gas against a path that needs
/// 1,259 is the thing this constant means; the number that expresses it is the
/// price's business, not this file's.
///
/// Both ends matter: too low and the compute phase is skipped, the VM never
/// runs, and the test proves nothing.
const GAS_STARVED_VALUE: u64 = compute_fee(1_000);
/// TVM's out-of-gas exit code.
const EXIT_OUT_OF_GAS: i32 = -14;

const PROBE_SRC: &str = r#"
int op_deposit() asm "1 PUSHINT";
int gas_budget() asm "50000000 PUSHINT";
int err_underfunded() asm "40 PUSHINT";

;; Placeholder for Poseidon2: two 256-bit words -> one.
int h2(int a, int b) inline {
  return cell_hash(begin_cell().store_uint(a, 256).store_uint(b, 256).end_cell());
}

(int, int, int, int) load_state() inline {
  slice s = get_data().begin_parse();
  return (s~load_uint(64), s~load_uint(32), s~load_uint(256), s~load_uint(64));
}

() save_state(int liability, int leaves, int last_cm, int reserve) impure inline {
  set_data(begin_cell()
    .store_uint(liability, 64)
    .store_uint(leaves, 32)
    .store_uint(last_cm, 256)
    .store_uint(reserve, 64)
    .end_cell());
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  ;; Deploy, plain top-up, or a bounce: nothing to admit.
  if (in_msg_body.slice_bits() < 32) { return (); }
  slice cs = in_msg_full.begin_parse();
  int flags = cs~load_uint(4);
  if (flags & 1) { return (); }

  int op = in_msg_body~load_uint(32);
  if (op != op_deposit()) { return (); }

  ;; NO ACCEPT anywhere in this contract. The inbound value is the whole gas
  ;; budget; if it runs out, the transaction fails and the state is untouched.

  int principal = in_msg_body~load_uint(64);
  int owner_cm = in_msg_body~load_uint(256);
  ;; A depositor may append what it would like the final commitment to be.
  ;; It is read so that a mutation can be written to trust it; it is never used.
  int claimed_cm = 0;
  if (in_msg_body.slice_bits() >= 256) { claimed_cm = in_msg_body~load_uint(256); }

  ;; The principal is admitted only if the message also pays for itself, so
  ;; that what gets credited to liability is never what gas consumed.
  throw_unless(err_underfunded(), msg_value >= principal + gas_budget());

  (int liability, int leaves, int last_cm, int reserve) = load_state();

  ;; The note is built from the admitted principal and the contract's own
  ;; leaf index. Nothing the depositor sent decides the final commitment.
  int note_body = h2(principal, owner_cm);
  int final_cm = h2(note_body, leaves);

  save_state(liability + principal, leaves + 1, final_cm, reserve);
}

int liability() method_id { (int l, _, _, _) = load_state(); return l; }
int leaf_count() method_id { (_, int n, _, _) = load_state(); return n; }
int last_commitment() method_id { (_, _, int c, _) = load_state(); return c; }
int reserve_floor() method_id { (_, _, _, int r) = load_state(); return r; }

;; The commitment the contract would produce for these inputs. Used by the
;; test to say what it EXPECTS, so a contract that starts trusting the
;; depositor's value stops matching it.
int expected_commitment(int principal, int owner_cm, int leaf_index) method_id {
  return h2(h2(principal, owner_cm), leaf_index);
}

;; The backing invariant, read from inside the VM.
int backing_ok() method_id {
  (int liability, _, _, int reserve) = load_state();
  var [balance, _] = get_balance();
  return balance >= liability + reserve;
}

() recv_external(slice in_msg) impure { }
"#;

fn probe_code() -> Cell {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let src_dir = tempfile::tempdir().expect("a directory for the probe");
    let src = src_dir.path().join("tos_shielded_pool_deposit_probe.fc");
    std::fs::write(&src, PROBE_SRC).expect("write probe source");
    compile_func_with_stdlib(&[src]).expect("compile the deposit probe (needs build/crypto/func)")
}

fn initial_data() -> Cell {
    let mut b = BuilderData::new();
    b.append_u64(0).unwrap();
    b.append_u32(0).unwrap();
    b.append_raw(&[0u8; 32], 256).unwrap();
    b.append_u64(RESERVE_FLOOR).unwrap();
    b.into_cell().expect("initial data")
}

fn deposit_body(principal: u64, owner: &[u8; 32], claimed: Option<&[u8; 32]>) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(OP_DEPOSIT).unwrap();
    b.append_u64(principal).unwrap();
    b.append_raw(owner, 256).unwrap();
    if let Some(c) = claimed {
        b.append_raw(c, 256).unwrap();
    }
    b.into_cell().expect("deposit body")
}

fn u256_dec(bytes: &[u8; 32]) -> String {
    // Decimal rendering of a big-endian 256-bit value, to compare with what a
    // get-method returns. Done by hand so the test has no arithmetic dependency.
    let mut digits = vec![0u8]; // little-endian base-10
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

struct Pool {
    bc: Blockchain,
    addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

impl Pool {
    fn deploy() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(0);
        let payer = bc.treasury("depositor", 1_000 * TOS).expect("treasury");
        let si = StateInit::with_code_and_data(probe_code(), initial_data());
        let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).unwrap();
        // Deploy with enough to sit above the reserve floor. This value is not
        // a deposit and must not appear in liability.
        let deploy = MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, addr, payer }
    }

    fn get(&self, method: &str, args: Vec<StackItem>) -> Vec<String> {
        let res: GetMethodResult = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        res.expect_success();
        res.stack
            .iter()
            .map(|i| i.as_integer().unwrap_or_else(|_| panic!("{method}: non-integer")).to_string())
            .collect()
    }

    fn u64_of(&self, method: &str) -> u64 {
        let v = self.get(method, vec![]);
        v.last().unwrap().parse().unwrap_or_else(|_| panic!("{method} not u64: {v:?}"))
    }

    fn last_commitment(&self) -> String {
        self.get("last_commitment", vec![]).last().unwrap().clone()
    }

    fn expected_commitment(&self, principal: u64, owner: &[u8; 32], idx: u64) -> String {
        let owner_int = tos_vm::stack::integer::IntegerData::from_str_radix(&u256_dec(owner), 10)
            .expect("owner as integer");
        self.get(
            "expected_commitment",
            vec![
                StackItem::int(principal as i64),
                StackItem::integer(owner_int),
                StackItem::int(idx as i64),
            ],
        )
        .last()
        .unwrap()
        .clone()
    }

    fn backing_ok_in_vm(&self) -> bool {
        self.get("backing_ok", vec![]).last().unwrap() != "0"
    }

    fn pool_balance(&self) -> u64 {
        self.bc
            .get_account(&self.addr)
            .and_then(|a| a.balance().and_then(|c| c.coins.as_u64()))
            .expect("pool account has a balance")
    }

    /// The invariant read two ways: by the contract, and by the test from the
    /// account state. They must agree, and both must hold.
    fn assert_backing(&self, at: &str) {
        let balance = self.pool_balance();
        let liability = self.u64_of("liability");
        let reserve = self.u64_of("reserve_floor");
        assert!(
            balance >= liability + reserve,
            "{at}: balance {balance} < liability {liability} + reserve {reserve}"
        );
        assert!(
            self.backing_ok_in_vm(),
            "{at}: contract's own backing check disagrees with the account state"
        );
    }

    fn send(&mut self, value: u64, body: Cell) -> tos_sandbox::SendResult {
        let msg = MessageBuilder::internal(self.payer.address(), &self.addr, value)
            .bounce(true)
            .body(body)
            .build();
        self.bc.send_message(msg).expect("send")
    }
}

#[test]
fn deposit_binds_the_admitted_principal_and_ignores_a_claimed_commitment() {
    let mut p = Pool::deploy();
    p.assert_backing("after deploy");
    assert_eq!(p.u64_of("liability"), 0, "deploy value is reserve, not liability");

    // Honest deposit: 5 TOS principal, paying for itself on top.
    let owner = [7u8; 32];
    p.send(5 * TOS + GAS_BUDGET, deposit_body(5 * TOS, &owner, None)).expect_success();
    assert_eq!(p.u64_of("liability"), 5 * TOS);
    assert_eq!(p.u64_of("leaf_count"), 1);
    let expected0 = p.expected_commitment(5 * TOS, &owner, 0);
    assert_eq!(p.last_commitment(), expected0, "note must be built from the admitted principal");
    assert!(expected0.len() > 8, "commitment looks truncated; the comparison above proved nothing");
    p.assert_backing("after honest deposit");

    // Attacker: deposits 1 TOS, but appends exactly the commitment the contract
    // would produce for a 100 TOS note at the next index.
    let claimed = dec_to_u256(&p.expected_commitment(100 * TOS, &owner, 1));
    assert_eq!(
        u256_dec(&claimed),
        p.expected_commitment(100 * TOS, &owner, 1),
        "decimal <-> bytes round trip must be exact, or the claim is not what it says"
    );
    p.send(1 * TOS + GAS_BUDGET, deposit_body(1 * TOS, &owner, Some(&claimed))).expect_success();
    assert_eq!(
        p.u64_of("liability"),
        6 * TOS,
        "liability must grow by the admitted 1 TOS, not 100"
    );
    assert_eq!(p.u64_of("leaf_count"), 2);
    let expected1 = p.expected_commitment(1 * TOS, &owner, 1);
    let recorded = p.last_commitment();
    assert_eq!(recorded, expected1, "the contract must compute the note itself");
    assert_ne!(recorded, u256_dec(&claimed), "the depositor's claimed commitment must be ignored");
    p.assert_backing("after attacker deposit");

    // The principal really is in the hash: same owner and index, different amount, different note.
    assert_ne!(
        p.expected_commitment(5 * TOS, &owner, 1),
        p.expected_commitment(1 * TOS, &owner, 1),
        "amount is not bound into the commitment"
    );
}

#[test]
fn an_underfunded_deposit_is_refused_and_the_pool_pays_nothing() {
    let mut p = Pool::deploy();
    let owner = [9u8; 32];
    let before = p.pool_balance();
    let liability_before = p.u64_of("liability");

    // Exactly the principal, nothing to pay for execution.
    p.send(3 * TOS, deposit_body(3 * TOS, &owner, None)).expect_exit_code(40);

    assert_eq!(p.u64_of("liability"), liability_before, "a refused deposit must not be credited");
    assert_eq!(p.u64_of("leaf_count"), 0);
    let after = p.pool_balance();
    assert!(
        after >= before,
        "the pool paid for a message it refused: {before} -> {after}. \
         That is what ACCEPT would do, and this contract must never call it."
    );
    p.assert_backing("after refused deposit");
}

#[test]
fn a_declared_principal_larger_than_the_value_is_refused() {
    let mut p = Pool::deploy();
    let owner = [3u8; 32];
    let before = p.pool_balance();

    // Says 100 TOS, sends about 1.
    p.send(1 * TOS + GAS_BUDGET, deposit_body(100 * TOS, &owner, None)).expect_exit_code(40);

    assert_eq!(p.u64_of("liability"), 0, "declared principal must never exceed what arrived");
    assert!(p.pool_balance() >= before);
    p.assert_backing("after oversized declaration");
}

#[test]
fn a_message_that_cannot_pay_for_its_own_gas_never_reaches_the_pools_balance() {
    let mut p = Pool::deploy();
    let owner = [5u8; 32];
    let before = p.pool_balance();

    // Well-formed deposit, but carrying far less than its own execution costs.
    // With no ACCEPT the VM may only spend what this message bought.
    let r = p.send(GAS_STARVED_VALUE, deposit_body(3 * TOS, &owner, None));
    let descr = r.read_primary_description();

    let vm = match descr.compute_ph {
        TrComputePhase::Vm(vm) => vm,
        TrComputePhase::Skipped(s) => panic!(
            "compute was skipped ({:?}), so the VM never ran and this test proved nothing; \
             raise GAS_STARVED_VALUE above the skip threshold",
            s.reason
        ),
    };
    assert!(vm.gas_used > 0, "instrument check: the VM must have executed something");
    assert_eq!(
        vm.exit_code, EXIT_OUT_OF_GAS,
        "the message must die on the gas it bought ({} used), not on any later check; \
         an exit code from deeper in the contract means it was handed gas it did not pay for",
        vm.gas_used
    );

    let after = p.pool_balance();
    assert!(
        after >= before,
        "the pool funded a message that could not pay for itself: {before} -> {after}. \
         That is precisely what ACCEPT buys an attacker, and this contract must never call it."
    );
    assert_eq!(
        p.u64_of("liability"),
        0,
        "nothing may be credited by a message that ran out of gas"
    );
    assert_eq!(p.u64_of("leaf_count"), 0);
    p.assert_backing("after a gas-starved deposit");
}

/// Exact inverse of `u256_dec`: decimal string -> big-endian 32 bytes.
fn dec_to_u256(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32]; // big-endian accumulator
    for ch in s.bytes() {
        let mut carry = (ch - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let v = (*byte as u32) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "value does not fit in 256 bits: {s}");
    }
    out
}

// Mutations that must turn a test red (run each, one at a time, then restore):
//
//  M1  in recv_internal, replace `int final_cm = h2(note_body, leaves);`
//      with `int final_cm = claimed_cm ? claimed_cm : h2(note_body, leaves);`
//      -> deposit_binds_... fails (recorded == claimed).
//  M2  insert `accept_message();` right after the op check
//      -> a_message_that_cannot_pay_for_its_own_gas_... fails: the starved message
//         is carried past its own gas (exit 40 instead of -14, 1,285 gas used where
//         it bought 1,000) and the pool pays the difference out of its own balance
//         (measured on a freshly deployed pool: -114,000 nanotos).
//         Measured note: this mutation leaves an_underfunded_... green. That test's
//         message carries 3 TOS, which buys the whole path either way, so it ends at
//         the same exit 40 with the same untouched balance. A refusal that the
//         message can afford says nothing about ACCEPT.
//  M3  replace `liability + principal` with `liability + msg_value`
//      -> deposit_binds_... fails on the liability assertion.
//  M4  delete the `throw_unless(err_underfunded(), ...)` line
//      -> a_declared_principal_... and an_underfunded_... fail.
