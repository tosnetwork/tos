/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! RUNTIME coverage for the TVM v6 fee primitives (`get_storage_fee` / `get_compute_fee`
//! / `get_forward_fee`). The sibling `crypto/smartcont/tests/stdlib-v6-fees-test.fc` only
//! checks that the stdlib declarations COMPILE; it never runs the opcodes. This test
//! actually executes them in the sandbox, which is what proves the default sandbox config
//! now carries the fee-price params (ConfigParam 18/20/21/24/25) that those opcodes read
//! from `c7[14]`. Before that config was populated, these get-methods aborted -- the
//! opcode threw on an empty config -- so any contract calling `get_storage_fee` (e.g. a
//! contract reserving its own storage rent) could not be tested at all.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, GetMethodResult, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;

/// A minimal contract whose get-methods return the raw fee-primitive results. `method_id`
/// (no explicit number) auto-assigns the crc16 get-method id, so `run_get_method` can call
/// them by name. `compile_func_with_stdlib` prepends the live `stdlib.fc`, so the v6
/// helpers are in scope without an `#include`.
fn probe_code() -> Cell {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let src_dir = tempfile::tempdir().expect("a directory for the probe");
    let src = src_dir.path().join("tos_fee_primitive_probe.fc");
    std::fs::write(
        &src,
        r#"
int storage_fee(int workchain, int seconds, int bits, int cells) method_id {
  return get_storage_fee(workchain, seconds, bits, cells);
}
int compute_fee(int workchain, int gas_used) method_id {
  return get_compute_fee(workchain, gas_used);
}
int forward_fee(int workchain, int bits, int cells) method_id {
  return get_forward_fee(workchain, bits, cells);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("write probe source");
    compile_func_with_stdlib(&[src])
        .expect("compile the fee-primitive probe (needs build/crypto/func + stdlib.fc)")
}

/// Assert the get-method ran (did not throw) and returned a strictly positive fee.
fn assert_positive_fee(res: &GetMethodResult, label: &str) {
    let item = res.stack.last().unwrap_or_else(|| panic!("{label}: empty result stack"));
    let n = item.as_integer().unwrap_or_else(|_| panic!("{label}: result is not an integer"));
    assert!(!n.is_zero() && !n.is_neg(), "{label}: expected a strictly positive fee");
}

#[test]
fn v6_fee_primitives_execute_against_the_default_sandbox_config() {
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let deployer = bc.treasury("fee-probe-deployer", 1_000 * TOS).expect("deployer");

    let si = StateInit::with_code_and_data(probe_code(), Cell::default());
    let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(-1, addr_hash).unwrap();

    // Deploy the probe (state init + empty body).
    let deploy = MessageBuilder::internal(deployer.address(), &addr, 2 * TOS)
        .bounce(false)
        .state_init(si)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    // Each fee opcode must now RUN (not throw) and return a positive fee, for both the
    // masterchain (-1) and basechain (0) price tables.
    let run = |bc: &Blockchain, method: &str, args: Vec<StackItem>, label: &str| {
        let res = bc.run_get_method(&addr, method, args).unwrap_or_else(|e| panic!("{label}: {e}"));
        res.expect_success();
        assert_positive_fee(&res, label);
    };

    for wc in [-1i64, 0i64] {
        run(
            &bc,
            "storage_fee",
            vec![
                StackItem::int(wc),
                StackItem::int(3600),
                StackItem::int(10_000),
                StackItem::int(30),
            ],
            &format!("get_storage_fee(wc={wc})"),
        );
        run(
            &bc,
            "compute_fee",
            vec![StackItem::int(wc), StackItem::int(1_000_000)],
            &format!("get_compute_fee(wc={wc})"),
        );
        run(
            &bc,
            "forward_fee",
            vec![StackItem::int(wc), StackItem::int(1_000), StackItem::int(3)],
            &format!("get_forward_fee(wc={wc})"),
        );
    }
}

#[test]
fn basechain_compute_fee_uses_the_basechain_price_table() {
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    let deployer = bc.treasury("basechain-fee-probe", 1_000 * TOS).expect("deployer");
    let si = StateInit::with_code_and_data(probe_code(), Cell::default());
    let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(-1, addr_hash).unwrap();
    let deploy = MessageBuilder::internal(deployer.address(), &addr, 2 * TOS)
        .bounce(false)
        .state_init(si)
        .body(Cell::default())
        .build();
    bc.send_message(deploy).expect("deploy").expect_success();

    // ConfigParam 21's basechain gas_price is 4,369,067, TON mainnet's live
    // value cut by ten: 6.666 nanotomi a gas, plus a flat 667 for the first
    // hundred. So 380,000 gas costs 2,533,336 nanotomi, not the
    // masterchain-derived figure.
    //
    // It was six times the aligned figure until 2026-09-21, when the basechain
    // prices were aligned with TON's live table, and a tenth of that from
    // later the same day: a private transfer verifies a Groth16 proof on
    // chain, and at the aligned price the verification alone cost more than
    // the whole fee a transfer was meant to fit inside.
    let result = bc
        .run_get_method(&addr, "compute_fee", vec![StackItem::int(0), StackItem::int(380_000)])
        .expect("get basechain compute fee");
    let res = result.expect_success();
    let fee: u64 = res
        .stack
        .last()
        .expect("basechain compute fee result")
        .as_integer_value(0..=u64::MAX)
        .expect("basechain compute fee is a u64");
    assert_eq!(fee, 2_533_336);

    // A plain payout has no StateInit/body DAG. GETFORWARDFEE therefore sees
    // zero priced attachment bits/cells and must return the basechain lump
    // price from ConfigParam 25. This is the reserve input used by the market's
    // strict native payout paths.
    let forward = bc
        .run_get_method(
            &addr,
            "forward_fee",
            vec![StackItem::int(0), StackItem::int(0), StackItem::int(0)],
        )
        .expect("get basechain forward fee");
    let forward = forward.expect_success();
    let forward_fee: u64 = forward
        .stack
        .last()
        .expect("basechain forward fee result")
        .as_integer_value(0..=u64::MAX)
        .expect("basechain forward fee is a u64");
    assert_eq!(forward_fee, 66_667);
}
