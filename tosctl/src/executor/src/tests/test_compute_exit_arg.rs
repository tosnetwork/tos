/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The exit argument of a compute phase. As in the native engine
//! (crypto/block/transaction.cpp, prepare_compute_phase), a compute phase that
//! committed its state reports none, however the VM ended; one that did not
//! reports the integer left on top of the stack, if any.

use super::*;
use crate::OrdinaryTransactionExecutor;
use chain_block::{
    BuilderData, CurrencyCollection, InternalMessageHeader, MsgAddressInt, Serializable, StateInit,
};

const BALANCE: u64 = 1_000_000_000_000_000;
const VALUE: u64 = 1_000_000_000;

fn code(bytes: &[u8]) -> Cell {
    BuilderData::with_raw(bytes.to_vec(), bytes.len() * 8)
        .and_then(|b| b.into_cell())
        .expect("a code cell")
}

fn address() -> MsgAddressInt {
    MsgAddressInt::with_standart(None, 0, [0x46; 32].into()).expect("an address")
}

fn internal() -> Cell {
    let src = MsgAddressInt::with_standart(None, 0, [0x99; 32].into()).expect("an address");
    let header = InternalMessageHeader::with_addresses(
        src,
        address(),
        CurrencyCollection::with_coins(VALUE),
    );
    Message::with_int_header(header).serialize().expect("a message cell")
}

/// The compute phase's exit code, success and exit argument.
fn run(code: Cell) -> (i32, bool, Option<i32>) {
    let vm = compute(code);
    (vm.exit_code, vm.success, vm.exit_arg)
}

fn compute(code: Cell) -> TrComputePhaseVm {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/real_boc/default_config.boc");
    let params = chain_block::ConfigParams::construct_from_file(path).expect("the configuration");
    let cfg = BlockchainConfig::with_config(params).expect("a configuration");
    let mut init = StateInit::default();
    init.set_code(code);
    init.set_data(Cell::default());
    let mut acc = Account::active(
        address(),
        CurrencyCollection::with_coins(BALANCE),
        0,
        1_750_000_000,
        init,
        0,
    )
    .expect("an account");
    let params = ExecuteParams {
        block_unixtime: 1_750_000_000,
        block_lt: 2_000_000,
        last_tr_lt: 2_000_000,
        ..ExecuteParams::default()
    };
    let tr = OrdinaryTransactionExecutor::new(cfg)
        .execute_with_params(Some(internal()), &mut acc, params)
        .expect("a transaction");
    match tr.read_description().expect("a description").compute_phase_ref() {
        Some(TrComputePhase::Vm(vm)) => vm.clone(),
        other => panic!("the compute phase ran: {other:?}"),
    }
}

// 5 PUSHNULL; PUSH c2; JMPX: the default exception handler fails to pop an exit code from the
// null, ends the VM with 7, and leaves the 5.
const EXIT_7_OVER_5: [u8; 5] = [0x75, 0x6d, 0xed, 0x42, 0xd9];
const COMMIT: [u8; 2] = [0xf8, 0x0f];

#[test]
fn a_committed_compute_phase_reports_no_exit_argument() {
    let program = [&COMMIT[..], &EXIT_7_OVER_5[..]].concat();
    assert_eq!(run(code(&program)), (7, true, None));
}

#[test]
fn a_committed_compute_phase_ending_with_a_chosen_exit_code_reports_no_exit_argument() {
    // COMMIT; 7; 13; PUSH c2; JMPX
    assert_eq!(run(code(&[0xf8, 0x0f, 0x77, 0x80, 0x0d, 0xed, 0x42, 0xd9])), (13, true, None));
}

#[test]
fn an_uncommitted_compute_phase_reports_the_integer_left_on_the_stack() {
    assert_eq!(run(code(&EXIT_7_OVER_5)), (7, false, Some(5)));
}

// The argument a THROWARG leaves on the stack is the exit argument when it is a nonzero 32-bit
// integer. Each pusher below is a program fragment that pushes one value.
const ARGUMENTS: &[(&str, &[u8], Option<i32>)] = &[
    ("zero", &[0x70], None),
    ("minus one", &[0x7f], Some(-1)),
    ("i32::MAX", &[0x84, 0x1e], Some(i32::MAX)), // PUSHPOW2DEC 31
    ("i32::MIN", &[0x85, 0x1e], Some(i32::MIN)), // PUSHNEGPOW2 31
    ("i32::MAX + 1", &[0x83, 0x1e], None),       // PUSHPOW2 31
    ("i32::MIN - 1", &[0x85, 0x1e, 0xa5], None), // PUSHNEGPOW2 31; DEC
    ("null", &[0x6d], None),                     // PUSHNULL
];

#[test]
fn every_throwarg_form_reports_its_argument() {
    // THROWARG 9; THROWARGANY with 9; THROWARGIF 9 and THROWARGIFNOT 9 when they throw.
    let forms: [(&str, &[u8], &[u8]); 4] = [
        ("THROWARG", &[], &[0xf2, 0xc8, 0x09]),
        ("THROWARGANY", &[], &[0x79, 0xf2, 0xf1]),
        ("THROWARGIF", &[], &[0x7f, 0xf2, 0xd8, 0x09]),
        ("THROWARGIFNOT", &[], &[0x70, 0xf2, 0xe8, 0x09]),
    ];
    for (form, prefix, suffix) in forms {
        for (name, push, exit_arg) in ARGUMENTS {
            let program = [prefix, push, suffix].concat();
            assert_eq!(run(code(&program)), (9, false, *exit_arg), "{form} {name}");
        }
    }
}

#[test]
fn a_chosen_exit_code_13_is_not_out_of_gas() {
    // 42 THROWARG 13
    assert_eq!(run(code(&[0x80, 0x2a, 0xf2, 0xc8, 0x0d])), (13, false, Some(42)));
    // 42 13 PUSH c2 JMPX: the default handler takes 13 and leaves 42
    assert_eq!(run(code(&[0x80, 0x2a, 0x80, 0x0d, 0xed, 0x42, 0xd9])), (13, false, Some(42)));
}

#[test]
fn running_out_of_gas_reports_the_gas_consumed() {
    // 42 PUSHCONT {} AGAIN. The VM leaves the gas it consumed, which passes the limit by the
    // instruction that ran out; the compute phase reports gas used capped at the limit
    // (crypto/block/transaction.cpp, prepare_compute_phase).
    let vm = compute(code(&[0x80, 0x2a, 0x90, 0xea]));
    let gas_used = i32::try_from(vm.gas_used.as_u64()).expect("gas used fits");
    assert_eq!((vm.exit_code, vm.success), (-14, false));
    let consumed = vm.exit_arg.expect("the gas consumed");
    assert!(consumed > gas_used, "consumed {consumed}, reported {gas_used}");
    assert!(consumed - gas_used < 100, "consumed {consumed}, reported {gas_used}");
}

#[test]
fn a_gas_limit_below_the_gas_used_reports_the_gas_consumed() {
    // 42 0 SETGASLIMIT
    let vm = compute(code(&[0x80, 0x2a, 0x70, 0xf8, 0x01]));
    let gas_used = i32::try_from(vm.gas_used.as_u64()).expect("gas used fits");
    assert_eq!((vm.exit_code, vm.success, vm.exit_arg), (-14, false, Some(gas_used)));
}
