/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Compute-phase gas for an external message to a contract whose code hash
//! ConfigParam 45 lists as precompiled. As in the native engine
//! (crypto/block/transaction.cpp, prepare_compute_phase), the precompiled gas
//! usage of an external message is compared with gas_max, since the message
//! has no gas limit until it is accepted, and the VM that runs in place of the
//! implementation gives an unaccepted external the credit alone.

use super::*;
use crate::{ExecutorError, OrdinaryTransactionExecutor};
use chain_block::{
    BuilderData, ConfigParamEnum, ConfigParams, CurrencyCollection, ExternalInboundMessageHeader,
    InternalMessageHeader, MsgAddressExt, MsgAddressInt, PrecompiledContractsList, Serializable,
    StateInit,
};

const BALANCE: u64 = 1_000_000_000_000_000;

fn code(bytes: &[u8]) -> Cell {
    BuilderData::with_raw(bytes.to_vec(), bytes.len() * 8)
        .and_then(|b| b.into_cell())
        .expect("a code cell")
}

/// ACCEPT
fn accept_code() -> Cell {
    code(&[0xf8, 0x00])
}

/// Returns without accepting.
fn no_accept_code() -> Cell {
    code(&[])
}

/// UNTIL:<{ GASCONSUMED; 2^pow2 PUSHPOW2; GREATER }>
/// Burns just over 2^pow2 gas without accepting.
fn burn_code(pow2: u8) -> Cell {
    code(&[0x95, 0xf8, 0x07, 0x83, pow2 - 1, 0xbc, 0xe6])
}

/// The same, then ACCEPT.
fn burn_then_accept_code(pow2: u8) -> Cell {
    code(&[0x95, 0xf8, 0x07, 0x83, pow2 - 1, 0xbc, 0xe6, 0xf8, 0x00])
}

/// Exit code of a VM that ran out of gas.
const OUT_OF_GAS: i32 = -14;

fn fixture() -> ConfigParams {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/real_boc/default_config.boc");
    ConfigParams::construct_from_file(path).expect("the fixture configuration")
}

fn config(code: &Cell, gas_usage: Option<u64>) -> BlockchainConfig {
    let mut params = fixture();
    if let Some(gas_usage) = gas_usage {
        let mut list = PrecompiledContractsList::default();
        list.add(&code.repr_hash(), gas_usage).expect("a precompiled entry");
        params.set_config(ConfigParamEnum::ConfigParam45(list)).expect("param 45");
    }
    BlockchainConfig::with_config(params).expect("a configuration")
}

fn gas_limit() -> u64 {
    BlockchainConfig::with_config(fixture())
        .expect("a configuration")
        .get_gas_config(false)
        .gas_limit
}

fn address() -> MsgAddressInt {
    MsgAddressInt::with_standart(None, 0, [0x45; 32].into()).expect("an address")
}

fn account(code: Cell, balance: u64) -> Account {
    let mut init = StateInit::default();
    init.set_code(code);
    init.set_data(Cell::default());
    Account::active(address(), CurrencyCollection::with_coins(balance), 0, 1_750_000_000, init, 0)
        .expect("an account")
}

fn external() -> Cell {
    let header = ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, address());
    Message::with_ext_in_header(header).serialize().expect("a message cell")
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

const VALUE: u64 = 1_000_000_000;

enum Outcome {
    /// gas_used of an executed compute phase, and whether it succeeded
    Ran {
        gas_used: u64,
        success: bool,
    },
    Skipped,
    ComputeFailed,
    /// exit code of a compute phase that did not accept the message
    NotAccepted(i32),
}

fn run(code: Cell, gas_usage: Option<u64>, message: Cell, balance: u64) -> Outcome {
    let cfg = config(&code, gas_usage);
    run_with_config(code, message, balance, cfg)
}

fn run_with_config(code: Cell, message: Cell, balance: u64, cfg: BlockchainConfig) -> Outcome {
    let mut acc = account(code, balance);
    let params = ExecuteParams {
        block_unixtime: 1_750_000_000,
        block_lt: 2_000_000,
        last_tr_lt: 2_000_000,
        ..ExecuteParams::default()
    };
    let executor = OrdinaryTransactionExecutor::new(cfg);
    match executor.execute_with_params(Some(message), &mut acc, params) {
        Ok(tr) => match tr.read_description().expect("a description").compute_phase_ref() {
            Some(TrComputePhase::Vm(vm)) => {
                Outcome::Ran { gas_used: vm.gas_used.as_u64(), success: vm.success }
            }
            Some(TrComputePhase::Skipped(_)) => Outcome::Skipped,
            None => panic!("an ordinary transaction has a compute phase"),
        },
        Err(err) => match err.downcast_ref::<ExecutorError>() {
            Some(ExecutorError::ExtMsgComputeSkipped(_)) => Outcome::Skipped,
            Some(ExecutorError::PrecompiledComputeOutOfGas) => Outcome::ComputeFailed,
            Some(ExecutorError::NoAcceptError(code, _)) => Outcome::NotAccepted(*code),
            _ => panic!("unexpected executor error: {err}"),
        },
    }
}

#[test]
fn an_external_within_gas_max_is_accepted_and_charged_the_precompiled_gas() {
    match run(accept_code(), Some(5000), external(), BALANCE) {
        Outcome::Ran { gas_used, success } => {
            assert_eq!(gas_used, 5000);
            assert!(success);
        }
        Outcome::ComputeFailed => panic!("unexpected compute phase failure"),
        Outcome::Skipped => {
            panic!("skipped: the precompiled usage was compared with the zero limit")
        }
        Outcome::NotAccepted(code) => panic!("not accepted: {code}"),
    }
}

#[test]
fn an_external_above_gas_max_is_skipped() {
    let limit = gas_limit();
    assert!(matches!(run(accept_code(), Some(limit + 1), external(), BALANCE), Outcome::Skipped));
    assert!(matches!(run(accept_code(), Some(u64::MAX), external(), BALANCE), Outcome::Skipped));
}

#[test]
fn an_external_that_does_not_accept_is_refused() {
    assert!(matches!(
        run(no_accept_code(), Some(5000), external(), BALANCE),
        Outcome::NotAccepted(0)
    ));
}

#[test]
fn precompiled_credit_above_u32_does_not_imply_acceptance() {
    for limit in [(1u64 << 32) - 1, 1u64 << 32, (1u64 << 32) + 1] {
        for (contract, accepts) in [(no_accept_code(), false), (accept_code(), true)] {
            let mut params = config(&contract, Some(5000)).raw_config().clone();
            let mut gas = params.gas_prices(false).expect("gas prices");
            gas.gas_limit = limit;
            params.set_config(ConfigParamEnum::ConfigParam21(gas)).expect("param 21");
            let cfg = BlockchainConfig::with_config(params).expect("a configuration");
            let outcome = run_with_config(contract, external(), BALANCE, cfg);
            if accepts {
                assert!(
                    matches!(outcome, Outcome::Ran { gas_used: 5000, success: true }),
                    "gas limit {limit}"
                );
            } else {
                assert!(matches!(outcome, Outcome::NotAccepted(0)), "gas limit {limit}");
            }
        }
    }
}

#[test]
fn an_unaccepted_external_runs_on_the_credit_alone() {
    let limit = gas_limit();
    // The two burn targets bracket the gas limit, which is the credit here.
    let over = 64 - (limit - 1).leading_zeros() as u8; // smallest power of two at or above the limit
    let under = over - 2;
    assert!((1u64 << under) < limit / 2, "the lower target leaves room to accept");
    assert!((1u64 << over) > limit && (1u64 << over) < limit * 2 - limit / 8, "{limit}");
    assert!(matches!(
        run(burn_then_accept_code(under), Some(0), external(), BALANCE),
        Outcome::Ran { success: true, .. }
    ));
    // Granting the gas limit on top of the credit would let it reach ACCEPT.
    assert!(matches!(
        run(burn_then_accept_code(over), Some(0), external(), BALANCE),
        Outcome::ComputeFailed
    ));
    // Without ACCEPT it is cut off at the credit instead of finishing on twice the limit.
    assert!(matches!(run(burn_code(over), Some(0), external(), BALANCE), Outcome::ComputeFailed));
}

#[test]
fn internal_messages_are_unchanged() {
    match run(accept_code(), Some(5000), internal(), BALANCE) {
        Outcome::Ran { gas_used, success } => {
            assert_eq!(gas_used, 5000);
            assert!(success);
        }
        _ => panic!("an internal message within the limit runs"),
    }
}

#[test]
fn precompiled_real_oog_refuses_the_compute_phase() {
    let over = 64 - (gas_limit() - 1).leading_zeros() as u8;
    for prefix in [&[][..], &[0xf8, 0x00][..], &[0xf8, 0x00, 0xf8, 0x0f][..]] {
        for message in [external(), internal()] {
            let mut bytes = prefix.to_vec();
            bytes.extend([0x95, 0xf8, 0x07, 0x83, over - 1, 0xbc, 0xe6]);
            let contract = code(&bytes);
            let cfg = config(&contract, Some(0));
            let mut acc = account(contract, BALANCE);
            let params = ExecuteParams {
                block_unixtime: 1_750_000_000,
                block_lt: 2_000_000,
                last_tr_lt: 2_000_000,
                ..ExecuteParams::default()
            };
            let error = OrdinaryTransactionExecutor::new(cfg)
                .execute_with_params(Some(message), &mut acc, params)
                .expect_err("native refuses a precompiled fallback that exhausts gas");
            assert_eq!(
                error.downcast_ref::<ExecutorError>(),
                Some(&ExecutorError::PrecompiledComputeOutOfGas)
            );
            assert_eq!(
                error.to_string(),
                "Precompiled fallback exhausted gas during compute phase"
            );
        }
    }
}

#[test]
fn real_oog_is_distinct_from_user_throw_and_ordinary_oog() {
    let over = 64 - (gas_limit() - 1).leading_zeros() as u8;
    assert!(matches!(
        run(burn_code(over), None, external(), BALANCE),
        Outcome::NotAccepted(OUT_OF_GAS)
    ));
    assert!(matches!(
        run(code(&[0xf2, 0x0d]), Some(0), external(), BALANCE),
        Outcome::NotAccepted(13)
    ));
    // PUSHINT -14; THROWANY is range-checked, not a real OOG exception.
    assert!(matches!(
        run(code(&[0x80, 0xf2, 0xf2, 0xf0]), Some(0), external(), BALANCE),
        Outcome::NotAccepted(5)
    ));
    for message in [external(), internal()] {
        assert!(matches!(
            run(code(&[0xf8, 0x00, 0xf2, 0x0d]), Some(0), message, BALANCE),
            Outcome::Ran { success: false, gas_used: 0 }
        ));
    }
}
