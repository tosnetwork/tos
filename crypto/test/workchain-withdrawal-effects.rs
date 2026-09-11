// Executed statement fixture, not a Native account publication adapter.
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use tos_uno_crypto_prototype::{ffi::KernelLimits,
    withdrawal_statement::{WithdrawalAmounts, WithdrawalStatement}};

fn main() {
    let limits = KernelLimits { max_balance: 1000, max_value: 100,
        max_collect: 8, max_context_bytes: 4096, max_proof_bytes: 4096 };
    let point = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
    for (label, points, expected_success) in [
        ("success", [point; 6], true), ("decode", [[0; 32]; 6], false),
    ] {
        let result = WithdrawalStatement::new(&limits, [0; 80], [1; 32], [2; 32],
            WithdrawalAmounts { principal: 1, outward_fee: 1, return_reserve: 1,
                operation_fee: 1 }, &[3], points);
        match result {
            Ok(_) if expected_success => println!("STATEMENT_SUCCESS={label}"),
            Err(e) if !expected_success && e as u32 == 2 => println!("STATEMENT_DECODE={label}"),
            _ => panic!("statement fixture reached the wrong result layer"),
        }
    }
}
