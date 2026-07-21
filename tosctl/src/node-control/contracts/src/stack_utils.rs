/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use tl_api::tos::tvm::StackEntry;

/// Helper to create a number stack entry from bytes (big-endian 256-bit)
pub fn bytes_to_stack_entry(bytes: &[u8; 32]) -> StackEntry {
    let n = tl_api::tos::tvm::numberdecimal::NumberDecimal {
        number: "0x".to_owned() + &hex::encode_upper(bytes),
    };
    StackEntry::Tvm_StackEntryNumber(tl_api::tos::tvm::stackentry::StackEntryNumber {
        number: tl_api::tos::tvm::Number::Tvm_NumberDecimal(n),
    })
}

/// Helper to create a number stack entry from i64 -- e.g. the `request_id`
/// argument `get_request`/`get_refund` (Service Actor) take as a get-method
/// parameter. Callers outside this crate don't otherwise need to depend on
/// `tl_api` directly just to build one integer stack argument.
pub fn i64_to_stack_entry(value: i64) -> StackEntry {
    let n = tl_api::tos::tvm::numberdecimal::NumberDecimal { number: value.to_string() };
    StackEntry::Tvm_StackEntryNumber(tl_api::tos::tvm::stackentry::StackEntryNumber {
        number: tl_api::tos::tvm::Number::Tvm_NumberDecimal(n),
    })
}

/// Unsigned counterpart used by Service Actor's full-width `uint64`
/// request IDs. Casting these IDs through `i64` corrupts values above
/// `i64::MAX`, precisely where overflow-boundary diagnostics matter.
pub fn u64_to_stack_entry(value: u64) -> StackEntry {
    let n = tl_api::tos::tvm::numberdecimal::NumberDecimal { number: value.to_string() };
    StackEntry::Tvm_StackEntryNumber(tl_api::tos::tvm::stackentry::StackEntryNumber {
        number: tl_api::tos::tvm::Number::Tvm_NumberDecimal(n),
    })
}
