/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Result types with fluent assertion methods for sandbox test harnesses.

use chain_block::{
    Cell, ComputeSkipReason, Message, MsgAddressInt, SliceData, TrComputePhase,
    TrComputePhaseSkipped, TrComputePhaseVm, Transaction, TransactionDescr,
    TransactionDescrOrdinary,
};
use tos_vm::stack::StackItem;

/// Result of sending a message. Contains the full cascade of transactions
/// produced by the emulator, plus any external outbound messages.
pub struct SendResult {
    pub transactions: Vec<(MsgAddressInt, Transaction)>,
    pub external_out_messages: Vec<Message>,
}

impl SendResult {
    /// Returns the first transaction in the cascade, if any.
    pub fn first_transaction(&self) -> Option<&Transaction> {
        self.transactions.first().map(|(_, tr)| tr)
    }

    /// Returns all transactions that targeted the given address.
    pub fn transactions_for(&self, addr: &MsgAddressInt) -> Vec<&Transaction> {
        self.transactions.iter().filter(|(a, _)| a == addr).map(|(_, tr)| tr).collect()
    }

    /// Total number of transactions in the cascade.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    // ---- fluent assertions (panic on failure — designed for #[test]) ----

    /// Asserts that the first transaction was not aborted.
    pub fn expect_success(&self) -> &Self {
        let descr = self.read_primary_description();
        assert!(!descr.aborted, "expected first transaction to succeed, but it was aborted");
        self
    }

    /// Asserts that the first transaction was aborted.
    pub fn expect_aborted(&self) -> &Self {
        let descr = self.read_primary_description();
        assert!(descr.aborted, "expected first transaction to be aborted, but it succeeded");
        self
    }

    /// Asserts that the compute phase of the first transaction finished with the
    /// given `exit_code`.
    pub fn expect_exit_code(&self, code: i32) -> &Self {
        let descr = self.read_primary_description();
        match descr.compute_ph {
            TrComputePhase::Vm(ref vm) => {
                assert_eq!(vm.exit_code, code, "expected exit code {code}, got {}", vm.exit_code);
            }
            TrComputePhase::Skipped(TrComputePhaseSkipped { reason }) => {
                panic!(
                    "expected VM compute phase with exit code {code}, but compute was skipped \
                     (reason: {reason:?})"
                );
            }
        }
        self
    }

    /// Asserts the number of outbound messages produced by the first transaction.
    pub fn expect_out_msgs(&self, count: usize) -> &Self {
        let tr = self.first_transaction().expect("expected at least one transaction");
        let actual = tr.out_msgs.len().expect("failed to read out_msgs length");
        assert_eq!(actual, count, "expected {count} outbound messages, got {actual}");
        self
    }

    /// Asserts the total number of transactions in the cascade.
    pub fn expect_transaction_count(&self, count: usize) -> &Self {
        let actual = self.transaction_count();
        assert_eq!(actual, count, "expected {count} transactions, got {actual}");
        self
    }

    /// Reads the description of the first transaction, expecting it to be an
    /// ordinary transaction. Panics if there are no transactions or the
    /// description is not `TransactionDescr::Ordinary`.
    pub fn read_primary_description(&self) -> TransactionDescrOrdinary {
        let tr = self.first_transaction().expect("no transactions in SendResult");
        match tr.read_description().expect("failed to read transaction description") {
            TransactionDescr::Ordinary(descr) => descr,
            other => panic!("expected ordinary transaction description, got {other:?}"),
        }
    }
}

/// Result of running a get-method on a contract.
pub struct GetMethodResult {
    pub exit_code: i32,
    pub gas_used: i64,
    pub stack: Vec<StackItem>,
}

impl GetMethodResult {
    /// Asserts that the get-method exited successfully (exit_code == 0).
    pub fn expect_success(&self) -> &Self {
        assert_eq!(
            self.exit_code, 0,
            "expected get-method to succeed (exit_code 0), got {}",
            self.exit_code
        );
        self
    }

    /// Extracts an integer value from the result stack at the given `index`,
    /// converting it to `i128`. Panics if the stack item is not an integer or
    /// if the value does not fit in `i128`.
    pub fn int_at(&self, index: usize) -> i128 {
        let item = self.stack.get(index).unwrap_or_else(|| {
            panic!("stack index {index} out of bounds (len {})", self.stack.len())
        });
        item.as_integer()
            .unwrap_or_else(|e| panic!("stack[{index}] is not an integer: {e}"))
            .as_integer_value(i128::MIN..=i128::MAX)
            .unwrap_or_else(|e| panic!("stack[{index}] integer does not fit in i128: {e}"))
    }

    /// Extracts a `Cell` from the result stack at the given `index`.
    /// Panics if the stack item is not a cell.
    pub fn cell_at(&self, index: usize) -> Cell {
        let item = self.stack.get(index).unwrap_or_else(|| {
            panic!("stack index {index} out of bounds (len {})", self.stack.len())
        });
        item.as_cell().unwrap_or_else(|e| panic!("stack[{index}] is not a cell: {e}")).clone()
    }

    /// Extracts a `SliceData` from the result stack at the given `index`.
    /// Panics if the stack item is not a slice.
    pub fn slice_at(&self, index: usize) -> SliceData {
        let item = self.stack.get(index).unwrap_or_else(|| {
            panic!("stack index {index} out of bounds (len {})", self.stack.len())
        });
        item.as_slice().unwrap_or_else(|e| panic!("stack[{index}] is not a slice: {e}")).clone()
    }
}
