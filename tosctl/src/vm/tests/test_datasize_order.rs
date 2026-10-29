// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use chain_block::{BuilderData, Cell, IBitstring};
use tos_vm::stack::Stack;

mod common;
use common::*;

fn graph() -> (Cell, Cell, Cell) {
    let mut left = BuilderData::new();
    left.append_u8(1).unwrap();
    let left = left.into_cell().unwrap();
    let mut right = BuilderData::new();
    right.append_u8(2).unwrap();
    let right = right.into_cell().unwrap();
    let mut parent = BuilderData::new();
    parent.checked_append_reference(left.clone()).unwrap();
    parent.checked_append_reference(right.clone()).unwrap();
    (parent.into_cell().unwrap(), left, right)
}

#[test]
fn bounded_cdatasize_loads_left_reference_before_right() {
    let (parent, left, right) = graph();
    // C++ VmStorageStat visits ref0 first. With a two-cell bound, root and
    // left are loaded before the scan stops; the later CTOS reloads left.
    for (probe, gas) in [(left, 364), (right, 439)] {
        test_case_with_refs(
            "PUSHREF PUSHINT 2 CDATASIZEQ DROP PUSHREF CTOS DROP",
            vec![parent.clone(), probe],
        )
        .with_block_version(16)
        .expect_stack(&Stack::new())
        .expect_gas_used(gas);
    }
}

#[test]
fn bounded_sdatasize_loads_left_reference_before_right() {
    let (parent, left, right) = graph();
    for (probe, gas) in [(left, 382), (right, 457)] {
        test_case_with_refs(
            "PUSHREF CTOS PUSHINT 1 SDATASIZEQ DROP PUSHREF CTOS DROP",
            vec![parent.clone(), probe],
        )
        .with_block_version(16)
        .expect_stack(&Stack::new())
        .expect_gas_used(gas);
    }
}

#[test]
fn completed_datasize_leaves_both_children_warm() {
    let (parent, left, right) = graph();
    for probe in [left, right] {
        test_case_with_refs(
            "PUSHREF PUSHINT 3 CDATASIZEQ DROP DROP DROP DROP PUSHREF CTOS DROP",
            vec![parent.clone(), probe],
        )
        .with_block_version(16)
        .expect_stack(&Stack::new())
        .expect_gas_used(518);
    }
}
