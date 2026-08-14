/*
 * Copyright (C) 2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

use chain_block::{sha256_digest, BuilderData, ExceptionCode, IBitstring};
use tos_vm::stack::{integer::IntegerData, Stack, StackItem};

mod common;
use common::*;

fn snake(parts: &[&[u8]]) -> chain_block::Cell {
    let mut next = None;
    for part in parts.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(part, part.len() * 8).unwrap();
        if let Some(cell) = next {
            builder.checked_append_reference(cell).unwrap();
        }
        next = Some(builder.into_cell().unwrap());
    }
    next.expect("non-empty snake")
}

fn expected_hash(bytes: &[u8]) -> Stack {
    let mut stack = Stack::new();
    stack.push(StackItem::integer(IntegerData::from_unsigned_bytes_be(sha256_digest(bytes))));
    stack
}

#[test]
fn sha256c_is_chunk_independent_at_version_14() {
    let expected = expected_hash(b"hello world");
    test_case_with_refs("PUSHREF SHA256C", vec![snake(&[b"hello world"])])
        .with_block_version(14)
        .expect_stack(&expected);
    test_case_with_refs("PUSHREF SHA256C", vec![snake(&[b"hello ", b"world"])])
        .with_block_version(14)
        .expect_stack(&expected);
}

#[test]
fn sha256c_matches_cpp_consensus_differential_vector() {
    // Keep this vector identical to crypto/test/vm.cpp's
    // VM.sha256_canonical_snake case. Both VMs must hash the same two-cell
    // canonical snake to standard SHA-256 before version 14 is activated.
    let first = vec![b'a'; 120];
    let second = vec![b'b'; 120];
    let mut bytes = first.clone();
    bytes.extend_from_slice(&second);
    test_case_with_refs("PUSHREF SHA256C", vec![snake(&[&first, &second])])
        .with_block_version(14)
        .expect_stack(&expected_hash(&bytes));
}

#[test]
fn sha256c_is_rejected_before_version_14() {
    test_case_with_refs("PUSHREF SHA256C", vec![snake(&[b"hello world"])])
        .with_block_version(13)
        .expect_failure(ExceptionCode::InvalidOpcode);
}

#[test]
fn sha256c_rejects_noncanonical_cells() {
    let mut two_refs = BuilderData::new();
    two_refs.checked_append_reference(snake(&[b"one"])).unwrap();
    two_refs.checked_append_reference(snake(&[b"two"])).unwrap();
    test_case_with_refs("PUSHREF SHA256C", vec![two_refs.into_cell().unwrap()])
        .with_block_version(14)
        .expect_failure(ExceptionCode::CellUnderflow);

    let mut non_byte_aligned = BuilderData::new();
    non_byte_aligned.append_bit_one().unwrap();
    test_case_with_refs("PUSHREF SHA256C", vec![non_byte_aligned.into_cell().unwrap()])
        .with_block_version(14)
        .expect_failure(ExceptionCode::CellUnderflow);
}
