/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The Poseidon2 instruction pair in the Rust VM, against the same generated
//! vectors the C++ VM is checked with. The permutation itself is tested in
//! `chain_block`; what is checked here is the instruction: its stack contract,
//! the version it starts at, what it refuses, and what it costs.

use chain_block::{
    poseidon2_kat::{HASH7, PERM8},
    poseidon2_params::MODULUS_BE,
    BuilderData, Cell, ExceptionCode, IBitstring,
};
use tos_vm::stack::{integer::IntegerData, Stack, StackItem};

mod common;
use common::*;

const ACTIVE_VERSION: u32 = 17;
/// The measured tariff, the cost of a 24-bit instruction, and the implicit
/// return. Written as specification literals, not read from the
/// implementation: a test that reads the constant it checks cannot catch that
/// constant changing.
const EXPECTED_GAS: i64 = 2800 + 34 + 5;

fn stack_of(values: &[[u8; 32]]) -> Stack {
    let mut stack = Stack::new();
    for value in values {
        stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(value)));
    }
    stack
}

fn field(value: &[u8; 32]) -> StackItem {
    StackItem::int(IntegerData::from_unsigned_bytes_be(value))
}

/// The eight-lane state with one lane replaced, so a rejection can be attributed
/// to a lane rather than to the shape of the stack.
fn stack_with_lane(values: &[[u8; 32]; 8], lane: usize, item: StackItem) -> Stack {
    let mut stack = Stack::new();
    for (index, value) in values.iter().enumerate() {
        stack.push(if index == lane { item.clone() } else { field(value) });
    }
    stack
}

#[test]
fn every_pinned_permutation_vector_runs_in_the_vm() {
    for (name, input, output) in PERM8 {
        test_case("POSEIDON2_PERM8")
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success_extended(Some(name))
            .expect_stack_extended(&stack_of(&output), Some(name));
    }
}

#[test]
fn every_pinned_hash_vector_runs_in_the_vm() {
    for (name, state, output) in HASH7 {
        test_case("POSEIDON2_HASH7")
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&state))
            .expect_success_extended(Some(name))
            .expect_stack_extended(Stack::new().push(field(&output)), Some(name));
    }
}

#[test]
fn hash7_is_lane_zero_of_the_permutation_and_no_other_lane() {
    let (_, input, output) = PERM8[0];
    test_case("POSEIDON2_HASH7")
        .with_block_version(ACTIVE_VERSION)
        .with_stack(stack_of(&input))
        .expect_success()
        .expect_stack(Stack::new().push(field(&output[0])));
    for lane in 1..8 {
        assert_ne!(output[0], output[lane], "lane {lane} coincides with the hash output");
    }
}

#[test]
fn neither_instruction_exists_before_its_version() {
    let (_, input, _) = PERM8[0];
    for version in 0..ACTIVE_VERSION {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            test_case(code)
                .with_block_version(version)
                .with_stack(stack_of(&input))
                .expect_failure_extended(
                    ExceptionCode::InvalidOpcode,
                    Some(&format!("{code} at version {version}")),
                );
        }
    }
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success();
    }
}

#[test]
fn anything_that_is_not_already_a_field_element_is_refused() {
    let (_, input, _) = PERM8[0];
    let mut largest = MODULUS_BE;
    largest[31] -= 1; // the modulus ends in 0x01, so this cannot borrow

    for lane in 0..8 {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            for (label, item) in [
                ("the modulus", field(&MODULUS_BE)),
                ("2^256-1", field(&[0xff; 32])),
                ("a negative value", StackItem::int(IntegerData::minus_one())),
            ] {
                test_case(code)
                    .with_block_version(ACTIVE_VERSION)
                    .with_stack(stack_with_lane(&input, lane, item))
                    .expect_failure_extended(
                        ExceptionCode::RangeCheckError,
                        Some(&format!("{label} accepted in lane {lane} by {code}")),
                    );
            }
            // The value immediately below the modulus must still be legal.
            test_case(code)
                .with_block_version(ACTIVE_VERSION)
                .with_stack(stack_with_lane(&input, lane, field(&largest)))
                .expect_success_extended(Some(&format!("largest field element in lane {lane}")));
        }
    }
}

#[test]
fn a_nan_operand_is_refused() {
    let (_, input, _) = PERM8[0];
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(format!("PUSHNAN\n{code}"))
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input[..7]))
            .expect_failure(ExceptionCode::RangeCheckError);
    }
}

#[test]
fn a_short_stack_underflows_and_a_wrong_type_is_a_type_error() {
    let (_, input, _) = PERM8[0];
    for depth in 0..8 {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            test_case(code)
                .with_block_version(ACTIVE_VERSION)
                .with_stack(stack_of(&input[..depth]))
                .expect_failure_extended(
                    ExceptionCode::StackUnderflow,
                    Some(&format!("{code} with {depth} operands")),
                );
        }
    }
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        let mut stack = stack_of(&input[..7]);
        stack.push(StackItem::None);
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack)
            .expect_failure(ExceptionCode::TypeCheckError);
    }
}

#[test]
fn both_instructions_cost_the_tariff() {
    let (_, input, _) = PERM8[0];
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success()
            .expect_gas_used(EXPECTED_GAS);
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .with_gas_limit(EXPECTED_GAS - 1)
            .expect_failure(ExceptionCode::OutOfGas);
    }
    // A refused operand is still charged: probing must not be cheaper.
    test_case("POSEIDON2_PERM8")
        .with_block_version(ACTIVE_VERSION)
        .with_stack(stack_with_lane(&input, 7, field(&MODULUS_BE)))
        .with_gas_limit(2800 - 1)
        .expect_failure(ExceptionCode::OutOfGas);
}

// --- POSEIDON2_PATH7 --------------------------------------------------------

/// The version PATH7 shipped in, which is one past the pair above.
const PATH7_VERSION: u32 = 18;
/// 500 base, 3,700 a level for twelve levels, and the twenty-four cells the
/// path is made of at the VM's own first-load price, plus the instruction and
/// the implicit return. Written as literals for the same reason as
/// `EXPECTED_GAS`.
///
/// The cell loads are what caught a divergence: the Rust VM's loader charges
/// them and the C++ one's does not, so the C++ implementation charges them
/// explicitly. Two VMs that price the same instruction differently do not
/// agree at all, and this is the assertion that says so.
const PATH7_EXPECTED_GAS: i64 = 500 + 12 * 3000 + 24 * 100 + 34 + 5;
const DEPTH: usize = 12;

/// A field element from a small number, which is always canonical.
fn small(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Section 7.2's path: two cells a level, three field elements each, the
/// first carrying a reference to the second and the second to the next level,
/// except at the last level where it carries none.
fn path_cells(siblings: &[[[u8; 32]; 6]], short_level: Option<usize>, extra_ref: bool) -> Cell {
    let mut next: Option<Cell> = None;
    for (level, six) in siblings.iter().enumerate().rev() {
        let last = level == siblings.len() - 1;
        for half in (0..2).rev() {
            let mut builder = BuilderData::new();
            let fields = if half == 0 { &six[..3] } else { &six[3..] };
            let mut written = 0;
            for value in fields {
                if short_level == Some(level) && half == 1 && written == 2 {
                    break; // one element missing, so the cell is 512 bits
                }
                builder.append_raw(value, 256).expect("a field element");
                written += 1;
            }
            let tail = last && half == 1;
            if let Some(child) = next.take() {
                builder.checked_append_reference(child).expect("a reference");
            }
            if tail && extra_ref {
                builder.checked_append_reference(Cell::default()).expect("an extra reference");
            }
            next = Some(builder.into_cell().expect("a path cell"));
        }
    }
    next.expect("a path")
}

/// The same fold, done with HASH7 alone, so the instruction is checked against
/// the primitive it is made of rather than against itself.
fn fold_with_hash7(
    leaf: [u8; 32],
    domain: [u8; 32],
    siblings: &[[[u8; 32]; 6]],
    index: u64,
) -> [u8; 32] {
    let mut carry = leaf;
    let mut remaining = index;
    for six in siblings {
        let digit = (remaining % 7) as usize;
        remaining /= 7;
        let mut state = [[0u8; 32]; 8];
        state[0] = domain;
        let mut taken = 0;
        for slot in 0..7 {
            state[1 + slot] = if slot == digit {
                carry
            } else {
                let value = six[taken];
                taken += 1;
                value
            };
        }
        carry = chain_block::poseidon2::permute(&state)[0];
    }
    carry
}

fn sample(levels: usize) -> Vec<[[u8; 32]; 6]> {
    (0..levels)
        .map(|level| core::array::from_fn(|i| small(0x5eed_0000 + (level * 6 + i) as u64)))
        .collect()
}

fn path_stack(leaf: [u8; 32], domain: [u8; 32], path: Cell, index: u64, depth: u64) -> Stack {
    let mut stack = Stack::new();
    stack.push(field(&leaf));
    stack.push(field(&domain));
    stack.push(StackItem::Cell(path));
    stack.push(StackItem::int(IntegerData::from(index).expect("an index")));
    stack.push(StackItem::int(IntegerData::from(depth).expect("a depth")));
    stack
}

/// The instruction computes what the primitive computes, twelve times.
#[test]
fn a_path_is_the_same_fold_done_with_hash7() {
    let siblings = sample(DEPTH);
    let leaf = small(0x1234);
    let domain = small(0x4321);
    // Indices whose base-seven digits exercise every child position.
    for index in [0u64, 1, 6, 7, 48, 117_648, 13_841_287_200 % 13_841_287_201] {
        let expected = fold_with_hash7(leaf, domain, &siblings, index);
        test_case("POSEIDON2_PATH7")
            .with_block_version(PATH7_VERSION)
            .with_stack(path_stack(
                leaf,
                domain,
                path_cells(&siblings, None, false),
                index,
                DEPTH as u64,
            ))
            .expect_success_extended(Some(&format!("index {index}")))
            .expect_stack_extended(&stack_of(&[expected]), Some(&format!("index {index}")));
    }
}

/// The one vector both VMs are pinned to.
///
/// The C++ VM had no path test at all, and shipped a fold that wrote the
/// domain into lane 0 once before the loop rather than at every level --
/// `permute` works in place there, so from the second level on it folded its
/// own previous output in place of the domain. Nothing disagreed until a pool
/// was deployed on a node: every contract test runs in this VM.
///
/// So the two now share a vector. `test/poseidon2/test.cpp` computes the same
/// path and asserts the same constant; if either implementation moves, both
/// tests say so.
#[test]
fn the_vector_the_cpp_vm_is_pinned_to() {
    // Byte for byte what `check_path7` in test/poseidon2/test.cpp builds.
    let leaf = small(0x11);
    let domain = small(0x072b);
    let siblings: Vec<[[u8; 32]; 6]> = (0..4)
        .map(|level: u64| {
            core::array::from_fn(|position| {
                small(((level + 1) << 16) | ((position as u64 + 1) << 8) | 0x5b)
            })
        })
        .collect();
    // Digits 3, 1, 6, 0 in base seven.
    let index = 3 + 7 * (1 + 7 * (6 + 7 * 0));

    let produced = fold_with_hash7(leaf, domain, &siblings, index);
    assert_eq!(
        hex::encode(produced),
        CPP_VM_VECTOR,
        "this VM's path fold no longer matches the vector the C++ VM is pinned to"
    );
    test_case("POSEIDON2_PATH7")
        .with_block_version(PATH7_VERSION)
        .with_stack(path_stack(leaf, domain, path_cells(&siblings, None, false), index, 4))
        .expect_success()
        .expect_stack(&stack_of(&[produced]));
}

/// Pinned in `test/poseidon2/test.cpp` as `kRustVm`.
const CPP_VM_VECTOR: &str = "12d4dd5748fd48cd8a53067a28ca130a52134c5877c81426b8328cdacfa0ee35";

#[test]
/// An index that does not fit its depth is decided before any level is paid
/// for.
///
/// Pinned by starving it rather than by reading a gas figure: given a budget
/// that covers the base charge and no level, the refusal must still be a range
/// check. A VM that walked the twelve levels first would run out of gas before
/// it ever looked at the leftover digit, and would answer `OutOfGas` here.
///
/// This is the half that was missing. The malformed corpus below asserts the
/// exception and says nothing about the price, and the two VMs disagreed about
/// the price by twelve levels -- the C++ one charged more to refuse an
/// oversized index than to walk a real path. An exception that is right at any
/// price is not the same instruction.
#[test]
fn an_index_past_the_depth_is_refused_before_a_level_is_charged() {
    let siblings = sample(DEPTH);
    // 7^12: the smallest index needing a thirteenth base-seven digit.
    const PAST_THE_DEPTH: u64 = 13_841_287_201;
    // The base, and not one level. Enough slack for the surrounding
    // continuation, nowhere near the 3,000 a level costs.
    const ONLY_THE_BASE: i64 = 500 + 100;

    test_case("POSEIDON2_PATH7")
        .with_block_version(PATH7_VERSION)
        .with_stack(path_stack(
            small(1),
            small(2),
            path_cells(&siblings, None, false),
            PAST_THE_DEPTH,
            DEPTH as u64,
        ))
        .with_gas_limit(ONLY_THE_BASE)
        .expect_failure(ExceptionCode::RangeCheckError);
}

#[test]
fn a_path_costs_its_base_plus_a_level() {
    let siblings = sample(DEPTH);
    test_case("POSEIDON2_PATH7")
        .with_block_version(PATH7_VERSION)
        .with_stack(path_stack(
            small(1),
            small(2),
            path_cells(&siblings, None, false),
            5,
            DEPTH as u64,
        ))
        .expect_success()
        .expect_gas_used(PATH7_EXPECTED_GAS);
}

#[test]
fn the_path_instruction_does_not_exist_before_its_version() {
    let siblings = sample(DEPTH);
    for version in 0..PATH7_VERSION {
        test_case("POSEIDON2_PATH7")
            .with_block_version(version)
            .with_stack(path_stack(
                small(1),
                small(2),
                path_cells(&siblings, None, false),
                5,
                DEPTH as u64,
            ))
            .expect_failure_extended(
                ExceptionCode::InvalidOpcode,
                Some(&format!("POSEIDON2_PATH7 at version {version}")),
            );
    }
}

/// The five refusals the specification names, each with the input that trips
/// it. Removing any one of them makes exactly one of these pass.
#[test]
fn every_malformed_path_is_refused() {
    let siblings = sample(DEPTH);
    let good = || path_cells(&siblings, None, false);
    let run = |stack: Stack, code: ExceptionCode, what: &str| {
        test_case("POSEIDON2_PATH7")
            .with_block_version(PATH7_VERSION)
            .with_stack(stack)
            .expect_failure_extended(code, Some(what));
    };

    // A cell that is not three field elements.
    run(
        path_stack(small(1), small(2), path_cells(&siblings, Some(4), false), 5, DEPTH as u64),
        ExceptionCode::CellUnderflow,
        "a short level",
    );
    // A reference where the layout allows none.
    run(
        path_stack(small(1), small(2), path_cells(&siblings, None, true), 5, DEPTH as u64),
        ExceptionCode::CellUnderflow,
        "an extra reference on the last cell",
    );
    // A sibling at the modulus, which must be rejected and not reduced.
    let mut poisoned = siblings.clone();
    poisoned[3][2] = MODULUS_BE;
    run(
        path_stack(small(1), small(2), path_cells(&poisoned, None, false), 5, DEPTH as u64),
        ExceptionCode::RangeCheckError,
        "a sibling at the modulus",
    );
    // A depth past the bound, and one below it.
    run(
        path_stack(small(1), small(2), good(), 5, 65),
        ExceptionCode::RangeCheckError,
        "a depth past the bound",
    );
    run(
        path_stack(small(1), small(2), good(), 5, 0),
        ExceptionCode::RangeCheckError,
        "a zero depth",
    );
    // An index with a digit left over after the depth given.
    run(
        path_stack(small(1), small(2), good(), 13_841_287_201, DEPTH as u64),
        ExceptionCode::RangeCheckError,
        "an index past the depth",
    );
    // A path shorter than the depth.
    run(
        path_stack(
            small(1),
            small(2),
            path_cells(&sample(DEPTH - 1), None, false),
            5,
            DEPTH as u64,
        ),
        ExceptionCode::CellUnderflow,
        "a path shorter than its depth",
    );
}
