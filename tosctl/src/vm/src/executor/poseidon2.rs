// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! The Poseidon2 t=8 instruction pair, mirroring `crypto/vm/poseidon2ops.cpp`.
//! The permutation itself lives in `chain_block::poseidon2`, beside the frozen
//! parameters it reads; what is here is the stack contract, the version gate,
//! the tariff, and the refusal of anything that is not already a field element.

use super::{
    engine::{storage::fetch_stack, Engine},
    gas::gas_state::Gas,
    types::Instruction,
};
use crate::stack::{integer::IntegerData, StackItem};
use chain_block::{fail, poseidon2, Cell, ExceptionCode, Result, Status};

pub(super) const MIN_VERSION: u32 = 17;
/// Measured against instructions whose price is already fixed, and matching
/// `poseidon2_perm8_gas_price` in the C++ VM. See the note there; the two are
/// changed at once.
///
/// This VM is the slower of the two for this instruction -- 1.66x, where the
/// BLS anchors differ by 1.08 to 1.17 -- so this price is the one it set.
pub(super) const GAS_PRICE: i64 = 2800;

const STATE_WIDTH: usize = 8;

/// Fail closed. A negative value, one that does not fit in 256 unsigned bits,
/// and one at or above the modulus are all refused rather than reduced: a
/// silent reduction would let two different stack values hash the same.
fn field_bytes(value: &IntegerData) -> Result<poseidon2::FieldBytes> {
    if value.is_nan() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is not a number");
    }
    if value.is_neg() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is negative");
    }
    let bytes = value.as_u256()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    if !poseidon2::is_canonical(&out) {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is not below the field modulus");
    }
    Ok(out)
}

/// Both instructions consume a whole state and differ only in what they return.
fn permute_stack_state(
    engine: &mut Engine,
    name: &'static str,
) -> Result<[poseidon2::FieldBytes; STATE_WIDTH]> {
    // Before activation the opcode does not exist. The metering matches the
    // older instruction's: from v4 the invalid-instruction charge can exhaust
    // gas before exception dispatch, earlier versions charge it regardless.
    if engine.block_version() < MIN_VERSION {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new(name))?;
    if engine.cc.stack.depth() < STATE_WIDTH {
        fail!(ExceptionCode::StackUnderflow);
    }
    // Charged before the operands are inspected, so probing for a valid field
    // element is never cheaper than doing the work.
    engine.try_use_gas(GAS_PRICE)?;
    fetch_stack(engine, STATE_WIDTH)?;
    let mut state = [[0u8; 32]; STATE_WIDTH];
    for index in 0..STATE_WIDTH {
        // var(0) is the top of the stack, which is the last lane of the state.
        state[STATE_WIDTH - 1 - index] = field_bytes(engine.cmd.var(index).as_integer()?)?;
    }
    Ok(poseidon2::permute(&state))
}

pub(super) fn execute_poseidon2_perm8(engine: &mut Engine) -> Status {
    let result = permute_stack_state(engine, "POSEIDON2_PERM8")?;
    for value in result.iter() {
        engine.cc.stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(value)));
    }
    Ok(())
}

pub(super) fn execute_poseidon2_hash7(engine: &mut Engine) -> Status {
    // The domain constant sits in lane 0 and the result is lane 0: no capacity
    // element and no padding rule beyond that.
    let result = permute_stack_state(engine, "POSEIDON2_HASH7")?;
    engine.cc.stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(&result[0])));
    Ok(())
}

// --- POSEIDON2_PATH7 --------------------------------------------------------

/// PATH7 is newer than the two above; a node built for 17 implements them and
/// not it.
pub(super) const PATH7_MIN_VERSION: u32 = 18;
/// Matching `poseidon2_path7_*_gas_price` in the C++ VM, and changed with it.
/// One HASH7 a level plus the two cells the level's siblings live in, so
/// moving the loop into the VM buys nothing cheaply. Neither figure is
/// measured; see the note in `crypto/vm/poseidon2ops.h`.
pub(super) const PATH7_BASE_GAS_PRICE: i64 = 500;
pub(super) const PATH7_LEVEL_GAS_PRICE: i64 = 3000;
/// A level is two 768-bit cells, so this is 128 cells.
const PATH7_MAX_DEPTH: usize = 64;

/// The depth operand, which must be a small positive integer inside the bound.
fn path_depth(value: &IntegerData) -> Result<usize> {
    if value.is_nan() || value.is_neg() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 path depth is not a positive integer");
    }
    let bytes = value.as_u256()?;
    let depth =
        if bytes[..31].iter().any(|byte| *byte != 0) { usize::MAX } else { usize::from(bytes[31]) };
    if depth < 1 || depth > PATH7_MAX_DEPTH {
        fail!(
            ExceptionCode::RangeCheckError,
            "Poseidon2 path depth is outside the permitted range"
        );
    }
    Ok(depth)
}

/// The base-seven digits of `index`, least significant first, and a refusal if
/// anything is left over: an index past the tree the given depth describes is
/// rejected rather than silently folded.
fn base7_digits(index: &IntegerData, depth: usize) -> Result<Vec<u8>> {
    if index.is_nan() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 path index is not a number");
    }
    if index.is_neg() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 path index is negative");
    }
    let mut value = [0u8; 32];
    value.copy_from_slice(&index.as_u256()?);
    let mut digits = Vec::with_capacity(depth);
    for _ in 0..depth {
        let mut remainder: u16 = 0;
        for byte in value.iter_mut() {
            let current = remainder * 256 + u16::from(*byte);
            *byte = (current / 7) as u8;
            remainder = current % 7;
        }
        digits.push(remainder as u8);
    }
    if value.iter().any(|byte| *byte != 0) {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 path index is past the depth given");
    }
    Ok(digits)
}

/// One level's three field elements, from a cell that must be exactly that and
/// carry exactly the reference count its position calls for.
///
/// Loaded through `load_hashed_cell`, which charges the cell and refuses a
/// pruned branch. The FunC this replaces relies on `begin_parse` doing the
/// same, and a path forged out of pruned branches would otherwise be an attack
/// on every caller of this instruction at once.
fn read_triple(
    engine: &mut Engine,
    cell: Option<Cell>,
    last: bool,
) -> Result<([poseidon2::FieldBytes; 3], Option<Cell>)> {
    let Some(cell) = cell else {
        fail!(ExceptionCode::CellUnderflow, "Poseidon2 path ends before its depth");
    };
    let mut slice = engine.load_hashed_cell(cell, false)?;
    if slice.remaining_bits() != 768 {
        fail!(ExceptionCode::CellUnderflow, "a Poseidon2 path cell is not three field elements");
    }
    let expected = usize::from(!last);
    if slice.remaining_references() != expected {
        fail!(ExceptionCode::CellUnderflow, "a Poseidon2 path cell has the wrong reference count");
    }
    let mut out = [[0u8; 32]; 3];
    for element in out.iter_mut() {
        let bits = slice.get_next_bits(256)?;
        element.copy_from_slice(&bits);
        // Rejected, never reduced.
        if !poseidon2::is_canonical(element) {
            fail!(
                ExceptionCode::RangeCheckError,
                "a Poseidon2 path sibling is not below the field modulus"
            );
        }
    }
    let next = if last { None } else { Some(slice.checked_drain_reference()?) };
    Ok((out, next))
}

pub(super) fn execute_poseidon2_path7(engine: &mut Engine) -> Status {
    if engine.block_version() < PATH7_MIN_VERSION {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("POSEIDON2_PATH7"))?;
    if engine.cc.stack.depth() < 5 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(PATH7_BASE_GAS_PRICE)?;
    fetch_stack(engine, 5)?;

    // var(0) is the top of the stack: (leaf domain path index depth - root).
    let depth = path_depth(engine.cmd.var(0).as_integer()?)?;
    let digits = base7_digits(engine.cmd.var(1).as_integer()?, depth)?;
    let path = engine.cmd.var(2).as_cell()?.clone();
    let domain = field_bytes(engine.cmd.var(3).as_integer()?)?;
    let mut carry = field_bytes(engine.cmd.var(4).as_integer()?)?;

    let mut node = Some(path);
    for (level, digit) in digits.iter().enumerate() {
        // Charged as the level is read, so an oversized path is paid for on
        // the way in rather than after it fails.
        engine.try_use_gas(PATH7_LEVEL_GAS_PRICE)?;
        let last = level == depth - 1;
        let (first, next) = read_triple(engine, node, false)?;
        let (second, after) = read_triple(engine, next, last)?;

        let mut state = [[0u8; 32]; STATE_WIDTH];
        state[0] = domain;
        let siblings = [first[0], first[1], first[2], second[0], second[1], second[2]];
        let mut taken = 0;
        for slot in 0..7 {
            state[1 + slot] = if slot == usize::from(*digit) {
                carry
            } else {
                let value = siblings[taken];
                taken += 1;
                value
            };
        }
        carry = poseidon2::permute(&state)[0];
        node = after;
    }
    if node.is_some() {
        fail!(ExceptionCode::CellUnderflow, "Poseidon2 path is longer than its depth");
    }
    engine.cc.stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(&carry)));
    Ok(())
}
