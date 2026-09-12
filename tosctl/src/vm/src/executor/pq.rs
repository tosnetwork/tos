// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{
    engine::{storage::fetch_stack, Engine},
    gas::gas_state::Gas,
    types::Instruction,
};
use crate::stack::StackItem;
use chain_block::{fail, Cell, CellType, ExceptionCode, Result, Status};

const PUBLIC_KEY_BYTES: usize = 1312;
const SIGNATURE_BYTES: usize = 2420;
const MAX_MESSAGE_BYTES: usize = 8192;
const MAX_CONTEXT_BYTES: usize = 255;
const BASE_GAS: i64 = 50_000;
const CHUNK_BYTES: usize = 127;

extern "C" {
    fn tos_rust_mldsa44_native_verify(
        sig: *const u8,
        message: *const u8,
        message_len: usize,
        context: *const u8,
        context_len: usize,
        public_key: *const u8,
    ) -> i32;
}

fn read_bytes(engine: &mut Engine, mut cell: Cell, limit: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    loop {
        if cell.level() != 0 {
            fail!(ExceptionCode::CellUnderflow, "PQ cells must have level zero");
        }
        // Meter the actual cell load, including repeated-cell cache hits, but do
        // not resolve library references into a different byte string.
        let slice = engine.load_hashed_cell(cell, false)?;
        let size = slice.remaining_bits() / 8;
        let refs = slice.remaining_references();
        if slice.cell_type() != CellType::Ordinary
            || slice.level() != 0
            || slice.remaining_bits() % 8 != 0
            || refs > 1
            || size > CHUNK_BYTES
            || (refs != 0 && size != CHUNK_BYTES)
            || (size == 0 && (!result.is_empty() || refs != 0))
            || size > limit.saturating_sub(result.len())
        {
            fail!(ExceptionCode::CellUnderflow, "noncanonical PQ byte chain");
        }
        engine.try_use_gas(size as i64)?;
        result.extend_from_slice(&slice.get_bytestring(0));
        if refs == 0 {
            return Ok(result);
        }
        cell = slice.reference(0)?;
    }
}

pub(super) fn execute_pq_mldsa44(engine: &mut Engine) -> Status {
    // Preserve historical exception metering before activation. From v4 the
    // invalid-instruction charge can exhaust gas before exception dispatch;
    // older versions charge the exception too before detecting exhaustion.
    if engine.block_version() < 16 {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_MLDSA44"))?;
    if engine.cc.stack.depth() < 4 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(BASE_GAS)?;
    fetch_stack(engine, 4)?;
    // Type-check all four values before decoding any, in top-to-bottom order.
    let key = engine.cmd.var(0).as_cell()?.clone();
    let signature = engine.cmd.var(1).as_cell()?.clone();
    let context = engine.cmd.var(2).as_cell()?.clone();
    let message = engine.cmd.var(3).as_cell()?.clone();
    let key = read_bytes(engine, key, PUBLIC_KEY_BYTES)?;
    let signature = read_bytes(engine, signature, SIGNATURE_BYTES)?;
    let context = read_bytes(engine, context, MAX_CONTEXT_BYTES)?;
    let message = read_bytes(engine, message, MAX_MESSAGE_BYTES)?;
    if key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        fail!(ExceptionCode::CellUnderflow, "incorrect ML-DSA-44 input length");
    }
    // SAFETY: the fixed-size buffers have been checked above; Vec owns all
    // buffers throughout this synchronous call, including non-null empty slices.
    // No mutable key material, random source or runtime provider participates.
    let status = unsafe {
        tos_rust_mldsa44_native_verify(
            signature.as_ptr(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            key.as_ptr(),
        )
    };
    let valid = match status {
        0 => true,
        -6 => false, // The pinned backend's MLD_ERR_INVALID_SIGNATURE.
        _ => {
            fail!(ExceptionCode::FatalError, "ML-DSA verifier backend failure");
        }
    };
    // Deliberately do not consult chksig_always_succeed or the classic free-call allowance.
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}
