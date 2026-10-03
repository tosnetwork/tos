// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::lms_fee;
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
    /// The backend's own MLD_ERR_INVALID_SIGNATURE, exported by the C shim so
    /// the value is never restated here and cannot drift from the header.
    static tos_rust_mldsa44_invalid_signature: i32;
}

fn read_bytes(engine: &mut Engine, cell: Cell, limit: usize) -> Result<Vec<u8>> {
    read_bytes_priced(engine, cell, limit, 1)
}

fn read_bytes_priced(
    engine: &mut Engine,
    mut cell: Cell,
    limit: usize,
    byte_gas: i64,
) -> Result<Vec<u8>> {
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
        let charge = (size as i64).checked_mul(byte_gas);
        let Some(charge) = charge else {
            fail!(ExceptionCode::OutOfGas);
        };
        engine.try_use_gas(charge)?;
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
    // SAFETY: reading a const int the shim defines at compile time.
    let invalid_signature = unsafe { tos_rust_mldsa44_invalid_signature };
    let valid = if status == 0 {
        true
    } else if status == invalid_signature {
        false
    } else {
        fail!(ExceptionCode::FatalError, "ML-DSA verifier backend failure");
    };
    // Deliberately do not consult chksig_always_succeed or the classic free-call allowance.
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_pq_constants.rs"]
mod tests;

extern "C" {
    fn tos_falcon512_padded_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> i32;
}

pub(super) fn execute_pq_falcon512(engine: &mut Engine) -> Status {
    if engine.block_version() < 19 {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_FALCON512_PADDED"))?;
    if engine.cc.stack.depth() < 3 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(20_000)?;
    fetch_stack(engine, 3)?;
    let key = engine.cmd.var(0).as_cell()?.clone();
    let signature = engine.cmd.var(1).as_cell()?.clone();
    let message = engine.cmd.var(2).as_cell()?.clone();
    let key = read_bytes(engine, key, 897)?;
    let signature = read_bytes(engine, signature, 666)?;
    let message = read_bytes(engine, message, 8192)?;
    if key.len() != 897 || signature.len() != 666 {
        fail!(ExceptionCode::CellUnderflow, "incorrect Falcon-512 padded length");
    }
    // SAFETY: bounded owned buffers outlive this synchronous, verify-only call.
    let result = unsafe {
        tos_falcon512_padded_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            key.as_ptr(),
            key.len(),
        )
    };
    let valid = match result {
        1 => true,
        0 => false,
        -1 => {
            fail!(ExceptionCode::CellUnderflow);
        }
        _ => {
            fail!(ExceptionCode::FatalError, "Falcon-512 verifier backend failure");
        }
    };
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}

extern "C" {
    fn tos_rust_slhdsa128s_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        context: *const u8,
        context_len: usize,
        public_key: *const u8,
    ) -> i32;
}

// PROTOTYPE generic instruction F93102 (version 19 in this prototype; the R0a proposal moves
// it to a new version gate): message context signature public_key suite -> bool. Order of pops,
// charges and errors follows the C++ VM exactly; the parity scenarios check that.
const SUITE_MLDSA44: i32 = 1;
const SUITE_FALCON512: i32 = 2;
const SUITE_SLHDSA128S: i32 = 3;
const SUITE_LMS_FEE: i32 = 4;
const SLH_BASE_GAS: i64 = 750_000;
const SLH_PUBLIC_KEY_BYTES: usize = 32;
const SLH_SIGNATURE_BYTES: usize = 7856;
const LMS_BASE_GAS: i64 = 500;
const LMS_GAS_PER_COMPRESSION: i64 = 3;

fn push_outcome(engine: &mut Engine, valid: Option<bool>, name: &str) -> Status {
    match valid {
        Some(v) => {
            engine.cc.stack.push(StackItem::boolean(v));
            Ok(())
        }
        None => fail!(ExceptionCode::CellUnderflow, "malformed {} input", name),
    }
}

pub(super) fn execute_pq_suite(engine: &mut Engine) -> Status {
    if engine.block_version() < 19 {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_SUITE"))?;
    if engine.cc.stack.depth() < 5 {
        fail!(ExceptionCode::StackUnderflow);
    }
    fetch_stack(engine, 5)?;
    let suite = engine.cmd.var(0).as_integer_value(0..=255)?;
    let key = engine.cmd.var(1).as_cell()?.clone();
    let signature = engine.cmd.var(2).as_cell()?.clone();
    let context = engine.cmd.var(3).as_cell()?.clone();
    let message = engine.cmd.var(4).as_cell()?.clone();
    match suite {
        SUITE_MLDSA44 => {
            engine.try_use_gas(BASE_GAS)?;
            let key = read_bytes(engine, key, PUBLIC_KEY_BYTES)?;
            let signature = read_bytes(engine, signature, SIGNATURE_BYTES)?;
            let context = read_bytes(engine, context, MAX_CONTEXT_BYTES)?;
            let message = read_bytes(engine, message, MAX_MESSAGE_BYTES)?;
            if key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
                fail!(ExceptionCode::CellUnderflow, "malformed ML-DSA-44 input");
            }
            // SAFETY: fixed-size buffers checked above, owned for this synchronous call.
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
            // SAFETY: reading a const int the shim defines at compile time.
            let invalid_signature = unsafe { tos_rust_mldsa44_invalid_signature };
            if status == 0 {
                push_outcome(engine, Some(true), "ML-DSA-44")
            } else if status == invalid_signature {
                push_outcome(engine, Some(false), "ML-DSA-44")
            } else {
                fail!(ExceptionCode::FatalError, "ML-DSA-44 verifier backend failure")
            }
        }
        SUITE_FALCON512 => {
            engine.try_use_gas(20_000)?;
            // Falcon has no context parameter; only the empty context is accepted.
            read_bytes(engine, context, 0)?;
            let key = read_bytes(engine, key, 897)?;
            let signature = read_bytes(engine, signature, 666)?;
            let message = read_bytes(engine, message, 8192)?;
            // SAFETY: bounded owned buffers outlive this synchronous, verify-only call.
            let result = unsafe {
                tos_falcon512_padded_verify(
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    key.as_ptr(),
                    key.len(),
                )
            };
            match result {
                1 => push_outcome(engine, Some(true), "Falcon-512"),
                0 => push_outcome(engine, Some(false), "Falcon-512"),
                -1 => push_outcome(engine, None, "Falcon-512"),
                _ => fail!(ExceptionCode::FatalError, "Falcon-512 verifier backend failure"),
            }
        }
        SUITE_SLHDSA128S => {
            engine.try_use_gas(SLH_BASE_GAS)?;
            let key = read_bytes(engine, key, SLH_PUBLIC_KEY_BYTES)?;
            let signature = read_bytes(engine, signature, SLH_SIGNATURE_BYTES)?;
            let context = read_bytes(engine, context, MAX_CONTEXT_BYTES)?;
            let message = read_bytes(engine, message, MAX_MESSAGE_BYTES)?;
            if key.len() != SLH_PUBLIC_KEY_BYTES || signature.len() != SLH_SIGNATURE_BYTES {
                return push_outcome(engine, None, "SLH-DSA-SHA2-128s");
            }
            // SAFETY: lengths checked above; owned buffers outlive this synchronous call.
            let result = unsafe {
                tos_rust_slhdsa128s_verify(
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    context.as_ptr(),
                    context.len(),
                    key.as_ptr(),
                )
            };
            match result {
                1 => push_outcome(engine, Some(true), "SLH-DSA-SHA2-128s"),
                0 => push_outcome(engine, Some(false), "SLH-DSA-SHA2-128s"),
                _ => fail!(ExceptionCode::FatalError, "SLH-DSA-SHA2-128s verifier backend failure"),
            }
        }
        SUITE_LMS_FEE => {
            read_bytes_priced(engine, context, 0, 0)?;
            let key = read_bytes_priced(engine, key, lms_fee::PUBLIC_KEY_BYTES, 0)?;
            let message = read_bytes_priced(engine, message, lms_fee::MAX_MESSAGE_BYTES, 0)?;
            let Some(worst) = lms_fee::worst_compressions(&key, message.len()) else {
                fail!(ExceptionCode::CellUnderflow, "unsupported LMS fee profile");
            };
            // Charge the worst case for this profile before reading or verifying the signature.
            let charge = i64::try_from(worst)
                .ok()
                .and_then(|w| w.checked_mul(LMS_GAS_PER_COMPRESSION))
                .and_then(|g| g.checked_add(LMS_BASE_GAS));
            let Some(charge) = charge else {
                fail!(ExceptionCode::OutOfGas);
            };
            engine.try_use_gas(charge)?;
            let signature = read_bytes_priced(engine, signature, lms_fee::MAX_SIGNATURE_BYTES, 0)?;
            match lms_fee::verify(&message, &signature, &key) {
                lms_fee::Outcome::Valid => push_outcome(engine, Some(true), "LMS fee"),
                lms_fee::Outcome::Invalid => push_outcome(engine, Some(false), "LMS fee"),
                lms_fee::Outcome::Malformed => push_outcome(engine, None, "LMS fee"),
            }
        }
        _ => fail!(ExceptionCode::RangeCheckError, "unknown PQ suite"),
    }
}
