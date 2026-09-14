use super::{
    engine::{storage::fetch_stack, Engine},
    gas::gas_state::Gas,
    types::Instruction,
};
use crate::stack::StackItem;
use chain_block::{
    fail, sha256_digest, Cell, CellType, ExceptionCode, GlobalCapabilities, Result, SliceData,
    Status,
};
use tos_validator_auth_crypto::AdmittedKey;

const CAPABILITY: u64 = GlobalCapabilities::CapValidatorAuth as u64;
const MAX_MESSAGE: usize = 65536;
const BASE_GAS: i64 = 50000;

fn ordinary(engine: &mut Engine, cell: Cell) -> Result<SliceData> {
    if cell.level() != 0 {
        fail!(ExceptionCode::CellUnderflow, "P0 AuthBytes must have level zero");
    }
    let slice = engine.load_hashed_cell(cell, false)?;
    if slice.cell_type() != CellType::Ordinary || slice.level() != 0 {
        fail!(ExceptionCode::CellUnderflow, "P0 AuthBytes must use ordinary cells");
    }
    Ok(slice)
}

fn read_node(engine: &mut Engine, cell: Cell, expected: usize, output: &mut Vec<u8>) -> Status {
    let mut slice = ordinary(engine, cell)?;
    let branch = slice.get_next_bit()?;
    if expected <= 120 {
        if branch {
            fail!(ExceptionCode::CellUnderflow, "invalid P0 byte leaf");
        }
        let size = slice.get_next_int(7)? as usize;
        if size != expected
            || size == 0
            || slice.remaining_bits() != size * 8
            || slice.remaining_references() != 0
        {
            fail!(ExceptionCode::CellUnderflow, "noncanonical P0 byte leaf");
        }
        engine.try_use_gas(size as i64)?;
        output.extend_from_slice(&slice.get_next_bits(size * 8)?);
    } else {
        if !branch || slice.remaining_bits() != 35 {
            fail!(ExceptionCode::CellUnderflow, "invalid P0 byte branch");
        }
        let count = slice.get_next_int(3)? as usize;
        let length = slice.get_next_u32()? as usize;
        let mut cap = 120;
        while expected > 4 * cap {
            cap *= 4;
        }
        if length != expected
            || count != expected.div_ceil(cap)
            || !(2..=4).contains(&count)
            || slice.remaining_references() != count
        {
            fail!(ExceptionCode::CellUnderflow, "noncanonical P0 byte partition");
        }
        // Each canonical child has a strictly smaller expected size. The admitted
        // root length bounds recursion, total cell occurrences and output bytes.
        for index in 0..expected.div_ceil(cap) {
            read_node(engine, slice.reference(index)?, cap.min(expected - index * cap), output)?;
        }
    }
    Ok(())
}

fn read_message(engine: &mut Engine, cell: Cell) -> Result<Vec<u8>> {
    let mut slice = ordinary(engine, cell)?;
    if slice.remaining_bits() != 336
        || slice.remaining_references() != 1
        || slice.get_next_u32()? != 0x76616231
        || slice.get_next_u16()? != 1
    {
        fail!(ExceptionCode::CellUnderflow, "invalid P0 AuthBytes root");
    }
    let size = slice.get_next_u32()? as usize;
    if size == 0 || size > MAX_MESSAGE {
        fail!(ExceptionCode::CellUnderflow, "P0 message bound");
    }
    let hash = slice.get_next_bits(256)?;
    let mut output = Vec::with_capacity(size);
    read_node(engine, slice.reference(0)?, size, &mut output)?;
    if sha256_digest(&output).as_slice() != hash {
        fail!(ExceptionCode::CellUnderflow, "P0 message hash mismatch");
    }
    Ok(output)
}

pub(super) fn execute_p0_chksign(engine: &mut Engine) -> Status {
    if engine.block_version() < 16 || !engine.check_capabilities(CAPABILITY) {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("VAUTH_CHKSIGN"))?;
    if engine.cc.stack.depth() < 3 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(BASE_GAS)?;
    fetch_stack(engine, 3)?;
    let public_key = engine.cmd.var(0).as_integer()?.as_vec(256, false, true)?;
    let signature = engine.cmd.var(1).as_slice()?;
    let message = engine.cmd.var(2).as_cell()?.clone();
    if signature.remaining_bits() != 512 || signature.remaining_references() != 0 {
        fail!(
            ExceptionCode::CellUnderflow,
            "P0 signature must be exactly 512 bits without references"
        );
    }
    let signature = signature.get_bytestring(0);
    let message = read_message(engine, message)?;
    // No generic signature bypass or free-call counter supplies authorization.
    let valid = match AdmittedKey::admit(&public_key) {
        Ok(key) => key.verify(&message, &signature),
        Err(_) => false,
    };
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}

fn native_gate(engine: &mut Engine) -> Status {
    if engine.block_version() < 16 || !engine.check_capabilities(CAPABILITY) {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    Ok(())
}
fn charge_native(engine: &mut Engine, gas: i64) -> Status {
    if gas < 0 {
        fail!(ExceptionCode::RangeCheckError);
    }
    engine.try_use_gas(gas)
}
pub(super) fn execute_p0_state(engine: &mut Engine) -> Status {
    native_gate(engine)?;
    engine.load_instruction(Instruction::new("VAUTH_STATE"))?;
    let Some(host) = engine.validator_auth_host() else {
        fail!(ExceptionCode::InvalidOpcode);
    };
    let result = host
        .lock()
        .map_err(|_| chain_block::error!("P0 host poisoned"))?
        .checkpoint(&mut |gas| charge_native(engine, gas))?;
    engine.cc.stack.push(StackItem::Cell(result));
    Ok(())
}
pub(super) fn execute_p0_apply(engine: &mut Engine) -> Status {
    native_gate(engine)?;
    engine.load_instruction(Instruction::new("VAUTH_APPLY"))?;
    let Some(host) = engine.validator_auth_host() else {
        fail!(ExceptionCode::InvalidOpcode);
    };
    if engine.cc.stack.depth() < 2 {
        fail!(ExceptionCode::StackUnderflow);
    }
    fetch_stack(engine, 2)?;
    let evidence = engine.cmd.var(0).as_cell()?.clone();
    let update = engine.cmd.var(1).as_cell()?.clone();
    let result = host.lock().map_err(|_| chain_block::error!("P0 host poisoned"))?.apply(
        update,
        evidence,
        &mut |gas| charge_native(engine, gas),
    )?;
    engine.cc.stack.push(StackItem::Cell(result));
    Ok(())
}
