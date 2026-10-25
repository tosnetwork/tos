/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    error::TvmError,
    executor::{
        engine::{storage::fetch_stack, Engine},
        types::Instruction,
    },
    stack::{
        integer::{conversion::FromInt, IntegerData},
        StackItem,
    },
};
use chain_block::{fail, ExceptionCode, Status};
use num::bigint::Sign;

pub mod gas_state;

fn setgaslimit(engine: &mut Engine, gas_limit: i64) -> Status {
    let gas_used = engine.gas_used();
    if gas_limit < gas_used {
        fail!(TvmError::exception(
            ExceptionCode::OutOfGas,
            "gas limit below the gas used",
            gas_used,
            file!(),
            line!()
        ));
    }
    engine.new_gas_limit(gas_limit);
    Ok(())
}

// Application-specific primitives - A.10; Gas-related primitives - A.10.2
// ACCEPT - F800
pub fn execute_accept(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ACCEPT"))?;
    engine.new_gas_limit(i64::MAX);
    Ok(())
}
// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// SETGASLIMIT - F801
pub fn execute_setgaslimit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETGASLIMIT"))?;
    fetch_stack(engine, 1)?;
    // At most 0 means 0; from 2^63 the limit is unlimited, as ACCEPT sets it. NaN is an overflow.
    let gas_limit = engine.cmd.var(0).as_integer()?.take_value_of(|x| {
        Some(match x.sign() {
            Sign::Plus => i64::from_int(x).unwrap_or(i64::MAX),
            Sign::Minus | Sign::NoSign => 0,
        })
    })?;
    setgaslimit(engine, gas_limit)
}

// Returns gas consumed by VM so far (including this instruction).
pub fn execute_gasconsumed(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GASCONSUMED"))?;
    let gas = engine.gas_used();
    engine.cc.stack.push(int!(gas));
    Ok(())
}

// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// COMMIT - F80F
pub fn execute_commit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("COMMIT"))?;
    engine.try_commit()
}
