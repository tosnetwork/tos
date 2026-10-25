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
        integer::{behavior::Quiet, conversion::FromInt, math::Round, IntegerData},
        StackItem,
    },
};
use chain_block::{fail, ExceptionCode, Result, Status};
use num::bigint::Sign;

pub mod gas_state;

fn tomitogas(engine: &Engine, nanocoins: &IntegerData) -> Result<i64> {
    let gas_price = IntegerData::from_i64(engine.get_gas().get_gas_price());
    let gas = nanocoins.div::<Quiet>(&gas_price, Round::FloorToZero)?.0;
    let ret = gas.take_value_of(|x| i64::from_int(x).ok()).unwrap_or(i64::MAX);
    Ok(ret)
}
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
// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// BUYGAS - F802
pub fn execute_buygas(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BUYGAS"))?;
    fetch_stack(engine, 1)?;
    let nanocoins = engine.cmd.var(0).as_integer()?;
    let gas_limit = tomitogas(engine, nanocoins)?;
    setgaslimit(engine, gas_limit)
}
// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// TOMITOGAS - F804
pub fn execute_tomitogas(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("TOMITOGAS"))?;
    fetch_stack(engine, 1)?;
    let nanocoins_input = engine.cmd.var(0);
    let gas = if nanocoins_input.as_integer()?.is_neg() {
        0
    } else {
        let nanocoins = nanocoins_input.as_integer()?;
        tomitogas(engine, nanocoins)?
    };
    engine.cc.stack.push(int!(gas));
    Ok(())
}

// Returns gas consumed by VM so far (including this instruction).
pub fn execute_gasconsumed(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GASCONSUMED"))?;
    let gas = engine.gas_used();
    engine.cc.stack.push(int!(gas));
    Ok(())
}

// Application-specific primitives - A.10; Gas-related primitives - A.10.2
// GASTOTOMI - F805
pub fn execute_gastotomi(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GASTOTOMI"))?;
    fetch_stack(engine, 1)?;
    let gas = engine.cmd.var(0).as_integer()?;
    let gas_price = engine.get_gas().get_gas_price();
    let nanocoin_output = gas.mul::<Quiet>(&IntegerData::from_i64(gas_price))?;
    engine.cc.stack.push(StackItem::int(nanocoin_output));
    Ok(())
}

// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// COMMIT - F80F
pub fn execute_commit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("COMMIT"))?;
    engine.try_commit()
}
