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
        continuation::{check_underflow, pop_cont},
        engine::{
            control::{define_c, force_cdata},
            storage::fetch_stack,
            Engine,
        },
        types::{Instruction, InstructionOptions},
    },
    stack::StackItem,
};
use chain_block::{fail, Exception, Status};
use std::ops::Range;

//Utilities **********************************************************************************
// (c c' -): exec_try. The current continuation is captured with c0, c1 and c2 (and, for
// TRYARGS p,r, all but the top p entries and r return values); c' keeps its own c2 and c0 or
// gets the old c2 and the capture; c0 becomes the capture and c2 becomes c'; then c is jumped to.
fn init_try_catch(engine: &mut Engine, args: Option<(usize, usize)>) -> Status {
    let need = match args {
        Some((params, _)) => params + 2,
        None => 2,
    };
    check_underflow(engine, need)?;
    let mut handler = pop_cont(engine)?;
    let cont = pop_cont(engine)?;
    let old_c2 = engine.get_c(2);
    let cc = match args {
        Some((params, retvals)) => engine.extract_cc(7, params as isize, retvals as isize)?,
        None => engine.extract_cc(7, -1, -1)?,
    };
    let cc = StackItem::continuation(cc);
    let save = &mut force_cdata(&mut handler).savelist;
    define_c(save, 2, old_c2);
    define_c(save, 0, cc.clone());
    engine.ctrls.put_opt(0, cc);
    engine.ctrls.put_opt(2, StackItem::Continuation(handler));
    engine.jump(cont)
}

fn do_throw(
    engine: &mut Engine,
    number_index: Option<usize>,
    value_index: Option<usize>,
) -> Status {
    let number = if let Some(number_index) = number_index {
        engine.cmd.var(number_index).as_integer_value(0..=0xFFFFi32)?
    } else {
        engine.cmd.integer() as i32
    };
    let value = if let Some(value_index) = value_index {
        engine.cmd.var(value_index).clone()
    } else {
        StackItem::int(0)
    };
    let exception = Exception::from_number(number, String::new(), file!(), line!());
    fail!(TvmError::new(exception, value))
}

//Handlers ***********************************************************************************

fn execute_throw(engine: &mut Engine, range: Range<isize>) -> Status {
    engine
        .load_instruction(Instruction::new("THROW").set_opts(InstructionOptions::Integer(range)))?;
    do_throw(engine, None, None)
}

// (=> throw 0 n)
pub(super) fn execute_throw_short(engine: &mut Engine) -> Status {
    execute_throw(engine, 0..64)
}

// (=> throw 0 n)
pub(super) fn execute_throw_long(engine: &mut Engine) -> Status {
    execute_throw(engine, 0..2048)
}

// helper for THROWIF/THROWIFNOT instructions
fn execute_throwif_throwifnot(
    engine: &mut Engine,
    reverse_condition: bool,
    range: Range<isize>,
) -> Status {
    engine.load_instruction(
        Instruction::new(if reverse_condition { "THROWIFNOT" } else { "THROWIF" })
            .set_opts(InstructionOptions::Integer(range)),
    )?;
    fetch_stack(engine, 1)?;
    if reverse_condition ^ engine.cmd.var(0).as_bool()? {
        do_throw(engine, None, None)
    } else {
        Ok(())
    }
}

pub(super) fn execute_throwif_short(engine: &mut Engine) -> Status {
    execute_throwif_throwifnot(engine, false, 0..64)
}

pub(super) fn execute_throwif_long(engine: &mut Engine) -> Status {
    execute_throwif_throwifnot(engine, false, 0..2048)
}

pub(super) fn execute_throwifnot_short(engine: &mut Engine) -> Status {
    execute_throwif_throwifnot(engine, true, 0..64)
}

pub(super) fn execute_throwifnot_long(engine: &mut Engine) -> Status {
    execute_throwif_throwifnot(engine, true, 0..2048)
}

// helper for THROWANYIF/THROWANYIFNOT instructions
fn execute_throwanyif_throwanyifnot(engine: &mut Engine, reverse_condition: bool) -> Status {
    engine.load_instruction(Instruction::new(if reverse_condition {
        "THROWANYIFNOT"
    } else {
        "THROWANYIF"
    }))?;
    fetch_stack(engine, 2)?;
    if reverse_condition ^ engine.cmd.var(0).as_bool()? {
        do_throw(engine, Some(1), None)
    } else {
        Ok(())
    }
}

// (n f, f!=0 => throw 0 n)
pub(super) fn execute_throwanyif(engine: &mut Engine) -> Status {
    execute_throwanyif_throwanyifnot(engine, false)
}

// (n f, f==0 => throw 0 n)
pub(super) fn execute_throwanyifnot(engine: &mut Engine) -> Status {
    execute_throwanyif_throwanyifnot(engine, true)
}

// (n => throw 0 n)
pub(super) fn execute_throwany(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THROWANY"))?;
    fetch_stack(engine, 1)?;
    do_throw(engine, Some(0), None)
}

// (x => throw x n)
pub(super) fn execute_throwarg(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("THROWARG").set_opts(InstructionOptions::Integer(0..2048)),
    )?;
    fetch_stack(engine, 1)?;
    do_throw(engine, None, Some(0))
}

// (x n => throw x n)
pub(super) fn execute_throwargany(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THROWARGANY"))?;
    fetch_stack(engine, 2)?;
    do_throw(engine, Some(0), Some(1))
}

// helper for THROWARGANYIF[NOT] instructions
fn execute_throwarganyif_throwarganyifnot(engine: &mut Engine, reverse_condition: bool) -> Status {
    engine.load_instruction(Instruction::new(if reverse_condition {
        "THROWARGANYIFNOT"
    } else {
        "THROWARGANYIF"
    }))?;
    fetch_stack(engine, 3)?;
    if reverse_condition ^ engine.cmd.var(0).as_bool()? {
        do_throw(engine, Some(1), Some(2))
    } else {
        Ok(())
    }
}

// (x n f, f!=0 => throw x n)
pub(super) fn execute_throwarganyif(engine: &mut Engine) -> Status {
    execute_throwarganyif_throwarganyifnot(engine, false)
}

// (x n f, f==0 => throw x n)
pub(super) fn execute_throwarganyifnot(engine: &mut Engine) -> Status {
    execute_throwarganyif_throwarganyifnot(engine, true)
}

// helper for THROWARGIF[NOT] instructions
fn execute_throwargif_throwargifnot(engine: &mut Engine, reverse_condition: bool) -> Status {
    engine.load_instruction(
        Instruction::new(if reverse_condition { "THROWARGIFNOT" } else { "THROWARGIF" })
            .set_opts(InstructionOptions::Integer(0..2048)),
    )?;
    fetch_stack(engine, 2)?;
    if reverse_condition ^ engine.cmd.var(0).as_bool()? {
        do_throw(engine, None, Some(1))
    } else {
        Ok(())
    }
}

// (x f, f!=0 => throw x n)
pub(super) fn execute_throwargif(engine: &mut Engine) -> Status {
    execute_throwargif_throwargifnot(engine, false)
}

// (x f, f==0 => throw x n)
pub(super) fn execute_throwargifnot(engine: &mut Engine) -> Status {
    execute_throwargif_throwargifnot(engine, true)
}

// (c c' - )
pub(super) fn execute_try(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("TRY"))?;
    init_try_catch(engine, None)
}

// (c c' - )
//move 0<=p<=15 stack elements from cc to c, return 0<=r<=15 stack values of resulting stack of c or c'.
pub(super) fn execute_tryargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("TRYARGS").set_opts(InstructionOptions::ArgumentAndReturnConstraints),
    )?;
    let args = (engine.cmd.pargs(), engine.cmd.rargs());
    init_try_catch(engine, Some(args))
}
