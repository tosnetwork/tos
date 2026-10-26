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

//! The continuation instructions, each as its C++ counterpart in `crypto/vm/contops.cpp`
//! (named in its comment), on the control primitives of `engine/control.rs`.

use crate::{
    executor::{
        engine::{
            control::{cont_of, define, define_c, force_cdata},
            storage::fetch_stack,
            Engine,
        },
        gas::gas_state::Gas,
        types::{Instruction, InstructionOptions},
        RunChildVm,
    },
    stack::{
        continuation::{ContEdge, ContinuationData, ContinuationType},
        integer::IntegerData,
        Stack, StackItem,
    },
};
use chain_block::{fail, Cell, ExceptionCode, GasConsumer, Mask, Result, Status};
use std::{mem, sync::Arc};

// Operands, popped one at a time with the C++ VM's checks ************************************

pub(super) fn check_underflow(engine: &Engine, depth: usize) -> Status {
    if engine.cc.stack.depth() < depth {
        fail!(ExceptionCode::StackUnderflow)
    }
    Ok(())
}

pub(super) fn pop(engine: &mut Engine) -> Result<StackItem> {
    engine.cc.stack.drop(0)
}

pub(super) fn pop_cont(engine: &mut Engine) -> Result<Arc<ContinuationData>> {
    let item = pop(engine)?;
    cont_of(&item)
}

/// C++ `Stack::pop_smallint_range(max, min)`.
pub(super) fn pop_smallint_range(engine: &mut Engine, max: i64, min: i64) -> Result<i64> {
    pop(engine)?.as_integer_value(min..=max)
}

/// C++ `Stack::pop_bool`: a finite integer, true when not zero.
pub(super) fn pop_bool(engine: &mut Engine) -> Result<bool> {
    pop(engine)?.as_bool()
}

/// C++ `VmState::ref_to_cont`: the cell loaded as an ordinary continuation.
pub(super) fn ref_to_cont(engine: &mut Engine, cell: Cell) -> Result<Arc<ContinuationData>> {
    let code = engine.load_cell(cell)?;
    Ok(Arc::new(ContinuationData::with_code(code)))
}

/// The next reference of the code (C++ `exec_do_with_ref` / `exec_do_with_cell`): an invalid
/// opcode when there is none.
fn fetch_ref(engine: &mut Engine) -> Result<Cell> {
    engine.cc.drain_reference()
}

fn cont_item(cont: Arc<ContinuationData>) -> StackItem {
    StackItem::Continuation(cont)
}

// Calls, jumps and returns (contops.cpp register_continuation_jump_ops) **********************

// EXECUTE: exec_execute
pub(super) fn execute_callx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLX"))?;
    let cont = pop_cont(engine)?;
    engine.call(cont)
}

// CALLXARGS p,r (DA) and CALLXARGS p,-1 (DB0p): exec_callx_args, exec_callx_args_p
pub(super) fn execute_callxargs(engine: &mut Engine) -> Status {
    let cmd = engine.last_cmd();
    let both = cmd == 0xDA;
    engine.load_instruction(Instruction::new("CALLXARGS").set_opts(if both {
        InstructionOptions::ArgumentAndReturnConstraints
    } else {
        InstructionOptions::Pargs(0..16)
    }))?;
    let params = engine.cmd.pargs() as isize;
    let retvals = if both { engine.cmd.rargs() as isize } else { -1 };
    let cont = pop_cont(engine)?;
    engine.call_args(cont, params, retvals)
}

// JMPX: exec_jmpx
pub(super) fn execute_jmpx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPX"))?;
    let cont = pop_cont(engine)?;
    engine.jump(cont)
}

// JMPXARGS p: exec_jmpx_args
pub(super) fn execute_jmpxargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("JMPXARGS").set_opts(InstructionOptions::Pargs(0..16)),
    )?;
    let params = engine.cmd.pargs() as isize;
    let cont = pop_cont(engine)?;
    engine.jump_args(cont, params)
}

// RET: exec_ret
pub(super) fn execute_ret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RET"))?;
    engine.ret()
}

// RETARGS p: exec_ret_args
pub(super) fn execute_retargs(engine: &mut Engine) -> Status {
    engine
        .load_instruction(Instruction::new("RETARGS").set_opts(InstructionOptions::Pargs(0..16)))?;
    let params = engine.cmd.pargs() as isize;
    engine.ret_args(params)
}

// RETALT: exec_ret_alt
pub(super) fn execute_retalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETALT"))?;
    engine.ret_alt()
}

// RETBOOL: exec_ret_bool
pub(super) fn execute_retbool(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETBOOL"))?;
    if pop_bool(engine)? {
        engine.ret()
    } else {
        engine.ret_alt()
    }
}

// CALLCC: exec_callcc
pub(super) fn execute_callcc(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLCC"))?;
    let cont = pop_cont(engine)?;
    let cc = engine.extract_cc(3, -1, -1)?;
    engine.cc.stack.push(StackItem::continuation(cc));
    engine.jump(cont)
}

// JMPXDATA: exec_jmpx_data
pub(super) fn execute_jmpxdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPXDATA"))?;
    let cont = pop_cont(engine)?;
    engine.push_code();
    engine.jump(cont)
}

// CALLCCARGS p,r: exec_callcc_args
pub(super) fn execute_callccargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("CALLCCARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let params = engine.cmd.pargs() as isize;
    let retvals = engine.cmd.nargs();
    check_underflow(engine, params as usize + 1)?;
    let cont = pop_cont(engine)?;
    let cc = engine.extract_cc(3, params, retvals)?;
    engine.cc.stack.push(StackItem::continuation(cc));
    engine.jump(cont)
}

// CALLXVARARGS: exec_callx_varargs
pub(super) fn execute_callxva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLXVARARGS"))?;
    check_underflow(engine, 3)?;
    let retvals = pop_smallint_range(engine, 254, -1)? as isize;
    let params = pop_smallint_range(engine, 254, -1)? as isize;
    let cont = pop_cont(engine)?;
    engine.call_args(cont, params, retvals)
}

// RETVARARGS: exec_ret_varargs
pub(super) fn execute_retva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETVARARGS"))?;
    let retvals = pop_smallint_range(engine, 254, -1)? as isize;
    engine.ret_args(retvals)
}

// JMPXVARARGS: exec_jmpx_varargs
pub(super) fn execute_jmpxva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPXVARARGS"))?;
    check_underflow(engine, 2)?;
    let params = pop_smallint_range(engine, 254, -1)?;
    check_underflow(engine, (params + 1) as usize)?;
    let cont = pop_cont(engine)?;
    engine.jump_args(cont, params as isize)
}

// CALLCCVARARGS: exec_callcc_varargs
pub(super) fn execute_callccva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLCCVARARGS"))?;
    check_underflow(engine, 3)?;
    let retvals = pop_smallint_range(engine, 254, -1)? as isize;
    let params = pop_smallint_range(engine, 254, -1)?;
    check_underflow(engine, (params + 1) as usize)?;
    let cont = pop_cont(engine)?;
    let cc = engine.extract_cc(3, params as isize, retvals)?;
    engine.cc.stack.push(StackItem::continuation(cc));
    engine.jump(cont)
}

// CALLREF: exec_do_with_ref + call
pub(super) fn execute_callref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLREF"))?;
    let cell = fetch_ref(engine)?;
    let cont = ref_to_cont(engine, cell)?;
    engine.call(cont)
}

// JMPREF: exec_do_with_ref + jump
pub(super) fn execute_jmpref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPREF"))?;
    let cell = fetch_ref(engine)?;
    let cont = ref_to_cont(engine, cell)?;
    engine.jump(cont)
}

// JMPREFDATA: exec_do_with_ref + push_code + jump
pub(super) fn execute_jmprefdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPREFDATA"))?;
    let cell = fetch_ref(engine)?;
    let cont = ref_to_cont(engine, cell)?;
    engine.push_code();
    engine.jump(cont)
}

// RETDATA: exec_ret_data
pub(super) fn execute_retdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETDATA"))?;
    engine.push_code();
    engine.ret()
}

// Conditions and loops (register_continuation_cond_loop_ops) *********************************

// IF: exec_if
pub(super) fn execute_if(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IF"))?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    if pop_bool(engine)? {
        engine.call(cont)
    } else {
        Ok(())
    }
}

// IFNOT: exec_ifnot
pub(super) fn execute_ifnot(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOT"))?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    if !pop_bool(engine)? {
        engine.call(cont)
    } else {
        Ok(())
    }
}

// IFJMP: exec_if_jmp
pub(super) fn execute_ifjmp(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFJMP"))?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    if pop_bool(engine)? {
        engine.jump(cont)
    } else {
        Ok(())
    }
}

// IFNOTJMP: exec_ifnot_jmp
pub(super) fn execute_ifnotjmp(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOTJMP"))?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    if !pop_bool(engine)? {
        engine.jump(cont)
    } else {
        Ok(())
    }
}

// IFRET: exec_ifret
pub(super) fn execute_ifret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFRET"))?;
    if pop_bool(engine)? {
        engine.ret()
    } else {
        Ok(())
    }
}

// IFNOTRET: exec_ifnotret
pub(super) fn execute_ifnotret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOTRET"))?;
    if !pop_bool(engine)? {
        engine.ret()
    } else {
        Ok(())
    }
}

// IFELSE: exec_if_else
pub(super) fn execute_ifelse(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFELSE"))?;
    check_underflow(engine, 3)?;
    let cont0 = pop_cont(engine)?;
    let cont1 = pop_cont(engine)?;
    let cont = if pop_bool(engine)? { cont1 } else { cont0 };
    engine.call(cont)
}

// IFRETALT: exec_ifretalt
pub(super) fn execute_ifretalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFRETALT"))?;
    if pop_bool(engine)? {
        engine.ret_alt()
    } else {
        Ok(())
    }
}

// IFNOTRETALT: exec_ifnotretalt
pub(super) fn execute_ifnotretalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOTRETALT"))?;
    if !pop_bool(engine)? {
        engine.ret_alt()
    } else {
        Ok(())
    }
}

// IFREF: exec_do_with_cell; the reference is loaded only when the branch is taken
pub(super) fn execute_ifref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFREF"))?;
    let cell = fetch_ref(engine)?;
    if pop_bool(engine)? {
        let cont = ref_to_cont(engine, cell)?;
        engine.call(cont)
    } else {
        Ok(())
    }
}

// IFNOTREF
pub(super) fn execute_ifnotref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOTREF"))?;
    let cell = fetch_ref(engine)?;
    if pop_bool(engine)? {
        Ok(())
    } else {
        let cont = ref_to_cont(engine, cell)?;
        engine.call(cont)
    }
}

// IFJMPREF
pub(super) fn execute_ifjmpref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFJMPREF"))?;
    let cell = fetch_ref(engine)?;
    if pop_bool(engine)? {
        let cont = ref_to_cont(engine, cell)?;
        engine.jump(cont)
    } else {
        Ok(())
    }
}

// IFNOTJMPREF
pub(super) fn execute_ifnotjmpref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFNOTJMPREF"))?;
    let cell = fetch_ref(engine)?;
    if pop_bool(engine)? {
        Ok(())
    } else {
        let cont = ref_to_cont(engine, cell)?;
        engine.jump(cont)
    }
}

// IFREFELSE and IFELSEREF: exec_ifelse_ref(mode)
fn ifelse_ref(engine: &mut Engine, name: &'static str, mode: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let cell = fetch_ref(engine)?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    let cont = if pop_bool(engine)? == mode { ref_to_cont(engine, cell)? } else { cont };
    engine.call(cont)
}

pub(super) fn execute_ifrefelse(engine: &mut Engine) -> Status {
    ifelse_ref(engine, "IFREFELSE", true)
}

pub(super) fn execute_ifelseref(engine: &mut Engine) -> Status {
    ifelse_ref(engine, "IFELSEREF", false)
}

// IFREFELSEREF: exec_ifref_elseref
pub(super) fn execute_ifrefelseref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("IFREFELSEREF"))?;
    let cell1 = fetch_ref(engine)?;
    let cell2 = fetch_ref(engine)?;
    let cell = if pop_bool(engine)? { cell1 } else { cell2 };
    let cont = ref_to_cont(engine, cell)?;
    engine.call(cont)
}

/// C++ `pop_int_finite` then `get_bit`: the integer goes back on the stack.
fn test_bit(engine: &mut Engine, bit: u32) -> Result<bool> {
    let item = pop(engine)?;
    let x = item.as_integer()?;
    if x.is_nan() {
        fail!(ExceptionCode::IntegerOverflow)
    }
    let mask = IntegerData::from_u32(1 << bit);
    let set = !x.and::<crate::stack::integer::behavior::Signaling>(&mask)?.is_zero();
    engine.cc.stack.push(item);
    Ok(set)
}

// IFBITJMP and IFNBITJMP: exec_if_bit_jmp
fn ifbitjmp(engine: &mut Engine, name: &'static str, negate: bool) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Integer(0..32)))?;
    let bit = engine.cmd.integer() as u32;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    if test_bit(engine, bit)? ^ negate {
        engine.jump(cont)
    } else {
        Ok(())
    }
}

pub(super) fn execute_ifbitjmp(engine: &mut Engine) -> Status {
    ifbitjmp(engine, "IFBITJMP", false)
}

pub(super) fn execute_ifnbitjmp(engine: &mut Engine) -> Status {
    ifbitjmp(engine, "IFNBITJMP", true)
}

// IFBITJMPREF and IFNBITJMPREF: exec_if_bit_jmpref
fn ifbitjmpref(engine: &mut Engine, name: &'static str, negate: bool) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Integer(0..32)))?;
    let bit = engine.cmd.integer() as u32;
    let cell = fetch_ref(engine)?;
    if test_bit(engine, bit)? ^ negate {
        let cont = ref_to_cont(engine, cell)?;
        engine.jump(cont)
    } else {
        Ok(())
    }
}

pub(super) fn execute_ifbitjmpref(engine: &mut Engine) -> Status {
    ifbitjmpref(engine, "IFBITJMPREF", false)
}

pub(super) fn execute_ifnbitjmpref(engine: &mut Engine) -> Status {
    ifbitjmpref(engine, "IFNBITJMPREF", true)
}

/// The count of REPEAT: C++ `pop_smallint_range(0x7fffffff, 0x80000000)`, a signed 32-bit int.
fn pop_count(engine: &mut Engine) -> Result<i64> {
    pop_smallint_range(engine, 0x7FFF_FFFF, -0x8000_0000)
}

// REPEAT and REPEATBRK: exec_repeat
fn repeat(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let cont = pop_cont(engine)?;
    let count = pop_count(engine)?;
    if count <= 0 {
        return Ok(());
    }
    let cc = Arc::new(engine.extract_cc(1, -1, -1)?);
    let after = engine.c1_envelope_if(brk, cc);
    engine.repeat(cont, after, count)
}

pub(super) fn execute_repeat(engine: &mut Engine) -> Status {
    repeat(engine, "REPEAT", false)
}

pub(super) fn execute_repeat_break(engine: &mut Engine) -> Status {
    repeat(engine, "REPEATBRK", true)
}

// REPEATEND and REPEATENDBRK: exec_repeat_end
fn repeat_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 1)?;
    let count = pop_count(engine)?;
    if count <= 0 {
        return engine.ret();
    }
    let cont = Arc::new(engine.extract_cc(0, -1, -1)?);
    let c0 = engine.get_cont(0)?;
    let after = engine.c1_envelope_if(brk, c0);
    engine.repeat(cont, after, count)
}

pub(super) fn execute_repeatend(engine: &mut Engine) -> Status {
    repeat_end(engine, "REPEATEND", false)
}

pub(super) fn execute_repeatend_break(engine: &mut Engine) -> Status {
    repeat_end(engine, "REPEATENDBRK", true)
}

// UNTIL and UNTILBRK: exec_until
fn until(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let cont = pop_cont(engine)?;
    let cc = Arc::new(engine.extract_cc(1, -1, -1)?);
    let after = engine.c1_envelope_if(brk, cc);
    engine.until(cont, after)
}

pub(super) fn execute_until(engine: &mut Engine) -> Status {
    until(engine, "UNTIL", false)
}

pub(super) fn execute_until_break(engine: &mut Engine) -> Status {
    until(engine, "UNTILBRK", true)
}

// UNTILEND and UNTILENDBRK: exec_until_end
fn until_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let cont = Arc::new(engine.extract_cc(0, -1, -1)?);
    let c0 = engine.get_cont(0)?;
    let after = engine.c1_envelope_if(brk, c0);
    engine.until(cont, after)
}

pub(super) fn execute_untilend(engine: &mut Engine) -> Status {
    until_end(engine, "UNTILEND", false)
}

pub(super) fn execute_untilend_break(engine: &mut Engine) -> Status {
    until_end(engine, "UNTILENDBRK", true)
}

// WHILE and WHILEBRK: exec_while
fn while_(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let body = pop_cont(engine)?;
    let cond = pop_cont(engine)?;
    let cc = Arc::new(engine.extract_cc(1, -1, -1)?);
    let after = engine.c1_envelope_if(brk, cc);
    engine.loop_while(cond, body, after)
}

pub(super) fn execute_while(engine: &mut Engine) -> Status {
    while_(engine, "WHILE", false)
}

pub(super) fn execute_while_break(engine: &mut Engine) -> Status {
    while_(engine, "WHILEBRK", true)
}

// WHILEEND and WHILEENDBRK: exec_while_end
fn while_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let cond = pop_cont(engine)?;
    let body = Arc::new(engine.extract_cc(0, -1, -1)?);
    let c0 = engine.get_cont(0)?;
    let after = engine.c1_envelope_if(brk, c0);
    engine.loop_while(cond, body, after)
}

pub(super) fn execute_whileend(engine: &mut Engine) -> Status {
    while_end(engine, "WHILEEND", false)
}

pub(super) fn execute_whileend_break(engine: &mut Engine) -> Status {
    while_end(engine, "WHILEENDBRK", true)
}

// AGAIN and AGAINBRK: exec_again; the break form captures before it pops the body
fn again(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    if brk {
        let cc = engine.extract_cc(3, -1, -1)?;
        engine.ctrls.put_opt(1, StackItem::continuation(cc));
    }
    let body = pop_cont(engine)?;
    engine.again(body)
}

pub(super) fn execute_again(engine: &mut Engine) -> Status {
    again(engine, "AGAIN", false)
}

pub(super) fn execute_again_break(engine: &mut Engine) -> Status {
    again(engine, "AGAINBRK", true)
}

// AGAINEND and AGAINENDBRK: exec_again_end
fn again_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    if brk {
        engine.c1_save_set()?;
    }
    let body = Arc::new(engine.extract_cc(0, -1, -1)?);
    engine.again(body)
}

pub(super) fn execute_againend(engine: &mut Engine) -> Status {
    again_end(engine, "AGAINEND", false)
}

pub(super) fn execute_againend_break(engine: &mut Engine) -> Status {
    again_end(engine, "AGAINENDBRK", true)
}

// CONDSEL: exec_condsel
pub(super) fn execute_condsel(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CONDSEL"))?;
    fetch_stack(engine, 3)?;
    if !engine.cmd.var(2).as_bool()? {
        engine.cc.stack.push(engine.cmd.vars.remove(0));
    } else {
        engine.cc.stack.push(engine.cmd.vars.remove(1));
    }
    Ok(())
}

// CONDSELCHK: exec_condsel_chk
pub(super) fn execute_condselchk(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CONDSELCHK"))?;
    fetch_stack(engine, 3)?;
    if mem::discriminant(engine.cmd.var(0)) != mem::discriminant(engine.cmd.var(1)) {
        fail!(ExceptionCode::TypeCheckError)
    }
    if !engine.cmd.var(2).as_bool()? {
        engine.cc.stack.push(engine.cmd.vars.remove(0));
    } else {
        engine.cc.stack.push(engine.cmd.vars.remove(1));
    }
    Ok(())
}

// Changing continuations (register_continuation_change_ops) *********************************

/// C++ `exec_setcontargs_common`: copies `copy` entries into the continuation's stack and sets
/// its number of arguments.
fn setcontargs_common(engine: &mut Engine, copy: usize, more: isize) -> Status {
    check_underflow(engine, copy + 1)?;
    let mut cont = pop_cont(engine)?;
    if copy > 0 || more >= 0 {
        let cdata = force_cdata(&mut cont);
        if copy > 0 {
            if cdata.nargs >= 0 && (cdata.nargs as usize) < copy {
                fail!(
                    ExceptionCode::StackOverflow,
                    "too many arguments copied into a closure continuation"
                )
            }
            let depth = engine.cc.stack.storage.len();
            cdata.stack.storage.extend(engine.cc.stack.storage.drain(depth - copy..));
            let captured = cdata.stack.depth();
            if cdata.nargs >= 0 {
                cdata.nargs -= copy as isize;
            }
            engine.consume_gas(Gas::stack_price(captured))?;
        }
        if more >= 0 {
            let cdata = force_cdata(&mut cont);
            if cdata.nargs > more {
                cdata.nargs = 0x4000_0000;
            } else if cdata.nargs < 0 {
                cdata.nargs = more;
            }
        }
    }
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

// SETCONTARGS r,n: exec_setcontargs
pub(super) fn execute_setcontargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let copy = engine.cmd.pargs();
    let more = engine.cmd.nargs();
    setcontargs_common(engine, copy, more)
}

// SETCONTVARARGS: exec_setcont_varargs
pub(super) fn execute_setcontva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)? as isize;
    let copy = pop_smallint_range(engine, 255, 0)? as usize;
    setcontargs_common(engine, copy, more)
}

// SETNUMVARARGS: exec_setnum_varargs
pub(super) fn execute_setnumvarargs(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETNUMVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)? as isize;
    setcontargs_common(engine, 0, more)
}

/// C++ `exec_return_args_common`: all but the top `count` entries move into c0's stack.
fn return_args_common(engine: &mut Engine, count: usize) -> Status {
    check_underflow(engine, count)?;
    let depth = engine.cc.stack.depth();
    if depth == count {
        return Ok(());
    }
    let copy = depth - count;
    let mut cont = engine.get_cont(0)?;
    let cdata = force_cdata(&mut cont);
    if cdata.nargs >= 0 && (cdata.nargs as usize) < copy {
        fail!(ExceptionCode::StackOverflow, "too many arguments copied into a closure continuation")
    }
    let moved: Vec<StackItem> = engine.cc.stack.storage.drain(..copy).collect();
    cdata.stack.storage.extend(moved);
    let captured = cdata.stack.depth();
    if cdata.nargs >= 0 {
        cdata.nargs -= copy as isize;
    }
    engine.consume_gas(Gas::stack_price(captured))?;
    engine.ctrls.put_opt(0, cont_item(cont));
    Ok(())
}

// RETURNARGS p: exec_return_args
pub(super) fn execute_returnargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("RETURNARGS").set_opts(InstructionOptions::Rargs(0..16)),
    )?;
    let count = engine.cmd.rargs();
    return_args_common(engine, count)
}

// RETURNVARARGS: exec_return_varargs
pub(super) fn execute_returnva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETURNVARARGS"))?;
    let count = pop_smallint_range(engine, 255, 0)? as usize;
    return_args_common(engine, count)
}

// BLESS: exec_bless
pub(super) fn execute_bless(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BLESS"))?;
    let code = pop(engine)?.as_slice()?.clone();
    engine.cc.stack.push(StackItem::continuation(ContinuationData::with_code(code)));
    Ok(())
}

/// C++ `exec_bless_args_common`.
fn bless_args_common(engine: &mut Engine, copy: usize, more: isize) -> Status {
    check_underflow(engine, copy + 1)?;
    let code = pop(engine)?.as_slice()?.clone();
    let depth = engine.cc.stack.storage.len();
    let captured = Stack::with_storage(engine.cc.stack.storage.drain(depth - copy..).collect());
    engine.consume_gas(Gas::stack_price(captured.depth()))?;
    let mut cont = ContinuationData::with_code_and_stack(code, captured);
    cont.nargs = more;
    engine.cc.stack.push(StackItem::continuation(cont));
    Ok(())
}

// BLESSVARARGS: exec_bless_varargs
pub(super) fn execute_blessva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BLESSVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)? as isize;
    let copy = pop_smallint_range(engine, 255, 0)? as usize;
    bless_args_common(engine, copy, more)
}

// BLESSARGS r,n: exec_bless_args
pub(super) fn execute_blessargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("BLESSARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let copy = engine.cmd.pargs();
    let more = engine.cmd.nargs();
    bless_args_common(engine, copy, more)
}

fn typechk(ok: bool) -> Status {
    if !ok {
        fail!(ExceptionCode::TypeCheckError, "invalid value type for control register")
    }
    Ok(())
}

/// Before version 14 defining an occupied savelist slot was a type check error.
fn silent_if_set(engine: &Engine) -> bool {
    engine.block_version() >= 14
}

// SETCONTCTR c(i): exec_setcont_ctr
pub(super) fn execute_setcontctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    let index = engine.cmd.creg();
    check_underflow(engine, 2)?;
    let mut cont = pop_cont(engine)?;
    let silent = silent_if_set(engine);
    let value = pop(engine)?;
    typechk(define(&mut force_cdata(&mut cont).savelist, index, value, silent))?;
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

// SETRETCTR c(i): exec_setret_ctr
pub(super) fn execute_setretctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETRETCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    let index = engine.cmd.creg();
    let mut cont = engine.get_cont(0)?;
    let silent = silent_if_set(engine);
    let value = pop(engine)?;
    typechk(define(&mut force_cdata(&mut cont).savelist, index, value, silent))?;
    engine.ctrls.put_opt(0, cont_item(cont));
    Ok(())
}

// SETALTCTR c(i): exec_setalt_ctr
pub(super) fn execute_setaltctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETALTCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    let index = engine.cmd.creg();
    let mut cont = engine.get_cont(1)?;
    let silent = silent_if_set(engine);
    let value = pop(engine)?;
    typechk(define(&mut force_cdata(&mut cont).savelist, index, value, silent))?;
    engine.ctrls.put_opt(1, cont_item(cont));
    Ok(())
}

/// SAVECTR and SAVEALTCTR: exec_save_ctr, exec_savealt_ctr.
fn save_ctr(engine: &mut Engine, name: &'static str, target: usize) -> Status {
    engine
        .load_instruction(Instruction::new(name).set_opts(InstructionOptions::ControlRegister))?;
    let index = engine.cmd.creg();
    let mut cont = engine.get_cont(target)?;
    let silent = silent_if_set(engine);
    let value = engine.get_c(index);
    typechk(define(&mut force_cdata(&mut cont).savelist, index, value, silent))?;
    engine.ctrls.put_opt(target, cont_item(cont));
    Ok(())
}

// SAVECTR c(i)
pub(super) fn execute_save(engine: &mut Engine) -> Status {
    save_ctr(engine, "SAVE", 0)
}

// SAVEALTCTR c(i)
pub(super) fn execute_savealt(engine: &mut Engine) -> Status {
    save_ctr(engine, "SAVEALT", 1)
}

// SAVEBOTHCTR c(i): exec_saveboth_ctr; c0, c1 and the value are read before either changes and
// the definitions' results are ignored
pub(super) fn execute_saveboth(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SAVEBOTH").set_opts(InstructionOptions::ControlRegister),
    )?;
    let index = engine.cmd.creg();
    let mut c0 = engine.get_cont(0)?;
    let mut c1 = engine.get_cont(1)?;
    let value = engine.get_c(index);
    define(&mut force_cdata(&mut c0).savelist, index, value.clone(), false);
    define(&mut force_cdata(&mut c1).savelist, index, value, false);
    engine.ctrls.put_opt(0, cont_item(c0));
    engine.ctrls.put_opt(1, cont_item(c1));
    Ok(())
}

// SAMEALT and SAMEALTSAVE: exec_samealt
fn samealt(engine: &mut Engine, name: &'static str, save: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let mut c0 = engine.get_cont(0)?;
    if save {
        let c1 = engine.get_c(1);
        define_c(&mut force_cdata(&mut c0).savelist, 1, c1);
        engine.ctrls.put_opt(0, cont_item(c0.clone()));
    }
    engine.ctrls.put_opt(1, cont_item(c0));
    Ok(())
}

pub(super) fn execute_samealt(engine: &mut Engine) -> Status {
    samealt(engine, "SAMEALT", false)
}

pub(super) fn execute_samealt_save(engine: &mut Engine) -> Status {
    samealt(engine, "SAMEALTSAVE", true)
}

/// C++ `ControlRegs::valid_idx`.
fn valid_idx(index: i64) -> bool {
    matches!(index, 0..=5 | 7)
}

// SETCONTCTRX: exec_setcont_ctr_var
pub(super) fn execute_setcontctrx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTCTRX"))?;
    check_underflow(engine, 3)?;
    let index = pop_smallint_range(engine, 16, 0)?;
    if !valid_idx(index) {
        fail!(ExceptionCode::RangeCheckError, "control register index out of range")
    }
    let mut cont = pop_cont(engine)?;
    let silent = silent_if_set(engine);
    let value = pop(engine)?;
    typechk(define(&mut force_cdata(&mut cont).savelist, index as usize, value, silent))?;
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

/// SETCONTCTRMANY(X): each selected register is defined into the continuation's savelist.
fn setcontctrmany_common(
    engine: &mut Engine,
    mask: i64,
    mut cont: Arc<ContinuationData>,
) -> Status {
    let silent = silent_if_set(engine);
    for index in 0..8usize {
        if mask & (1 << index) != 0 {
            let value = engine.get_c(index);
            typechk(define(&mut force_cdata(&mut cont).savelist, index, value, silent))?;
        }
    }
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

// SETCONTCTRMANY mask: exec_setcont_ctr_many; c6 is refused before the continuation is popped
pub(super) fn execute_setcontctrmany(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTCTRMANY").set_opts(InstructionOptions::Length(0..256)),
    )?;
    let mask = engine.cmd.length() as i64;
    if mask & (1 << 6) != 0 {
        fail!(ExceptionCode::RangeCheckError, "no control register c6")
    }
    let cont = pop_cont(engine)?;
    setcontctrmany_common(engine, mask, cont)
}

// SETCONTCTRMANYX: exec_setcont_ctr_many_var
pub(super) fn execute_setcontctrmanyx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTCTRMANYX"))?;
    check_underflow(engine, 2)?;
    let mask = pop_smallint_range(engine, 255, 0)?;
    if mask & (1 << 6) != 0 {
        fail!(ExceptionCode::RangeCheckError, "no control register c6")
    }
    let cont = pop_cont(engine)?;
    setcontctrmany_common(engine, mask, cont)
}

/// BOOLAND, BOOLOR, COMPOSBOTH: exec_compos; the popped continuation is defined as c0 and/or c1
/// of the one below it.
fn compos(engine: &mut Engine, name: &'static str, mask: u8) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let val = pop_cont(engine)?;
    let mut cont = pop_cont(engine)?;
    let save = &mut force_cdata(&mut cont).savelist;
    if mask & 1 != 0 {
        define_c(save, 0, cont_item(val.clone()));
    }
    if mask & 2 != 0 {
        define_c(save, 1, cont_item(val));
    }
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

pub(super) fn execute_compos(engine: &mut Engine) -> Status {
    compos(engine, "BOOLAND", 1)
}

pub(super) fn execute_composalt(engine: &mut Engine) -> Status {
    compos(engine, "BOOLOR", 2)
}

pub(super) fn execute_composboth(engine: &mut Engine) -> Status {
    compos(engine, "COMPOSBOTH", 3)
}

// ATEXIT: exec_atexit
pub(super) fn execute_atexit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ATEXIT"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.get_c(0);
    define_c(&mut force_cdata(&mut cont).savelist, 0, c0);
    engine.ctrls.put_opt(0, cont_item(cont));
    Ok(())
}

// ATEXITALT: exec_atexit_alt
pub(super) fn execute_atexitalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ATEXITALT"))?;
    let mut cont = pop_cont(engine)?;
    let c1 = engine.get_c(1);
    define_c(&mut force_cdata(&mut cont).savelist, 1, c1);
    engine.ctrls.put_opt(1, cont_item(cont));
    Ok(())
}

// SETEXITALT: exec_setexit_alt; both definitions, then the continuation becomes c1
pub(super) fn execute_setexitalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETEXITALT"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.get_c(0);
    let c1 = engine.get_c(1);
    let save = &mut force_cdata(&mut cont).savelist;
    define_c(save, 0, c0);
    define_c(save, 1, c1);
    engine.ctrls.put_opt(1, cont_item(cont));
    Ok(())
}

// THENRET: exec_thenret
pub(super) fn execute_thenret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THENRET"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.get_c(0);
    define_c(&mut force_cdata(&mut cont).savelist, 0, c0);
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

// THENRETALT: exec_thenret_alt; c1 is defined as the continuation's c0
pub(super) fn execute_thenretalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THENRETALT"))?;
    let mut cont = pop_cont(engine)?;
    let c1 = engine.get_c(1);
    define_c(&mut force_cdata(&mut cont).savelist, 0, c1);
    engine.cc.stack.push(cont_item(cont));
    Ok(())
}

// INVERT: exec_invert
pub(super) fn execute_invert(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("INVERT"))?;
    let c0 = engine.get_c(0);
    let c1 = engine.get_c(1);
    for (index, value) in [(0, c1), (1, c0)] {
        if value.is_null() {
            engine.ctrls.remove(index);
        } else {
            engine.ctrls.put_opt(index, value);
        }
    }
    Ok(())
}

// BOOLEVAL: exec_booleval; both exits push their flag and continue with the captured
// continuation
pub(super) fn execute_booleval(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BOOLEVAL"))?;
    let cont = pop_cont(engine)?;
    let cc = ContEdge::new(engine.extract_cc(3, -1, -1)?);
    let yes = ContinuationData::with_type(ContinuationType::PushInt(-1, cc.clone()));
    let no = ContinuationData::with_type(ContinuationType::PushInt(0, cc));
    engine.ctrls.put_opt(0, StackItem::continuation(yes));
    engine.ctrls.put_opt(1, StackItem::continuation(no));
    engine.jump(cont)
}

// Dictionary calls through c3 (register_continuation_dict_jump_ops) **************************

// CALLDICT n: exec_calldict_short, exec_calldict
fn calldict(engine: &mut Engine, name: &'static str, range: std::ops::Range<isize>) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Integer(range)))?;
    let n = engine.cmd.integer();
    engine.cc.stack.push(int!(n));
    let c3 = engine.get_cont(3)?;
    engine.call(c3)
}

pub(super) fn execute_call_short(engine: &mut Engine) -> Status {
    calldict(engine, "CALLDICT", 0..256)
}

pub(super) fn execute_call_long(engine: &mut Engine) -> Status {
    calldict(engine, "CALLDICT", 0..16384)
}

// JMPDICT n: exec_jmpdict
pub(super) fn execute_jmp(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("JMP").set_opts(InstructionOptions::Integer(0..16384)),
    )?;
    let n = engine.cmd.integer();
    engine.cc.stack.push(int!(n));
    let c3 = engine.get_cont(3)?;
    engine.jump(c3)
}

// PREPAREDICT n: exec_preparedict
pub(super) fn execute_prepare(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("PREPARE").set_opts(InstructionOptions::Integer(0..16384)),
    )?;
    let n = engine.cmd.integer();
    engine.cc.stack.push(int!(n));
    let c3 = engine.get_c(3);
    engine.cc.stack.push(c3);
    Ok(())
}

// RUNVM ************************************************************************************

fn run_vm(engine: &mut Engine, mode: isize) -> Status {
    if mode >= 512 {
        fail!(ExceptionCode::RangeCheckError, "invalid flags {mode:#x}");
    }
    engine.try_use_gas(Gas::runvm_gas_price())?;
    let mut gas_max = if mode.bit(64) {
        engine.cc.stack.pop()?.as_integer_value(0..=Gas::infinity())?
    } else {
        Gas::infinity()
    };
    let gas_limit = if mode.bit(8) {
        engine.cc.stack.pop()?.as_integer_value(0..=Gas::infinity())?
    } else {
        Gas::infinity()
    };
    gas_max = if mode.bit(64) { gas_max.max(gas_limit) } else { gas_limit };
    let c7 = if mode.bit(16) { engine.cc.stack.pop()? } else { StackItem::tuple(Vec::new()) };
    c7.as_tuple()?;
    let data =
        if mode.bit(4) { engine.cc.stack.pop()? } else { StackItem::cell(Default::default()) };
    data.as_cell()?;
    let ret_vals =
        if mode.bit(256) { engine.cc.stack.pop()?.as_integer_value(0..=1i32 << 30)? } else { -1 };
    let code = engine.cc.stack.pop()?.as_slice()?.clone();
    let stack_size = engine.cc.stack.pop()?.as_integer_value(0..=engine.cc.stack.depth())?;
    fetch_stack(engine, stack_size)?;
    engine.try_use_gas(Gas::stack_price(stack_size))?;

    let mut stack = engine.cmd.withdraw_vars();
    stack.reverse();
    let stack = Stack::with_storage(stack);

    let params = RunChildVm {
        code,
        c7,
        data,
        stack,
        gas_max,
        gas_limit,
        same_c3: mode.bit(1),
        return_data: mode.bit(4),
        return_actions: mode.bit(32),
        return_gas: mode.bit(8),
        isolate_gas: mode.bit(128),
        ret_vals,
    };
    log::debug!(
        target: "tvm",
        "Child VM run with mode: {mode:#b}, params: {params:?}\n"
    );
    engine.run_child_vm(params)?;
    Ok(())
}

// RUNVM and RUNVMX exist from version 4; the engine's codepage 0 check refuses them before.
pub(super) fn execute_runvm(engine: &mut Engine) -> Status {
    let opts = InstructionOptions::Integer(0..0x1000);
    engine.load_instruction(Instruction::new("RUNVM").set_opts(opts))?;
    let mode = engine.cmd.integer();
    run_vm(engine, mode)
}

pub(super) fn execute_runvmx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RUNVMX"))?;
    let mode = engine.cc.stack.pop()?.as_integer_value(0..=0xFFF)?;
    run_vm(engine, mode)
}
