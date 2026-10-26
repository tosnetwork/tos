/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! How control passes between continuations, as the C++ VM does it (`crypto/vm/vm.cpp`,
//! `vm.h`, `continuation.cpp`). Every instruction that calls, jumps, returns, captures the
//! current continuation or runs a loop goes through these functions.
//!
//! | Phase | Function | C++ | Notes |
//! |---|---|---|---|
//! | simple call | `call` | `VmState::call(cont)` | a target whose savelist defines c0 is jumped to |
//! | call with arguments | `call_args` | `VmState::call(cont, pass, ret)` | stack charged once, on the branch taken |
//! | jump | `jump`, `jump_args` | `VmState::jump` | adjustment, then the dispatch chain |
//! | adjustment | `adjust_jump_cont` | `VmState::adjust_jump_cont` | depth/nargs checks, preclear, stack move and its gas |
//! | dispatch chain | `jump_to` | `VmState::jump_to` | one dispatch per continuation; hop gas after the 8th |
//! | return | `ret`, `ret_args`, `ret_alt` | `VmState::ret*` | the register becomes quit0/quit1 first |
//! | capture | `extract_cc` | `VmState::extract_cc` | top `stack_copy` entries stay active |
//! | exits | `c1_envelope`, `c1_envelope_if`, `c1_save_set` | same names | |
//! | loops | `repeat`, `again`, `until`, `loop_while` | same names | whole body/condition/after continuations |
//!
//! The dispatch of a kind (`dispatch`) follows its C++ `jump`: an Ordinary continuation applies
//! its savelist and installs its code, which ends the chain (even empty code: the step then
//! makes an implicit RET); an Envelope applies its savelist and continues with the continuation
//! it wraps; Quit and ExcQuit end the VM (ExcQuit pops the exit code there, and an error popping
//! it is the exit code); PushInt pushes its value and continues; a loop chooses its next
//! continuation and, unless that one defines c0, installs the loop's next state as c0.
//!
//! Only codepage 0 exists, and every continuation runs in it, so the codepage a C++
//! continuation carries is not modelled: an Ordinary continuation's is 0, an Envelope's is
//! unspecified and changes nothing.
//!
//! A C++ continuation may hold a captured stack that is present but empty; the Rust one holds a
//! possibly empty stack. The two behave alike: where C++ takes the general path because a stack
//! is present, an empty one moves nothing, charges nothing and leaves the same result as the
//! simple path (the return continuation of a simple call has no stack, of a general call an
//! empty one, and both return the same way).

use crate::{
    error::tvm_exception_or_custom_code,
    executor::{engine::Engine, gas::gas_state::Gas},
    stack::{
        continuation::{ContEdge, ContinuationData, ContinuationType},
        savelist::SaveList,
        Stack, StackItem,
    },
};
use chain_block::{error, fail, ExceptionCode, Result, Status};
use std::sync::Arc;

/// C++ `VmState::free_nested_cont_jump`: dispatches of one jump that cost nothing.
const FREE_NESTED_CONT_JUMP: u32 = 8;

/// How the VM ends when a dispatch reaches a quit continuation; resolved during the dispatch.
#[derive(Debug)]
pub(in crate::executor) enum Terminal {
    /// QuitCont: exit with this code.
    Quit(i32),
    /// ExcQuitCont: the exit code it popped (or the error code of popping it).
    ExcQuit(i32),
    /// ExcQuitCont entered by the dispatch of an exception, which popped that exception's own
    /// code: the VM ends with the exception (the same exit code, with its kind kept).
    Raised(chain_block::Exception),
}

pub(in crate::executor) fn quit0() -> StackItem {
    StackItem::continuation(ContinuationData::with_type(ContinuationType::Quit(
        ExceptionCode::NormalTermination as i32,
    )))
}

pub(in crate::executor) fn quit1() -> StackItem {
    StackItem::continuation(ContinuationData::with_type(ContinuationType::Quit(
        ExceptionCode::AlternativeTermination as i32,
    )))
}

/// The continuation a stack item holds, shared.
pub(in crate::executor) fn cont_of(item: &StackItem) -> Result<Arc<ContinuationData>> {
    match item {
        StackItem::Continuation(cont) => Ok(cont.clone()),
        _ => fail!(ExceptionCode::TypeCheckError, "not a continuation"),
    }
}

/// C++ `force_cdata`: the control data of the continuation, wrapping one that has none in an
/// Envelope first.
pub(in crate::executor) fn force_cdata(cont: &mut Arc<ContinuationData>) -> &mut ContinuationData {
    if !cont.has_control_data() {
        let inner = ContEdge::from_arc(cont.clone());
        *cont = Arc::new(ContinuationData::with_type(ContinuationType::Envelope(inner)));
    }
    Arc::make_mut(cont)
}

/// C++ `define_c0`/`define_c1`/`define_c2`: keep an occupied slot; an empty register defines
/// nothing.
pub(in crate::executor) fn define_c(save: &mut SaveList, index: usize, value: StackItem) {
    if !value.is_null() && save.get(index).is_none() {
        save.put_opt(index, value);
    }
}

/// C++ `ControlRegs::define`: the value must suit the register (a continuation for c0-c3, a
/// cell for c4-c5, a tuple for c7); then an occupied c0-c5 slot is kept and the result is
/// `silent_if_set`, while c7 always succeeds.
pub(in crate::executor) fn define(
    save: &mut SaveList,
    index: usize,
    value: StackItem,
    silent_if_set: bool,
) -> bool {
    let suits = match index {
        0..=3 => value.as_continuation().is_ok(),
        4 | 5 => value.as_cell().is_ok(),
        7 => value.as_tuple().is_ok(),
        _ => false,
    };
    if !suits {
        return false;
    }
    if save.get(index).is_some() {
        return index == 7 || silent_if_set;
    }
    save.put_opt(index, value);
    true
}

/// C++ `ControlRegs::set` for a live register: the same types as `define`, null refused.
pub(in crate::executor) fn can_set(index: usize, value: &StackItem) -> bool {
    match index {
        0..=3 => value.as_continuation().is_ok(),
        4 | 5 => value.as_cell().is_ok(),
        7 => value.as_tuple().is_ok(),
        _ => false,
    }
}

/// Moves the top `count` entries of `from` onto the top of `to`, keeping their order.
fn move_top(to: &mut Stack, from: &mut Stack, count: usize) {
    let depth = from.storage.len();
    let moved = from.storage.drain(depth - count..);
    to.storage.extend(moved);
}

/// C++ `Stack::split_top(top, drop)`: a new stack of the top `top` entries; the `drop` entries
/// below them are removed too.
fn split_top(stack: &mut Stack, top: usize, drop: usize) -> Stack {
    let depth = stack.storage.len();
    let new = Stack::with_storage(stack.storage.drain(depth - top..).collect());
    let depth = stack.storage.len();
    stack.storage.truncate(depth - drop);
    new
}

impl Engine {
    /// C++ `consume_stack_gas`: entries beyond the free depth cost gas.
    fn consume_stack_gas(&mut self, depth: usize) -> Status {
        self.consume_gas(Gas::stack_price(depth))
    }

    fn take_c(&mut self, index: usize) -> StackItem {
        self.ctrls.remove(index).unwrap_or_default()
    }

    /// C++ `preclear_cr`: the registers the savelist is about to replace are cleared.
    fn preclear_cr(&mut self, save: &SaveList) {
        for index in SaveList::REGS {
            if save.get(index).is_some() {
                self.ctrls.remove(index);
            }
        }
    }

    /// C++ `adjust_cr`: every register the savelist holds replaces the live one.
    fn adjust_cr(&mut self, save: &mut SaveList) {
        self.ctrls.apply(save);
    }

    /// C++ `VmState::jump(cont)`.
    pub(in crate::executor) fn jump(&mut self, cont: Arc<ContinuationData>) -> Status {
        if cont.has_control_data() && (cont.stack.depth() != 0 || cont.nargs >= 0) {
            self.jump_args(cont, -1)
        } else {
            self.jump_to(cont)
        }
    }

    /// C++ `VmState::jump(cont, pass_args)`.
    pub(in crate::executor) fn jump_args(
        &mut self,
        cont: Arc<ContinuationData>,
        pass_args: isize,
    ) -> Status {
        let cont = self.adjust_jump_cont(cont, pass_args)?;
        self.jump_to(cont)
    }

    /// C++ `VmState::adjust_jump_cont`: the target takes its arguments from the active stack.
    fn adjust_jump_cont(
        &mut self,
        mut cont: Arc<ContinuationData>,
        pass_args: isize,
    ) -> Result<Arc<ContinuationData>> {
        let depth = self.cc.stack.depth() as isize;
        if cont.has_control_data() {
            if pass_args > depth || cont.nargs > depth {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while jumping to a continuation: not enough arguments on stack"
                )
            }
            if cont.nargs > pass_args && pass_args >= 0 {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while jumping to closure continuation: not enough arguments passed"
                )
            }
            self.preclear_cr(&cont.savelist);
            let mut copy = cont.nargs;
            if pass_args >= 0 && copy < 0 {
                copy = pass_args;
            }
            if cont.stack.depth() != 0 {
                if copy < 0 {
                    copy = depth;
                }
                let data = Arc::make_mut(&mut cont);
                let mut new_stack = std::mem::take(&mut data.stack);
                move_top(&mut new_stack, &mut self.cc.stack, copy as usize);
                let new_depth = new_stack.depth();
                self.cc.stack = new_stack;
                self.consume_stack_gas(new_depth)?;
            } else if copy >= 0 && copy < depth {
                let drop = (depth - copy) as usize;
                self.cc.stack.storage.drain(..drop);
                self.consume_stack_gas(copy as usize)?;
            }
        } else if pass_args >= 0 {
            if pass_args > depth {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while jumping to a continuation: not enough arguments on stack"
                )
            } else if pass_args < depth {
                let drop = (depth - pass_args) as usize;
                self.cc.stack.storage.drain(..drop);
                self.consume_stack_gas(pass_args as usize)?;
            }
        }
        Ok(cont)
    }

    /// C++ `VmState::jump_to`: dispatches continuations until one ends the chain. From version
    /// 9 every dispatch after the first eight costs one gas, and a continuation reached from
    /// another that has a stack or a fixed number of arguments is adjusted as by a jump.
    pub(in crate::executor) fn jump_to(&mut self, mut cont: Arc<ContinuationData>) -> Status {
        let mut count = 0u32;
        loop {
            let next = self.dispatch(cont)?;
            count += 1;
            if count > FREE_NESTED_CONT_JUMP && self.block_version() >= 9 {
                self.consume_gas(1)?;
            }
            let Some(mut next) = next else {
                return Ok(());
            };
            if self.block_version() >= 9
                && next.has_control_data()
                && (next.stack.depth() != 0 || next.nargs >= 0)
            {
                next = self.adjust_jump_cont(next, -1)?;
            }
            cont = next;
        }
    }

    /// One continuation's own `jump`: what it does, and the continuation that runs next.
    fn dispatch(
        &mut self,
        mut cont: Arc<ContinuationData>,
    ) -> Result<Option<Arc<ContinuationData>>> {
        debug_assert!(cont.invariant_holds());
        match &cont.type_of {
            ContinuationType::Ordinary => {
                let data = Arc::make_mut(&mut cont);
                let mut save = std::mem::take(&mut data.savelist);
                self.adjust_cr(&mut save);
                *self.cc.code_mut() = data.code().clone();
                Ok(None)
            }
            ContinuationType::Envelope(next) => {
                let next = next.arc();
                let data = Arc::make_mut(&mut cont);
                let mut save = std::mem::take(&mut data.savelist);
                self.adjust_cr(&mut save);
                Ok(Some(next))
            }
            ContinuationType::Quit(exit_code) => {
                self.terminal = Some(Terminal::Quit(*exit_code));
                Ok(None)
            }
            ContinuationType::ExcQuit => {
                let number = match self.cc.stack.drop(0) {
                    Ok(item) => item.as_integer_value(0..=0xffffi32),
                    Err(err) => Err(err),
                }
                .unwrap_or_else(|err| tvm_exception_or_custom_code(&err));
                self.terminal = Some(Terminal::ExcQuit(number));
                Ok(None)
            }
            ContinuationType::PushInt(value, next) => {
                let next = next.arc();
                self.cc.stack.push_int(*value);
                Ok(Some(next))
            }
            ContinuationType::Repeat { body, after, count } => {
                if *count <= 0 {
                    return Ok(Some(after.arc()));
                }
                let body_cont = body.arc();
                if body_cont.has_c0() {
                    return Ok(Some(body_cont));
                }
                let again = ContinuationType::Repeat {
                    body: body.clone(),
                    after: after.clone(),
                    count: count - 1,
                };
                self.ctrls.put_opt(0, StackItem::continuation(ContinuationData::with_type(again)));
                Ok(Some(body_cont))
            }
            ContinuationType::Again { body } => {
                let body_cont = body.arc();
                if !body_cont.has_c0() {
                    self.ctrls.put_opt(0, StackItem::Continuation(cont.clone()));
                }
                Ok(Some(body_cont))
            }
            ContinuationType::Until { body, after } => {
                let done = self.cc.stack.drop(0)?.as_bool()?;
                if done {
                    return Ok(Some(after.arc()));
                }
                let body_cont = body.arc();
                if !body_cont.has_c0() {
                    self.ctrls.put_opt(0, StackItem::Continuation(cont.clone()));
                }
                Ok(Some(body_cont))
            }
            ContinuationType::While { cond, body, after, check_cond } => {
                if *check_cond {
                    let go_on = self.cc.stack.drop(0)?.as_bool()?;
                    if !go_on {
                        return Ok(Some(after.arc()));
                    }
                    let body_cont = body.arc();
                    if !body_cont.has_c0() {
                        let next = ContinuationType::While {
                            cond: cond.clone(),
                            body: body.clone(),
                            after: after.clone(),
                            check_cond: false,
                        };
                        let next = ContinuationData::with_type(next);
                        self.ctrls.put_opt(0, StackItem::continuation(next));
                    }
                    Ok(Some(body_cont))
                } else {
                    let cond_cont = cond.arc();
                    if !cond_cont.has_c0() {
                        let next = ContinuationType::While {
                            cond: cond.clone(),
                            body: body.clone(),
                            after: after.clone(),
                            check_cond: true,
                        };
                        let next = ContinuationData::with_type(next);
                        self.ctrls.put_opt(0, StackItem::continuation(next));
                    }
                    Ok(Some(cond_cont))
                }
            }
        }
    }

    /// The return continuation of a call: the rest of the current code, with `stack` and
    /// `nargs`, saving the old c0.
    fn return_continuation(&mut self, stack: Stack, nargs: isize, old_c0: StackItem) -> StackItem {
        let code = std::mem::take(self.cc.code_mut());
        let mut ret = ContinuationData::with_code_and_stack(code, stack);
        ret.nargs = nargs;
        if !old_c0.is_null() {
            ret.savelist.put_opt(0, old_c0);
        }
        StackItem::continuation(ret)
    }

    /// C++ `VmState::call(cont)`.
    pub(in crate::executor) fn call(&mut self, cont: Arc<ContinuationData>) -> Status {
        if cont.has_control_data() {
            if cont.savelist.get(0).is_some() {
                return self.jump(cont);
            }
            if cont.stack.depth() != 0 || cont.nargs >= 0 {
                return self.call_args(cont, -1, -1);
            }
        }
        let old_c0 = self.take_c(0);
        let ret = self.return_continuation(Stack::new(), -1, old_c0);
        self.ctrls.put_opt(0, ret);
        self.jump_to(cont)
    }

    /// C++ `VmState::call(cont, pass_args, ret_args)`.
    pub(in crate::executor) fn call_args(
        &mut self,
        mut cont: Arc<ContinuationData>,
        pass_args: isize,
        ret_args: isize,
    ) -> Status {
        let depth = self.cc.stack.depth() as isize;
        if cont.has_control_data() {
            if cont.savelist.get(0).is_some() {
                return self.jump_args(cont, pass_args);
            }
            if pass_args > depth || cont.nargs > depth {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while calling a continuation: not enough arguments on stack"
                )
            }
            if cont.nargs > pass_args && pass_args >= 0 {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while calling a closure continuation: not enough arguments passed"
                )
            }
            let old_c0 = self.take_c(0);
            self.preclear_cr(&cont.savelist);
            let mut copy = cont.nargs;
            let mut skip = 0;
            if pass_args >= 0 {
                if copy >= 0 {
                    skip = pass_args - copy;
                } else {
                    copy = pass_args;
                }
            }
            let new_stack = if cont.stack.depth() != 0 {
                if copy < 0 {
                    copy = depth;
                }
                let data = Arc::make_mut(&mut cont);
                let mut new_stack = std::mem::take(&mut data.stack);
                move_top(&mut new_stack, &mut self.cc.stack, copy as usize);
                if skip > 0 {
                    let rest = self.cc.stack.depth();
                    self.cc.stack.storage.truncate(rest - skip as usize);
                }
                let new_depth = new_stack.depth();
                self.consume_stack_gas(new_depth)?;
                new_stack
            } else if copy >= 0 {
                let new_stack = split_top(&mut self.cc.stack, copy as usize, skip as usize);
                self.consume_stack_gas(new_stack.depth())?;
                new_stack
            } else {
                std::mem::take(&mut self.cc.stack)
            };
            let rest = std::mem::replace(&mut self.cc.stack, new_stack);
            let ret = self.return_continuation(rest, ret_args, old_c0);
            self.ctrls.put_opt(0, ret);
            self.jump_to(cont)
        } else {
            if pass_args > depth {
                fail!(
                    ExceptionCode::StackUnderflow,
                    "stack underflow while calling a continuation: not enough arguments on stack"
                )
            }
            let new_stack = if pass_args >= 0 {
                let new_stack = split_top(&mut self.cc.stack, pass_args as usize, 0);
                self.consume_stack_gas(new_stack.depth())?;
                new_stack
            } else {
                std::mem::take(&mut self.cc.stack)
            };
            let rest = std::mem::replace(&mut self.cc.stack, new_stack);
            let old_c0 = self.take_c(0);
            let ret = self.return_continuation(rest, ret_args, old_c0);
            self.ctrls.put_opt(0, ret);
            self.jump_to(cont)
        }
    }

    fn take_return(&mut self, index: usize) -> Result<Arc<ContinuationData>> {
        let quit = if index == 0 { quit0() } else { quit1() };
        let cont = self.ctrls.put_opt(index, quit).unwrap_or_else(|| {
            if index == 0 {
                quit0()
            } else {
                quit1()
            }
        });
        cont_of(&cont)
    }

    /// C++ `VmState::ret()`: c0 becomes quit0, then the old c0 is jumped to.
    pub(in crate::executor) fn ret(&mut self) -> Status {
        let cont = self.take_return(0)?;
        self.jump(cont)
    }

    pub(in crate::executor) fn ret_args(&mut self, ret_args: isize) -> Status {
        let cont = self.take_return(0)?;
        self.jump_args(cont, ret_args)
    }

    /// C++ `VmState::ret_alt()`: c1 becomes quit1, then the old c1 is jumped to.
    pub(in crate::executor) fn ret_alt(&mut self) -> Status {
        let cont = self.take_return(1)?;
        self.jump(cont)
    }

    /// C++ `VmState::extract_cc`: the current continuation (the rest of the code, with the stack
    /// below the top `stack_copy` entries) as a continuation of `cc_args` arguments; the top
    /// `stack_copy` entries (all for a negative count) stay as the active stack. Bits 1, 2 and
    /// 4 of `save_cr` move c0, c1 and c2 into its savelist; c0 and c1 then become quit0 and
    /// quit1, c2 is left empty.
    pub(in crate::executor) fn extract_cc(
        &mut self,
        save_cr: u8,
        stack_copy: isize,
        cc_args: isize,
    ) -> Result<ContinuationData> {
        let depth = self.cc.stack.depth() as isize;
        let new_stack = if stack_copy < 0 || stack_copy == depth {
            std::mem::take(&mut self.cc.stack)
        } else if stack_copy > 0 {
            if stack_copy > depth {
                fail!(ExceptionCode::StackUnderflow)
            }
            let new_stack = split_top(&mut self.cc.stack, stack_copy as usize, 0);
            self.consume_stack_gas(new_stack.depth())?;
            new_stack
        } else {
            Stack::new()
        };
        let rest = std::mem::replace(&mut self.cc.stack, new_stack);
        let code = std::mem::take(self.cc.code_mut());
        let mut cc = ContinuationData::with_code_and_stack(code, rest);
        cc.nargs = cc_args;
        if save_cr & 1 != 0 {
            let c0 = self.ctrls.put_opt(0, quit0()).unwrap_or_default();
            if !c0.is_null() {
                cc.savelist.put_opt(0, c0);
            }
        }
        if save_cr & 2 != 0 {
            let c1 = self.ctrls.put_opt(1, quit1()).unwrap_or_default();
            if !c1.is_null() {
                cc.savelist.put_opt(1, c1);
            }
        }
        if save_cr & 4 != 0 {
            if let Some(c2) = self.ctrls.remove(2) {
                cc.savelist.put_opt(2, c2);
            }
        }
        Ok(cc)
    }

    /// C++ `VmState::c1_envelope(cont, save)`: with `save`, the continuation keeps c1 and c0
    /// unless it has its own; it becomes c1.
    pub(in crate::executor) fn c1_envelope(
        &mut self,
        mut cont: Arc<ContinuationData>,
        save: bool,
    ) -> Arc<ContinuationData> {
        if save {
            let c1 = self.ctrls.get(1).cloned().unwrap_or_default();
            let c0 = self.ctrls.get(0).cloned().unwrap_or_default();
            let data = force_cdata(&mut cont);
            define_c(&mut data.savelist, 1, c1);
            define_c(&mut data.savelist, 0, c0);
        }
        self.ctrls.put_opt(1, StackItem::Continuation(cont.clone()));
        cont
    }

    pub(in crate::executor) fn c1_envelope_if(
        &mut self,
        cond: bool,
        cont: Arc<ContinuationData>,
    ) -> Arc<ContinuationData> {
        if cond {
            self.c1_envelope(cont, true)
        } else {
            cont
        }
    }

    /// C++ `VmState::c1_save_set`: c0 keeps c1 unless it has its own, and becomes c1 as well.
    pub(in crate::executor) fn c1_save_set(&mut self) -> Status {
        let c1 = self.ctrls.get(1).cloned().unwrap_or_default();
        let mut c0 = cont_of(&self.take_c(0))?;
        define_c(&mut force_cdata(&mut c0).savelist, 1, c1);
        self.ctrls.put_opt(0, StackItem::Continuation(c0.clone()));
        self.ctrls.put_opt(1, StackItem::Continuation(c0));
        Ok(())
    }

    /// C++ `VmState::repeat`.
    pub(in crate::executor) fn repeat(
        &mut self,
        body: Arc<ContinuationData>,
        after: Arc<ContinuationData>,
        count: i64,
    ) -> Status {
        if count <= 0 {
            self.jump(after)
        } else {
            let cont = ContinuationType::Repeat {
                body: ContEdge::from_arc(body),
                after: ContEdge::from_arc(after),
                count,
            };
            self.jump(Arc::new(ContinuationData::with_type(cont)))
        }
    }

    /// C++ `VmState::again`.
    pub(in crate::executor) fn again(&mut self, body: Arc<ContinuationData>) -> Status {
        let cont = ContinuationType::Again { body: ContEdge::from_arc(body) };
        self.jump(Arc::new(ContinuationData::with_type(cont)))
    }

    /// C++ `VmState::until`.
    pub(in crate::executor) fn until(
        &mut self,
        body: Arc<ContinuationData>,
        after: Arc<ContinuationData>,
    ) -> Status {
        if !body.has_c0() {
            let cont = ContinuationType::Until {
                body: ContEdge::from_arc(body.clone()),
                after: ContEdge::from_arc(after),
            };
            self.ctrls.put_opt(0, StackItem::continuation(ContinuationData::with_type(cont)));
        }
        self.jump(body)
    }

    /// C++ `VmState::loop_while`.
    pub(in crate::executor) fn loop_while(
        &mut self,
        cond: Arc<ContinuationData>,
        body: Arc<ContinuationData>,
        after: Arc<ContinuationData>,
    ) -> Status {
        if !cond.has_c0() {
            let cont = ContinuationType::While {
                cond: ContEdge::from_arc(cond.clone()),
                body: ContEdge::from_arc(body),
                after: ContEdge::from_arc(after),
                check_cond: true,
            };
            self.ctrls.put_opt(0, StackItem::continuation(ContinuationData::with_type(cont)));
        }
        self.jump(cond)
    }

    /// The current code as a slice, as C++ `push_code` pushes it.
    pub(in crate::executor) fn push_code(&mut self) {
        let code = self.cc.code().clone();
        self.cc.stack.push(StackItem::Slice(code));
    }

    /// The live value of a register, as C++ `VmState::get`.
    pub(in crate::executor) fn get_c(&self, index: usize) -> StackItem {
        self.ctrls.get(index).cloned().unwrap_or_default()
    }

    /// C++ `VmState::set`: a live register write, type-checked.
    pub(in crate::executor) fn set_c(&mut self, index: usize, value: StackItem) -> Status {
        if !can_set(index, &value) {
            fail!(ExceptionCode::TypeCheckError, "invalid value type for control register")
        }
        self.ctrls.put_opt(index, value);
        Ok(())
    }

    pub(in crate::executor) fn get_cont(&self, index: usize) -> Result<Arc<ContinuationData>> {
        match self.ctrls.get(index) {
            Some(item) => cont_of(item),
            None => Err(error!(ExceptionCode::TypeCheckError, "c{} holds no continuation", index)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::tvm_exception_code;
    use chain_block::Cell;

    const DEPTH: usize = 100_000;

    fn quit(code: i32) -> ContinuationData {
        ContinuationData::with_type(ContinuationType::Quit(code))
    }

    fn envelopes(depth: usize, end: ContinuationData) -> ContinuationData {
        let mut cont = end;
        for _ in 0..depth {
            cont = ContinuationData::with_type(ContinuationType::Envelope(ContEdge::new(cont)));
        }
        cont
    }

    fn finished_repeats(depth: usize, end: ContinuationData) -> ContinuationData {
        let mut cont = end;
        for _ in 0..depth {
            cont = ContinuationData::with_type(ContinuationType::Repeat {
                body: ContEdge::new(ContinuationData::new_empty()),
                after: ContEdge::new(cont),
                count: 0,
            });
        }
        cont
    }

    fn pushints(depth: usize, end: ContinuationData) -> ContinuationData {
        let mut cont = end;
        for i in 0..depth {
            cont = ContinuationData::with_type(ContinuationType::PushInt(
                i as i32,
                ContEdge::new(cont),
            ));
        }
        cont
    }

    fn engine(gas: i64) -> Engine {
        let mut engine = Engine::with_capabilities(0);
        engine.set_block_version(16);
        engine.set_gas(Gas::test_with_limit(gas));
        engine
    }

    // Releasing long chains goes through the iterative release of stack items, whatever edge
    // holds them, also when a tail is shared.
    #[test]
    fn deep_chains_are_released_without_recursion() {
        drop(StackItem::continuation(envelopes(DEPTH, quit(0))));
        drop(StackItem::continuation(finished_repeats(DEPTH, quit(0))));
        drop(StackItem::continuation(pushints(DEPTH, quit(0))));
        drop(envelopes(DEPTH, quit(0)));
        let tail = Arc::new(envelopes(DEPTH, quit(0)));
        let a = ContinuationType::Envelope(ContEdge::from_arc(tail.clone()));
        let b = ContinuationType::Repeat {
            body: ContEdge::from_arc(tail.clone()),
            after: ContEdge::from_arc(tail.clone()),
            count: 0,
        };
        drop(tail);
        drop(StackItem::continuation(ContinuationData::with_type(a)));
        drop(StackItem::continuation(ContinuationData::with_type(b)));
    }

    // Formatting names an edge's kind only; equality walks the chains with a work list.
    #[test]
    fn deep_chains_format_and_compare_without_recursion() {
        let a = envelopes(DEPTH, quit(0));
        let b = envelopes(DEPTH, quit(0));
        let c = envelopes(DEPTH, quit(1));
        assert!(a == b);
        assert!(a != c);
        assert!(finished_repeats(DEPTH, quit(0)) == finished_repeats(DEPTH, quit(0)));
        assert!(pushints(DEPTH, quit(0)) != pushints(DEPTH, quit(1)));
        assert!(format!("{:?}", a).len() < 1_000);
        assert!(format!("{}", a).len() < 1_000);
    }

    // A continuation shared by two stack items keeps its state when the other one is changed.
    #[test]
    fn a_changed_copy_leaves_the_shared_continuation_alone() {
        let shared = Arc::new(envelopes(10, quit(0)));
        let mut alias = shared.clone();
        define_c(&mut force_cdata(&mut alias).savelist, 0, StackItem::continuation(quit(1)));
        assert!(shared.savelist.get(0).is_none());
        assert!(alias.savelist.get(0).is_some());
        let mut quit_alias = Arc::new(quit(0));
        let original = quit_alias.clone();
        force_cdata(&mut quit_alias).savelist.put_opt(4, StackItem::cell(Cell::default()));
        assert!(matches!(quit_alias.type_of, ContinuationType::Envelope(_)));
        assert!(original.invariant_holds() && original.savelist.is_empty());
    }

    // One jump through 100,000 envelopes: every dispatch past the eighth costs one gas, and the
    // chain ends on the quit continuation; with too little gas it runs out and is released.
    #[test]
    fn a_deep_chain_is_dispatched_iteratively_and_charged_per_hop() -> Status {
        let mut engine = engine(1_000_000);
        engine.jump(Arc::new(envelopes(DEPTH, quit(0))))?;
        assert!(matches!(engine.terminal, Some(Terminal::Quit(0))));
        assert_eq!(engine.gas_used(), (DEPTH + 1 - FREE_NESTED_CONT_JUMP as usize) as i64);
        let mut engine = engine_with_little_gas();
        let err = engine.jump(Arc::new(finished_repeats(DEPTH, quit(0)))).unwrap_err();
        assert_eq!(tvm_exception_code(&err), Some(ExceptionCode::OutOfGas));
        Ok(())
    }

    fn engine_with_little_gas() -> Engine {
        engine(1_000)
    }
}
