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
    executor::{engine::Engine, microcode::CC},
    stack::StackItem,
};
use chain_block::{fail, ExceptionCode, Status};

// Microfunctions *************************************************************

// ctx.cmd.push_var(src.references[0])
pub(in crate::executor) fn fetch_reference(engine: &mut Engine, src: u16) -> Status {
    let cell = match address_tag!(src) {
        CC => engine.cc.drain_reference()?,
        _ => fail!("fetch_reference: {:X}", src),
    };
    engine.cmd.push_var(StackItem::Cell(cell));
    Ok(())
}

// ctx.cmd.push_var(CC.stack[0..depth])
pub(in crate::executor) fn fetch_stack(engine: &mut Engine, depth: usize) -> Status {
    if engine.cc.stack.depth() < depth {
        fail!(ExceptionCode::StackUnderflow)
    } else {
        engine.cmd.vars.append(&mut engine.cc.stack.drop_range(0..depth)?);
        Ok(())
    }
}
