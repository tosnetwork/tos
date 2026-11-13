// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! vm harness: one program on the Rust engine, set up as test/conformance/ref/harness-vm.cpp sets
//! up `vm::VmState` (schema/harness/vm-v1.schema.json).
use chain_block::{ExceptionCode, HashmapE};
use serde_json::{json, Value};
use tos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code},
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        integer::IntegerData,
        savelist::SaveList,
        Stack, StackItem,
    },
};

use super::common::{self, Object};

const REQUIRED: &[&str] = &["code", "global_version", "gas", "stack"];
const ALLOWED: &[&str] =
    &["code", "global_version", "gas", "stack", "data", "c7", "flags", "libraries"];
const MAX_LIBRARIES: usize = 4;
/// VmState flags: bit 0 starts with c3 set to the code, bit 1 then pushes an implicit 0. Bit 2 only
/// enables a stack trace in the log; higher bits are not read by the constructor.
const FLAG_SAME_C3: i64 = 1;
const FLAG_PUSH_0: i64 = 2;
/// Unused by the engine outside child VMs, whose limits it only carries; the value the engine's
/// own test gas uses.
const GAS_PRICE: i64 = 10;

pub fn run(ctx: &Object) -> anyhow::Result<Value> {
    common::check_keys(ctx, REQUIRED, ALLOWED, "vm context")?;
    let code = common::ordinary_slice(common::required_boc(ctx, "code")?, "code")?;
    let version = common::required_integer(ctx, "global_version", 0, 255)?;
    let flags = common::integer(ctx, "flags", 0, 255)?.unwrap_or(0);
    let gas = ctx
        .get("gas")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("gas must be an object"))?;
    common::check_keys(gas, &["limit", "max"], &["limit", "max", "credit"], "gas")?;
    let gas_limit = common::required_integer(gas, "limit", 0, i64::MAX)?;
    let gas_max = common::required_integer(gas, "max", 0, i64::MAX)?;
    let gas_credit = common::integer(gas, "credit", 0, i64::MAX)?.unwrap_or(0);
    // The reference adds the two without a check; a sum past 63 bits has no defined meaning there.
    anyhow::ensure!(gas_limit.checked_add(gas_credit).is_some(), "gas limit plus credit overflows");
    let data = common::optional_boc(ctx, "data")?;
    let c7 = match ctx.get("c7") {
        Some(value) => {
            let item = common::stack_item(value, 0)?;
            anyhow::ensure!(item.as_tuple().is_ok(), "c7 must be a tuple");
            Some(item)
        }
        None => None,
    };
    let items = ctx
        .get("stack")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("stack must be an array"))?;
    anyhow::ensure!(items.len() <= common::MAX_ITEMS, "initial stack too deep");
    let mut stack = Stack::new();
    for item in items {
        stack.push(common::stack_item(item, 0)?);
    }
    let mut libraries = Vec::new();
    if let Some(value) = ctx.get("libraries") {
        let list = value.as_array().ok_or_else(|| anyhow::anyhow!("libraries must be an array"))?;
        anyhow::ensure!(list.len() <= MAX_LIBRARIES, "too many library collections");
        for library in list {
            let root = common::boc(library, "library collection")?;
            libraries.push(HashmapE::with_hashmap(256, Some(root)));
        }
    }

    // The C++ VM starts with an empty tuple in c7 and an empty cell in c4 unless given others, and
    // with c3 quitting with 11 unless told to start with c3 set to the code (the engine's default).
    let mut ctrls = SaveList::new();
    ctrls.put(7, c7.unwrap_or_else(|| StackItem::tuple(vec![])))?;
    if let Some(data) = data {
        ctrls.put(4, StackItem::cell(data))?;
    }
    if flags & FLAG_SAME_C3 == 0 {
        let quit = ContinuationData::with_type(ContinuationType::Quit(11));
        ctrls.put(3, StackItem::continuation(quit))?;
    } else if flags & FLAG_PUSH_0 != 0 {
        stack.push(StackItem::int(IntegerData::zero()));
    }
    let mut engine = Engine::with_capabilities(0).setup_checked(
        code.cell()?,
        ctrls,
        stack,
        Gas::new(gas_limit, gas_credit, gas_max, GAS_PRICE),
        libraries,
    )?;
    engine.set_block_version(u32::try_from(version)?);
    let result = engine.execute();
    // As the reference reports it: a custom code as is, out of gas as -14.
    let exit_code = match &result {
        Ok(code) => *code,
        Err(e) => match tvm_exception_code(e) {
            Some(ExceptionCode::OutOfGas) => -14,
            _ => tvm_exception_or_custom_code(e),
        },
    };
    let stack = common::stack_items_text(engine.stack(), 0)?;
    let (gas_used, steps) = (engine.gas_used(), engine.steps());
    let (committed, c4_hash, c5_hash) = match engine.get_committed_state() {
        Some((c4, c5)) => (
            true,
            Value::String(format!("{:X}", c4.repr_hash())),
            Value::String(format!("{:X}", c5.repr_hash())),
        ),
        None => (false, Value::Null, Value::Null),
    };
    Ok(json!({
        "exit_code": exit_code,
        "gas_used": gas_used,
        "steps": steps,
        "committed": committed,
        "c4_hash": c4_hash,
        "c5_hash": c5_hash,
        "stack": stack,
    }))
}
