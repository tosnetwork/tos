// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// EXPERIMENT. End-state differential driver (Rust VM). Prints the same columns as
// test/rescue-fee-gate/vm-endstate.cpp, then two more: what execute() returned (ok, an exception
// code, or a custom code) and the argument its error carries ("missing" when it carries none, "-"
// when there is no error). See test/rescue-fee-gate/vm_endstate_compare.py.
use chain_block::{read_single_root_boc, Error, ExceptionCode, SliceData};
use std::{env, fs};
use tos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code, TvmError},
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        integer::IntegerData,
        savelist::SaveList,
        Stack, StackItem,
    },
};

fn push(stack: &mut Stack, field: &str) -> anyhow::Result<()> {
    if field == "skip" {
        return Ok(());
    }
    if let Some(value) = field.strip_prefix("int:") {
        stack.push(StackItem::int(IntegerData::from_i64(value.parse::<i64>()?)));
        return Ok(());
    }
    stack.push(StackItem::Cell(read_single_root_boc(hex::decode(field)?)?));
    Ok(())
}

fn slice(s: &SliceData) -> anyhow::Result<String> {
    let refs = s.get_references();
    Ok(format!(
        "{:X}:{}-{}:{}-{}",
        s.cell()?.repr_hash(),
        s.pos(),
        s.pos() + s.remaining_bits(),
        refs.start,
        refs.end
    ))
}

fn savelist(save: &SaveList) -> String {
    let out: String = [0, 1, 2, 3, 4, 5, 7]
        .iter()
        .filter(|&&i| save.get(i).is_some())
        .map(|i| format!("c{i}"))
        .collect();
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

// Named as the C++ VM names its continuation classes.
fn continuation(cont: &ContinuationData) -> anyhow::Result<String> {
    let name = match &cont.type_of {
        ContinuationType::Ordinary => "vmc_std",
        ContinuationType::Envelope(_) => "vmc_envelope",
        ContinuationType::Quit(_) => "vmc_quit",
        ContinuationType::ExcQuit => "vmc_quit_exc",
        ContinuationType::PushInt(..) => "vmc_pushint",
        ContinuationType::Repeat { .. } => "vmc_repeat",
        ContinuationType::Again { .. } => "vmc_again",
        ContinuationType::Until { .. } => "vmc_until",
        ContinuationType::While { check_cond: true, .. } => "vmc_while_cond",
        ContinuationType::While { check_cond: false, .. } => "vmc_while_body",
    };
    // As in the C++ VM, only ordinary continuations and envelopes carry control data.
    if !cont.has_control_data() {
        return Ok(format!("cont:{name}"));
    }
    Ok(format!(
        "cont:{name}:nargs={}:save={}:stack=[{}]",
        cont.nargs,
        savelist(&cont.savelist),
        stack_items(&cont.stack)?
    ))
}

fn entry(item: &StackItem) -> anyhow::Result<String> {
    Ok(match item {
        StackItem::None => "null".to_string(),
        StackItem::Integer(x) => x.to_str(),
        StackItem::Cell(cell) => format!("cell:{:X}", cell.repr_hash()),
        StackItem::Slice(s) => format!("slice:{}", slice(s)?),
        StackItem::Builder(b) => format!(
            "builder:{}:{}:{:X}",
            b.length_in_bits(),
            b.references().len(),
            b.as_ref().clone().into_cell()?.repr_hash()
        ),
        StackItem::Continuation(cont) => continuation(cont)?,
        StackItem::Tuple(items) => {
            let items = items.iter().map(entry).collect::<anyhow::Result<Vec<_>>>()?;
            format!("({})", items.join(" "))
        }
    })
}

fn stack_items(stack: &Stack) -> anyhow::Result<String> {
    Ok(stack.iter().map(entry).collect::<anyhow::Result<Vec<_>>>()?.join(" "))
}

// What execute() returned, and the argument of its error. With an empty final stack the
// argument is null, printed as missing, as the C++ stack top is.
fn raw_result(result: &Result<i32, Error>, stack: &Stack) -> anyhow::Result<(String, String)> {
    let err = match result {
        Ok(_) => return Ok(("ok".to_string(), "-".to_string())),
        Err(err) => err,
    };
    let kind = match tvm_exception_code(err) {
        Some(code) => format!("exception:{}", code as i32),
        None => format!("custom:{}", tvm_exception_or_custom_code(err)),
    };
    let arg = match err.downcast_ref::<TvmError>() {
        Some(TvmError { value: StackItem::None, .. }) if stack.depth() == 0 => {
            "missing".to_string()
        }
        Some(error) => entry(&error.value)?,
        None => "missing".to_string(),
    };
    Ok((kind, arg))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: vm-endstate scenarios.tsv");
    let data = fs::read_to_string(&args[1])?;
    let mut count = 0;
    for line in data.lines() {
        let f: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(f.len() == 10, "invalid scenario: a program is required");
        let version = f[1].parse::<u32>()?;
        let budget = f[2].parse::<i64>()?;
        let mut stack = Stack::new();
        for field in &f[5..9] {
            push(&mut stack, field)?;
        }
        push(&mut stack, f[4])?;
        let code = read_single_root_boc(hex::decode(f[9])?)?;
        // The C++ VM starts with an empty tuple in c7 unless given one, and c3 quitting with 11
        // unless told to start with c3 set to the code.
        let mut ctrls = SaveList::new();
        ctrls.put(7, StackItem::tuple(vec![]))?;
        let quit = ContinuationData::with_type(ContinuationType::Quit(11));
        ctrls.put(3, StackItem::continuation(quit))?;
        let mut engine = Engine::with_capabilities(0).setup_checked(
            code,
            ctrls,
            stack,
            Gas::test_with_limit(budget),
            vec![],
        )?;
        engine.set_block_version(version);
        let result = engine.execute();
        // As the executor reports it: a custom code as is, out of gas as -14.
        let exit = match &result {
            Ok(code) => *code,
            Err(e) => match tvm_exception_code(e) {
                Some(ExceptionCode::OutOfGas) => -14,
                _ => tvm_exception_or_custom_code(e),
            },
        };
        let (kind, arg) = raw_result(&result, engine.stack())?;
        let stack = stack_items(engine.stack())?;
        let (gas, steps) = (engine.gas_used(), engine.steps());
        let (committed, c4, c5) = match engine.get_committed_state() {
            Some((c4, c5)) => {
                ("1", format!("{:X}", c4.repr_hash()), format!("{:X}", c5.repr_hash()))
            }
            None => ("0", "-".to_string(), "-".to_string()),
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            f[0],
            exit,
            gas,
            steps,
            committed,
            c4,
            c5,
            if stack.is_empty() { "-" } else { &stack },
            kind,
            arg
        );
        count += 1;
    }
    anyhow::ensure!(count > 0, "incomplete scenario set");
    Ok(())
}
