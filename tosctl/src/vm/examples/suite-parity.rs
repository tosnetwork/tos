// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// EXPERIMENT. PQCHECKSIG_SUITE differential driver (Rust VM). Scenario format and output match
// test/rescue-fee-gate/suite-parity.cpp; see test/rescue-fee-gate/suite_scenarios.py.
use chain_block::{read_single_root_boc, BuilderData, ExceptionCode};
use std::{env, fs};
use tos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
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

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: suite-parity scenarios.tsv");
    let data = fs::read_to_string(&args[1])?;
    let mut count = 0;
    for line in data.lines() {
        let f: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(f.len() == 9, "invalid scenario");
        let version = f[1].parse::<u32>()?;
        let budget = f[2].parse::<i64>()?;
        let mut stack = Stack::new();
        for field in &f[5..9] {
            push(&mut stack, field)?;
        }
        push(&mut stack, f[4])?;
        let mut code = BuilderData::new();
        code.append_raw(&[0xf9, 0x31, 0x02], 24)?;
        let mut engine = Engine::with_capabilities(0).setup_checked(
            code.into_cell()?,
            SaveList::new(),
            stack,
            Gas::test_with_limit(budget),
            vec![],
        )?;
        engine.set_block_version(version);
        let exit = match engine.execute() {
            Ok(code) => code,
            Err(e) => match tvm_exception_code(&e) {
                Some(ExceptionCode::OutOfGas) => -14,
                Some(code) => code as i32,
                None => return Err(e),
            },
        };
        let value = if exit == 0 {
            anyhow::ensure!(engine.stack().depth() == 1, "unexpected stack");
            engine.stack().get(0)?.as_integer_value(-1i64..=0i64)?
        } else {
            99
        };
        println!("{}\t{}\t{}\t{}", f[0], exit, engine.gas_used(), value);
        count += 1;
    }
    anyhow::ensure!(count >= 20, "incomplete scenario set");
    Ok(())
}
