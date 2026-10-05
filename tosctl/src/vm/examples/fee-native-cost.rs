// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// EXPERIMENT ONLY: native cost-control programs, not an admission opcode.
use chain_block::{read_single_root_boc, BuilderData, ExceptionCode, StorageUsageCalc};
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
    if args.len() == 5 && args[1] == "--storage" {
        let cell = read_single_root_boc(hex::decode(&args[2])?)?;
        let cells = args[3].parse::<u64>()?;
        let bits = args[4].parse::<u64>()?;
        let mut calc = StorageUsageCalc::with_limits(cells, bits);
        calc.append_cell(&cell, false, &mut 0)?;
        let accepted = (cells == 0 || calc.cells() <= cells) && (bits == 0 || calc.bits() <= bits);
        println!("{{\"accepted\":{accepted},\"cells\":{},\"bits\":{}}}", calc.cells(), calc.bits());
        return Ok(());
    }
    anyhow::ensure!(args.len() == 2, "usage: fee-native-cost scenarios.tsv");
    let data = fs::read_to_string(&args[1])?;
    let mut count = 0;
    for line in data.lines() {
        let f: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(f.len() >= 4, "invalid scenario");
        let version = f[1].parse::<u32>()?;
        let budget = f[2].parse::<i64>()?;
        let mut stack = Stack::new();
        for field in &f[4..] {
            push(&mut stack, field)?;
        }
        let mut code = BuilderData::new();
        let bytes = hex::decode(f[3])?;
        code.append_raw(&bytes, bytes.len() * 8)?;
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
            engine.stack().get(0)?.as_integer_value(i64::MIN..=i64::MAX)?
        } else {
            99
        };
        println!("{}\t{}\t{}\t{}", f[0], exit, engine.gas_used(), value);
        count += 1;
    }
    anyhow::ensure!(count > 0, "incomplete scenario set");
    Ok(())
}
