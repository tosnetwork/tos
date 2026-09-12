// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use chain_block::{read_single_root_boc, BuilderData, ExceptionCode, IBitstring};
use std::{env, fs};
use tos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, BehaviorModifiers, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: pq-parity scenarios.tsv");
    let data = fs::read_to_string(&args[1])?;
    let mut count = 0;
    for line in data.lines() {
        let f: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(f.len() == 10, "invalid scenario");
        let version = f[1].parse::<u32>()?;
        let budget = f[2].parse::<i64>()?;
        let repeats = f[4].parse::<usize>()?;
        anyhow::ensure!((1..=11).contains(&repeats) && budget >= 0, "invalid limits");
        let mut stack = Stack::new();
        for _ in 0..repeats {
            for field in &f[6..10] {
                match *field {
                    "skip" => {}
                    "int" => {
                        stack.push(StackItem::int(1));
                    }
                    value => {
                        let raw = hex::decode(value)?;
                        stack.push(StackItem::Cell(read_single_root_boc(raw)?));
                    }
                }
            }
        }
        let mut code = BuilderData::new();
        for i in 0..repeats {
            code.append_raw(&[0xf9, 0x31, 0], 24)?;
            if i + 1 < repeats {
                code.append_raw(&[0x30], 8)?;
            }
        }
        let mut engine = Engine::with_capabilities(0).setup_checked(
            code.into_cell()?,
            SaveList::new(),
            stack,
            Gas::test_with_limit(budget),
            vec![],
        )?;
        engine.set_block_version(version);
        let mut modifiers = BehaviorModifiers::default();
        modifiers.chksig_always_succeed = f[3] == "1";
        engine.modify_behavior(modifiers);
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
        let gas = engine.gas_used();
        let committed = engine.is_committed_state();
        let (c4, c5) = match engine.get_committed_state() {
            Some((a, b)) => (a.repr_hash().to_hex_string(), b.repr_hash().to_hex_string()),
            None => ("-".to_string(), "-".to_string()),
        };
        println!("{}\t{}\t{}\t{}\t{}\t{}\t{}", f[0], exit, gas, value, u8::from(committed), c4, c5);
        count += 1;
    }
    anyhow::ensure!(count >= 20, "incomplete scenario set");
    Ok(())
}
