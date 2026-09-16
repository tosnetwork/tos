use chain_block::{read_single_root_boc, BuilderData, ExceptionCode, SliceData};
use std::{env, fs, path::Path};
use tos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, BehaviorModifiers, Engine},
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
};

fn execute(dir: &Path) -> anyhow::Result<()> {
    let meta = fs::read_to_string(dir.join("meta"))?;
    let fields = meta.split_whitespace().map(str::parse::<i64>).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(fields.len() == 10, "fixture metadata");
    let message = read_single_root_boc(fs::read(dir.join("message.boc"))?)?;
    let signature =
        SliceData::load_cell(read_single_root_boc(fs::read(dir.join("signature.boc"))?)?)?;
    let public_key = fs::read(dir.join("key"))?;
    anyhow::ensure!(public_key.len() == 32 && (1..=2).contains(&fields[6]), "fixture input");
    let mut stack = Stack::new();
    let fault = if dir.join("fault").exists() {
        fs::read_to_string(dir.join("fault"))?.trim().parse::<u8>()?
    } else {
        0
    };
    for _ in 0..fields[6] {
        stack.push(if fault == 5 {
            StackItem::Slice(SliceData::load_cell(message.clone())?)
        } else {
            StackItem::Cell(message.clone())
        });
        stack.push(if fault == 4 {
            StackItem::int(0)
        } else {
            StackItem::Slice(signature.clone())
        });
        match fault {
            1 => stack.push(StackItem::int(-1)),
            2 => stack.push(StackItem::integer(IntegerData::nan())),
            3 => stack.push(StackItem::Cell(message.clone())),
            6 => &mut stack,
            _ => stack.push(StackItem::integer(IntegerData::from_unsigned_bytes_be(&public_key))),
        };
    }
    if fields[4] == 1 {
        stack.push(StackItem::int(3));
        stack.push(StackItem::Slice(SliceData::load_cell(
            BuilderData::with_raw(vec![0xf9, 0x17], 16)?.into_cell()?,
        )?));
    }
    let mut registers = SaveList::new();
    if fields[5] == 1 {
        registers.put(7, StackItem::tuple(vec![StackItem::int(1024)]))?;
    }
    let code = read_single_root_boc(fs::read(dir.join("code.boc"))?)?;
    let mut engine = Engine::with_capabilities(fields[1].try_into()?).setup_checked(
        code,
        registers,
        stack,
        Gas::test_with_limit(fields[2]),
        vec![],
    )?;
    engine.set_block_version(fields[0].try_into()?);
    engine.modify_behavior(BehaviorModifiers {
        chksig_always_succeed: fields[3] == 1,
        ..Default::default()
    });
    let exit = match engine.execute() {
        Ok(code) => code,
        Err(error) => match tvm_exception_code(&error) {
            Some(ExceptionCode::OutOfGas) => -14,
            Some(code) => code as i32,
            None => return Err(error),
        },
    };
    let value = if exit == 0 {
        anyhow::ensure!(engine.stack().depth() == 1, "fixture stack result");
        engine.stack().get(0)?.as_integer_value(-1i64..=0i64)?
    } else {
        99
    };
    let got = [exit as i64, engine.gas_used(), value];
    anyhow::ensure!(got == fields[7..10], "{}: {:?} != {:?}", dir.display(), got, &fields[7..10]);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    anyhow::ensure!(args.len() == 2, "usage: validator-auth-parity fixtures");
    let dir = Path::new(&args[1]);
    let count = fs::read_to_string(dir.join("complete"))?.trim().parse::<usize>()?;
    anyhow::ensure!((35..=10000).contains(&count), "incomplete fixture set");
    for index in 0..count {
        execute(&dir.join(index.to_string()))?;
    }
    println!("PASS: {count} native C++/Rust P0 VM result and gas comparisons");
    Ok(())
}
