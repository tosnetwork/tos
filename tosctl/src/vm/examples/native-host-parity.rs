use chain_block::{
    read_single_root_boc, BuilderData, Cell, ExceptionCode, Result, SliceData, Status,
};
use std::{
    env, fs,
    path::Path,
    sync::{Arc, Mutex},
};
use tos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
    validator_auth_host::ValidatorAuthHost,
};
fn cell(value: u8) -> Result<Cell> {
    BuilderData::with_raw(vec![value], 8)?.into_cell()
}
struct Host {
    cost: i64,
    states: usize,
    updates: usize,
    first: Cell,
    second: Cell,
    state: Cell,
    applied: Cell,
}
impl ValidatorAuthHost for Host {
    fn checkpoint(&mut self, charge: &mut dyn FnMut(i64) -> Status) -> Result<Cell> {
        charge(self.cost)?;
        self.states += 1;
        Ok(self.state.clone())
    }
    fn apply(
        &mut self,
        update: Cell,
        evidence: Cell,
        charge: &mut dyn FnMut(i64) -> Status,
    ) -> Result<Cell> {
        charge(self.cost)?;
        self.updates += 1;
        if update.repr_hash() != self.first.repr_hash()
            || evidence.repr_hash() != self.second.repr_hash()
        {
            chain_block::fail!(ExceptionCode::RangeCheckError);
        }
        Ok(self.applied.clone())
    }
}
fn execute(dir: &Path) -> anyhow::Result<()> {
    let raw = fs::read_to_string(dir.join("case"))?;
    let f: Vec<_> = raw.split_whitespace().collect();
    anyhow::ensure!(f.len() == 14, "case-shape");
    let n = |i: usize| f[i].parse::<i64>();
    let op = n(0)?;
    let child = n(4)? != 0;
    let fault = n(8)?;
    let host = Arc::new(Mutex::new(Host {
        cost: n(6)?,
        states: 0,
        updates: 0,
        first: cell(0x11)?,
        second: cell(0x22)?,
        state: cell(0x31)?,
        applied: cell(0x32)?,
    }));
    let mut stack = Stack::new();
    let mut args = 0;
    if op != 0 && fault != 1 {
        stack.push(StackItem::Cell(cell(0x11)?));
        args += 1;
        if fault != 2 {
            stack.push(if fault == 3 { StackItem::int(9) } else { StackItem::Cell(cell(0x22)?) });
            args += 1;
        }
    }
    if child {
        stack.push(StackItem::int(args));
        stack.push(StackItem::Slice(SliceData::load_cell(
            BuilderData::with_raw(vec![0xf9, 0x18 + u8::try_from(op)?], 16)?.into_cell()?,
        )?));
    }
    let mut registers = SaveList::new();
    if n(5)? != 0 {
        registers.put(7, StackItem::tuple(vec![StackItem::int(1024)]))?;
    }
    let code = read_single_root_boc(fs::read(dir.join("code"))?)?;
    let mut engine = Engine::with_capabilities(n(2)?.try_into()?).setup_checked(
        code,
        registers,
        stack,
        Gas::test_with_limit(n(7)?),
        vec![],
    )?;
    engine.set_block_version(n(1)?.try_into()?);
    if n(3)? != 0 {
        engine.set_validator_auth_host(host.clone());
    }
    let exit = match engine.execute() {
        Ok(code) => code,
        Err(e) => match tvm_exception_code(&e) {
            Some(ExceptionCode::OutOfGas) => -14,
            Some(code) => code as i32,
            None => return Err(e),
        },
    };
    let top = if exit == 0 {
        if child {
            engine
                .stack()
                .get(0)
                .ok()
                .and_then(|x| x.as_integer_value(0i64..=100).ok())
                .unwrap_or(-2)
        } else {
            let expected = cell(if op == 0 { 0x31 } else { 0x32 })?;
            if engine.stack().depth() != 1 {
                -2
            } else {
                engine
                    .stack()
                    .get(0)
                    .ok()
                    .and_then(|x| x.as_cell().ok())
                    .map_or(-2, |c| i64::from(c.repr_hash() == expected.repr_hash()))
            }
        }
    } else {
        -1
    };
    let locked = host.lock().map_err(|_| anyhow::anyhow!("host-poison"))?;
    let got = [i64::from(exit), engine.gas_used(), top, (locked.states + locked.updates) as i64];
    let expected = [n(9)?, n(10)?, n(11)?, n(12)?];
    if got != expected {
        eprintln!("DETAIL {}: {:?} != {:?}", f[13], got, expected);
        anyhow::bail!("{}", f[13]);
    }
    Ok(())
}
fn run() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    anyhow::ensure!(args.len() == 2, "arguments");
    let path = Path::new(&args[1]);
    let count = fs::read_to_string(path.join("complete"))?.trim().parse::<usize>()?;
    anyhow::ensure!(count >= 25, "complete-corpus");
    for i in 0..count {
        execute(&path.join(i.to_string()))?;
    }
    println!("PASS: native C++/Rust transaction host VM parity {count} cases");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
