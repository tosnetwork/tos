use chain_block::{Deserializable, MerkleProof};
use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{encode, Error, Hash},
    lifecycle::KeyHistory,
};
use tos_validator_auth_native::{cells, registry::StateReadBudget, registry_view::RegistryView};
fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
    }
}
fn lookup(view: &RegistryView, mode: usize, id: &Hash) -> Result<Vec<u8>, Error> {
    match mode {
        0 => encode(view.policy()),
        1 => encode(&view.identity(id)?),
        2 => encode(&view.find(id)?),
        _ => Err(Error("fixture-mode")),
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    check(args.len() == 2, "arguments")?;
    let path = Path::new(&args[1]);
    let count: usize = fs::read_to_string(path.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 21, "complete-corpus")?;
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let f: Vec<_> = meta.split_whitespace().collect();
        check(f.len() == 8, "fields")?;
        let n = |index: usize| f[index].parse::<usize>().map_err(|_| "number".to_owned());
        let mode = n(0)?;
        let id: Hash = read("id")?.try_into().map_err(|_| "id")?;
        let root = cells::read_boc(&read("boc")?, true).map_err(|e| e.0.to_owned())?;
        let root = if n(4)? == 1 {
            MerkleProof::construct_from_full_cell(root)
                .map_err(|e| e.to_string())?
                .proof
                .virtualize(1)
        } else {
            root
        };
        let view = RegistryView::open(root, 0, StateReadBudget { entries: n(1)?, bytes: n(2)? });
        let result = match &view {
            Ok(view) => lookup(view, mode, &id),
            Err(e) => Err(e.clone()),
        };
        check(result.is_ok() == (n(3)? == 1), &format!("{}: {:?}", f[7], result.as_ref().err()))?;
        if let Ok(value) = result {
            let view = view.map_err(|e| e.0.to_owned())?;
            check(value == read("value")?, "view-value")?;
            let remaining = view.remaining().map_err(|e| e.0.to_owned())?;
            check(remaining.entries == n(5)? && remaining.bytes == n(6)?, "view-budget-charge")?;
            let repeated = lookup(&view, mode, &id);
            let after = view.remaining().map_err(|e| e.0.to_owned())?;
            check(
                repeated.as_ref().is_ok_and(|v| *v == value)
                    && after.entries == remaining.entries
                    && after.bytes == remaining.bytes,
                "view-cache",
            )?;
            check(
                view.ever_registered(&id).is_err() && view.latest_epoch(&id, (1, 1, 1)).is_err(),
                "view-read-only",
            )?;
        }
    }
    println!("PASS: independent bounded authenticated registry view {count} cases");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
