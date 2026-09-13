use chain_block::{validator_auth_config::validate_validator_auth_transition, ConfigParams};
use std::{env, fs, path::Path};
use tos_validator_auth_native::cells;
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return Err("arguments".into());
    }
    let root = Path::new(&args[1]);
    let count: usize = fs::read_to_string(root.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    if count < 30 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let read = |name: &str| -> Result<ConfigParams, String> {
            let cell =
                cells::read_boc(&fs::read(folder.join(name)).map_err(|e| e.to_string())?, true)
                    .map_err(|e| e.0.to_string())?;
            ConfigParams::with_root(cell).map_err(|e| e.to_string())
        };
        let before = read("old")?;
        let after = read("new")?;
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let f: Vec<_> = meta.split_whitespace().collect();
        if f.len() != 3 {
            return Err("metadata".into());
        }
        let result = validate_validator_auth_transition(&before, &after);
        if (f[1] == "-" && result.is_err())
            || (f[1] != "-" && result.as_ref().err().is_none_or(|e| e.to_string() != f[1]))
        {
            eprintln!("DETAIL {} expected={} actual={result:?}", f[0], f[1]);
            return Err(f[0].into());
        }
        if after.valid_config_data(false, None).map_err(|e| e.to_string())? != (f[2] == "1") {
            return Err(format!("config-data-{}", f[0]));
        }
        if before != read("old")? || after != read("new")? {
            return Err("config-check-read-only".into());
        }
    }
    println!(
        "PASS: independent native configuration gates {count} cases through production admission"
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
