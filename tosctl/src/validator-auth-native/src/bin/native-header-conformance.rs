use std::{cell::Cell as Counter, env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    context::ChainContext,
    types::Anchor,
};
use tos_validator_auth_native::{
    cells,
    native_history::{native_header_proof, HistoryReadBudget, NativeFinalizedHistory},
};
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
        .map_err(|_| "complete")?;
    if count < 25 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let read = |name: &str| fs::read(folder.join(name)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        if fields.len() != 3 {
            return Err("case-metadata".into());
        }
        let result = (|| -> Result<(), Error> {
            let at: u32 = fields[0].parse().map_err(|_| Error("coordinate"))?;
            let raw = read("chain")?;
            if raw.len() != 100 {
                return Err(Error("chain-size"));
            }
            let chain = ChainContext {
                network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| Error("network"))?),
                genesis_root: raw[4..36].try_into().map_err(|_| Error("root"))?,
                genesis_file: raw[36..68].try_into().map_err(|_| Error("file"))?,
                chain_domain: raw[68..].try_into().map_err(|_| Error("domain"))?,
            };
            let calls = Counter::new(0);
            let history = NativeFinalizedHistory::open(
                cells::read_boc(&read("state")?, true)?,
                decode(&read("head")?)?,
                chain,
                |_: &chain_block::BlockIdExt, _: usize| -> Result<Vec<u8>, Error> {
                    calls.set(calls.get() + 1);
                    Err(Error("archive-offline"))
                },
                HistoryReadBudget { blocks: 0, bytes: 0 },
            )?;
            let proof = cells::read_boc(&read("proof")?, true)?;
            for _ in 0..2 {
                match history.authenticate_header(at, proof.clone()) {
                    Ok(anchor) if fields[2] == "-" => {
                        if anchor != decode::<Anchor>(&read("result")?)? {
                            return Err(Error("wrong-anchor"));
                        }
                        let generated =
                            native_header_proof(cells::read_boc(&read("block")?, true)?)?;
                        if generated.repr_hash() != proof.repr_hash() {
                            return Err(Error("header-generation-parity"));
                        }
                    }
                    Err(e) if e.0 == fields[2] => (),
                    Err(e) => return Err(e),
                    Ok(_) => return Err(Error("unexpected-acceptance")),
                }
                if calls.get() != 0 {
                    return Err(Error("unexpected-archive-read"));
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("DETAIL: {e:?}");
            return Err(fields[1].into());
        }
    }
    println!("PASS: independent native header authentication {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1);
    }
}
