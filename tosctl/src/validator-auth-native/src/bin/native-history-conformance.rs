use std::{cell::Cell as Counter, env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    context::ChainContext,
    types::Anchor,
};
use tos_validator_auth_native::{
    cells,
    native_apply::FinalizedAnchorSource,
    native_history::{HistoryReadBudget, NativeFinalizedHistory},
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
    if count < 30 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let read = |name: &str| fs::read(folder.join(name)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        if fields.len() < 7 {
            return Err("case-metadata".into());
        }
        let n = |index: usize| fields[index].parse::<usize>().map_err(|_| Error("metadata-number"));
        let calls = Counter::new(0usize);
        let result = (|| -> Result<(), Error> {
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
            let data = read("block")?;
            let mode = n(2)?;
            let source = |id: &chain_block::BlockIdExt, maximum: usize| -> Result<Vec<u8>, Error> {
                calls.set(calls.get() + 1);
                if id.seq_no != 99 || !id.shard_id.is_masterchain_ext() || maximum > 67_108_864 {
                    return Err(Error("history-source-contract"));
                }
                if mode == 1 || mode == 2 && calls.get() > 1 {
                    return Err(Error("archive-offline"));
                }
                Ok(data.clone())
            };
            let state = cells::read_boc(&read("state")?, true)?;
            let head = decode::<Anchor>(&read("head")?)?;
            let history = NativeFinalizedHistory::open(
                state,
                head,
                chain,
                source,
                HistoryReadBudget { blocks: n(0)?, bytes: n(1)? },
            );
            if fields[5] != "-" {
                return match history {
                    Err(e) if e.0 == fields[5] => Ok(()),
                    Err(e) => Err(e),
                    Ok(_) => Err(Error("unexpected-open-acceptance")),
                };
            }
            let history = history?;
            if fields.len() != 7 + n(6)? * 2 {
                return Err(Error("query-count"));
            }
            for j in 0..n(6)? {
                let at = u32::try_from(n(7 + j * 2)?).map_err(|_| Error("coordinate"))?;
                let expected = fields[8 + j * 2];
                let result = history.finalized_anchor(at);
                match result {
                    Ok(anchor) if expected == "-" => {
                        if anchor != decode::<Anchor>(&read(&format!("result{j}"))?)? {
                            return Err(Error("wrong-anchor"));
                        }
                    }
                    Err(e) if e.0 == expected => (),
                    Err(e) => return Err(e),
                    Ok(_) => return Err(Error("unexpected-query-acceptance")),
                }
            }
            Ok(())
        })();
        if result.is_err() || calls.get() != n(3).map_err(|e| e.0.to_owned())? {
            eprintln!("DETAIL: result={result:?}, reads={}", calls.get());
            return Err(fields[4].into());
        }
    }
    println!("PASS: independent authenticated native history {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1);
    }
}
