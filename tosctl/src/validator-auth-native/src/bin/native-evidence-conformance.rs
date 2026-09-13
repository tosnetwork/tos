use std::{cell::Cell as Counter, env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error},
    context::ChainContext,
    types::Anchor,
};
use tos_validator_auth_native::{
    cells,
    native_evidence::NativeEvidence,
    native_history::{HistoryReadBudget, NativeFinalizedHistory},
};
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return Err("arguments".into());
    }
    let root = Path::new(&args[1]);
    let read = |path: &Path| fs::read(path).map_err(|_| Error("fixture-input"));
    let setup = (|| -> Result<_, Error> {
        let raw = read(&root.join("chain"))?;
        if raw.len() != 100 {
            return Err(Error("fixture-chain"));
        }
        let chain = ChainContext {
            network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| Error("network"))?),
            genesis_root: raw[4..36].try_into().map_err(|_| Error("genesis-root"))?,
            genesis_file: raw[36..68].try_into().map_err(|_| Error("genesis-file"))?,
            chain_domain: raw[68..].try_into().map_err(|_| Error("domain"))?,
        };
        Ok((
            cells::read_boc(&read(&root.join("state"))?, true)?,
            decode(&read(&root.join("head"))?)?,
            chain,
            decode::<Anchor>(&read(&root.join("anchor"))?)?,
        ))
    })()
    .map_err(|e| e.0.to_string())?;
    let reads = Counter::new(0);
    let history = NativeFinalizedHistory::open(
        setup.0,
        setup.1,
        setup.2,
        |_: &chain_block::BlockIdExt, _: usize| -> Result<Vec<u8>, Error> {
            reads.set(reads.get() + 1);
            Err(Error("archive-offline"))
        },
        HistoryReadBudget { blocks: 0, bytes: 0 },
    )
    .map_err(|e| e.0.to_string())?;
    let count: usize = fs::read_to_string(root.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "complete")?;
    if count < 35 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        if fields.len() != 4 {
            return Err("case-metadata".into());
        }
        let reject: usize = fields[2].parse().map_err(|_| "charge-index")?;
        let owner = fields[3] == "1";
        let mut charges = Vec::new();
        let outcome = (|| -> Result<(), Error> {
            let evidence = NativeEvidence::open(
                cells::read_boc(&read(&folder.join("evidence"))?, true)?,
                |n| {
                    charges.push(n);
                    if charges.len() == reject {
                        Err(Error("test-out-of-gas"))
                    } else {
                        Ok(())
                    }
                },
            )?;
            if owner && evidence.authenticate_owner(&history)? != setup.3 {
                return Err(Error("fixture-anchor-result"));
            }
            if fields[1] == "-"
                && encode(evidence.authorizations())? != read(&folder.join("authorizations"))?
            {
                return Err(Error("fixture-auth-result"));
            }
            Ok(())
        })();
        match outcome {
            Ok(()) if fields[1] == "-" => {}
            Err(e) if e.0 == fields[1] => {}
            other => {
                eprintln!("observed: {other:?}");
                return Err(fields[0].into());
            }
        }
        let expected: Vec<usize> = fs::read_to_string(folder.join("charges"))
            .map_err(|e| e.to_string())?
            .split_whitespace()
            .map(|v| v.parse().map_err(|_| "charge"))
            .collect::<Result<_, _>>()?;
        if charges != expected {
            {
                eprintln!("charges: {charges:?} != {expected:?}");
                return Err(fields[0].into());
            }
        }
        if reads.get() != 0 {
            return Err("evidence-no-io".into());
        }
    }
    println!("PASS: Rust native evidence {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1)
    }
}
