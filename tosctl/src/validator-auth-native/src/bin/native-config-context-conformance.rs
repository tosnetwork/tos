use chain_block::{BuilderData, Cell};
use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error, Hash},
    context::ChainContext,
    types::Anchor,
};
use tos_validator_auth_native::{
    cells, native_config_context::NativeConfigContext, native_registry::NativeRegistry,
    registry::StateReadBudget,
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
    if count < 22 {
        return Err("complete-corpus".into());
    }
    for i in 0..count {
        let folder = root.join(i.to_string());
        let read = |name: &str| fs::read(folder.join(name)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let f: Vec<_> = meta.split_whitespace().collect();
        if f.len() != 4 {
            return Err("metadata".into());
        }
        let result = (|| -> Result<(), Error> {
            let cache: u8 = f[0].parse().map_err(|_| Error("cache-mode"))?;
            let bind: u8 = f[1].parse().map_err(|_| Error("bind-mode"))?;
            let head: Anchor = decode(&read("head")?)?;
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
            let checkpoint = cells::read_boc(&read("cache")?, true)?;
            let registry = checkpoint.reference(0).map_err(|_| Error("checkpoint"))?;
            let cached = NativeRegistry::restore(
                checkpoint,
                registry.repr_hash().as_slice(),
                if cache == 3 { 1 } else { head.seqno },
                StateReadBudget::default(),
            )?;
            let admitted = NativeConfigContext::open(
                cells::read_boc(&read("state")?, true)?,
                &head,
                &chain,
                if cache == 0 { None } else { Some(&cached) },
                StateReadBudget::default(),
            );
            let check = (|| -> Result<(), Error> {
                let context = admitted?;
                let address: Hash = read("address")?.try_into().map_err(|_| Error("address"))?;
                let mut other = address;
                other[31] ^= 1;
                let alternate: Cell = BuilderData::with_raw(vec![1], 8)
                    .and_then(|b| b.into_cell())
                    .map_err(|_| Error("alternate"))?;
                let code = if bind == 3 {
                    alternate.clone()
                } else {
                    cells::read_boc(&read("code")?, true)?
                };
                let data = if bind == 4 {
                    alternate.clone()
                } else {
                    cells::read_boc(&read("data")?, true)?
                };
                context.binds(
                    if bind == 1 { 0 } else { -1 },
                    if bind == 2 { &other } else { &address },
                    code,
                    data,
                    if bind == 5 { Some(alternate) } else { None },
                )?;
                if context.address() != &address
                    || context.head() != &head
                    || context.chain().chain_domain != chain.chain_domain
                    || encode(context.committee().snapshot().committee())? != read("committee")?
                    || context.parent().checkpoint()?.repr_hash()
                        != cells::read_boc(&read("checkpoint")?, true)?.repr_hash()
                {
                    return Err(Error("context-output"));
                }
                Ok(())
            })();
            match check {
                Ok(()) if f[3] == "-" => Ok(()),
                Err(e) if e.0 == f[3] => Ok(()),
                Err(e) => Err(e),
                Ok(()) => Err(Error("unexpected-acceptance")),
            }
        })();
        if let Err(e) = result {
            eprintln!("DETAIL: {e:?}");
            return Err(f[2].into());
        }
    }
    println!("PASS: independent native configuration context {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1);
    }
}
