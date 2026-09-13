use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error},
    transfer::{ObjectReader, CHUNK_BYTES},
    types::{Anchor, Proofref},
};
use tos_validator_auth_native::{committee::ChainContext, committee_proof::verify_committee_proof};
fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
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
    check(count >= 20, "complete-corpus")?;
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let f: Vec<_> = meta.split_whitespace().collect();
        check(f.len() == 5, "fields")?;
        let wc: i32 = f[0].parse().map_err(|_| "workchain")?;
        let shard: u64 = f[1].parse().map_err(|_| "shard")?;
        let cc: u32 = f[2].parse().map_err(|_| "catchain")?;
        let proof = decode::<Proofref>(&read("proof")?).map_err(|e| e.0.to_owned())?;
        let anchor = decode::<Anchor>(&read("anchor")?).map_err(|e| e.0.to_owned())?;
        let c = read("chain")?;
        check(c.len() == 100, "chain-length")?;
        let chain = ChainContext {
            network: i32::from_be_bytes(c[..4].try_into().map_err(|_| "network")?),
            genesis_root: c[4..36].try_into().map_err(|_| "genesis")?,
            genesis_file: c[36..68].try_into().map_err(|_| "genesis")?,
            chain_domain: c[68..100].try_into().map_err(|_| "domain")?,
        };
        let raw = read("raw")?;
        let mut reader = ObjectReader::new(|_, n| {
            let offset = usize::from(n) * CHUNK_BYTES;
            Ok(raw
                .get(offset..raw.len().min(offset + CHUNK_BYTES))
                .ok_or(Error("fixture-chunk"))?
                .to_vec())
        });
        let result = verify_committee_proof(&proof, &anchor, &chain, wc, shard, cc, &mut reader);
        check(result.is_ok() == (f[3] == "1"), &format!("{}: {:?}", f[4], result.as_ref().err()))?;
        if let Ok(committee) = result {
            check(
                encode(committee.snapshot().committee()).map_err(|e| e.0.to_owned())?
                    == read("committee")?,
                "proof-committee",
            )?;
        }
    }
    println!("PASS: independent native committee proofs {count} cases");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
