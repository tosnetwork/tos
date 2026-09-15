use std::{collections::BTreeMap, env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error, Hash},
    transfer::{ObjectReader, CHUNK_BYTES},
    types::{Anchor, Duty, ObjectRef},
};
use tos_validator_auth_native::{
    certificate_proof::verify_native_certificate_response, committee::ChainContext,
};
fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
    }
}
fn hex(id: &Hash) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
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
    check(count >= 40, "complete-corpus")?;
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        check(fields.len() == 4, "fields")?;
        let method: u8 = fields[0].parse().map_err(|_| "method")?;
        let accepted = fields[1] == "1";
        let anchor = decode::<Anchor>(&read("anchor")?).map_err(|e| e.0.to_owned())?;
        let expected = decode::<Duty>(&read("expected")?).map_err(|e| e.0.to_owned())?;
        let raw = read("chain")?;
        check(raw.len() == 100, "chain-length")?;
        let chain = ChainContext {
            network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| "network")?),
            genesis_root: raw[4..36].try_into().map_err(|_| "genesis")?,
            genesis_file: raw[36..68].try_into().map_err(|_| "genesis")?,
            chain_domain: raw[68..100].try_into().map_err(|_| "domain")?,
        };
        let mut fetched = BTreeMap::new();
        let mut reader = ObjectReader::new(|object: &ObjectRef, n| {
            *fetched.entry((object.object_id, n)).or_insert(0u32) += 1;
            let raw = fs::read(path.join("objects").join(hex(&object.object_id)))
                .map_err(|_| Error("fixture-object"))?;
            let offset = usize::from(n) * CHUNK_BYTES;
            Ok(raw
                .get(offset..raw.len().min(offset + CHUNK_BYTES))
                .ok_or(Error("fixture-chunk"))?
                .to_vec())
        });
        let result = verify_native_certificate_response(
            method,
            &read("request")?,
            &read("response")?,
            &anchor,
            &chain,
            &expected,
            &mut reader,
        );
        check(result.is_ok() == accepted, &format!("{}: {:?}", fields[2], result.as_ref().err()))?;
        if let Ok(verified) = result {
            let actual = verified.result().map_err(|e| e.0.to_owned())?;
            check(
                encode(&actual).map_err(|e| e.0.to_owned())? == read("verified")?,
                "verified-native-values",
            )?;
            check(fetched.values().all(|n| *n == 1), "proof-chunks-once")?;
        } else if fields[3] != "-" {
            check(result.err().map(|e| e.0) == Some(fields[3]), fields[2])?;
        }
    }
    println!("PASS: independent native certificate proofs {count} cases");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
