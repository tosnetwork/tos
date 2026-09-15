use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    context::ChainContext,
    crypto::object_id,
    transfer::ObjectReader,
    types::*,
};
use tos_validator_auth_native::{cells, owner_proof::verify_owner_execution};
fn depth_boc(depth: u16) -> Vec<u8> {
    let mut bytes = vec![0xb5, 0xee, 0x9c, 0x72, 2, 2];
    for n in [depth + 1, 1, 0, depth * 4 + 2, 0] {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    for i in 0..depth {
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&(i + 1).to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return Err("arguments".into());
    }
    if cells::read_boc(&depth_boc(1024), true).is_err() {
        return Err("owner-boc-depth-boundary".into());
    }
    if cells::read_boc(&depth_boc(1025), true).is_ok() {
        return Err("owner-boc-depth".into());
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
        let read = |n: &str| fs::read(folder.join(n)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(folder.join("case")).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        if fields.len() != 2 {
            return Err("case-metadata".into());
        }
        let result = (|| -> Result<Vec<u8>, Error> {
            let auth = decode::<OwnerAuth>(&read("auth")?)?;
            let update = decode::<Update>(&read("update")?)?;
            let identity = decode::<Identity>(&read("identity")?)?;
            let anchor = decode::<Anchor>(&read("anchor")?)?;
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
            let mut reader = ObjectReader::new(|_, _| Err(Error("unexpected-fetch")));
            let verified =
                verify_owner_execution(&auth, &update, &identity, &anchor, &chain, &mut reader)?;
            if verified.anchor() != &anchor
                || verified.update_id() != &object_id("update", &update)?
            {
                return Err(Error("owner-result"));
            }
            Ok(verified.transaction_id().to_vec())
        })();
        match result {
            Ok(bytes)
                if fields[0] == "-"
                    && bytes == read("transaction").map_err(|e| e.0.to_owned())? => {}
            Err(error) if fields[0] == error.0 => {}
            result => {
                eprintln!("expected {}, got {:?}", fields[0], result);
                return Err(fields[1].to_owned());
            }
        }
    }
    println!("PASS: independent native owner execution {count} cases");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ASSERTION: {e}");
        std::process::exit(1)
    }
}
