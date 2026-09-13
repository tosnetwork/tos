use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error},
    context::*,
    types::*,
    verify::RegistrySnapshot,
};
fn read(path: &Path, name: &str) -> Result<Vec<u8>, Error> {
    fs::read(path.join(name)).map_err(|_| Error("fixture-input"))
}
fn run(path: &Path, mode: u8) -> Result<Vec<u8>, Error> {
    let raw = read(path, "chain")?;
    if raw.len() != 100 {
        return Err(Error("fixture-chain"));
    }
    let chain = ChainContext {
        network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| Error("network"))?),
        genesis_root: raw[4..36].try_into().map_err(|_| Error("genesis"))?,
        genesis_file: raw[36..68].try_into().map_err(|_| Error("genesis"))?,
        chain_domain: raw[68..100].try_into().map_err(|_| Error("domain"))?,
    };
    let raw = read(path, "origin")?;
    if raw.len() != 40 {
        return Err(Error("fixture-origin"));
    }
    let origin = SessionOrigin {
        native_options_hash: raw[..32].try_into().map_err(|_| Error("origin"))?,
        vertical_seqno: u32::from_be_bytes(raw[32..36].try_into().map_err(|_| Error("origin"))?),
        key_block_seqno: u32::from_be_bytes(raw[36..40].try_into().map_err(|_| Error("origin"))?),
    };
    let snapshot = RegistrySnapshot::compile(
        &decode::<Committee>(&read(path, "committee")?)?,
        &decode::<Policy>(&read(path, "policy")?)?,
    )?;
    let identity = decode::<Identity>(&read(path, "identity")?)?;
    let key = decode::<Key>(&read(path, "key")?)?;
    let update = decode::<Update>(&read(path, "update")?)?;
    match mode {
        1 => Ok(session_id(&chain, &snapshot, &origin)?.to_vec()),
        2 => Ok(admin_session_id(&chain, &identity.identity)?.to_vec()),
        3 => {
            let expected = decode::<Duty>(&read(path, "expected")?)?;
            encode(&make_duty(
                &chain,
                &snapshot,
                expected.session,
                expected.role,
                expected.position,
                &read(path, "payload")?,
            )?)
        }
        4 => possession_preimage(&chain, &update, &key),
        5 => {
            verify_possession(
                &chain,
                &update,
                &key,
                &decode::<PossessionAuth>(&read(path, "pop")?)?,
            )?;
            Ok(vec![1])
        }
        6 => {
            let inclusion = u32::from_be_bytes(
                read(path, "inclusion")?.try_into().map_err(|_| Error("fixture-inclusion"))?,
            );
            let count = read(path, "key-count")?;
            if count.len() != 1 || count[0] > 2 {
                return Err(Error("fixture-key-count"));
            }
            verify_identity_certificate(
                &decode::<Certificate>(&read(path, "certificate")?)?,
                &decode::<Duty>(&read(path, "expected")?)?,
                &identity,
                &vec![key; usize::from(count[0])],
                inclusion,
            )?;
            Ok(vec![1])
        }
        _ => Err(Error("fixture-mode")),
    }
}
fn main() {
    let check = || -> Result<(), String> {
        let args: Vec<_> = env::args().collect();
        if args.len() != 2 {
            return Err("arguments".to_owned());
        }
        let root = Path::new(&args[1]);
        let count: usize = fs::read_to_string(root.join("complete"))
            .map_err(|e| e.to_string())?
            .trim()
            .parse()
            .map_err(|_| "count")?;
        if count < 50 {
            return Err("complete-corpus".to_owned());
        }
        for i in 0..count {
            let path = root.join(i.to_string());
            let meta = fs::read_to_string(path.join("case")).map_err(|e| e.to_string())?;
            let fields: Vec<_> = meta.split_whitespace().collect();
            if fields.len() != 3 {
                return Err("case".to_owned());
            }
            let result = run(&path, fields[0].parse().map_err(|_| "mode")?);
            let matches = if fields[2] == "-" {
                result.as_ref().ok() == Some(&read(&path, "golden").map_err(|e| e.0.to_owned())?)
            } else {
                result.as_ref().err().map(|e| e.0) == Some(fields[2])
            };
            if !matches {
                eprintln!(
                    "DETAIL: expected={} actual={}",
                    fields[2],
                    result.as_ref().err().map(|e| e.0).unwrap_or("accepted")
                );
                return Err(fields[1].to_owned());
            }
        }
        println!("PASS: current authority and context {count} cases");
        Ok(())
    };
    if let Err(error) = check() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
