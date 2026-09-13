use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, Error},
    context::ChainContext,
    transfer::ObjectReader,
    types::*,
    verify::RegistrySnapshot,
};
use tos_validator_auth_native::{
    cells,
    governance::verify_current_governance,
    registry::{RegistryState, StateReadBudget},
};
fn run() -> Result<(), String> {
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
    if count < 28 {
        return Err("complete-corpus".to_owned());
    }
    for i in 0..count {
        let path = root.join(i.to_string());
        let read = |name: &str| fs::read(path.join(name)).map_err(|_| Error("fixture-input"));
        let meta = fs::read_to_string(path.join("case")).map_err(|e| e.to_string())?;
        let f: Vec<_> = meta.split_whitespace().collect();
        if f.len() != 4 {
            return Err("fixture-case".to_owned());
        }
        let execute = || -> Result<Vec<u8>, Error> {
            let coordinate = f[0].parse().map_err(|_| Error("coordinate"))?;
            let inclusion = f[1].parse().map_err(|_| Error("inclusion"))?;
            let cell = cells::read_boc(&read("registry")?, true)?;
            let before = cell.repr_hash();
            let current = RegistryState::decode_cell(cell, coordinate, StateReadBudget::default())?;
            let committee = decode::<Committee>(&read("committee")?)?;
            let policy = decode::<Policy>(&read("policy")?)?;
            let snapshot = RegistrySnapshot::compile(&committee, &policy)?;
            let raw = read("chain")?;
            if raw.len() != 100 {
                return Err(Error("fixture-chain"));
            }
            let chain = ChainContext {
                network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| Error("network"))?),
                genesis_root: raw[4..36].try_into().map_err(|_| Error("genesis"))?,
                genesis_file: raw[36..68].try_into().map_err(|_| Error("genesis"))?,
                chain_domain: raw[68..].try_into().map_err(|_| Error("domain"))?,
            };
            let mut reader =
                ObjectReader::new(|_: &ObjectRef, _: u8| Err(Error("object-unavailable")));
            let result = verify_current_governance(
                &chain,
                &snapshot,
                &current,
                &decode::<Update>(&read("update")?)?,
                &decode::<Authorizations>(&read("evidence")?)?,
                inclusion,
                &mut reader,
            );
            if current.encode_cell()?.repr_hash() != before {
                return Err(Error("verification-read-only"));
            }
            let result = result?;
            let mut bytes = result.certificate_id().to_vec();
            bytes.extend_from_slice(&result.weight().to_be_bytes());
            bytes.extend_from_slice(&(result.signers().len() as u16).to_be_bytes());
            for id in result.signers() {
                bytes.extend_from_slice(id);
            }
            Ok(bytes)
        };
        let result = execute();
        let correct = if f[3] == "-" {
            result.as_ref().ok() == Some(&read("verified").map_err(|e| e.0.to_owned())?)
        } else {
            result.as_ref().err().map(|e| e.0) == Some(f[3])
        };
        if !correct {
            eprintln!(
                "DETAIL: expected={} actual={}",
                f[3],
                result.as_ref().err().map(|e| e.0).unwrap_or("accepted")
            );
            return Err(f[2].to_owned());
        }
    }
    println!("PASS: current governance authority {count} cases");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
