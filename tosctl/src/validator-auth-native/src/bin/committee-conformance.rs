use chain_block::{Deserializable, Serializable};
use std::{env, fs, path::Path};
use tos_validator_auth::{
    codec::{decode, encode, Error},
    types::Anchor,
};
use tos_validator_auth_native::{
    committee::{ChainContext, NativeCommittee},
    registry::StateReadBudget,
};
fn check(ok: bool, name: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(name.to_owned())
    }
}
fn main_run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    check(args.len() == 2, "arguments")?;
    let path = Path::new(&args[1]);
    let count: usize = fs::read_to_string(path.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 25, "complete-corpus")?;
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        check(fields.len() == 5, "fields")?;
        let wc: i32 = fields[0].parse().map_err(|_| "workchain")?;
        let shard: u64 = fields[1].parse().map_err(|_| "shard")?;
        let cc: u32 = fields[2].parse().map_err(|_| "catchain")?;
        let accepted = fields[3] == "1";
        if ["zero-identity", "zero-stake"].contains(&fields[4]) {
            let root =
                chain_block::read_single_root_boc(read("election")?).map_err(|e| e.to_string())?;
            check(
                chain_block::ValidatorSet::construct_from_full_cell(root).is_err(),
                &format!("descriptor-{}", fields[4]),
            )?;
        }
        let anchor = decode::<Anchor>(&read("anchor")?).map_err(|e| e.0.to_owned())?;
        let raw = read("chain")?;
        check(raw.len() == 100, "chain-size")?;
        let chain = ChainContext {
            network: i32::from_be_bytes(raw[0..4].try_into().map_err(|_| "network")?),
            genesis_root: raw[4..36].try_into().map_err(|_| "genesis")?,
            genesis_file: raw[36..68].try_into().map_err(|_| "genesis")?,
            chain_domain: raw[68..100].try_into().map_err(|_| "domain")?,
        };
        let result = (|| -> Result<NativeCommittee, Error> {
            let root =
                chain_block::read_single_root_boc(read("boc").map_err(|_| Error("fixture-file"))?)
                    .map_err(|_| Error("native-boc"))?;
            NativeCommittee::derive(
                root,
                &anchor,
                &chain,
                wc,
                shard,
                cc,
                StateReadBudget::default(),
            )
        })();
        check(
            result.is_ok() == accepted,
            &format!("case-{i}-{}-admission: {:?}", fields[4], result.as_ref().err()),
        )?;
        if let Ok(native) = result {
            if i == 0 {
                for (entries, bytes, name) in [
                    (1, 268435456, "registry-entry-budget"),
                    (1000000, 375, "registry-byte-budget"),
                ] {
                    let root = chain_block::read_single_root_boc(read("boc")?)
                        .map_err(|e| e.to_string())?;
                    check(
                        NativeCommittee::derive(
                            root,
                            &anchor,
                            &chain,
                            wc,
                            shard,
                            cc,
                            StateReadBudget { entries, bytes },
                        )
                        .is_err(),
                        name,
                    )?;
                }
            }
            let election =
                chain_block::read_single_root_boc(read("election")?).map_err(|e| e.to_string())?;
            let restored = chain_block::ValidatorSet::construct_from_full_cell(election.clone())
                .map_err(|e| e.to_string())?;
            check(
                restored.serialize().map_err(|e| e.to_string())?.repr_hash()
                    == election.repr_hash(),
                &format!("case-{i}-descriptor-roundtrip"),
            )?;
            check(
                encode(native.snapshot().committee()).map_err(|e| e.0.to_owned())?
                    == read("committee")?,
                &format!("case-{i}-committee"),
            )?;
            let mut order = Vec::new();
            for member in native.transport_order() {
                let binding = member.auth_binding.as_ref().ok_or("binding")?;
                order.extend_from_slice(binding.identity.as_slice());
            }
            check(order == read("order")?, &format!("case-{i}-order"))?;
        }
    }
    println!("PASS: independent native committee derivation {count} cases");
    Ok(())
}
fn main() {
    if let Err(error) = main_run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
