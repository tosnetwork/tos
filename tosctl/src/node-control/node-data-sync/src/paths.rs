use anyhow::{Result, ensure};

pub const CHAIN_ROOTS: [&str; 4] = ["celldb", "files", "archive", "static"];

pub const LOCAL_CONFIGS: [&str; 5] = [
    "custom-overlays.json",
    "collator-options.json",
    "collators-list.json",
    "shard-block-verifier-config.json",
    "noncritical-params-overrides.json",
];

pub fn relative(path: &str) -> Result<Vec<&str>> {
    ensure!(
        !path.is_empty() && path.len() <= 4096 && !path.starts_with('/'),
        "unsafe relative path"
    );
    let parts: Vec<_> = path.split('/').collect();
    ensure!(parts.len() <= 32, "path depth limit");
    ensure!(
        parts.iter().all(|p| !p.is_empty()
            && *p != "."
            && *p != ".."
            && p.len() <= 255
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))),
        "unsafe path component"
    );
    Ok(parts)
}
fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}
fn hex_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn db_file(name: &str) -> bool {
    matches!(name, "CURRENT" | "IDENTITY")
        || name.strip_prefix("MANIFEST-").is_some_and(digits)
        || name.strip_prefix("OPTIONS-").is_some_and(digits)
        || name.strip_suffix(".sst").is_some_and(digits)
        || name.strip_suffix(".log").is_some_and(digits)
        || name.strip_suffix(".ldb").is_some_and(digits)
}
fn package(stem: &str) -> bool {
    ["temp.archive.", "key.archive.", "archive."].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|rest| {
            let mut split = rest.split('.');
            let Some(id) = split.next() else {
                return false;
            };
            if !digits(id) {
                return false;
            }
            match split.next() {
                None => true,
                Some(shard) => {
                    let valid = shard
                        .split_once('_')
                        .or_else(|| shard.split_once(':'))
                        .is_some_and(|(wc, prefix)| {
                            wc.parse::<i32>().is_ok()
                                && !prefix.is_empty()
                                && prefix.len() <= 16
                                && u64::from_str_radix(prefix, 16).is_ok()
                        });
                    split.next().is_none() && valid
                }
            }
        })
    })
}
pub fn public_path(path: &str) -> Result<()> {
    let p = relative(path)?;
    let allowed = match p.as_slice() {
        ["state-records.cbor"] => true,
        ["metadata", "zero-state.boc" | "tip-block.boc"] => true,
        ["chain", "celldb", name] => db_file(name),
        ["chain", "files", "globalindex", name] => db_file(name),
        ["chain", "static", name] => hex_id(name),
        ["chain", "files", "packages", name] => name.strip_suffix(".pack").is_some_and(package),
        ["chain", "files", "packages", index, name] => {
            index.strip_suffix(".index").is_some_and(package) && db_file(name)
        }
        ["chain", "archive", "packages", bucket, name] => {
            valid_bucket(bucket) && name.strip_suffix(".pack").is_some_and(package)
        }
        ["chain", "archive", "packages", bucket, index, name] => {
            valid_bucket(bucket)
                && index.strip_suffix(".index").is_some_and(package)
                && db_file(name)
        }
        ["chain", "archive", "states", name] => state_file(name),
        _ => false,
    };
    ensure!(allowed, "non-chain or unknown generation path: {path}");
    Ok(())
}
fn valid_bucket(value: &str) -> bool {
    value.strip_prefix("arch").is_some_and(digits) || value.strip_prefix("key").is_some_and(digits)
}
fn state_file(value: &str) -> bool {
    let parts: Vec<_> = value.split('_').collect();
    let workchain = |s: &str| s.parse::<i32>().is_ok();
    let shard =
        |s: &str| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    match parts.as_slice() {
        ["zerostate", wc, hash] => workchain(wc) && hex_id(hash),
        ["state" | "statesplit", seqno, wc, prefix, hash] => {
            digits(seqno) && workchain(wc) && shard(prefix) && hex_id(hash)
        }
        ["stateaccount", seqno, wc, prefix, effective, hash] => {
            digits(seqno) && workchain(wc) && shard(prefix) && shard(effective) && hex_id(hash)
        }
        _ => false,
    }
}
pub fn immutable_sst(path: &str) -> bool {
    public_path(path).is_ok() && path.ends_with(".sst")
}
