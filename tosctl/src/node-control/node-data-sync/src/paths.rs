use anyhow::{Context, Result, ensure};

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
/// Exclude only named non-chain outputs, after the captured database has recovered/reopened.
/// This does not widen the manifest allowlist: publishers still cannot ship these files.
pub fn excluded_public_file(path: &str) -> Result<bool> {
    relative(path)?;
    if path == "celldb/db_stats.txt" {
        return Ok(true);
    }
    if path.starts_with("archive/tmp/") {
        return Ok(true);
    }
    let (parent, name) =
        path.rsplit_once('/').ok_or_else(|| anyhow::anyhow!("native file parent missing"))?;
    if public_path(&format!("chain/{parent}/CURRENT")).is_err() {
        return Ok(false);
    }
    let excluded = name == "LOCK"
        || name == "LOG"
        || name == "LOG.old"
        || name.strip_prefix("LOG.old.").is_some_and(|v| digits(v) && v.parse::<u64>().is_ok())
        || name.strip_suffix(".dbtmp").is_some_and(|v| digits(v) && v.parse::<u64>().is_ok())
        || name
            .strip_prefix("OPTIONS-")
            .and_then(|v| v.strip_suffix(".dbtmp"))
            .is_some_and(|v| digits(v) && v.parse::<u64>().is_ok());
    Ok(excluded)
}

pub fn immutable_sst(path: &str) -> bool {
    public_path(path).is_ok() && path.ends_with(".sst")
}

/// A replacement must account for every database-root directory, never silently discard one.
pub fn restore_root(root: &std::path::Path) -> Result<()> {
    use crate::safe_io::Kind;
    // Listed and inspected through the held root descriptor; nothing is followed by name.
    let root = crate::safe_io::Root::open(root)?;
    // Any entry named wc0-index (directory, file or link) means an engine that runs the
    // in-process wallet index has used, or may use, this database.
    let index = root.path.join("wc0-index");
    if root.kind("wc0-index")?.is_some() {
        anyhow::bail!(
            "wallet-indexed nodes are not supported by restore in this version: {} exists. An engine that predates the standalone wallet index opens it whenever JSON-RPC is enabled; disable that index on the target (add --json-rpc-without-wallet-index to the unit, or remove --json-rpc-address), stop the node, and the operator must remove {} before restore (a retired index must be removed; the tool never deletes it). See doc/node-data-sync.md#supported-targets",
            index.display(),
            index.display()
        );
    }
    for name in root.names()? {
        let path = root.path.join(&name);
        let Some(kind) = root.kind(&name)? else {
            continue;
        };
        ensure!(kind != Kind::Link, "database-root symlink is unsupported: {}", path.display());
        if kind != Kind::Directory {
            continue;
        }
        match name.as_str() {
            "celldb" | "files" | "archive" | "static" | "state" | "keyring" | "consensus"
            | "catchains" | "adnl" | "overlays" | "error" | "tmp" => {}
            "import" => ensure!(
                crate::trees::optional_directory(&root, "import")?
                    .context("pending import directory vanished")?
                    .names()?
                    .is_empty(),
                "pending import directory is not supported by restore: {}",
                path.display()
            ),
            "packed" => anyhow::bail!(
                "legacy packed archive directory is not supported by restore: {}",
                path.display()
            ),
            value if value.starts_with("dht-") => {}
            _ => anyhow::bail!(
                "unknown database-root directory is not supported by restore: {}",
                path.display()
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod restore_tests {
    use super::*;
    #[test]
    fn every_unsupported_root_has_a_specific_refusal() -> Result<()> {
        for (name, message) in [
            ("wc0-index", "retired index must be removed"),
            ("packed", "legacy packed archive"),
            ("unexpected", "unknown database-root directory"),
            ("import", "pending import directory"),
        ] {
            let root = tempfile::tempdir()?;
            std::fs::create_dir(root.path().join(name))?;
            if name == "import" {
                std::fs::write(root.path().join(name).join("pending"), b"input")?;
            }
            let error =
                restore_root(root.path()).expect_err("unsupported root accepted").to_string();
            assert!(error.contains(message), "wrong refusal: {error}");
            assert!(root.path().join(name).exists(), "refusal deleted operator data");
        }
        Ok(())
    }
    /// Names, sizes and modification times of a directory and of one level below it.
    fn listing(path: &std::path::Path) -> Result<Vec<(String, u64, i64, i64)>> {
        use std::os::unix::fs::MetadataExt;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            entries.push((
                entry.file_name().to_string_lossy().into_owned(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ));
            if metadata.is_dir() {
                for child in std::fs::read_dir(entry.path())? {
                    let child = child?;
                    let metadata = child.path().symlink_metadata()?;
                    entries.push((
                        child.path().to_string_lossy().into_owned(),
                        metadata.len(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                    ));
                }
            }
        }
        entries.sort();
        Ok(entries)
    }
    #[test]
    fn any_wallet_index_entry_refuses_and_nothing_is_written() -> Result<()> {
        for kind in ["directory", "file", "symlink"] {
            let temporary = tempfile::tempdir()?;
            let root = temporary.path().canonicalize()?;
            std::fs::create_dir(root.join("celldb"))?;
            std::fs::write(root.join("celldb/CURRENT"), b"MANIFEST-000001\n")?;
            let index = root.join("wc0-index");
            match kind {
                "directory" => std::fs::create_dir(&index)?,
                "file" => std::fs::write(&index, b"index")?,
                _ => std::os::unix::fs::symlink(root.join("celldb"), &index)?,
            }
            let before = listing(&root)?;
            let error = restore_root(&root).expect_err(kind).to_string();
            assert!(
                error.contains("wallet-indexed nodes")
                    && error.contains(&index.display().to_string())
                    && error.contains("--json-rpc-without-wallet-index"),
                "{kind}: wrong refusal: {error}"
            );
            assert_eq!(listing(&root)?, before, "{kind}: the refusal wrote or removed something");
        }
        // Without an index entry the same database is a supported target.
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        std::fs::create_dir(root.join("celldb"))?;
        restore_root(&root)?;
        Ok(())
    }
    #[test]
    fn supported_roots_and_empty_import_are_allowed_but_links_are_not() -> Result<()> {
        let root = tempfile::tempdir()?;
        for name in [
            "celldb",
            "files",
            "archive",
            "static",
            "state",
            "keyring",
            "consensus",
            "catchains",
            "adnl",
            "overlays",
            "tmp",
            "import",
            "dht-local",
            "error",
        ] {
            std::fs::create_dir(root.path().join(name))?;
        }
        restore_root(root.path())?;
        std::os::unix::fs::symlink("absent", root.path().join("wc0-index"))?;
        assert!(restore_root(root.path()).unwrap_err().to_string().contains("retired index"));
        std::fs::remove_file(root.path().join("wc0-index"))?;
        std::os::unix::fs::symlink("absent", root.path().join("unexpected"))?;
        assert!(
            restore_root(root.path()).unwrap_err().to_string().contains("database-root symlink")
        );
        Ok(())
    }
}
