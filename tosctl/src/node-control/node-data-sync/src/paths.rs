use crate::model::MANIFEST_LIMIT;
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

/// Node-local private directories an operator bundle keeps in the database root. They are
/// preserved through restore with the node's identity and never published or transferred.
pub const LOCAL_PRIVATE_TREES: [&str; 1] = ["console-client"];
/// Where the node's `keys` directory is, as the resolved context decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeysLocation {
    /// The work root is the database root: `<db>/keys` is the work-root key directory and
    /// is preserved with the node's identity.
    Database,
    /// The work root is elsewhere: a `keys` directory in the database root belongs to
    /// nothing the tool preserves, so restore refuses it rather than discard it.
    Elsewhere,
}
/// A replacement must account for every database-root directory, never silently discard one.
pub fn restore_root(root: &std::path::Path, keys: KeysLocation) -> Result<()> {
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
            value if LOCAL_PRIVATE_TREES.contains(&value) => {}
            "keys" => ensure!(
                keys == KeysLocation::Database,
                "database-root keys directory is not the selected work-root key directory and is not supported by restore: {}",
                path.display()
            ),
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

/// Bounds for one bundle-created private tree of a new node (`keyring`, `console-client`).
const NEW_TREE_ENTRIES: usize = 1024;
const NEW_TREE_BYTES: u64 = 16 << 20;
/// Bounds for the genesis files an operator places in `static` before the first start.
const NEW_STATIC_FILES: usize = 64;
const NEW_STATIC_BYTES: u64 = 4 << 30;

/// A database root that has never run a node: only what the engine's first start and the
/// operator bundle write before the first real start. Read through the held root
/// descriptor; every entry must be a regular file or directory on the same device, with no
/// link, hard link or special file anywhere.
///
/// - `config.json` and `keyring/`: required, written by the first start;
/// - `config.json.lock`: empty, taken by the first start and the bundle's configuration;
/// - `error/`: the empty error log the first start creates (`files/` and an empty `log.txt`);
/// - `console-client/`: the bundle's console client keys;
/// - `static/`: genesis files named by their 64-hex file hash;
/// - the optional local configuration files.
///
/// Anything else (chain data, StateDb, signing or session state, `keys/`, an index or
/// operator input) means the database is not new, and this refuses with its path.
pub fn new_node_root(path: &std::path::Path) -> Result<()> {
    use crate::safe_io::Kind;
    let root = crate::safe_io::Root::open(path)?;
    let device = root.identity()?.0;
    let refuse = |name: &str, why: &str| -> anyhow::Error {
        anyhow::anyhow!(
            "bootstrap target is not a new node database: {} {why}; bootstrap installs only into a database that has never run (use tosctl node sync restore for an existing node)",
            root.path.join(name).display()
        )
    };
    let mut config = false;
    let mut keyring = false;
    for name in root.names()? {
        if relative(&name).is_err() {
            return Err(refuse(&name, "has an unsupported name"));
        }
        let entry = root.entry(&name)?.with_context(|| format!("entry vanished: {name}"))?;
        if entry.identity.0 != device {
            return Err(refuse(&name, "is on another device"));
        }
        let regular = entry.kind == Kind::File && entry.links == 1;
        match name.as_str() {
            "config.json" => {
                ensure!(
                    regular && entry.size <= MANIFEST_LIMIT,
                    refuse(&name, "is not a bounded regular file")
                );
                config = true;
            }
            "config.json.lock" => {
                ensure!(
                    regular && entry.size == 0,
                    refuse(&name, "is not the empty configuration lock")
                )
            }
            value if LOCAL_CONFIGS.contains(&value) => {
                ensure!(
                    regular && entry.size <= MANIFEST_LIMIT,
                    refuse(&name, "is not a bounded regular file")
                )
            }
            "keyring" | "console-client" => {
                ensure!(entry.kind == Kind::Directory, refuse(&name, "is not a directory"));
                let tree = crate::trees::optional_directory(&root, &name)?
                    .with_context(|| format!("{name} vanished"))?;
                crate::trees::private_tree(&tree, NEW_TREE_ENTRIES, NEW_TREE_BYTES).map_err(
                    |error| refuse(&name, &format!("is not a bounded private tree ({error:#})")),
                )?;
                keyring |= name == "keyring";
            }
            "static" => {
                ensure!(entry.kind == Kind::Directory, refuse(&name, "is not a directory"));
                let tree = crate::trees::optional_directory(&root, &name)?
                    .with_context(|| format!("{name} vanished"))?;
                let files =
                    crate::trees::private_tree(&tree, NEW_STATIC_FILES + 1, NEW_STATIC_BYTES)
                        .map_err(|error| {
                            refuse(
                                &name,
                                &format!("is not a bounded genesis directory ({error:#})"),
                            )
                        })?;
                for file in files.iter().skip(1) {
                    ensure!(
                        !file.directory && hex_id(&file.path),
                        refuse(
                            &format!("static/{}", file.path),
                            "is not a genesis file named by its file hash"
                        )
                    );
                }
            }
            "error" => {
                ensure!(entry.kind == Kind::Directory, refuse(&name, "is not a directory"));
                let tree = crate::trees::optional_directory(&root, &name)?
                    .with_context(|| format!("{name} vanished"))?;
                let entries = crate::trees::private_tree(&tree, 3, 0)
                    .map_err(|_| refuse(&name, "is not the empty error log of a first start"))?;
                for item in entries.iter().skip(1) {
                    let fresh = (item.path == "files" && item.directory)
                        || (item.path == "log.txt" && !item.directory && item.size == 0);
                    ensure!(fresh, refuse(&name, "is not the empty error log of a first start"));
                }
            }
            "keys" => return Err(refuse(&name, "holds validator key material")),
            _ => return Err(refuse(&name, "is not part of a new node")),
        }
    }
    ensure!(config, refuse("config.json", "is missing"));
    ensure!(keyring, refuse("keyring", "is missing"));
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
            let error = restore_root(root.path(), KeysLocation::Elsewhere)
                .expect_err("unsupported root accepted")
                .to_string();
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
            let error = restore_root(&root, KeysLocation::Elsewhere).expect_err(kind).to_string();
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
        restore_root(&root, KeysLocation::Elsewhere)?;
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
        restore_root(root.path(), KeysLocation::Elsewhere)?;
        std::os::unix::fs::symlink("absent", root.path().join("wc0-index"))?;
        assert!(
            restore_root(root.path(), KeysLocation::Elsewhere)
                .unwrap_err()
                .to_string()
                .contains("retired index")
        );
        std::fs::remove_file(root.path().join("wc0-index"))?;
        std::os::unix::fs::symlink("absent", root.path().join("unexpected"))?;
        assert!(
            restore_root(root.path(), KeysLocation::Elsewhere)
                .unwrap_err()
                .to_string()
                .contains("database-root symlink")
        );
        Ok(())
    }
    #[test]
    fn bundle_private_trees_are_restore_roots_and_keys_follow_the_resolved_work_root() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        for name in ["celldb", "state", "keyring", "console-client"] {
            std::fs::create_dir(root.path().join(name))?;
        }
        std::fs::write(root.path().join("console-client/client"), b"console key")?;
        restore_root(root.path(), KeysLocation::Elsewhere)?;
        std::fs::create_dir(root.path().join("keys"))?;
        let error = restore_root(root.path(), KeysLocation::Elsewhere)
            .expect_err("unpreserved keys accepted")
            .to_string();
        assert!(error.contains("not the selected work-root key directory"), "{error}");
        restore_root(root.path(), KeysLocation::Database)?;
        assert!(root.path().join("keys").is_dir(), "refusal removed operator data");
        std::fs::remove_dir(root.path().join("keys"))?;
        std::fs::remove_file(root.path().join("console-client/client"))?;
        std::fs::remove_dir(root.path().join("console-client"))?;
        std::os::unix::fs::symlink("keyring", root.path().join("console-client"))?;
        let error = restore_root(root.path(), KeysLocation::Database)
            .expect_err("linked console-client accepted")
            .to_string();
        assert!(error.contains("database-root symlink"), "{error}");
        Ok(())
    }

    const HASH_A: &str = "9DBD3E2BDC8DFC1AA00DA63EC7E6E3C2D6E3AF8BEE8CD5BCFE6EA69EAB590358";
    const HASH_B: &str = "fda144a4cc63fd393878f8091d28d785bcb8d3a835a110aa10750e8adf1de6c0";
    /// The layout a bundle node has after its first start and console configuration,
    /// before it has ever run: the entries `new_node_root` admits.
    fn new_node() -> Result<(tempfile::TempDir, std::path::PathBuf)> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?.join("db");
        let db = crate::safe_io::Root::create(&root)?;
        db.write_new("config.json", b"{}")?;
        db.write_new("config.json.lock", b"")?;
        db.write_new(
            "keyring/9DBD3E2BDC8DFC1AA00DA63EC7E6E3C2D6E3AF8BEE8CD5BCFE6EA69EAB590358",
            b"key",
        )?;
        for name in ["client", "client.pub", "server.pub", "liteserver.pub"] {
            db.write_new(&format!("console-client/{name}"), b"console")?;
        }
        db.write_new(&format!("static/{HASH_A}"), b"zero state")?;
        db.write_new(&format!("static/{HASH_B}"), b"base state")?;
        db.ensure_directory("error/files")?;
        db.write_new("error/log.txt", b"")?;
        db.write_new("custom-overlays.json", b"{}")?;
        Ok((temporary, root))
    }
    #[test]
    fn a_new_bundle_node_is_a_bootstrap_target_and_anything_else_refuses() -> Result<()> {
        let (_keep, root) = new_node()?;
        new_node_root(&root)?;
        let cases: Vec<(&str, Box<dyn Fn(&std::path::Path) -> Result<()>>, &str)> = vec![
            (
                "state",
                Box::new(|r| Ok(std::fs::create_dir(r.join("state"))?)),
                "is not part of a new node",
            ),
            (
                "celldb",
                Box::new(|r| Ok(std::fs::create_dir(r.join("celldb"))?)),
                "is not part of a new node",
            ),
            (
                "consensus",
                Box::new(|r| Ok(std::fs::create_dir(r.join("consensus"))?)),
                "is not part of a new node",
            ),
            (
                "empty keys",
                Box::new(|r| Ok(std::fs::create_dir(r.join("keys"))?)),
                "validator key material",
            ),
            (
                "index",
                Box::new(|r| Ok(std::fs::create_dir(r.join("wc0-index"))?)),
                "is not part of a new node",
            ),
            (
                "root link",
                Box::new(|r| Ok(std::os::unix::fs::symlink("keyring", r.join("unexpected"))?)),
                "is not part of a new node",
            ),
            (
                "volume directory",
                Box::new(|r| Ok(std::fs::create_dir(r.join("lost+found"))?)),
                "unsupported name",
            ),
            (
                "linked config",
                Box::new(|r| {
                    std::fs::rename(r.join("config.json"), r.join("../config.real"))?;
                    Ok(std::os::unix::fs::symlink("../config.real", r.join("config.json"))?)
                }),
                "not a bounded regular file",
            ),
            (
                "missing config",
                Box::new(|r| Ok(std::fs::remove_file(r.join("config.json"))?)),
                "config.json is missing",
            ),
            (
                "missing keyring",
                Box::new(|r| {
                    std::fs::remove_file(r.join(format!("keyring/{HASH_A}")))?;
                    Ok(std::fs::remove_dir(r.join("keyring"))?)
                }),
                "keyring is missing",
            ),
            (
                "held lock",
                Box::new(|r| Ok(std::fs::write(r.join("config.json.lock"), b"x")?)),
                "empty configuration lock",
            ),
            (
                "static name",
                Box::new(|r| Ok(std::fs::write(r.join("static/zerostate.boc"), b"x")?)),
                "named by its file hash",
            ),
            (
                "static directory",
                Box::new(|r| {
                    Ok(std::fs::create_dir(r.join(format!("static/{}", "ab".repeat(32))))?)
                }),
                "named by its file hash",
            ),
            (
                "static link",
                Box::new(|r| {
                    std::fs::remove_file(r.join(format!("static/{HASH_B}")))?;
                    Ok(std::os::unix::fs::symlink(HASH_A, r.join(format!("static/{HASH_B}")))?)
                }),
                "link or special file",
            ),
            (
                "static hard link",
                Box::new(|r| {
                    Ok(std::fs::hard_link(r.join(format!("static/{HASH_A}")), r.join("../alias"))?)
                }),
                "link or special file",
            ),
            (
                "keyring hard link",
                Box::new(|r| {
                    Ok(std::fs::hard_link(r.join(format!("keyring/{HASH_A}")), r.join("../alias"))?)
                }),
                "link or special file",
            ),
            (
                "console fifo",
                Box::new(|r| {
                    let path = std::ffi::CString::new(
                        r.join("console-client/pipe").as_os_str().as_encoded_bytes(),
                    )?;
                    // SAFETY: a terminated path in a private temporary directory.
                    ensure!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0, "mkfifo");
                    Ok(())
                }),
                "link or special file",
            ),
            (
                "used error log",
                Box::new(|r| Ok(std::fs::write(r.join("error/log.txt"), b"rejected candidate")?)),
                "empty error log",
            ),
            (
                "saved error file",
                Box::new(|r| Ok(std::fs::write(r.join("error/files/block"), b"x")?)),
                "empty error log",
            ),
        ];
        for (label, mutate, expected) in cases {
            let (_keep, root) = new_node()?;
            mutate(&root)?;
            let error = format!(
                "{:#}",
                new_node_root(&root).err().with_context(|| format!("{label}: accepted"))?
            );
            assert!(error.contains(expected), "{label}: wrong refusal: {error}");
            assert!(
                error.contains("bootstrap target is not a new node database"),
                "{label}: {error}"
            );
        }
        let (_keep, root) = new_node()?;
        for index in 0..NEW_STATIC_FILES {
            std::fs::write(root.join(format!("static/{index:064x}")), b"x")?;
        }
        let error = format!("{:#}", new_node_root(&root).expect_err("unbounded static accepted"));
        assert!(error.contains("bounded genesis directory"), "{error}");
        Ok(())
    }
}
