use crate::{
    model::{FILE_COUNT_LIMIT, RAW_LIMIT},
    safe_io::Root,
    service::Frozen,
    trees,
};
use anyhow::{Context, Result, ensure};
use std::fs;

/// Cold copy includes matched recovery material privately, before native reopen and public filtering.
/// The source's identity and signing databases are never copied into the validation image.
pub fn cold_image(frozen: &Frozen, source: &Root, image: &Root) -> Result<u64> {
    cold_image_impl(frozen, source, image, None)
}
pub fn cold_image_checked(
    frozen: &Frozen,
    source: &Root,
    image: &Root,
    secret: &crate::publisher::PublisherSecret,
) -> Result<u64> {
    cold_image_impl(frozen, source, image, Some(secret))
}
/// Native roots the engine creates only on demand. `static` is opened by the root database
/// but written only by a hardfork or by an operator who places genesis files; a node that
/// never had either has no such directory. `tmp` is created at start and may be absent in a
/// copied tree. An absent on-demand root is captured as an empty directory.
pub const ON_DEMAND_ROOTS: [&str; 2] = ["static", "tmp"];

/// Every captured native root, opened below the held source descriptor. Runs before the
/// source is stopped and again during capture: a missing required root, a link, a special
/// file, a replaced directory or another mount refuses.
pub fn precheck_roots(source: &Root) -> Result<()> {
    for name in crate::paths::CHAIN_ROOTS.into_iter().chain(["state", "tmp"]) {
        captured_root(source, name)?;
    }
    Ok(())
}
fn captured_root(source: &Root, name: &str) -> Result<Option<Root>> {
    match trees::optional_directory(source, name)
        .context("captured native root is a link or special file")?
    {
        Some(root) => Ok(Some(root)),
        None if ON_DEMAND_ROOTS.contains(&name) => Ok(None),
        None => anyhow::bail!("captured native root is missing: {name}"),
    }
}
fn cold_image_impl(
    frozen: &Frozen,
    source: &Root,
    image: &Root,
    secret: Option<&crate::publisher::PublisherSecret>,
) -> Result<u64> {
    ensure!(frozen.root == source.path, "freeze belongs to another database root");
    let mut total = 0_u64;
    let mut count = 0_usize;
    for name in crate::paths::CHAIN_ROOTS.into_iter().chain(["state", "tmp"]) {
        let Some(root) = captured_root(source, name)? else {
            // Recovery material is never invented; an absent chain root is an empty one.
            if name != "tmp" {
                ensure_image_root(image, name)?;
            }
            continue;
        };
        for file in trees::inventory(&root)? {
            count = count.checked_add(1).context("capture file count overflow")?;
            ensure!(count <= FILE_COUNT_LIMIT, "capture file count limit");
            total = total.checked_add(file.size).context("capture byte count overflow")?;
            ensure!(total <= RAW_LIMIT, "captured native image exceeds raw byte ceiling");
            let path = format!("{name}/{}", file.path);
            if let Some(secret) = secret {
                secret.reject_input(&source.read(&path, file.size)?)?;
            }
            trees::copy_file(source, &path, image, &path, file.size)?;
        }
        ensure_image_root(image, name)?;
    }
    Ok(total)
}
fn ensure_image_root(image: &Root, name: &str) -> Result<()> {
    if !image.path.join(name).try_exists()? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(image.path.join(name))?;
        image.sync()?;
    }
    Ok(())
}
/// Enumerate only native public file classes after the captured image has recovered and reopened.
pub fn public_files(image: &Root) -> Result<Vec<trees::TreeFile>> {
    let mut result = Vec::new();
    let mut bytes = 0_u64;
    for name in crate::paths::CHAIN_ROOTS {
        let root = Root::open(&image.path.join(name))?;
        for mut file in trees::inventory(&root)? {
            let path = format!("{name}/{}", file.path);
            if crate::paths::excluded_public_file(&path)? {
                continue;
            }
            let public = format!("chain/{path}");
            crate::paths::public_path(&public)?;
            bytes = bytes.checked_add(file.size).context("public size overflow")?;
            ensure!(bytes <= RAW_LIMIT && result.len() < FILE_COUNT_LIMIT, "public image budget");
            file.path = public;
            result.push(file);
        }
    }
    Ok(result)
}

/// File-only manifests do not encode empty directories; preserve the native root schema explicitly.
pub fn install_chain_roots(payload: &Root, replacement: &Root) -> Result<()> {
    for name in crate::paths::CHAIN_ROOTS {
        payload.ensure_directory(&format!("chain/{name}"))?;
        payload.rename(&format!("chain/{name}"), name)?;
        fs::rename(payload.path.join(name), replacement.path.join(name))?;
    }
    payload.sync()?;
    replacement.sync()?;
    Ok(())
}

#[cfg(test)]
mod on_demand_root_tests {
    use super::*;
    /// A stopped source with every engine-created root and one chain file, minus `omit`.
    fn source(omit: &[&str]) -> Result<(tempfile::TempDir, Root)> {
        let temporary = tempfile::tempdir()?;
        let source = Root::create(&temporary.path().canonicalize()?.join("source"))?;
        for name in ["celldb", "files", "archive", "static", "state", "tmp"] {
            if !omit.contains(&name) {
                source.ensure_directory(name)?;
            }
        }
        if !omit.contains(&"celldb") {
            source.write_new("celldb/CURRENT", b"MANIFEST-000001\n")?;
        }
        Ok((temporary, source))
    }
    #[test]
    fn a_source_that_never_had_static_captures_it_as_empty() -> Result<()> {
        let (temporary, source) = source(&["static"])?;
        precheck_roots(&source)?;
        let image = Root::create(&temporary.path().canonicalize()?.join("image"))?;
        let frozen = Frozen::acquire(&source.path)?;
        cold_image(&frozen, &source, &image)?;
        assert!(image.path.join("static").is_dir(), "absent static was not captured as empty");
        assert_eq!(std::fs::read_dir(image.path.join("static"))?.count(), 0);
        assert_eq!(std::fs::read(image.path.join("celldb/CURRENT"))?, b"MANIFEST-000001\n");
        assert!(!source.path.join("static").exists(), "capture created static in the source");
        Ok(())
    }
    #[test]
    fn a_missing_engine_root_still_refuses_before_and_during_capture() -> Result<()> {
        for name in ["celldb", "files", "archive", "state"] {
            let (temporary, source) = source(&[name])?;
            let message = format!("{:#}", precheck_roots(&source).expect_err(name));
            assert!(message.contains(&format!("missing: {name}")), "{name}: {message}");
            let image = Root::create(&temporary.path().canonicalize()?.join("image"))?;
            let frozen = Frozen::acquire(&source.path)?;
            let message = format!("{:#}", cold_image(&frozen, &source, &image).expect_err(name));
            assert!(message.contains(&format!("missing: {name}")), "{name}: {message}");
        }
        // An on-demand root that exists but is a link still refuses.
        let (_temporary, source) = source(&["static"])?;
        std::os::unix::fs::symlink("celldb", source.path.join("static"))?;
        let message = format!("{:#}", precheck_roots(&source).expect_err("linked static"));
        assert!(message.contains("link or special file"), "{message}");
        Ok(())
    }
    #[test]
    fn node_local_private_trees_are_never_captured_or_published() -> Result<()> {
        let (temporary, source) = source(&[])?;
        for path in
            ["console-client/client", "console-client/server.pub", "keyring/KEY", "keys/seed"]
        {
            source.write_new(path, b"node-local private bytes")?;
        }
        let image = Root::create(&temporary.path().canonicalize()?.join("image"))?;
        let frozen = Frozen::acquire(&source.path)?;
        cold_image(&frozen, &source, &image)?;
        for name in ["console-client", "keyring", "keys"] {
            assert!(!image.path.join(name).exists(), "{name} entered the capture image");
        }
        for files in public_files(&image)? {
            assert!(!files.path.contains("console-client"), "published {}", files.path);
        }
        for path in [
            "console-client/client",
            "chain/console-client/client",
            "chain/celldb/console-client",
            "keyring/KEY",
            "chain/keys/seed",
        ] {
            assert!(crate::paths::public_path(path).is_err(), "publishable private path {path}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod public_file_tests {
    use super::*;
    use std::collections::BTreeSet;
    fn fixture() -> Result<(tempfile::TempDir, Root)> {
        let temporary = tempfile::tempdir()?;
        let image = Root::create(&temporary.path().join("image"))?;
        for root in crate::paths::CHAIN_ROOTS {
            image.ensure_directory(root)?;
        }
        Ok((temporary, image))
    }
    #[test]
    fn every_native_file_has_an_explicit_public_disposition() -> Result<()> {
        let (_temporary, image) = fixture()?;
        let mut expected = BTreeSet::new();
        for parent in [
            "celldb",
            "files/globalindex",
            "files/packages/temp.archive.123.index",
            "archive/packages/arch0000/archive.00001.index",
        ] {
            for name in [
                "CURRENT",
                "MANIFEST-000001",
                "OPTIONS-000002",
                "IDENTITY",
                "000003.log",
                "000004.sst",
                "000005.ldb",
            ] {
                let path = format!("{parent}/{name}");
                image.write_new(&path, b"carried fixture bytes")?;
                expected.insert(format!("chain/{path}"));
            }
            for name in
                ["LOCK", "LOG", "LOG.old", "LOG.old.123", "000006.dbtmp", "OPTIONS-000007.dbtmp"]
            {
                let path = format!("{parent}/{name}");
                image.write_new(&path, b"excluded fixture bytes")?;
                assert!(
                    crate::paths::public_path(&format!("chain/{path}")).is_err(),
                    "publisher may ship excluded file: {path}"
                );
            }
        }
        for path in ["celldb/db_stats.txt", "archive/tmp/unfinished-write"] {
            image.write_new(path, b"diagnostics or staging")?;
        }
        for path in [
            format!("static/{}", "ab".repeat(32)),
            "files/packages/temp.archive.123.pack".to_owned(),
            format!("archive/states/zerostate_-1_{}", "cd".repeat(32)),
        ] {
            image.write_new(&path, b"chain fixture bytes")?;
            expected.insert(format!("chain/{path}"));
        }
        let result = public_files(&image);
        assert!(result.is_ok(), "listed native file rejected: {result:?}");
        let files = result?;
        assert_eq!(
            files.iter().map(|v| v.path.clone()).collect::<BTreeSet<_>>(),
            expected,
            "public disposition mismatch"
        );
        assert_eq!(files.len(), expected.len());
        for file in files {
            assert!(
                image
                    .bytes(file.path.strip_prefix("chain/").unwrap(), file.size)?
                    .starts_with(b"carried")
                    || file.path.starts_with("chain/static/")
                    || file.path.starts_with("chain/archive/states/")
                    || file.path.ends_with(".pack")
            );
        }
        Ok(())
    }
    #[test]
    fn unlisted_or_misplaced_files_still_refuse() -> Result<()> {
        for path in [
            "celldb/unlisted.txt",
            "celldb/LOG.old.18446744073709551616",
            "celldb/18446744073709551616.dbtmp",
            "static/LOG",
            "files/globalindex/LOG.old.bad",
            "celldb/OPTIONS-bad.dbtmp",
            "celldb/MANIFEST",
            "celldb/000001.blob",
            "celldb/METADB-1",
            "celldb/COMPACTION_PROGRESS-1",
            "celldb/COMPACTION_PROGRESS-1.dbtmp",
            "files/packages/temp.archive.123.pack.new",
            "files/packages/temp.archive.123.pack.tmp",
        ] {
            let (_temporary, image) = fixture()?;
            image.write_new(path, b"must refuse")?;
            let result = public_files(&image);
            assert!(result.is_err(), "unlisted or unsupported file admitted: {path}");
            let message = result.unwrap_err().to_string();
            assert!(
                message.contains("non-chain or unknown generation path"),
                "wrong refusal for {path}: {message}"
            );
        }
        Ok(())
    }
}
