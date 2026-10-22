use crate::{
    model::{FILE_COUNT_LIMIT, RAW_LIMIT},
    safe_io::{Root, copy_hash},
};
use anyhow::{Context, Result, ensure};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(Clone, Debug)]
pub struct TreeFile {
    pub path: String,
    pub size: u64,
    pub allocated: u64,
}
pub fn inventory(root: &Root) -> Result<Vec<TreeFile>> {
    root.attached()?;
    let mut files = Vec::new();
    let mut bytes = 0;
    walk(root, "", &mut files, &mut bytes)?;
    Ok(files)
}
fn walk(root: &Root, prefix: &str, files: &mut Vec<TreeFile>, bytes: &mut u64) -> Result<()> {
    let path = if prefix.is_empty() { root.path.clone() } else { root.path.join(prefix) };
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(entries.len() < FILE_COUNT_LIMIT, "directory entry count limit");
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        ensure!(files.len() < FILE_COUNT_LIMIT, "tree file count limit");
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-text native filename"))?;
        let relative = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        crate::paths::relative(&relative)?;
        let metadata = entry.path().symlink_metadata()?;
        if metadata.file_type().is_dir() {
            walk(root, &relative, files, bytes)?;
        } else {
            ensure!(
                metadata.file_type().is_file() && metadata.nlink() == 1,
                "tree contains a link or special file: {relative} (links={})",
                metadata.nlink()
            );
            *bytes = bytes.checked_add(metadata.len()).context("tree size overflow")?;
            ensure!(*bytes <= RAW_LIMIT, "tree exceeds raw byte ceiling");
            files.push(TreeFile {
                path: relative,
                size: metadata.len(),
                allocated: metadata.blocks().checked_mul(512).context("allocated size overflow")?,
            });
        }
    }
    Ok(())
}
pub fn copy_file(
    source: &Root,
    from: &str,
    target: &Root,
    to: &str,
    max: u64,
) -> Result<(u64, String)> {
    let input = source.read(from, max)?;
    let before = input.metadata()?;
    let probe = input.try_clone()?;
    let mut output = target.create_file(to)?;
    let result = copy_hash(input, &mut output, max);
    let after = probe.metadata()?;
    let stamp = |m: &fs::Metadata| {
        (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
    };
    let result = result.and_then(|result| {
        ensure!(
            stamp(&before) == stamp(&after) && result.0 == before.len(),
            "stopped source changed during capture"
        );
        Ok(result)
    });
    match result {
        Ok(result) => {
            output.sync_all()?;
            target.sync_parent(to)?;
            Ok(result)
        }
        Err(error) => {
            drop(output);
            target.unlink(to)?;
            Err(error)
        }
    }
}
pub fn copy_tree(source: &Root, target: &Root, prefix: &str) -> Result<u64> {
    let files = inventory(source)?;
    let mut total = 0_u64;
    for file in files {
        let to =
            if prefix.is_empty() { file.path.clone() } else { format!("{prefix}/{}", file.path) };
        let (size, _) = copy_file(source, &file.path, target, &to, file.size)?;
        total = total.checked_add(size).context("copied tree size overflow")?;
        ensure!(total <= RAW_LIMIT, "copied tree byte limit");
    }
    Ok(total)
}
/// Preserve the original recovery tree separately; never use this as a replacement overlay.
pub fn copy_optional_tree(root: &Root, name: &str, destination: &Root) -> Result<bool> {
    crate::paths::relative(name)?;
    match fs::symlink_metadata(root.path.join(name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            ensure!(metadata.file_type().is_dir(), "local tree is a symlink or special file");
            let source = Root::open(&root.path.join(name))?;
            // Empty directories also encode existence, especially for signing-state inventories.
            let target_path = destination.path.join(name);
            fs::create_dir(&target_path)?;
            let target = Root::open(&target_path)?;
            copy_tree(&source, &target, "")?;
            target.sync()?;
            destination.sync()?;
            Ok(true)
        }
    }
}
pub fn allocated_bytes(path: &Path) -> Result<u64> {
    inventory(&Root::open(path)?)?.into_iter().try_fold(0_u64, |sum, file| {
        sum.checked_add(file.allocated).context("tree allocation overflow")
    })
}

#[derive(serde::Serialize)]
pub struct PrivateTreeReceipt {
    pub path: String,
    pub present: bool,
    pub files: Vec<(String, u64, String)>,
}
/// Hash the stopped local tree, optionally copy it, and verify the complete result.
pub fn preserve(root: &Root, name: &str, destination: Option<&Root>) -> Result<PrivateTreeReceipt> {
    crate::paths::relative(name)?;
    if crate::safe_io::absent(&root.path.join(name))? {
        return Ok(PrivateTreeReceipt { path: name.to_owned(), present: false, files: vec![] });
    }
    let original = Root::open(&root.path.join(name))?;
    let files = inventory(&original)?;
    let mut receipt = PrivateTreeReceipt { path: name.to_owned(), present: true, files: vec![] };
    if let Some(target) = destination {
        copy_optional_tree(root, name, target)?;
    }
    let copied = destination.map(|target| Root::open(&target.path.join(name))).transpose()?;
    if let Some(target) = &copied {
        ensure!(inventory(target)?.len() == files.len(), "local preservation file count changed");
    }
    for file in files {
        let identity = crate::safe_io::file_hash(original.read(&file.path, file.size)?, file.size)?;
        if let Some(target) = &copied {
            ensure!(
                crate::safe_io::file_hash(target.read(&file.path, file.size)?, file.size)?
                    == identity,
                "local signing/transport bytes changed during preservation"
            );
        }
        receipt.files.push((file.path, identity.0, identity.1));
    }
    Ok(receipt)
}
