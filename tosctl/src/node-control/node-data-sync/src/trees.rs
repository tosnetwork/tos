use crate::{
    model::{FILE_COUNT_LIMIT, RAW_LIMIT},
    safe_io::{Kind, Root, copy_hash},
};
use anyhow::{Context, Result, ensure};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(Clone, Debug)]
pub struct TreeFile {
    pub path: String,
    pub size: u64,
    pub allocated: u64,
}
/// Every regular file below `root`. Entries are listed through each held directory and
/// every subdirectory is opened below that same descriptor, never by path: a link, a
/// replaced directory or another mount refuses.
pub fn inventory(root: &Root) -> Result<Vec<TreeFile>> {
    root.attached()?;
    let mut files = Vec::new();
    let mut bytes = 0;
    walk(root, "", &mut files, &mut bytes)?;
    Ok(files)
}
fn walk(directory: &Root, prefix: &str, files: &mut Vec<TreeFile>, bytes: &mut u64) -> Result<()> {
    let names = directory.names()?;
    ensure!(names.len() <= FILE_COUNT_LIMIT, "directory entry count limit");
    for name in names {
        ensure!(files.len() < FILE_COUNT_LIMIT, "tree file count limit");
        let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        crate::paths::relative(&relative)?;
        let Some(entry) = directory.entry(&name)? else {
            anyhow::bail!("tree entry vanished: {relative}");
        };
        match entry.kind {
            Kind::Directory => {
                let child = directory.open_child(&name)?;
                ensure!(
                    child.identity()? == entry.identity,
                    "tree directory was replaced: {relative}"
                );
                walk(&child, &relative, files, bytes)?;
            }
            Kind::File if entry.links == 1 => {
                *bytes = bytes.checked_add(entry.size).context("tree size overflow")?;
                ensure!(*bytes <= RAW_LIMIT, "tree exceeds raw byte ceiling");
                files.push(TreeFile {
                    path: relative,
                    size: entry.size,
                    allocated: entry.allocated,
                });
            }
            _ => anyhow::bail!(
                "tree contains a link or special file: {relative} (links={})",
                entry.links
            ),
        }
    }
    Ok(())
}
/// One directory or regular file of a small private tree, as read through descriptors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateEntry {
    /// Relative to the tree; the tree directory itself is the empty path.
    pub path: String,
    pub directory: bool,
    /// Permission and special bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}
/// Every directory (including empty ones and the tree itself) and regular file below a held
/// private tree, in path order. Traversal is through descriptors only: a symlink, special
/// file, hard-linked file, replaced directory or entry on another device refuses. The entry
/// count and byte total are bounded by the caller.
pub fn private_tree(root: &Root, max_entries: usize, max_bytes: u64) -> Result<Vec<PrivateEntry>> {
    root.attached()?;
    let (mode, uid, gid) = root.status()?;
    let device = root.identity()?.0;
    let mut entries =
        vec![PrivateEntry { path: String::new(), directory: true, mode, uid, gid, size: 0 }];
    let mut bytes = 0_u64;
    private_walk(root, "", device, max_entries, max_bytes, &mut entries, &mut bytes)?;
    Ok(entries)
}
fn private_walk(
    directory: &Root,
    prefix: &str,
    device: u64,
    max_entries: usize,
    max_bytes: u64,
    entries: &mut Vec<PrivateEntry>,
    bytes: &mut u64,
) -> Result<()> {
    for name in directory.names()? {
        ensure!(entries.len() < max_entries, "private tree entry count limit");
        let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        crate::paths::relative(&relative)?;
        let entry = directory
            .entry(&name)?
            .with_context(|| format!("private tree entry vanished: {relative}"))?;
        ensure!(entry.identity.0 == device, "private tree entry is on another device: {relative}");
        match entry.kind {
            Kind::Directory => {
                let child = directory.open_child(&name)?;
                ensure!(
                    child.identity()? == entry.identity,
                    "private tree directory was replaced: {relative}"
                );
                entries.push(PrivateEntry {
                    path: relative.clone(),
                    directory: true,
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    size: 0,
                });
                private_walk(&child, &relative, device, max_entries, max_bytes, entries, bytes)?;
            }
            Kind::File if entry.links == 1 => {
                *bytes = bytes.checked_add(entry.size).context("private tree size overflow")?;
                ensure!(*bytes <= max_bytes, "private tree byte limit");
                // Opened below the held directory without crossing a mount: a file bind-mounted
                // from the same filesystem has the same device, and only the open refuses it.
                let opened = directory
                    .read(&name, entry.size)
                    .with_context(|| {
                        format!("private tree file crosses another mount: {relative}")
                    })?
                    .metadata()?;
                ensure!(
                    (opened.dev(), opened.ino()) == entry.identity,
                    "private tree file was replaced: {relative}"
                );
                entries.push(PrivateEntry {
                    path: relative,
                    directory: false,
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    size: entry.size,
                });
            }
            _ => anyhow::bail!(
                "private tree contains a link or special file: {relative} (links={})",
                entry.links
            ),
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
/// One direct subdirectory, opened below the held `root` after checking it is a directory.
/// `None` when absent; a link, special file, replacement or other mount refuses.
pub fn optional_directory(root: &Root, name: &str) -> Result<Option<Root>> {
    ensure!(crate::paths::relative(name)?.len() == 1, "tree must be a direct child");
    let Some(entry) = root.entry(name)? else {
        return Ok(None);
    };
    ensure!(entry.kind == Kind::Directory, "local tree is a symlink or special file: {name}");
    let child = root.open_child(name)?;
    ensure!(child.identity()? == entry.identity, "local tree was replaced: {name}");
    Ok(Some(child))
}
/// Preserve the original recovery tree separately; never use this as a replacement overlay.
pub fn copy_optional_tree(root: &Root, name: &str, destination: &Root) -> Result<bool> {
    match optional_directory(root, name)? {
        None => Ok(false),
        Some(source) => {
            copy_held_tree(&source, name, destination)?;
            Ok(true)
        }
    }
}
fn copy_held_tree(source: &Root, name: &str, destination: &Root) -> Result<Root> {
    // Empty directories also encode existence, especially for signing-state inventories.
    let target_path = destination.path.join(name);
    fs::create_dir(&target_path)?;
    let target = Root::open(&target_path)?;
    copy_tree(source, &target, "")?;
    target.sync()?;
    destination.sync()?;
    Ok(target)
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
    let Some(original) = optional_directory(root, name)? else {
        return Ok(PrivateTreeReceipt { path: name.to_owned(), present: false, files: vec![] });
    };
    let files = inventory(&original)?;
    let mut receipt = PrivateTreeReceipt { path: name.to_owned(), present: true, files: vec![] };
    let copied = destination.map(|target| copy_held_tree(&original, name, target)).transpose()?;
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
