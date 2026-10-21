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
    ensure!(frozen.root == source.path, "freeze belongs to another database root");
    let mut total = 0_u64;
    let mut count = 0_usize;
    for name in ["celldb", "files", "archive", "static", "state", "tmp"] {
        let path = source.path.join(name);
        match path.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && name == "tmp" => continue,
            Err(e) => return Err(e.into()),
            Ok(metadata) => ensure!(
                metadata.file_type().is_dir(),
                "captured native root is a link or special file"
            ),
        }
        let root = Root::open(&path)?;
        for file in trees::inventory(&root)? {
            count = count.checked_add(1).context("capture file count overflow")?;
            ensure!(count <= FILE_COUNT_LIMIT, "capture file count limit");
            total = total.checked_add(file.size).context("capture byte count overflow")?;
            ensure!(total <= RAW_LIMIT, "captured native image exceeds raw byte ceiling");
            let path = format!("{name}/{}", file.path);
            trees::copy_file(source, &path, image, &path, file.size)?;
        }
        if !image.path.join(name).try_exists()? {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(image.path.join(name))?;
            image.sync()?;
        }
    }
    Ok(total)
}
/// Enumerate only native public file classes after the captured image has recovered and reopened.
pub fn public_files(image: &Root) -> Result<Vec<trees::TreeFile>> {
    let mut result = Vec::new();
    let mut bytes = 0_u64;
    for name in ["celldb", "files", "archive", "static"] {
        let root = Root::open(&image.path.join(name))?;
        for mut file in trees::inventory(&root)? {
            let path = format!("{name}/{}", file.path);
            if path.starts_with("archive/tmp/") {
                continue;
            }
            let basename = file.path.rsplit('/').next().context("native filename")?;
            let parent = path.rsplit_once('/').context("native parent")?.0;
            let native_db = crate::paths::public_path(&format!("chain/{parent}/CURRENT")).is_ok();
            if native_db
                && (basename == "LOCK" || basename == "LOG" || basename.starts_with("LOG.old."))
            {
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
