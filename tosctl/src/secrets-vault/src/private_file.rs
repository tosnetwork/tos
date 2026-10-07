//! Private, atomic persistence shared by configuration and vault storage.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub fn prepare_parent(path: &Path, private: bool) -> anyhow::Result<PathBuf> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }
    let meta = fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "persistence directory must be a real directory"
    );
    #[cfg(unix)]
    {
        anyhow::ensure!(
            meta.uid() == unsafe { libc::geteuid() },
            "persistence directory must be operator-owned"
        );
        anyhow::ensure!(
            meta.mode() & 0o022 == 0,
            "persistence directory must not be writable by other users"
        );
        if private {
            anyhow::ensure!(
                meta.mode() & 0o077 == 0,
                "vault directory must be private (mode 0700)"
            );
        }
    }
    // Resolve trusted ancestors once. The operator-owned directory cannot be
    // modified by another user while the temporary is written and published.
    let resolved = fs::canonicalize(parent)?;
    #[cfg(unix)]
    for ancestor in resolved.ancestors().skip(1) {
        let meta = fs::metadata(ancestor)?;
        anyhow::ensure!(
            meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() },
            "persistence ancestor must be trusted"
        );
        anyhow::ensure!(
            meta.mode() & 0o022 == 0 || (meta.uid() == 0 && meta.mode() & 0o1000 != 0),
            "persistence ancestor must not be writable by other users"
        );
    }
    Ok(resolved)
}

fn check_target(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            anyhow::ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "persistence target must be a regular file"
            );
            #[cfg(unix)]
            {
                anyhow::ensure!(
                    meta.uid() == unsafe { libc::geteuid() } && meta.nlink() == 1,
                    "persistence target must be operator-owned with one link"
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub fn write_private_atomic(
    path: &Path,
    data: &[u8],
    private_directory: bool,
) -> anyhow::Result<()> {
    let parent = prepare_parent(path, private_directory)?;
    let name = path.file_name().ok_or_else(|| anyhow::anyhow!("missing persistence filename"))?;
    let target = parent.join(name);
    check_target(&target)?;
    let mut file = tempfile::Builder::new().prefix(".private-write-").tempfile_in(&parent)?;
    #[cfg(unix)]
    file.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    check_target(&target)?;
    file.persist(&target).map_err(|e| e.error)?;
    fs::File::open(&parent)?.sync_all()?;
    Ok(())
}

pub fn read_regular(path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.is_file(), "vault must be a regular file");
    #[cfg(unix)]
    anyhow::ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.nlink() == 1,
        "vault must be operator-owned with one link"
    );
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    Ok(data)
}

pub fn write_private_backup(path: &Path, data: &[u8], version: u32) -> anyhow::Result<PathBuf> {
    let parent = prepare_parent(path, true)?;
    let prefix = format!(
        "{}.backup_v{version}_",
        path.file_name()
            .ok_or_else(|| anyhow::anyhow!("missing vault filename"))?
            .to_string_lossy()
    );
    let mut backup = tempfile::Builder::new().prefix(&prefix).tempfile_in(&parent)?;
    backup.write_all(data)?;
    backup.as_file().sync_all()?;
    let (_, name) = backup.keep().map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(name)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn atomic_write_is_private_and_refuses_links() {
        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let target = dir.path().join("config.json");
        write_private_atomic(&target, b"fake-secret", false).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        write_private_atomic(&target, b"updated", false).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"updated");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        fs::remove_file(&target).unwrap();
        symlink(&victim, &target).unwrap();
        assert!(write_private_atomic(&target, b"attack", false).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }
    #[test]
    fn vault_ignores_planted_temp_and_creates_private_backup() {
        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let target = dir.path().join("vault.json");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, target.with_extension("tmp")).unwrap();
        write_private_atomic(&target, b"vault", true).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        let backup = write_private_backup(&target, b"vault", 1).unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"vault");
        assert_eq!(fs::metadata(backup).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(dir.path()).unwrap().mode() & 0o777, 0o700);
    }
}
