//! Private, atomic persistence shared by configuration and vault storage.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Prepares the directory that holds a private file and returns its resolved
/// path.
///
/// The directory, and the directory it resolves to, must be a real directory
/// owned by the effective user and not writable by its group or by others:
/// whoever can write a directory can replace the files in it. Each ancestor
/// must be owned by the user or by root, and not group- or other-writable
/// unless it is a root-owned sticky directory such as `/tmp`. A missing
/// directory is created with mode 0700.
pub fn prepare_parent(path: &Path) -> anyhow::Result<PathBuf> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }
    check_directory(parent)?;
    // Resolve once and write relative to the resolved path: it contains no
    // symbolic links, and every component is checked below, so no other user
    // can redirect it between the check and the write.
    let resolved = fs::canonicalize(parent)?;
    check_directory(&resolved)?;
    #[cfg(unix)]
    for ancestor in resolved.ancestors().skip(1) {
        let meta = fs::metadata(ancestor)?;
        let euid = unsafe { libc::geteuid() };
        let owner_trusted = meta.uid() == 0 || meta.uid() == euid;
        let protected = meta.mode() & 0o022 == 0 || (meta.uid() == 0 && meta.mode() & 0o1000 != 0);
        anyhow::ensure!(
            owner_trusted && protected,
            "persistence directory {} is inside {} (mode {:04o}, owner uid {}), which another user can modify; \
             use a directory whose ancestors are owned by you or root and not group- or other-writable",
            resolved.display(),
            ancestor.display(),
            meta.mode() & 0o7777,
            meta.uid()
        );
    }
    Ok(resolved)
}

fn check_directory(dir: &Path) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    anyhow::ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "persistence directory {} must be a real directory, not a symbolic link",
        dir.display()
    );
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            meta.uid() == euid,
            "persistence directory {} is owned by uid {}, not by the current user (uid {euid}); \
             use a directory you own",
            dir.display(),
            meta.uid()
        );
        let mode = meta.mode() & 0o7777;
        anyhow::ensure!(
            mode & 0o022 == 0,
            "persistence directory {} is writable by {} (mode {mode:04o}); run 'chmod go-w {}' \
             or use a private directory",
            dir.display(),
            if mode & 0o002 != 0 { "other users" } else { "its group" },
            dir.display()
        );
    }
    Ok(())
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

pub fn write_private_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let parent = prepare_parent(path)?;
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
    let parent = prepare_parent(path)?;
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
        write_private_atomic(&target, b"fake-secret").unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        write_private_atomic(&target, b"updated").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"updated");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        fs::remove_file(&target).unwrap();
        symlink(&victim, &target).unwrap();
        assert!(write_private_atomic(&target, b"attack").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }
    #[test]
    fn writable_directories_are_refused_with_the_fix() {
        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        for mode in [0o770, 0o775, 0o757, 0o777] {
            let shared = dir.path().join(format!("shared-{mode:o}"));
            fs::create_dir(&shared).unwrap();
            fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).unwrap();
            let error = write_private_atomic(&shared.join("config.json"), b"secret").unwrap_err();
            assert!(error.to_string().contains("chmod go-w"), "{error}");
            assert!(!shared.join("config.json").exists());
        }
        // A directory that others can read but not modify is accepted: the
        // file itself is 0600.
        let readable = dir.path().join("readable");
        fs::create_dir(&readable).unwrap();
        fs::set_permissions(&readable, fs::Permissions::from_mode(0o755)).unwrap();
        write_private_atomic(&readable.join("vault.json"), b"secret").unwrap();
        assert_eq!(fs::metadata(readable.join("vault.json")).unwrap().mode() & 0o777, 0o600);
        // A directory reached through a link is refused.
        let link = dir.path().join("link");
        symlink(&readable, &link).unwrap();
        assert!(write_private_atomic(&link.join("vault.json"), b"secret").is_err());
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
        write_private_atomic(&target, b"vault").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        let backup = write_private_backup(&target, b"vault", 1).unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"vault");
        assert_eq!(fs::metadata(backup).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(dir.path()).unwrap().mode() & 0o777, 0o700);
    }
}
