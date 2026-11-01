// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Descriptor-based checks protect custody input against symlinks and replacement.
use anyhow::{ensure, Result};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub fn read(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        meta.is_file() && meta.uid() == uid && meta.nlink() == 1,
        "private input ownership/type"
    );
    ensure!(meta.mode() & 0o777 == 0o600, "private input must be mode 0600");
    ensure!(meta.len() > 0 && meta.len() <= u64::try_from(maximum)?, "private input bound");
    let mut bytes = Zeroizing::new(Vec::new());
    let limit = u64::try_from(maximum)?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("input bound overflow"))?;
    file.by_ref().take(limit).read_to_end(&mut bytes)?;
    ensure!(!bytes.is_empty() && bytes.len() <= maximum, "private input changed size");
    Ok(bytes)
}

pub fn seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = read(path, 32)?;
    ensure!(bytes.len() == 32, "seed width");
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn lock(directory: &Path) -> Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("operations.lock"))?;
    let m = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        m.is_file() && m.uid() == uid && m.nlink() == 1 && m.mode() & 0o777 == 0o600,
        "unsafe operations lock"
    );
    use std::os::fd::AsRawFd;
    // SAFETY: the live File owns this descriptor for the whole lock lifetime.
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another custody operation is active"
    );
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn custody_rejects_links_modes_and_sizes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("key");
        std::fs::write(&p, [7u8; 32])?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(*seed(&p)?, [7; 32]);
        let alias = dir.path().join("alias");
        symlink(&p, &alias)?;
        assert!(seed(&alias).is_err());
        std::fs::hard_link(&p, dir.path().join("hard"))?;
        assert!(seed(&p).is_err());
        std::fs::remove_file(dir.path().join("hard"))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640))?;
        assert!(seed(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(&p, [7u8; 33])?;
        assert!(seed(&p).is_err());
        Ok(())
    }
}
