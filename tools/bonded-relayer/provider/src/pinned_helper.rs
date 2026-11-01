// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Execute exactly the bounded bytes hashed from one opened descriptor.
use anyhow::{ensure, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub struct PinnedHelper(File);
impl PinnedHelper {
    pub fn new(path: &Path, digest: &str) -> Result<Self> {
        ensure!(path.is_absolute() && path.canonicalize()? == path, "unsafe proof verifier path");
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let m = source.metadata()?;
        let uid = unsafe { libc::geteuid() };
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && m.mode() & 0o111 != 0
                && (m.uid() == 0 || m.uid() == uid),
            "unsafe proof verifier"
        );
        const LIMIT: u64 = 128 * 1024 * 1024;
        ensure!((4..=LIMIT).contains(&m.len()), "proof verifier byte bound");
        let mut bytes = Vec::new();
        Read::by_ref(&mut source)
            .take(LIMIT.checked_add(1).ok_or_else(|| anyhow::anyhow!("helper bound"))?)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == m.len(), "proof verifier changed size");
        ensure!(crate::protocol::hash(&bytes) == digest, "proof verifier release pin");
        ensure!(bytes.starts_with(b"\x7fELF"), "proof verifier must be native ELF");
        // Deliberately inherited by the child: Command executes /proc/self/fd/N.
        // The owner keeps it open until the verifier and its children finish.
        let fd =
            unsafe { libc::memfd_create(c"br1-proof-verifier".as_ptr(), libc::MFD_ALLOW_SEALING) };
        ensure!(fd >= 0, "cannot snapshot proof verifier: {}", std::io::Error::last_os_error());
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == 0,
            "cannot seal proof verifier: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(file))
    }
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    #[test]
    fn replacement_cannot_change_executed_bytes_and_snapshot_is_sealed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper");
        let bytes = std::fs::read("/usr/bin/true")?;
        std::fs::write(&path, &bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))?;
        let helper = PinnedHelper::new(&path, &crate::protocol::hash(&bytes))?;
        std::fs::remove_file(&path)?;
        std::fs::copy("/usr/bin/false", &path)?;
        assert!(std::process::Command::new(helper.path()).status()?.success());
        assert_eq!(std::fs::read(helper.path())?, bytes);
        let error = helper.0.set_len(0).err().ok_or_else(|| anyhow::anyhow!("unsealed helper"))?;
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        let error = helper
            .0
            .write_at(b"x", 0)
            .err()
            .ok_or_else(|| anyhow::anyhow!("snapshot remains writable"))?;
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        Ok(())
    }
    #[test]
    fn wrong_release_and_writable_helper_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper");
        let bytes = std::fs::read("/usr/bin/true")?;
        std::fs::write(&path, &bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))?;
        let error = PinnedHelper::new(&path, &"0".repeat(64))
            .err()
            .ok_or_else(|| anyhow::anyhow!("wrong release accepted"))?;
        assert!(error.to_string().contains("release pin"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o522))?;
        let error = PinnedHelper::new(&path, &crate::protocol::hash(&bytes))
            .err()
            .ok_or_else(|| anyhow::anyhow!("writable helper accepted"))?;
        assert!(error.to_string().contains("unsafe proof verifier"));
        Ok(())
    }
}
