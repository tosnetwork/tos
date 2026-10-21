use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

/// Descriptor-relative traversal refuses symlinks at every component.
pub struct Root {
    directory: File,
    pub path: PathBuf,
}
impl Root {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute() && std::fs::canonicalize(path)? == path,
            "root must be canonical and link-free"
        );
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(directory.metadata()?.is_dir(), "root is not a directory");
        Ok(Self { directory, path: path.to_owned() })
    }
    pub fn create(path: &Path) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
        let root = Self::open(path)?;
        Self::open(path.parent().context("private directory parent")?)?.sync()?;
        Ok(root)
    }
    pub fn attached(&self) -> Result<()> {
        let held = self.directory.metadata()?;
        let current = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            current.file_type().is_dir()
                && held.dev() == current.dev()
                && held.ino() == current.ino(),
            "root path was exchanged or replaced; reopen the selected tree"
        );
        Ok(())
    }
    fn parent(&self, path: &str, create: bool) -> Result<(OwnedFd, CString)> {
        self.attached()?;
        let parts = super::paths::relative(path)?;
        let mut dir: OwnedFd = self.directory.try_clone()?.into();
        let (last, parents) = parts.split_last().context("empty path")?;
        for part in parents {
            let name = CString::new(*part)?;
            if create {
                // SAFETY: owned directory descriptor and terminated component remain valid.
                let result = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
                if result == 0 {
                    File::from(dir.try_clone()?).sync_all()?;
                }
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    ensure!(
                        error.kind() == std::io::ErrorKind::AlreadyExists,
                        "create directory: {error}"
                    );
                }
            }
            let raw = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            ensure!(raw >= 0, "refusing unsafe directory: {}", std::io::Error::last_os_error());
            dir = unsafe { OwnedFd::from_raw_fd(raw) };
        }
        Ok((dir, CString::new(*last)?))
    }
    /// Create or validate every directory component without following links.
    pub fn ensure_directory(&self, path: &str) -> Result<()> {
        let (directory, _) = self.parent(&format!("{path}/directory-probe"), true)?;
        File::from(directory).sync_all()?;
        Ok(())
    }
    pub fn read(&self, path: &str, max: u64) -> Result<File> {
        let (dir, name) = self.parent(path, false)?;
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        ensure!(raw >= 0, "cannot safely read {path}: {}", std::io::Error::last_os_error());
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= max,
            "non-regular or oversized file: {path}"
        );
        if metadata.len() > 0 {
            // Sparse payloads must not expand unexpectedly when materialized.
            let hole = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_HOLE) };
            ensure!(
                hole >= 0 && u64::try_from(hole)? == metadata.len(),
                "sparse or uninspectable regular file: {path}"
            );
            ensure!(
                unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) } == 0,
                "cannot rewind inspected file"
            );
        }
        Ok(file)
    }
    pub fn bytes(&self, path: &str, max: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read(path, max)?
            .take(max.checked_add(1).context("read bound overflow")?)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= max, "file grew beyond limit");
        Ok(bytes)
    }
    pub fn create_file(&self, path: &str) -> Result<File> {
        let (dir, name) = self.parent(path, true)?;
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(raw >= 0, "cannot create private file {path}: {}", std::io::Error::last_os_error());
        Ok(unsafe { File::from_raw_fd(raw) })
    }
    pub fn append_file(&self, path: &str, expected_size: u64) -> Result<File> {
        let (dir, name) = self.parent(path, false)?;
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(raw >= 0, "cannot resume private file: {}", std::io::Error::last_os_error());
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() == expected_size,
            "resume file identity or size changed"
        );
        Ok(file)
    }
    pub fn write_new(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let mut out = self.create_file(path)?;
        out.write_all(bytes)?;
        out.sync_all()?;
        self.sync_parent(path)
    }
    pub fn replace(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let temporary = format!("{path}.pending.{:016x}", rand::random::<u64>());
        self.write_new(&temporary, bytes)?;
        self.rename(&temporary, path)?;
        self.sync_parent(path)
    }
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (from_dir, from_name) = self.parent(from, false)?;
        let (to_dir, to_name) = self.parent(to, true)?;
        let result = unsafe {
            libc::renameat(
                from_dir.as_raw_fd(),
                from_name.as_ptr(),
                to_dir.as_raw_fd(),
                to_name.as_ptr(),
            )
        };
        ensure!(result == 0, "rename failed: {}", std::io::Error::last_os_error());
        File::from(from_dir).sync_all()?;
        File::from(to_dir).sync_all()?;
        Ok(())
    }
    pub fn unlink(&self, path: &str) -> Result<()> {
        let (dir, name) = self.parent(path, false)?;
        let result = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
        ensure!(result == 0, "unlink failed: {}", std::io::Error::last_os_error());
        self.sync_parent(path)
    }
    pub fn sync_parent(&self, path: &str) -> Result<()> {
        let (dir, _) = self.parent(path, false)?;
        File::from(dir).sync_all()?;
        Ok(())
    }
    pub fn sync(&self) -> Result<()> {
        self.directory.sync_all()?;
        Ok(())
    }
    pub fn lock(&self, path: &str) -> Result<File> {
        let (dir, name) = self.parent(path, true)?;
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(raw >= 0, "cannot open operation lock");
        let file = unsafe { File::from_raw_fd(raw) };
        ensure!(file.metadata()?.is_file(), "invalid lock file");
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "operation lock is busy"
        );
        Ok(file)
    }
    pub fn free_bytes(&self) -> Result<u64> {
        Ok(self.space()?.free)
    }
    pub fn space(&self) -> Result<crate::budget::Space> {
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::fstatvfs(self.directory.as_raw_fd(), stat.as_mut_ptr()) } == 0,
            "statvfs failed"
        );
        let stat = unsafe { stat.assume_init() };
        Ok(crate::budget::Space {
            capacity: stat.f_blocks.checked_mul(stat.f_frsize).context("disk capacity overflow")?,
            free: stat.f_bavail.checked_mul(stat.f_frsize).context("disk byte count overflow")?,
        })
    }
}
pub fn copy_hash(
    mut input: impl Read,
    mut output: impl Write,
    limit: u64,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buf = [0_u8; 65536];
    loop {
        crate::budget::check_active()?;
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).context("copy size overflow")?;
        ensure!(total <= limit, "copy exceeded byte limit");
        output.write_all(&buf[..count])?;
        hasher.update(&buf[..count]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}
pub fn file_hash(file: File, limit: u64) -> Result<(u64, String)> {
    copy_hash(file, std::io::sink(), limit)
}

/// Absence is a missing directory entry, not a dangling symlink to missing bytes.
pub fn absent(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(false),
    }
}
