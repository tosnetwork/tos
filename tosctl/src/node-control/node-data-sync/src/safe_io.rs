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
    /// Device of this still-attached directory descriptor, never a replacement path.
    pub fn device(&self) -> Result<u64> {
        self.attached()
            .with_context(|| format!("check allocation root attachment {}", self.path.display()))?;
        Ok(self
            .directory
            .metadata()
            .with_context(|| format!("stat allocation root descriptor {}", self.path.display()))?
            .dev())
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
    /// Remove one owned child tree through descriptors; never traverse links or mounts.
    pub fn remove_tree(&self, path: &str) -> Result<()> {
        ensure!(super::paths::relative(path)?.len() == 1, "cleanup requires one direct child");
        let (parent, name) = self.parent(path, false)?;
        let mut remaining = super::model::FILE_COUNT_LIMIT;
        remove_child(parent.as_raw_fd(), &name, &mut remaining)?;
        File::from(parent).sync_all()?;
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
    /// Owner and group of this still-attached directory descriptor.
    pub fn owner(&self) -> Result<(u32, u32)> {
        self.attached()?;
        let metadata = self.directory.metadata()?;
        Ok((metadata.uid(), metadata.gid()))
    }
    /// Open, or create, a file the directory owner's service must also be able to open.
    /// A file this call creates is given the directory's owner and group, through its
    /// descriptor, so a privileged invoker never leaves an unreadable file in a service tree.
    pub fn open_shared_lock(&self, name: &str) -> Result<File> {
        ensure!(super::paths::relative(name)?.len() == 1, "lock must be a direct child");
        self.attached()?;
        let name = CString::new(name)?;
        let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: held directory descriptor and terminated name remain valid for the call.
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        let (raw, created) = if raw >= 0 {
            (raw, true)
        } else {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.kind() == std::io::ErrorKind::AlreadyExists,
                "cannot create lock: {error}"
            );
            // SAFETY: as above; an existing entry is opened without creation.
            let raw = unsafe { libc::openat(self.directory.as_raw_fd(), name.as_ptr(), flags) };
            ensure!(raw >= 0, "cannot open lock: {}", std::io::Error::last_os_error());
            (raw, false)
        };
        // SAFETY: the descriptor was just returned by openat and is owned here.
        let file = unsafe { File::from_raw_fd(raw) };
        ensure!(file.metadata()?.is_file(), "lock is not a regular file");
        if created {
            give(&file, self.owner()?)?;
            self.sync()?;
        }
        self.attached()?;
        Ok(file)
    }
    /// Give every entry this invocation created beneath this directory to `owner`.
    pub fn hand_over(&self, owner: (u32, u32)) -> Result<()> {
        // SAFETY: geteuid has no preconditions.
        self.hand_over_from(owner, unsafe { libc::geteuid() })
    }
    /// Entries owned by `invoker` move to `owner`; entries `owner` already holds stay as
    /// they are; any other owner, a link or a special file refuses. Traversal is through
    /// descriptors only, never across a link or a mount.
    pub(crate) fn hand_over_from(&self, owner: (u32, u32), invoker: u32) -> Result<()> {
        self.attached()?;
        let directory = self.directory.try_clone()?;
        let mut remaining = crate::budget::MAX_ALLOCATION_ENTRIES;
        hand_over_entry(&directory, owner, invoker, &mut remaining)?;
        // One filesystem flush makes every ownership change durable before exposure.
        // SAFETY: held directory descriptor remains valid for the call.
        ensure!(
            unsafe { libc::syncfs(directory.as_raw_fd()) } == 0,
            "cannot flush ownership changes: {}",
            std::io::Error::last_os_error()
        );
        self.attached()
    }
}
fn give(file: &File, (uid, gid): (u32, u32)) -> Result<()> {
    let metadata = file.metadata()?;
    if (metadata.uid(), metadata.gid()) != (uid, gid) {
        // SAFETY: the descriptor is held open by `file` for the call.
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
            "cannot give {uid}:{gid} ownership: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
fn hand_over_entry(
    file: &File,
    owner: (u32, u32),
    invoker: u32,
    remaining: &mut usize,
) -> Result<()> {
    *remaining = remaining.checked_sub(1).context("ownership hand-over entry limit")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir() || (metadata.is_file() && metadata.nlink() == 1),
        "ownership hand-over refuses a link or special file"
    );
    if metadata.uid() == invoker {
        give(file, owner)?;
    } else {
        ensure!(
            metadata.uid() == owner.0,
            "ownership hand-over found an entry of another account (uid {})",
            metadata.uid()
        );
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))? {
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(entry?.file_name().as_bytes())?;
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 1 | 4 | 8, // NO_XDEV, NO_SYMLINKS, BENEATH
        };
        // SAFETY: parent descriptor, terminated name and open_how stay valid for the call.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                file.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        ensure!(
            raw >= 0,
            "ownership hand-over refuses an unsafe entry: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: openat2 returned a new descriptor owned here.
        let child = unsafe { File::from_raw_fd(i32::try_from(raw)?) };
        hand_over_entry(&child, owner, invoker, remaining)?;
    }
    Ok(())
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

fn remove_child(parent: i32, name: &std::ffi::CStr, remaining: &mut usize) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(*remaining > 0, "cleanup entry limit");
    *remaining -= 1;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 1 | 4 | 8, // NO_XDEV, NO_SYMLINKS, BENEATH
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    ensure!(raw >= 0, "refusing unsafe cleanup child: {}", std::io::Error::last_os_error());
    let file = unsafe { File::from_raw_fd(raw as i32) };
    let meta = file.metadata()?;
    if meta.is_dir() {
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))? {
            use std::os::unix::ffi::OsStrExt;
            let entry = entry?;
            let child = CString::new(entry.file_name().as_bytes())?;
            remove_child(file.as_raw_fd(), &child, remaining)?;
        }
        file.sync_all()?;
    } else {
        ensure!(meta.is_file() && meta.nlink() == 1, "cleanup child is a link or special file");
    }
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatat(parent, name.as_ptr(), &mut current, libc::AT_SYMLINK_NOFOLLOW) }
            == 0
            && current.st_dev == meta.dev()
            && current.st_ino == meta.ino(),
        "cleanup child identity changed"
    );
    let flags = if meta.is_dir() { libc::AT_REMOVEDIR } else { 0 };
    ensure!(
        unsafe { libc::unlinkat(parent, name.as_ptr(), flags) } == 0,
        "cleanup unlink failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod ownership_tests {
    use super::*;

    /// An owner this process may give files to that differs from what it creates them with:
    /// another account when running as root, otherwise one of its supplementary groups.
    pub(crate) fn other_owner() -> Option<(u32, u32)> {
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if uid == 0 {
            return Some((65534, 65534));
        }
        let mut groups = vec![0 as libc::gid_t; 256];
        // SAFETY: the buffer holds the advertised number of entries.
        let count = unsafe { libc::getgroups(256, groups.as_mut_ptr()) };
        let count = usize::try_from(count).ok()?;
        groups.truncate(count);
        groups.into_iter().find(|group| *group != gid).map(|group| (uid, group))
    }
    fn owner_of(path: &Path) -> Result<(u32, u32)> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok((metadata.uid(), metadata.gid()))
    }

    #[test]
    fn created_lock_takes_the_directory_owner() -> Result<()> {
        let Some(owner) = other_owner() else {
            eprintln!("SKIP: no second owner is available to this test process");
            return Ok(());
        };
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().canonicalize()?;
        let database = Root::open(&path)?;
        // SAFETY: path is a NUL-free temporary directory path.
        let directory = CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(unsafe { libc::chown(directory.as_ptr(), owner.0, owner.1) } == 0);
        drop(database.open_shared_lock("config.json.lock")?);
        assert_eq!(owner_of(&path.join("config.json.lock"))?, owner, "lock kept the invoker");
        // An existing lock is opened as it is; the production lock path uses the same call.
        drop(crate::service::Frozen::acquire(&path)?);
        assert_eq!(owner_of(&path.join("config.json.lock"))?, owner);
        assert!(database.open_shared_lock("../escape").is_err(), "lock left its directory");
        Ok(())
    }

    #[test]
    fn hand_over_gives_every_created_entry_and_refuses_links() -> Result<()> {
        let Some(owner) = other_owner() else {
            eprintln!("SKIP: no second owner is available to this test process");
            return Ok(());
        };
        // SAFETY: geteuid has no preconditions.
        let invoker = unsafe { libc::geteuid() };
        let temporary = tempfile::tempdir()?;
        let replacement = Root::create(&temporary.path().canonicalize()?.join("replacement"))?;
        replacement.write_new("state/CURRENT", b"MANIFEST-000001\n")?;
        replacement.write_new("keyring/KEY", b"private")?;
        replacement.ensure_directory("tmp")?;
        replacement.hand_over_from(owner, invoker)?;
        for path in ["", "state", "state/CURRENT", "keyring", "keyring/KEY", "tmp"] {
            assert_eq!(
                owner_of(&replacement.path.join(path))?,
                owner,
                "{path} was not handed over"
            );
        }
        // Entries of a third account are never taken over.
        assert!(
            replacement
                .hand_over_from((owner.0.wrapping_add(2), owner.1), owner.0.wrapping_add(1))
                .is_err(),
            "foreign entry handed over"
        );
        std::fs::hard_link(replacement.path.join("keyring/KEY"), temporary.path().join("alias"))?;
        let error = replacement.hand_over_from(owner, invoker).expect_err("hard link").to_string();
        assert!(error.contains("link or special file"), "wrong refusal: {error}");
        std::fs::remove_file(temporary.path().join("alias"))?;
        std::os::unix::fs::symlink("/etc", replacement.path.join("tmp/trap"))?;
        assert!(replacement.hand_over_from(owner, invoker).is_err(), "followed a symlink");
        Ok(())
    }
}
