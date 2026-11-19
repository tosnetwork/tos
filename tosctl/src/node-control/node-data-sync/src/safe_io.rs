use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
/// Every lookup below a held directory: no symlink, no `..` escape, no other mount.
const BENEATH: u64 =
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS;

/// `openat2(2)` with explicit resolution rules. There is no fallback: a kernel without it
/// refuses, rather than resolving a name that another account may have replaced.
#[cfg(target_os = "linux")]
fn openat2(dir: i32, name: &std::ffi::CStr, flags: i32, mode: u64, resolve: u64) -> Result<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow { flags: u64::try_from(flags | libc::O_CLOEXEC)?, mode, resolve };
    // SAFETY: descriptor, terminated name and open_how stay valid for the call.
    let raw = unsafe {
        libc::syscall(libc::SYS_openat2, dir, name.as_ptr(), &how, std::mem::size_of::<OpenHow>())
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() != Some(libc::ENOSYS),
            "this kernel lacks openat2, which safe traversal requires"
        );
        return Err(error.into());
    }
    // SAFETY: openat2 returned a new descriptor owned here.
    Ok(unsafe { File::from_raw_fd(i32::try_from(raw)?) })
}
/// macOS has no `openat2(2)`. The same rules are enforced by resolving the name one
/// component at a time below `dir`, each with `O_NOFOLLOW`: a symlink anywhere refuses
/// (`ELOOP`), an absolute name or a `..` component refuses (`EXDEV`, as a lookup leaving
/// the directory does on Linux), and with `RESOLVE_NO_XDEV` every component must stay on
/// the device of `dir`. macOS has no magic links, so `RESOLVE_NO_MAGICLINKS` needs no step.
/// A lookup that is not below a held directory resolves the whole name in one call with
/// `O_NOFOLLOW_ANY`, which refuses a symlink in any component.
#[cfg(target_os = "macos")]
fn openat2(dir: i32, name: &std::ffi::CStr, flags: i32, mode: u64, resolve: u64) -> Result<File> {
    let mode = libc::c_uint::try_from(mode)?;
    let open_one = |at: i32, component: &std::ffi::CStr, component_flags: i32| -> Result<File> {
        // SAFETY: descriptor and terminated name stay valid for the call.
        let raw = unsafe {
            libc::openat(at, component.as_ptr(), component_flags | libc::O_CLOEXEC, mode)
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new descriptor owned here.
        Ok(unsafe { File::from_raw_fd(raw) })
    };
    if resolve & RESOLVE_BENEATH == 0 {
        ensure!(
            resolve & RESOLVE_NO_SYMLINKS != 0,
            "an unrestricted lookup is never requested here"
        );
        // O_NOFOLLOW_ANY covers the last component too, and the kernel refuses it
        // combined with O_NOFOLLOW (EINVAL).
        return open_one(dir, name, (flags & !libc::O_NOFOLLOW) | libc::O_NOFOLLOW_ANY);
    }
    let escape = || anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EXDEV));
    let bytes = name.to_bytes();
    if bytes.starts_with(b"/") {
        return Err(escape());
    }
    let components: Vec<&[u8]> = bytes.split(|byte| *byte == b'/').collect();
    let (last, parents) = components.split_last().context("empty name")?;
    let device = |fd: i32| -> Result<u64> {
        // SAFETY: `stat` is plain integers, for which all-zero is valid.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: open descriptor and output buffer stay valid for the call.
        ensure!(
            unsafe { libc::fstat(fd, &mut stat) } == 0,
            "cannot inspect held directory: {}",
            std::io::Error::last_os_error()
        );
        Ok(device_of(&stat))
    };
    let held_device = if resolve & RESOLVE_NO_XDEV != 0 { Some(device(dir)?) } else { None };
    let mut current: Option<File> = None;
    for (index, component) in parents.iter().chain(std::iter::once(last)).enumerate() {
        if component.is_empty() || *component == b"." || *component == b".." {
            return Err(escape());
        }
        let component = CString::new(*component)?;
        let component_flags = if index == parents.len() {
            flags | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
        };
        let at = current.as_ref().map_or(dir, AsRawFd::as_raw_fd);
        let opened = open_one(at, &component, component_flags)?;
        if let Some(held) = held_device
            && device(opened.as_raw_fd())? != held
        {
            return Err(escape());
        }
        current = Some(opened);
    }
    current.context("empty name")
}
/// Open `name` below the held directory `dir` without following any link or crossing a mount.
fn open_beneath(dir: i32, name: &str, flags: i32, mode: u64) -> Result<File> {
    let name = CString::new(name)?;
    openat2(dir, &name, flags | libc::O_NOFOLLOW, mode, BENEATH)
}
/// The kind of one directory entry, read without following it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    File,
    Link,
    Other,
}
/// Entry names of a held directory, listed through that descriptor, never by path.
fn names(directory: &File) -> Result<Vec<String>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    for name in directory_entries(directory.as_raw_fd())? {
        names.push(
            std::str::from_utf8(name.as_bytes()).context("non-text directory entry")?.to_owned(),
        );
    }
    names.sort();
    Ok(names)
}
/// Stat one entry of a held directory without following it.
fn stat_beneath(directory: &File, name: &str) -> Result<Option<libc::stat>> {
    let name = CString::new(name)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: held descriptor, terminated name and output buffer stay valid for the call.
    if unsafe {
        libc::fstatat(directory.as_raw_fd(), name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
    } == 0
    {
        return Ok(Some(stat));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        return Ok(None);
    }
    Err(error.into())
}
/// Metadata of one entry, as `fstatat` reported it below a held directory.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub kind: Kind,
    pub size: u64,
    pub allocated: u64,
    pub links: u64,
    pub identity: (u64, u64),
    /// Permission and special bits (`st_mode & 0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}
/// Widen a C integer field to `u64`. The widths of `stat` and `statvfs` fields differ
/// between Linux targets (`st_nlink` is `u64` on x86-64 and `u32` on arm64), so a
/// field is never assumed to be `u64`. Only lossless `From` conversions compile: a
/// target where a field were wider than 64 bits would fail to build, not truncate.
fn wide(value: impl Into<u64>) -> u64 {
    value.into()
}
/// `st_dev` as `MetadataExt::dev` reports it, so identities from `fstatat` and from an
/// open descriptor compare equal. It is unsigned on Linux and a signed 32-bit `dev_t` on
/// macOS, which the standard library sign-extends; the same bits are kept here.
#[cfg(target_os = "linux")]
fn device_of(stat: &libc::stat) -> u64 {
    wide(stat.st_dev)
}
#[cfg(target_os = "macos")]
fn device_of(stat: &libc::stat) -> u64 {
    u64::from_ne_bytes(i64::from(stat.st_dev).to_ne_bytes())
}
/// Entry names of the directory open at `fd`, read through that descriptor.
#[cfg(target_os = "linux")]
fn directory_entries(fd: i32) -> Result<Vec<std::ffi::OsString>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{fd}"))? {
        ensure!(entries.len() < crate::budget::MAX_ALLOCATION_ENTRIES, "directory entry limit");
        entries.push(entry?.file_name());
    }
    Ok(entries)
}
/// macOS has no `/proc`. The directory is reopened through its own descriptor as `.`,
/// which names that same directory and never another, and listed with `fdopendir(3)`.
#[cfg(target_os = "macos")]
fn directory_entries(fd: i32) -> Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: descriptor and static terminated name stay valid for the call.
    let raw = unsafe {
        libc::openat(fd, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    ensure!(raw >= 0, "cannot list held directory: {}", std::io::Error::last_os_error());
    // SAFETY: on success the stream owns `raw`; on failure it is still ours to close.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: `raw` was returned by openat above and is not owned by any stream.
        unsafe { libc::close(raw) };
        return Err(anyhow::anyhow!("cannot list held directory: {error}"));
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: the stream is open and closed exactly once, here.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut entries = Vec::new();
    loop {
        // readdir signals an error only through errno, so it is cleared first.
        // SAFETY: errno is thread-local.
        unsafe { *libc::__error() = 0 };
        // SAFETY: the stream stays open for the call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            ensure!(error.raw_os_error() == Some(0), "cannot list held directory: {error}");
            break;
        }
        // SAFETY: readdir returned an entry whose name is terminated and valid until the
        // next call on this stream.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = name.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        ensure!(entries.len() < crate::budget::MAX_ALLOCATION_ENTRIES, "directory entry limit");
        entries.push(std::ffi::OsStr::from_bytes(name).to_owned());
    }
    Ok(entries)
}
fn kind(stat: &libc::stat) -> Kind {
    // `st_mode` and `S_IFMT` are both `mode_t` on every target, so they mask directly.
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Kind::Directory,
        libc::S_IFREG => Kind::File,
        libc::S_IFLNK => Kind::Link,
        _ => Kind::Other,
    }
}

/// Descriptor-relative traversal refuses symlinks at every component.
pub struct Root {
    directory: File,
    pub path: PathBuf,
}
impl Root {
    /// A canonical absolute root, resolved in one call that refuses a symlink in any component.
    /// Descendants of a tree another account controls are opened with `open_child`, below
    /// the descriptor already held, never by name from here.
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute() && std::fs::canonicalize(path)? == path,
            "root must be canonical and link-free"
        );
        let name = CString::new(path.as_os_str().as_encoded_bytes())?;
        let directory = openat2(
            libc::AT_FDCWD,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        )
        .with_context(|| format!("cannot open root {}", path.display()))?;
        ensure!(directory.metadata()?.is_dir(), "root is not a directory");
        Ok(Self { directory, path: path.to_owned() })
    }
    /// A descendant directory, opened below this held descriptor: no link, no `..`, no mount.
    pub fn open_child(&self, relative: &str) -> Result<Self> {
        self.open_child_optional(relative)?
            .with_context(|| format!("missing directory {relative} in {}", self.path.display()))
    }
    /// As `open_child`, with absence reported as `None` and every other refusal as an error.
    pub fn open_child_optional(&self, relative: &str) -> Result<Option<Self>> {
        super::paths::relative(relative)?;
        self.attached()?;
        match open_beneath(
            self.directory.as_raw_fd(),
            relative,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(directory) => Ok(Some(Self { directory, path: self.path.join(relative) })),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.context(format!(
                "refusing unsafe directory {relative} in {}",
                self.path.display()
            ))),
        }
    }
    /// Entry names of this directory, listed through the held descriptor.
    pub fn names(&self) -> Result<Vec<String>> {
        names(&self.directory)
    }
    /// Kind of one direct entry, read through the held descriptor without following it.
    pub fn kind(&self, name: &str) -> Result<Option<Kind>> {
        Ok(self.entry(name)?.map(|entry| entry.kind))
    }
    /// One direct entry, read through the held descriptor without following it.
    pub fn entry(&self, name: &str) -> Result<Option<Entry>> {
        ensure!(super::paths::relative(name)?.len() == 1, "entry must be a direct child");
        let Some(stat) = stat_beneath(&self.directory, name)? else {
            return Ok(None);
        };
        Ok(Some(Entry {
            kind: kind(&stat),
            // `off_t` and `blkcnt_t` are signed: a negative value refuses.
            size: u64::try_from(stat.st_size)?,
            allocated: u64::try_from(stat.st_blocks)?
                .checked_mul(512)
                .context("allocated size overflow")?,
            links: wide(stat.st_nlink),
            identity: (device_of(&stat), wide(stat.st_ino)),
            // `mode_t` is `u32` on Linux and `u16` on macOS; it widens losslessly.
            mode: u32::from(stat.st_mode & 0o7777),
            uid: stat.st_uid,
            gid: stat.st_gid,
        }))
    }
    /// A second handle on the same held directory.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self { directory: self.directory.try_clone()?, path: self.path.clone() })
    }
    /// A directory inside this tree is opened below the held descriptor; a directory
    /// elsewhere by its canonical path. A tree another account controls is never re-resolved.
    pub fn open_anchored(&self, directory: &Path) -> Result<Self> {
        if directory == self.path {
            return self.duplicate();
        }
        match directory.strip_prefix(&self.path) {
            Ok(relative) => self.open_child(relative.to_str().context("non-text path")?),
            Err(_) => Self::open(directory),
        }
    }
    /// Device and inode of the held descriptor.
    pub fn identity(&self) -> Result<(u64, u64)> {
        let metadata = self.directory.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    /// Permission bits, owner and group of the held directory descriptor.
    pub fn status(&self) -> Result<(u32, u32, u32)> {
        let metadata = self.directory.metadata()?;
        Ok((metadata.mode() & 0o7777, metadata.uid(), metadata.gid()))
    }
    /// Set the permission bits of the held directory through its descriptor.
    pub fn set_mode(&self, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        ensure!(mode <= 0o777, "directory mode carries special bits");
        self.directory.set_permissions(std::fs::Permissions::from_mode(mode))?;
        ensure!(self.status()?.0 == mode, "directory mode was not applied");
        Ok(())
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
            dir = open_beneath(dir.as_raw_fd(), part, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .context("refusing unsafe directory")?
                .into();
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
        let file = openat2(
            dir.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
            BENEATH,
        )
        .with_context(|| format!("cannot safely read {path}"))?;
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
            capacity: wide(stat.f_blocks)
                .checked_mul(wide(stat.f_frsize))
                .context("disk capacity overflow")?,
            free: wide(stat.f_bavail)
                .checked_mul(wide(stat.f_frsize))
                .context("disk byte count overflow")?,
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
            // SAFETY: as above; an existing entry is opened without creation, and a planted
            // FIFO cannot block the open.
            let raw = unsafe {
                libc::openat(self.directory.as_raw_fd(), name.as_ptr(), flags | libc::O_NONBLOCK)
            };
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
        flush_filesystem(&directory)?;
        self.attached()
    }
}
/// One filesystem flush makes every ownership change durable before exposure.
#[cfg(target_os = "linux")]
fn flush_filesystem(directory: &File) -> Result<()> {
    // SAFETY: held directory descriptor remains valid for the call.
    ensure!(
        unsafe { libc::syncfs(directory.as_raw_fd()) } == 0,
        "cannot flush ownership changes: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
/// macOS has no `syncfs(2)`. Every entry whose owner changed was already flushed by
/// `give`; this flushes the top directory the same way, to the drive's stable storage.
#[cfg(target_os = "macos")]
fn flush_filesystem(directory: &File) -> Result<()> {
    directory.sync_all().context("cannot flush ownership changes")
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
        // Without syncfs(2) each change is made durable where it is made; the standard
        // library's sync_all is F_FULLFSYNC on macOS.
        #[cfg(target_os = "macos")]
        file.sync_all().context("cannot flush ownership change")?;
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
    for name in names(file)? {
        let stat = stat_beneath(file, &name)?.context("hand-over entry vanished")?;
        ensure!(
            matches!(kind(&stat), Kind::Directory | Kind::File),
            "ownership hand-over refuses a link or special file"
        );
        let child = open_beneath(file.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            .context("ownership hand-over refuses an unsafe entry")?;
        let opened = child.metadata()?;
        ensure!(
            (opened.dev(), opened.ino()) == (device_of(&stat), wide(stat.st_ino)),
            "ownership hand-over entry was replaced"
        );
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
    let file = match openat2(
        parent,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
        0,
        RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    ) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        // One message carrying the cause, as callers and operators read it:
        // "refusing unsafe cleanup child: <the refusal>".
        Err(error) => return Err(anyhow::anyhow!("refusing unsafe cleanup child: {error:#}")),
    };
    let meta = file.metadata()?;
    if meta.is_dir() {
        for entry in directory_entries(file.as_raw_fd())? {
            use std::os::unix::ffi::OsStrExt;
            let child = CString::new(entry.as_bytes())?;
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
            && device_of(&current) == meta.dev()
            && wide(current.st_ino) == meta.ino(),
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
    fn descendants_never_resolve_through_a_swapped_intermediate_directory() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().canonicalize()?;
        let root = Root::create(&base.join("root"))?;
        root.write_new("a/b/file", b"own")?;
        let decoy = base.join("decoy");
        std::fs::create_dir_all(decoy.join("b"))?;
        std::fs::write(decoy.join("b/file"), b"decoy")?;
        std::fs::rename(root.path.join("a"), root.path.join("a.real"))?;
        std::os::unix::fs::symlink(&decoy, root.path.join("a"))?;
        for (label, result) in [
            ("open", root.open_child("a/b").map(|_| ())),
            ("read", root.read("a/b/file", 16).map(|_| ())),
            ("create", root.create_file("a/b/new").map(|_| ())),
        ] {
            let text = format!("{:#}", result.err().context(label)?);
            // A link as a path component is ELOOP; as the component opened with O_NOFOLLOW
            // and O_DIRECTORY it is ENOTDIR. Both are the link refusal, never a lookup.
            assert!(
                text.contains("refusing unsafe directory")
                    && (text.contains("Too many levels of symbolic links")
                        || text.contains("Not a directory")),
                "{label}: wrong refusal: {text}"
            );
        }
        assert_eq!(std::fs::read(decoy.join("b/file"))?, b"decoy");
        assert!(absent(&decoy.join("b/new"))?, "a file was created through the swapped link");
        Ok(())
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
