/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Reading secret material for import commands without process arguments.
//!
//! A secret passed as a command-line argument is visible to every process
//! that can read `/proc/<pid>/cmdline`, and is commonly kept by shell history
//! and command auditing. Import commands therefore take secrets only from:
//!
//! - a protected file: a regular file (not a symlink) owned by the effective
//!   user and not readable or writable by group or others;
//! - an inherited file descriptor: a pipe or socket set up by the caller, or
//!   a regular file meeting the same protection rule, read through a
//!   duplicate so the caller's descriptor is left open;
//! - a non-echoing prompt on the controlling terminal.
//!
//! Environment variables are deliberately not offered: they are inherited by
//! every child process and readable through `/proc/<pid>/environ`.
//!
//! Errors produced here never contain any byte of the secret.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Upper bound on the bytes read from any secret source. Key material and
/// mnemonics are far smaller; the bound stops an unexpected source (a device,
/// a large file) from being read without limit.
pub const MAX_SECRET_INPUT_BYTES: usize = 64 * 1024;

/// Where an import command reads its secret from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// A protected file (see the module documentation).
    File(PathBuf),
    /// An inherited file descriptor. Standard output and standard error are
    /// refused; standard input (0) is accepted.
    Fd(i32),
    /// A non-echoing prompt on the controlling terminal.
    Prompt(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretInputError {
    #[error("{0}")]
    ConflictingSources(String),
    #[error("secret file {path}: {reason}")]
    UnprotectedFile { path: String, reason: String },
    #[error("secret file {path} could not be read: {reason}")]
    FileUnreadable { path: String, reason: String },
    #[error("secret file descriptor {fd}: {reason}")]
    BadFd { fd: i32, reason: String },
    #[error("secret input exceeds {MAX_SECRET_INPUT_BYTES} bytes")]
    TooLarge,
    #[error("secret input is empty")]
    Empty,
    #[error("interactive secret input failed: {0}")]
    Prompt(String),
    #[error("secret is not valid {0}")]
    Encoding(&'static str),
}

/// Chooses the secret source from the two optional command-line selectors.
/// Neither selector given means an interactive prompt.
pub fn select_source(
    file: Option<&Path>,
    fd: Option<i32>,
    file_flag: &str,
    fd_flag: &str,
    prompt: &str,
) -> Result<SecretSource, SecretInputError> {
    match (file, fd) {
        (Some(_), Some(_)) => Err(SecretInputError::ConflictingSources(format!(
            "{file_flag} and {fd_flag} are mutually exclusive"
        ))),
        (Some(path), None) => Ok(SecretSource::File(path.to_path_buf())),
        (None, Some(fd)) => Ok(SecretSource::Fd(fd)),
        (None, None) => Ok(SecretSource::Prompt(prompt.to_owned())),
    }
}

/// Reads the secret from `source`. The result is wiped from memory on drop.
pub fn read_secret(source: &SecretSource) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    let data = read_secret_exact(source)?;
    if trim_ascii(&data).is_empty() {
        return Err(SecretInputError::Empty);
    }
    Ok(data)
}

/// Read exact bytes with the same protected-source and size checks, allowing an
/// empty or whitespace-only value. Use for passwords whose bytes are semantic;
/// do not apply this to mandatory key or mnemonic inputs.
pub fn read_secret_exact(source: &SecretSource) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    let data = match source {
        SecretSource::File(path) => read_protected_file(path)?,
        SecretSource::Fd(fd) => read_fd(*fd)?,
        SecretSource::Prompt(prompt) => {
            let line = Zeroizing::new(
                rpassword::prompt_password(prompt)
                    .map_err(|error| SecretInputError::Prompt(error.kind().to_string()))?,
            );
            Zeroizing::new(line.as_bytes().to_vec())
        }
    };
    Ok(data)
}

/// The input with surrounding ASCII whitespace (such as a trailing newline
/// written by `echo` or an editor) removed.
pub fn trim_ascii(data: &[u8]) -> &[u8] {
    data.trim_ascii()
}

/// Decodes hexadecimal secret text. The error names the encoding only, never
/// the offending character or its position.
pub fn decode_hex(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    hex::decode(trim_ascii(data)).map(Zeroizing::new).map_err(|_| SecretInputError::Encoding("hex"))
}

fn read_protected_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    let shown = path.display().to_string();
    // O_NOFOLLOW refuses a symlink at the final component, so the checks
    // below apply to the file actually read, and fstat on the open handle
    // leaves no window between checking and reading.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                SecretInputError::UnprotectedFile {
                    path: shown.clone(),
                    reason: "is a symbolic link".into(),
                }
            } else {
                SecretInputError::FileUnreadable {
                    path: shown.clone(),
                    reason: error.kind().to_string(),
                }
            }
        })?;
    let metadata = file.metadata().map_err(|error| SecretInputError::FileUnreadable {
        path: shown.clone(),
        reason: error.kind().to_string(),
    })?;
    check_protected(&metadata, &shown)?;
    read_bounded(file).map_err(|error| match error {
        ReadError::TooLarge => SecretInputError::TooLarge,
        ReadError::Io(kind) => SecretInputError::FileUnreadable { path: shown, reason: kind },
    })
}

fn check_protected(metadata: &std::fs::Metadata, shown: &str) -> Result<(), SecretInputError> {
    let unprotected =
        |reason: String| SecretInputError::UnprotectedFile { path: shown.to_owned(), reason };
    if !metadata.file_type().is_file() {
        return Err(unprotected("is not a regular file".into()));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(unprotected(format!(
            "has mode {mode:04o}; it must not be accessible to group or others (chmod 600)"
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(unprotected(format!(
            "is owned by uid {}, not by the current user (uid {euid})",
            metadata.uid()
        )));
    }
    Ok(())
}

fn read_fd(fd: i32) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    if fd == 1 || fd == 2 || fd < 0 {
        return Err(SecretInputError::BadFd {
            fd,
            reason: "must be standard input (0) or an inherited descriptor of 3 or more".into(),
        });
    }
    // Read through a duplicate of the inherited descriptor rather than by
    // reopening /dev/fd/N: reopening fails for sockets on Linux. The duplicate
    // is owned here, close-on-exec so no child inherits it, and closed on
    // drop. The original stays open, but it shares the duplicate's file
    // offset: what is read here is consumed from the caller's stream too.
    // SAFETY: fcntl(F_DUPFD_CLOEXEC) has no memory-safety preconditions; an
    // invalid descriptor makes it fail with EBADF, which is reported below.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(SecretInputError::BadFd {
            fd,
            reason: std::io::Error::last_os_error().kind().to_string(),
        });
    }
    // SAFETY: `duplicate` is a freshly created descriptor that nothing else
    // owns, so the File takes sole ownership and closes it exactly once.
    let file = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(duplicate) };
    let metadata = file
        .metadata()
        .map_err(|error| SecretInputError::BadFd { fd, reason: error.kind().to_string() })?;
    let file_type = metadata.file_type();
    if file_type.is_file() {
        // A regular file handed over as a descriptor must meet the same
        // protection rule as one named by path.
        check_protected(&metadata, &format!("behind descriptor {fd}"))?;
    } else if !(std::os::unix::fs::FileTypeExt::is_fifo(&file_type)
        || std::os::unix::fs::FileTypeExt::is_socket(&file_type))
    {
        return Err(SecretInputError::BadFd {
            fd,
            reason: "must be a pipe, a socket, or a protected regular file".into(),
        });
    }
    read_bounded(file).map_err(|error| match error {
        ReadError::TooLarge => SecretInputError::TooLarge,
        ReadError::Io(kind) => SecretInputError::BadFd { fd, reason: kind },
    })
}

enum ReadError {
    TooLarge,
    Io(String),
}

fn read_bounded(file: File) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let mut data = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_SECRET_INPUT_BYTES)
        .map_err(|_| ReadError::Io("size limit out of range".into()))?
        .saturating_add(1);
    file.take(limit)
        .read_to_end(&mut data)
        .map_err(|error| ReadError::Io(error.kind().to_string()))?;
    if data.len() > MAX_SECRET_INPUT_BYTES {
        return Err(ReadError::TooLarge);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    const SECRET: &str = "c2VjcmV0LWtleS1tYXRlcmlhbC10aGF0LW11c3Qtbm90LWxlYWs=";

    fn write_file(dir: &Path, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).expect("create");
        file.write_all(contents).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn exact_password_input_preserves_empty_and_whitespace() {
        let dir = tempfile::tempdir().expect("directory");
        for input in [b"".as_slice(), b" ", b" password \n"] {
            let path = write_file(dir.path(), "password", input, 0o600);
            let source = SecretSource::File(path);
            assert_eq!(
                read_secret_exact(&source).expect("exact password").as_slice(),
                input,
                "password bytes changed"
            );
            if input.trim_ascii().is_empty() {
                assert!(matches!(read_secret(&source), Err(SecretInputError::Empty)));
            }
        }
    }

    #[test]
    fn protected_file_is_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "key", format!("{SECRET}\n").as_bytes(), 0o600);
        let data = read_secret(&SecretSource::File(path)).expect("read");
        assert_eq!(trim_ascii(&data), SECRET.as_bytes());
    }

    #[test]
    fn group_or_world_accessible_file_is_refused_without_reading_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        for mode in [0o640, 0o604, 0o660, 0o644, 0o610] {
            let path = write_file(dir.path(), &format!("key-{mode:o}"), SECRET.as_bytes(), mode);
            let error = read_secret(&SecretSource::File(path)).expect_err("must refuse");
            assert!(
                matches!(error, SecretInputError::UnprotectedFile { .. }),
                "mode {mode:o}: {error}"
            );
            assert!(!error.to_string().contains(SECRET));
        }
    }

    #[test]
    fn symlink_to_protected_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = write_file(dir.path(), "key", SECRET.as_bytes(), 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error = read_secret(&SecretSource::File(link)).expect_err("must refuse");
        assert!(matches!(error, SecretInputError::UnprotectedFile { .. }), "{error}");
    }

    #[test]
    fn directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let error = read_secret(&SecretSource::File(sub)).expect_err("must refuse");
        assert!(matches!(error, SecretInputError::UnprotectedFile { .. }), "{error}");
    }

    #[test]
    fn empty_and_oversized_inputs_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = write_file(dir.path(), "empty", b" \n", 0o600);
        assert_eq!(read_secret(&SecretSource::File(empty)), Err(SecretInputError::Empty));
        let big = write_file(dir.path(), "big", &vec![b'a'; MAX_SECRET_INPUT_BYTES + 1], 0o600);
        assert_eq!(read_secret(&SecretSource::File(big)), Err(SecretInputError::TooLarge));
        let exact = write_file(dir.path(), "exact", &vec![b'a'; MAX_SECRET_INPUT_BYTES], 0o600);
        assert_eq!(
            read_secret(&SecretSource::File(exact)).expect("at limit").len(),
            MAX_SECRET_INPUT_BYTES
        );
    }

    #[test]
    fn inherited_pipe_descriptor_is_read() {
        let mut fds = [0i32; 2];
        // SAFETY: fds is a valid two-element buffer for pipe(2).
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let [read_end, write_end] = fds;
        {
            use std::os::fd::FromRawFd;
            // SAFETY: write_end was just created by pipe(2) and is owned here.
            let mut writer = unsafe { File::from_raw_fd(write_end) };
            writer.write_all(SECRET.as_bytes()).expect("write");
        }
        let data = read_secret(&SecretSource::Fd(read_end)).expect("read");
        // SAFETY: read_end was created above and is closed exactly once.
        unsafe { libc::close(read_end) };
        assert_eq!(&data[..], SECRET.as_bytes());
    }

    #[test]
    fn regular_file_descriptor_must_be_protected() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().expect("tempdir");
        let open = write_file(dir.path(), "open", SECRET.as_bytes(), 0o644);
        let file = File::open(&open).expect("open");
        let error = read_secret(&SecretSource::Fd(file.as_raw_fd())).expect_err("must refuse");
        assert!(matches!(error, SecretInputError::UnprotectedFile { .. }), "{error}");
        let closed = write_file(dir.path(), "closed", SECRET.as_bytes(), 0o600);
        let file = File::open(&closed).expect("open");
        assert_eq!(
            &read_secret(&SecretSource::Fd(file.as_raw_fd())).expect("read")[..],
            SECRET.as_bytes()
        );
    }

    const REFUSAL_CHILD_ENV: &str = "SECRET_INPUT_FD_REFUSAL_CHILD";

    /// Runs inside a child process whose standard output and error are an
    /// idle socket. Refusing descriptors 1 and 2 must not read them at all;
    /// a read would block on the socket, which no data ever reaches.
    #[test]
    #[ignore = "runs only as the child of standard_output_and_error_descriptors_are_refused"]
    fn fd_refusal_child() {
        let Some(marker) = std::env::var_os(REFUSAL_CHILD_ENV) else {
            return;
        };
        let mut refused = 0;
        for fd in [1, 2, -1] {
            match read_secret(&SecretSource::Fd(fd)) {
                Err(SecretInputError::BadFd { reason, .. })
                    if reason.contains("must be standard input (0)") =>
                {
                    refused += 1
                }
                other => std::process::exit(if other.is_ok() { 3 } else { 4 }),
            }
        }
        // Proves to the parent that the checks above ran, so a child that
        // matched no test or checked nothing cannot pass.
        std::fs::write(marker, format!("refused {refused}")).expect("write marker");
    }

    #[test]
    fn standard_output_and_error_descriptors_are_refused() {
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        // The child's descriptors 1 and 2 are a connected socket that stays
        // open and silent, so any read of them blocks; the deadline turns
        // such a read into a failure instead of a hang.
        let marker_dir = tempfile::tempdir().expect("tempdir");
        let marker = marker_dir.path().join("checked");
        let (child_end, parent_end) = UnixStream::pair().expect("socketpair");
        let stderr_end = child_end.try_clone().expect("clone");
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "secret_input::tests::fd_refusal_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env(REFUSAL_CHILD_ENV, &marker)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(std::os::fd::OwnedFd::from(child_end)))
            .stderr(std::process::Stdio::from(std::os::fd::OwnedFd::from(stderr_end)))
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("reading descriptor 1 or 2 blocked: they were not refused before use");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(parent_end);
        assert!(status.success(), "child refused incorrectly: {status}");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("child ran the refusal checks"),
            "refused 3"
        );
    }

    #[test]
    fn inherited_socket_descriptor_is_read() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (mut writer, reader) = UnixStream::pair().expect("socketpair");
        writer.write_all(SECRET.as_bytes()).expect("write");
        writer.shutdown(std::net::Shutdown::Write).expect("shutdown");
        let data = read_secret(&SecretSource::Fd(reader.as_raw_fd())).expect("read socket");
        assert_eq!(&data[..], SECRET.as_bytes());
        // The caller's descriptor stays open and usable after the read.
        assert!(reader.peer_addr().is_ok());
    }

    #[test]
    fn neither_selector_means_prompt_and_both_conflict() {
        let path = Path::new("/x");
        assert_eq!(
            select_source(None, None, "--f", "--d", "Key: "),
            Ok(SecretSource::Prompt("Key: ".into()))
        );
        assert_eq!(
            select_source(Some(path), None, "--f", "--d", "Key: "),
            Ok(SecretSource::File(path.into()))
        );
        assert_eq!(select_source(None, Some(3), "--f", "--d", "Key: "), Ok(SecretSource::Fd(3)));
        assert!(matches!(
            select_source(Some(path), Some(3), "--f", "--d", "Key: "),
            Err(SecretInputError::ConflictingSources(_))
        ));
    }

    #[test]
    fn hex_decoding_error_does_not_reveal_input() {
        let error = decode_hex(b"00ffzz-secret-tail").expect_err("invalid");
        assert_eq!(error.to_string(), "secret is not valid hex");
        assert_eq!(&decode_hex(b" 00ff\n").expect("valid")[..], &[0x00, 0xff]);
    }
}
