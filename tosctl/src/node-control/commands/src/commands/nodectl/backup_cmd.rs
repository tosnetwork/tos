/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

/// Backup management commands
#[derive(clap::Args, Clone)]
#[command(about = "Manage backups")]
pub struct BackupCmd {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the configuration file",
        default_value = "tosctl-config.json",
        env = "CONFIG_PATH",
        global = true
    )]
    config: String,

    #[command(subcommand)]
    action: BackupAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum BackupAction {
    /// Create a new backup
    Create(BackupCreateCmd),
    /// Restore from a backup
    Restore(BackupRestoreCmd),
    /// Verify backup integrity
    Verify(BackupVerifyCmd),
}

#[derive(clap::Args, Clone)]
pub struct BackupCreateCmd {
    #[arg(short = 'o', long = "output", help = "Output directory", default_value = ".")]
    output: String,
    #[arg(long = "config-dir", help = "TOS config directory", default_value = "/var/tos-work")]
    config_dir: String,
}

#[derive(clap::Args, Clone)]
pub struct BackupRestoreCmd {
    #[arg(short = 'f', long = "file", help = "Backup archive file path")]
    file: String,
    #[arg(long = "config-dir", help = "TOS config directory", default_value = "/var/tos-work")]
    config_dir: String,
    #[arg(long = "yes", help = "Skip confirmation")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
pub struct BackupVerifyCmd {
    #[arg(short = 'f', long = "file", help = "Backup archive file path")]
    file: String,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Read the system hostname, falling back to "unknown".
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// Format a `SystemTime` as `YYYYMMDD_HHMMSS` in UTC.
fn format_timestamp(t: SystemTime) -> String {
    let dur = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();

    // Manual UTC breakdown (no chrono dependency required).
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Days since 1970-01-01 → (year, month, day) using the civil-from-days algorithm.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mon <= 2 { y + 1 } else { y };

    format!("{:04}{:02}{:02}_{:02}{:02}{:02}", year, mon, d, h, m, s)
}

/// Largest file a backup copies. Configs and keys are small; anything larger
/// is not one of them, and a device file could otherwise be read without end.
const MAX_BACKUP_FILE_BYTES: u64 = 64 << 20;

/// A fresh directory only this user can enter (0700), with an unpredictable
/// name. Staging key material under a guessable /tmp path would let another
/// local user plant the directory, or links inside it, before we write.
fn private_temp_dir(prefix: &str) -> anyhow::Result<tempfile::TempDir> {
    // The mode is set when the directory is created: tempfile otherwise
    // creates it with the umask-filtered default, often 0775.
    Ok(tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?)
}

/// Whether `path` is a directory itself, not a symlink to one.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|meta| meta.is_dir()).unwrap_or(false)
}

/// Whether `path` is a regular file itself, not a symlink to one.
fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|meta| meta.is_file()).unwrap_or(false)
}

/// Read a regular file, refusing a symlink at `path` and anything that is not
/// a regular file. O_NONBLOCK keeps a FIFO from stalling the open.
fn read_regular_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| anyhow::anyhow!("refusing to read {}: {}", path.display(), err))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        anyhow::bail!("refusing to read {}: not a regular file", path.display());
    }
    if meta.len() > MAX_BACKUP_FILE_BYTES {
        anyhow::bail!(
            "refusing to read {}: larger than {} bytes",
            path.display(),
            MAX_BACKUP_FILE_BYTES
        );
    }
    let mut data = Vec::new();
    file.take(MAX_BACKUP_FILE_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_BACKUP_FILE_BYTES {
        anyhow::bail!(
            "refusing to read {}: larger than {} bytes",
            path.display(),
            MAX_BACKUP_FILE_BYTES
        );
    }
    Ok(data)
}

/// The directory `root/<components>`, creating missing components with mode
/// 0700. A component that exists as a symlink or a non-directory is refused, so
/// a write below it cannot be redirected elsewhere. `root` itself is trusted.
fn ensure_real_dir(root: &Path, components: &[&str]) -> anyhow::Result<PathBuf> {
    let mut dir = root.to_path_buf();
    for component in components {
        dir.push(component);
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => anyhow::bail!("refusing to use {}: not a real directory", dir.display()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(dir)
}

/// How a copied file may be written at its destination.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CopyMode {
    /// Only into a new file: an existing entry, a symlink included, is an error.
    CreateNew,
    /// Replace an existing regular file atomically; a symlink or a special file
    /// at the destination is an error rather than followed.
    Replace,
}

/// Copy one regular file to `dst` with mode 0600, never following a symlink at
/// either end. A replacement is written beside `dst` and renamed over it, so a
/// failed restore leaves the old file in place.
fn copy_file_private(src: &Path, dst: &Path, mode: CopyMode) -> anyhow::Result<()> {
    let data = read_regular_file(src)?;
    match mode {
        CopyMode::CreateNew => {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(dst)?;
            out.write_all(&data)?;
            out.sync_all()?;
        }
        CopyMode::Replace => {
            match std::fs::symlink_metadata(dst) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    anyhow::bail!("refusing to write through symlink {}", dst.display())
                }
                Ok(meta) if !meta.is_file() => {
                    anyhow::bail!("refusing to replace non-file {}", dst.display())
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            let parent = dst
                .parent()
                .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", dst.display()))?;
            let mut tmp = tempfile::Builder::new()
                .prefix(".tosctl-restore-")
                .permissions(std::fs::Permissions::from_mode(0o600))
                .tempfile_in(parent)?;
            tmp.write_all(&data)?;
            tmp.as_file().sync_all()?;
            tmp.persist(dst)
                .map_err(|err| anyhow::anyhow!("replacing {}: {}", dst.display(), err))?;
        }
    }
    Ok(())
}

/// Recursively copy a directory tree of regular files from `src` to `dst`.
/// `src` itself and everything in it must be real directories and regular
/// files: a restored archive could otherwise make the copy read any file on
/// the host.
fn copy_dir_recursive(src: &Path, dst: &Path, mode: CopyMode) -> anyhow::Result<()> {
    if !is_real_dir(src) {
        anyhow::bail!("refusing to copy {}: not a real directory", src.display());
    }
    match std::fs::symlink_metadata(dst) {
        Ok(meta) if !meta.is_dir() => {
            anyhow::bail!("refusing to copy into non-directory {}", dst.display())
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(dst)?;
        }
        Err(err) => return Err(err.into()),
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path, mode)?;
        } else if file_type.is_file() {
            copy_file_private(&entry.path(), &dest_path, mode)?;
        } else {
            anyhow::bail!(
                "refusing to copy {}: not a regular file or directory",
                entry.path().display()
            );
        }
    }
    Ok(())
}

/// Refuse an archive holding anything but regular files and directories under
/// safe relative names, before a byte of it is extracted.
fn screen_archive(archive: &Path) -> anyhow::Result<()> {
    let listing = Command::new("tar").arg("-tvzf").arg(archive).output()?;
    if !listing.status.success() {
        anyhow::bail!("cannot list archive {}", archive.display());
    }
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        match line.chars().next() {
            Some('-') | Some('d') => {}
            _ => anyhow::bail!("archive member is not a regular file or directory: {}", line),
        }
    }
    let names = Command::new("tar").arg("-tzf").arg(archive).output()?;
    if !names.status.success() {
        anyhow::bail!("cannot list archive {}", archive.display());
    }
    for name in String::from_utf8_lossy(&names.stdout).lines() {
        if name.starts_with('/') || name.split('/').any(|part| part == "..") {
            anyhow::bail!("archive member has an unsafe name: {}", name);
        }
    }
    Ok(())
}

/// Largest backup archive restore will take. Archives hold configs and keys.
const MAX_ARCHIVE_BYTES: u64 = 1 << 30;

/// Copy `archive` into a new 0600 file inside `private_root`. Screening and
/// extraction then read only this copy: the original could be replaced, or
/// rewritten in place, between the checks and the unpacking.
fn private_archive_copy(archive: &Path, private_root: &Path) -> anyhow::Result<PathBuf> {
    let mut source = std::fs::File::open(archive)
        .map_err(|err| anyhow::anyhow!("cannot open archive {}: {}", archive.display(), err))?;
    if !source.metadata()?.is_file() {
        anyhow::bail!("archive {} is not a regular file", archive.display());
    }
    let copy_path = private_root.join("archive.tar.gz");
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&copy_path)?;
    let copied = std::io::copy(&mut (&mut source).take(MAX_ARCHIVE_BYTES + 1), &mut copy)?;
    if copied > MAX_ARCHIVE_BYTES {
        anyhow::bail!("archive {} is larger than {} bytes", archive.display(), MAX_ARCHIVE_BYTES);
    }
    copy.sync_all()?;
    Ok(copy_path)
}

/// Extract a screened archive into a new 0700 directory inside `private_root`
/// and return it. `archive` must already be a private copy. The archive's own directory entries apply to that inner
/// directory, never to `private_root`, and owners are not restored.
fn extract_archive(archive: &Path, private_root: &Path) -> anyhow::Result<PathBuf> {
    screen_archive(archive)?;
    let inner = private_root.join("archive");
    std::fs::DirBuilder::new().mode(0o700).create(&inner)?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&inner)
        .arg("--no-same-owner")
        .arg("--no-same-permissions")
        .arg("--no-overwrite-dir")
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to extract archive (tar exit code: {:?})", status.code());
    }
    Ok(inner)
}

/// Write a gzip tar of `dir` to a new file at `archive_path`, created 0600: the
/// archive holds validator keys, so it must not inherit the umask.
fn write_private_archive(dir: &Path, archive_path: &Path) -> anyhow::Result<()> {
    let out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(archive_path)?;
    let status = Command::new("tar")
        .arg("-czf")
        .arg("-")
        .arg("-C")
        .arg(dir)
        .arg(".")
        .stdout(Stdio::from(out))
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(archive_path);
        anyhow::bail!("tar command failed with exit code: {:?}", status.code());
    }
    Ok(())
}

// ── Implementations ──────────────────────────────────────────────────

impl BackupCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            BackupAction::Create(cmd) => cmd.run(&self.config).await,
            BackupAction::Restore(cmd) => cmd.run().await,
            BackupAction::Verify(cmd) => cmd.run().await,
        }
    }
}

impl BackupCreateCmd {
    pub async fn run(&self, tosctl_config_path: &str) -> anyhow::Result<()> {
        use colored::Colorize;

        let timestamp = format_timestamp(SystemTime::now());
        let hostname = get_hostname();
        let archive_name = format!("tosctl_backup_{}_{}.tar.gz", hostname, timestamp);

        println!();
        println!("{}", "Creating backup...".bold());
        println!("{}", "──────────────────".dimmed());

        // Private staging directory, removed when `staging` is dropped.
        let staging = private_temp_dir("tosctl_backup_")?;
        let staging_dir = staging.path().to_string_lossy().to_string();

        let mut backed_up: Vec<String> = Vec::new();

        // 1. Copy config.json
        let config_json = format!("{}/db/config.json", self.config_dir);
        if is_real_file(Path::new(&config_json)) {
            let dest = format!("{}/db", staging_dir);
            std::fs::DirBuilder::new().mode(0o700).create(&dest)?;
            copy_file_private(
                Path::new(&config_json),
                Path::new(&format!("{}/config.json", dest)),
                CopyMode::CreateNew,
            )?;
            backed_up.push("db/config.json".into());
            println!("  {} db/config.json", "+".green());
        } else {
            println!("  {} db/config.json (not found, skipping)", "!".yellow());
        }

        // 2. Copy keyring directory
        let keyring_dir = format!("{}/db/keyring", self.config_dir);
        if is_real_dir(Path::new(&keyring_dir)) {
            ensure_real_dir(staging.path(), &["db"])?;
            let dest = format!("{}/db/keyring", staging_dir);
            copy_dir_recursive(Path::new(&keyring_dir), Path::new(&dest), CopyMode::CreateNew)?;
            backed_up.push("db/keyring/".into());
            println!("  {} db/keyring/", "+".green());
        } else {
            println!("  {} db/keyring/ (not found, skipping)", "!".yellow());
        }

        // 3. Copy keys directory
        let keys_dir = format!("{}/keys", self.config_dir);
        if is_real_dir(Path::new(&keys_dir)) {
            let dest = format!("{}/keys", staging_dir);
            copy_dir_recursive(Path::new(&keys_dir), Path::new(&dest), CopyMode::CreateNew)?;
            backed_up.push("keys/".into());
            println!("  {} keys/", "+".green());
        } else {
            println!("  {} keys/ (not found, skipping)", "!".yellow());
        }

        // 4. Copy tosctl config file
        let tosctl_cfg = Path::new(tosctl_config_path);
        if is_real_file(tosctl_cfg) {
            let file_name =
                tosctl_cfg.file_name().unwrap_or_default().to_string_lossy().to_string();
            copy_file_private(
                tosctl_cfg,
                Path::new(&format!("{}/{}", staging_dir, file_name)),
                CopyMode::CreateNew,
            )?;
            backed_up.push(file_name.clone());
            println!("  {} {}", "+".green(), file_name);
        } else {
            println!(
                "  {} tosctl config ({}) (not found, skipping)",
                "!".yellow(),
                tosctl_config_path
            );
        }

        if backed_up.is_empty() {
            anyhow::bail!("No files found to back up. Check --config-dir path.");
        }

        // Create output directory if needed
        std::fs::create_dir_all(&self.output)?;

        let archive_path = format!("{}/{}", self.output, archive_name);

        write_private_archive(staging.path(), Path::new(&archive_path))?;

        let metadata = std::fs::metadata(&archive_path)?;
        let size_kb = metadata.len() / 1024;

        println!();
        println!("{} Backup created: {} ({} KB)", "OK".green().bold(), archive_path, size_kb);
        println!();

        Ok(())
    }
}

impl BackupRestoreCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;
        use std::io::{self, Write};

        let archive = Path::new(&self.file);
        if !archive.exists() {
            anyhow::bail!("Backup archive not found: {}", self.file);
        }

        println!();
        println!("{}", "Restore backup".bold());
        println!("{}", "──────────────".dimmed());
        println!("  Archive:    {}", self.file);
        println!("  Config dir: {}", self.config_dir);
        println!();

        // Confirmation prompt
        if !self.yes {
            print!(
                "{}",
                "This will overwrite existing configuration files. Continue? [y/N] "
                    .yellow()
                    .bold()
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();
            if input != "y" && input != "yes" {
                println!("Restore cancelled.");
                return Ok(());
            }
        }

        // Private extraction directory, removed when `extract` is dropped. The
        // archive is screened and unpacked into a directory inside it.
        let extract = private_temp_dir("tosctl_restore_")?;
        let archive_copy = private_archive_copy(archive, extract.path())?;
        let extracted = extract_archive(&archive_copy, extract.path())?;
        let extract_dir = extracted.to_string_lossy().to_string();
        let config_root = Path::new(&self.config_dir);
        std::fs::create_dir_all(config_root)?;

        let mut restored: Vec<String> = Vec::new();

        // Restore db/config.json
        let src_config = format!("{}/db/config.json", extract_dir);
        if is_real_file(Path::new(&src_config)) {
            let dest_dir = ensure_real_dir(config_root, &["db"])?;
            copy_file_private(
                Path::new(&src_config),
                &dest_dir.join("config.json"),
                CopyMode::Replace,
            )?;
            restored.push("db/config.json".into());
            println!("  {} db/config.json", "+".green());
        }

        // Restore db/keyring/
        let src_keyring = format!("{}/db/keyring", extract_dir);
        if is_real_dir(Path::new(&src_keyring)) {
            let dest = ensure_real_dir(config_root, &["db", "keyring"])?;
            copy_dir_recursive(Path::new(&src_keyring), &dest, CopyMode::Replace)?;
            restored.push("db/keyring/".into());
            println!("  {} db/keyring/", "+".green());
        }

        // Restore keys/
        let src_keys = format!("{}/keys", extract_dir);
        if is_real_dir(Path::new(&src_keys)) {
            let dest = ensure_real_dir(config_root, &["keys"])?;
            copy_dir_recursive(Path::new(&src_keys), &dest, CopyMode::Replace)?;
            restored.push("keys/".into());
            println!("  {} keys/", "+".green());
        }

        // Restore tosctl config (any .json file in the root of the archive that is not
        // inside db/ or keys/)
        for entry in std::fs::read_dir(&extract_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.file_type()?.is_file() && name.ends_with(".json") {
                // Copy tosctl config to current working directory
                copy_file_private(&entry.path(), Path::new(&name), CopyMode::Replace)?;
                restored.push(name.clone());
                println!("  {} {} (to current directory)", "+".green(), name);
            }
        }

        println!();
        if restored.is_empty() {
            println!("{} No recognized files found in archive.", "WARN".yellow().bold());
        } else {
            println!("{} Restored {} item(s) successfully.", "OK".green().bold(), restored.len());
        }
        println!();

        Ok(())
    }
}

impl BackupVerifyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use colored::Colorize;

        let archive = Path::new(&self.file);
        if !archive.exists() {
            anyhow::bail!("Backup archive not found: {}", self.file);
        }

        println!();
        println!("{}", "Verifying backup archive...".bold());
        println!("{}", "───────────────────────────".dimmed());
        println!("  Archive: {}", self.file);
        println!();

        // Test archive integrity
        let integrity = Command::new("tar").args(["-tzf", &self.file]).output()?;

        if !integrity.status.success() {
            let stderr = String::from_utf8_lossy(&integrity.stderr);
            println!("{} Archive is corrupt or invalid.", "FAIL".red().bold());
            if !stderr.is_empty() {
                println!("  {}", stderr.trim());
            }
            anyhow::bail!("Archive verification failed");
        }

        let contents = String::from_utf8_lossy(&integrity.stdout);
        let entries: Vec<&str> = contents.lines().collect();

        println!("{}", "Contents:".bold());
        for entry in &entries {
            println!("  {}", entry);
        }
        println!();

        // Check for required files
        let has_config = entries.iter().any(|e| e.contains("db/config.json"));
        let has_keyring = entries.iter().any(|e| e.contains("db/keyring"));
        let has_keys = entries.iter().any(|e| e.contains("keys/"));

        println!("{}", "Required files:".bold());
        if has_config {
            println!("  {} db/config.json", "OK".green());
        } else {
            println!("  {} db/config.json (missing)", "WARN".yellow());
        }
        if has_keyring {
            println!("  {} db/keyring/", "OK".green());
        } else {
            println!("  {} db/keyring/ (missing)", "WARN".yellow());
        }
        if has_keys {
            println!("  {} keys/", "OK".green());
        } else {
            println!("  {} keys/ (missing)", "WARN".yellow());
        }

        println!();
        if has_config && has_keyring {
            println!("{} Archive is valid ({} entries).", "OK".green().bold(), entries.len());
        } else {
            println!(
                "{} Archive is readable but may be incomplete ({} entries).",
                "WARN".yellow().bold(),
                entries.len()
            );
        }
        println!();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0)
    }

    #[test]
    fn staging_directories_are_private_and_unpredictable() -> anyhow::Result<()> {
        let a = private_temp_dir("tosctl_backup_")?;
        let b = private_temp_dir("tosctl_backup_")?;
        assert_ne!(a.path(), b.path());
        assert_eq!(mode_of(a.path()), 0o700);
        Ok(())
    }

    #[test]
    fn a_symlink_in_the_source_tree_is_refused() -> anyhow::Result<()> {
        let src = tempfile::tempdir()?;
        let secret = tempfile::NamedTempFile::new()?;
        std::fs::write(secret.path(), b"not part of the backup")?;
        symlink(secret.path(), src.path().join("key"))?;
        let dst = tempfile::tempdir()?;
        let result = copy_dir_recursive(src.path(), &dst.path().join("keys"), CopyMode::CreateNew);
        assert!(result.is_err());
        assert!(!dst.path().join("keys").join("key").exists());
        Ok(())
    }

    #[test]
    fn a_planted_link_at_the_destination_is_never_followed() -> anyhow::Result<()> {
        let src = tempfile::tempdir()?;
        std::fs::write(src.path().join("key"), b"validator key")?;
        let victim = tempfile::NamedTempFile::new()?;
        std::fs::write(victim.path(), b"untouched")?;
        for mode in [CopyMode::CreateNew, CopyMode::Replace] {
            let dst = tempfile::tempdir()?;
            symlink(victim.path(), dst.path().join("key"))?;
            assert!(copy_dir_recursive(src.path(), dst.path(), mode).is_err());
            assert_eq!(std::fs::read(victim.path())?, b"untouched");
        }
        Ok(())
    }

    #[test]
    fn copies_are_owner_only_and_replace_regular_files() -> anyhow::Result<()> {
        let src = tempfile::tempdir()?;
        std::fs::write(src.path().join("key"), b"new key")?;
        let dst = tempfile::tempdir()?;
        std::fs::write(dst.path().join("key"), b"old key")?;
        std::fs::set_permissions(dst.path().join("key"), std::fs::Permissions::from_mode(0o644))?;
        // A fresh copy refuses to overwrite; a restore replaces.
        assert!(copy_dir_recursive(src.path(), dst.path(), CopyMode::CreateNew).is_err());
        copy_dir_recursive(src.path(), dst.path(), CopyMode::Replace)?;
        assert_eq!(std::fs::read(dst.path().join("key"))?, b"new key");
        assert_eq!(mode_of(&dst.path().join("key")), 0o600);
        Ok(())
    }

    #[test]
    fn the_archive_is_owner_only_whatever_the_umask() -> anyhow::Result<()> {
        let staging = private_temp_dir("tosctl_backup_")?;
        std::fs::write(staging.path().join("key"), b"validator key")?;
        let out = tempfile::tempdir()?;
        let archive = out.path().join("backup.tar.gz");
        // SAFETY: umask only changes this process's file-creation mask.
        let previous = unsafe { libc::umask(0o022) };
        let written = write_private_archive(staging.path(), &archive);
        // SAFETY: restores the mask read above.
        unsafe { libc::umask(previous) };
        written?;
        assert_eq!(mode_of(&archive), 0o600);
        // An existing path, link or file, is never written through.
        let victim = tempfile::NamedTempFile::new()?;
        let link = out.path().join("link.tar.gz");
        symlink(victim.path(), &link)?;
        assert!(write_private_archive(staging.path(), &link).is_err());
        assert!(write_private_archive(staging.path(), &archive).is_err());
        assert_eq!(std::fs::metadata(victim.path())?.len(), 0);
        Ok(())
    }

    fn make_fifo(path: &Path) -> anyhow::Result<()> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        // SAFETY: mkfifo reads a NUL-terminated path we own for the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        anyhow::ensure!(rc == 0, "mkfifo failed");
        Ok(())
    }

    fn tar_of(dir: &Path, out: &Path, extra: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("tar")
            .arg("-czf")
            .arg(out)
            .args(extra)
            .arg("-C")
            .arg(dir)
            .arg(".")
            .status()?;
        anyhow::ensure!(status.success(), "tar failed");
        Ok(())
    }

    #[test]
    fn sources_must_be_real_files_and_directories() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"outside")?;
        symlink(&secret, dir.path().join("link"))?;
        make_fifo(&dir.path().join("fifo"))?;
        // A link and a FIFO are refused, and the FIFO does not stall the read.
        assert!(read_regular_file(&dir.path().join("link")).is_err());
        let started = std::time::Instant::now();
        assert!(read_regular_file(&dir.path().join("fifo")).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // A symlinked source directory is refused as a whole, not only its entries.
        let real = tempfile::tempdir()?;
        std::fs::write(real.path().join("key"), b"key")?;
        symlink(real.path(), dir.path().join("keys"))?;
        let dst = tempfile::tempdir()?;
        assert!(
            copy_dir_recursive(
                &dir.path().join("keys"),
                &dst.path().join("keys"),
                CopyMode::CreateNew
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_symlinked_destination_component_is_refused() -> anyhow::Result<()> {
        let config = tempfile::tempdir()?;
        let elsewhere = tempfile::tempdir()?;
        symlink(elsewhere.path(), config.path().join("db"))?;
        assert!(ensure_real_dir(config.path(), &["db", "keyring"]).is_err());
        assert_eq!(std::fs::read_dir(elsewhere.path())?.count(), 0);
        // Real components are created owner-only.
        let made = ensure_real_dir(config.path(), &["keys", "sub"])?;
        assert_eq!(mode_of(&config.path().join("keys")), 0o700);
        assert!(made.is_dir());
        Ok(())
    }

    #[test]
    fn a_failed_replacement_keeps_the_old_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let dst = dir.path().join("config.json");
        std::fs::write(&dst, b"old")?;
        assert!(copy_file_private(&dir.path().join("missing"), &dst, CopyMode::Replace).is_err());
        assert_eq!(std::fs::read(&dst)?, b"old");
        Ok(())
    }

    #[test]
    fn archives_with_links_special_files_or_unsafe_names_are_refused() -> anyhow::Result<()> {
        let out = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        // A symlink member.
        let with_link = tempfile::tempdir()?;
        symlink(outside.path(), with_link.path().join("config.json"))?;
        tar_of(with_link.path(), &out.path().join("link.tgz"), &[])?;
        // A FIFO member.
        let with_fifo = tempfile::tempdir()?;
        make_fifo(&with_fifo.path().join("config.json"))?;
        tar_of(with_fifo.path(), &out.path().join("fifo.tgz"), &[])?;
        // A member named outside the extraction root.
        let plain = tempfile::tempdir()?;
        std::fs::write(plain.path().join("x"), b"x")?;
        tar_of(plain.path(), &out.path().join("dotdot.tgz"), &["--transform", "s,^\\./x,../x,"])?;
        for name in ["link.tgz", "fifo.tgz", "dotdot.tgz"] {
            let root = private_temp_dir("tosctl_restore_")?;
            assert!(
                extract_archive(&out.path().join(name), root.path()).is_err(),
                "{name} was accepted"
            );
            // Nothing was unpacked.
            assert!(!root.path().join("archive").exists());
        }
        Ok(())
    }

    #[test]
    fn the_archive_cannot_open_up_the_private_directory() -> anyhow::Result<()> {
        let src = tempfile::tempdir()?;
        std::fs::write(src.path().join("key"), b"key")?;
        std::fs::set_permissions(src.path(), std::fs::Permissions::from_mode(0o777))?;
        let out = tempfile::tempdir()?;
        tar_of(src.path(), &out.path().join("open.tgz"), &[])?;
        let root = private_temp_dir("tosctl_restore_")?;
        let inner = extract_archive(&out.path().join("open.tgz"), root.path())?;
        assert_eq!(mode_of(root.path()), 0o700);
        assert_eq!(mode_of(&inner), 0o700);
        assert_eq!(std::fs::read(inner.join("key"))?, b"key");
        Ok(())
    }

    #[tokio::test]
    async fn a_backup_restores_into_a_fresh_config_dir() -> anyhow::Result<()> {
        let config = tempfile::tempdir()?;
        std::fs::create_dir_all(config.path().join("db/keyring"))?;
        std::fs::create_dir_all(config.path().join("keys"))?;
        std::fs::write(config.path().join("db/config.json"), b"{\"config\":1}")?;
        std::fs::write(config.path().join("db/keyring/k1"), b"keyring key")?;
        std::fs::write(config.path().join("keys/k2"), b"server key")?;
        let out = tempfile::tempdir()?;
        let missing_tosctl_config = out.path().join("no-tosctl-config.json");
        BackupCreateCmd {
            output: out.path().to_string_lossy().to_string(),
            config_dir: config.path().to_string_lossy().to_string(),
        }
        .run(&missing_tosctl_config.to_string_lossy())
        .await?;
        let archive = std::fs::read_dir(out.path())?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.to_string_lossy().ends_with(".tar.gz"))
            .ok_or_else(|| anyhow::anyhow!("no archive written"))?;
        assert_eq!(mode_of(&archive), 0o600);

        let restored = tempfile::tempdir()?;
        BackupRestoreCmd {
            file: archive.to_string_lossy().to_string(),
            config_dir: restored.path().to_string_lossy().to_string(),
            yes: true,
        }
        .run()
        .await?;
        for file in ["db/config.json", "db/keyring/k1", "keys/k2"] {
            assert_eq!(
                std::fs::read(restored.path().join(file))?,
                std::fs::read(config.path().join(file))?
            );
            assert_eq!(mode_of(&restored.path().join(file)), 0o600);
        }
        Ok(())
    }

    #[test]
    fn restore_reads_the_archive_it_screened_not_a_later_swap() -> anyhow::Result<()> {
        // A good archive, copied privately before screening.
        let good = tempfile::tempdir()?;
        std::fs::write(good.path().join("key"), b"good key")?;
        let out = tempfile::tempdir()?;
        let archive = out.path().join("backup.tgz");
        tar_of(good.path(), &archive, &[])?;
        let root = private_temp_dir("tosctl_restore_")?;
        let copy = private_archive_copy(&archive, root.path())?;
        assert_eq!(mode_of(&copy), 0o600);

        // The original is then replaced by one holding a link to a sentinel.
        let sentinel = tempfile::NamedTempFile::new()?;
        std::fs::write(sentinel.path(), b"sentinel")?;
        let evil = tempfile::tempdir()?;
        symlink(sentinel.path(), evil.path().join("key"))?;
        std::fs::remove_file(&archive)?;
        tar_of(evil.path(), &archive, &[])?;

        // Extraction uses the screened copy.
        let inner = extract_archive(&copy, root.path())?;
        assert_eq!(std::fs::read(inner.join("key"))?, b"good key");
        assert!(!std::fs::symlink_metadata(inner.join("key"))?.file_type().is_symlink());
        assert_eq!(std::fs::read(sentinel.path())?, b"sentinel");
        Ok(())
    }
}
