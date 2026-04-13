/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

use std::path::Path;
use std::process::Command;
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
    let dur = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
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

/// Recursively copy a directory tree from `src` to `dst`.
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
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
        let staging_dir = format!("/tmp/tosctl_backup_{}", timestamp);

        println!();
        println!("{}", "Creating backup...".bold());
        println!("{}", "──────────────────".dimmed());

        // Create staging directory
        std::fs::create_dir_all(&staging_dir)?;

        // Ensure cleanup on all exit paths
        let _guard = scopeguard::guard((), |_| {
            let _ = std::fs::remove_dir_all(&staging_dir);
        });

        let mut backed_up: Vec<String> = Vec::new();

        // 1. Copy config.json
        let config_json = format!("{}/db/config.json", self.config_dir);
        if Path::new(&config_json).exists() {
            let dest = format!("{}/db", staging_dir);
            std::fs::create_dir_all(&dest)?;
            std::fs::copy(&config_json, format!("{}/config.json", dest))?;
            backed_up.push("db/config.json".into());
            println!("  {} db/config.json", "+".green());
        } else {
            println!("  {} db/config.json (not found, skipping)", "!".yellow());
        }

        // 2. Copy keyring directory
        let keyring_dir = format!("{}/db/keyring", self.config_dir);
        if Path::new(&keyring_dir).is_dir() {
            let dest = format!("{}/db/keyring", staging_dir);
            copy_dir_recursive(Path::new(&keyring_dir), Path::new(&dest))?;
            backed_up.push("db/keyring/".into());
            println!("  {} db/keyring/", "+".green());
        } else {
            println!("  {} db/keyring/ (not found, skipping)", "!".yellow());
        }

        // 3. Copy keys directory
        let keys_dir = format!("{}/keys", self.config_dir);
        if Path::new(&keys_dir).is_dir() {
            let dest = format!("{}/keys", staging_dir);
            copy_dir_recursive(Path::new(&keys_dir), Path::new(&dest))?;
            backed_up.push("keys/".into());
            println!("  {} keys/", "+".green());
        } else {
            println!("  {} keys/ (not found, skipping)", "!".yellow());
        }

        // 4. Copy tosctl config file
        let tosctl_cfg = Path::new(tosctl_config_path);
        if tosctl_cfg.exists() {
            let file_name = tosctl_cfg
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            std::fs::copy(tosctl_cfg, format!("{}/{}", staging_dir, file_name))?;
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

        // Create tar.gz archive
        let status = Command::new("tar")
            .args(["-czf", &archive_path, "-C", &staging_dir, "."])
            .status()?;

        if !status.success() {
            anyhow::bail!("tar command failed with exit code: {:?}", status.code());
        }

        let metadata = std::fs::metadata(&archive_path)?;
        let size_kb = metadata.len() / 1024;

        println!();
        println!(
            "{} Backup created: {} ({} KB)",
            "OK".green().bold(),
            archive_path,
            size_kb
        );
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

        let timestamp = format_timestamp(SystemTime::now());
        let extract_dir = format!("/tmp/tosctl_restore_{}", timestamp);
        std::fs::create_dir_all(&extract_dir)?;

        // Ensure cleanup on all exit paths
        let _guard = scopeguard::guard((), |_| {
            let _ = std::fs::remove_dir_all(&extract_dir);
        });

        // Extract archive to temp dir
        let status = Command::new("tar")
            .args(["-xzf", &self.file, "-C", &extract_dir])
            .status()?;

        if !status.success() {
            anyhow::bail!(
                "Failed to extract archive (tar exit code: {:?})",
                status.code()
            );
        }

        let mut restored: Vec<String> = Vec::new();

        // Restore db/config.json
        let src_config = format!("{}/db/config.json", extract_dir);
        if Path::new(&src_config).exists() {
            let dest_dir = format!("{}/db", self.config_dir);
            std::fs::create_dir_all(&dest_dir)?;
            std::fs::copy(&src_config, format!("{}/config.json", dest_dir))?;
            restored.push("db/config.json".into());
            println!("  {} db/config.json", "+".green());
        }

        // Restore db/keyring/
        let src_keyring = format!("{}/db/keyring", extract_dir);
        if Path::new(&src_keyring).is_dir() {
            let dest = format!("{}/db/keyring", self.config_dir);
            std::fs::create_dir_all(&dest)?;
            copy_dir_recursive(Path::new(&src_keyring), Path::new(&dest))?;
            restored.push("db/keyring/".into());
            println!("  {} db/keyring/", "+".green());
        }

        // Restore keys/
        let src_keys = format!("{}/keys", extract_dir);
        if Path::new(&src_keys).is_dir() {
            let dest = format!("{}/keys", self.config_dir);
            std::fs::create_dir_all(&dest)?;
            copy_dir_recursive(Path::new(&src_keys), Path::new(&dest))?;
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
                std::fs::copy(entry.path(), &name)?;
                restored.push(name.clone());
                println!("  {} {} (to current directory)", "+".green(), name);
            }
        }

        println!();
        if restored.is_empty() {
            println!(
                "{} No recognized files found in archive.",
                "WARN".yellow().bold()
            );
        } else {
            println!(
                "{} Restored {} item(s) successfully.",
                "OK".green().bold(),
                restored.len()
            );
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
            println!(
                "{} Archive is valid ({} entries).",
                "OK".green().bold(),
                entries.len()
            );
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
