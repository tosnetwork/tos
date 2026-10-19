/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use anyhow::Context;
use colored::Colorize;
use secrets_vault::{
    crypto::factory::{AutoCryptoFactory, CryptoFactory},
    secret_input::{read_secret, select_source, trim_ascii},
    types::{
        algorithm::Algorithm, metadata::Metadata, secret::Secret, secret_spec::SecretSpec,
        store_mode::StoreMode,
    },
    vault::SecretVault,
    vault_builder::SecretVaultBuilder,
};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(clap::Args, Clone)]
#[command(about = "Manage vault keys")]
pub struct KeyCmd {
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
    action: KeyAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum KeyAction {
    /// Generate a new key in the vault
    Add(KeyAddCmd),
    /// Import a key from a private key into the vault
    Import(KeyImportCmd),
    /// List all keys in the vault
    Ls(KeyLsCmd),
    /// Remove a key from the vault
    Rm(KeyRmCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Generate a new key in the vault")]
pub struct KeyAddCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
    #[arg(short = 'a', long = "algorithm", default_value = "ed25519")]
    algorithm: String,
    #[arg(short = 'e', long = "extractable")]
    extractable: bool,
}

/// Where an import command reads a base64-encoded private key from. The key
/// itself is never a command-line value: argv is readable by other local
/// processes and is kept by shell history.
#[derive(clap::Args, Clone, Default)]
pub struct PrivateKeyInput {
    /// Read the base64 private key from a file you own with mode 0600.
    #[arg(long = "private-key-file", conflicts_with = "private_key_fd")]
    private_key_file: Option<PathBuf>,
    /// Read the base64 private key from an inherited file descriptor
    /// (0 for standard input, or 3 and above). Neither option: prompt
    /// without echo.
    #[arg(long = "private-key-fd", conflicts_with = "private_key_file")]
    private_key_fd: Option<i32>,
    /// No longer accepted; kept only to explain the replacement.
    #[arg(short = 'k', long = "private-key", hide = true, allow_hyphen_values = true)]
    legacy_private_key: Option<String>,
}

/// Message for the retired `--private-key` option. It never repeats the value.
pub const LEGACY_PRIVATE_KEY_MESSAGE: &str = "--private-key is no longer accepted: a key in \
process arguments is visible to other local processes and is kept by shell history. Pass \
--private-key-file <PATH> (a file you own with mode 0600), --private-key-fd <N> (an inherited \
descriptor, 0 for standard input), or neither to be prompted without echo. Treat the key you \
passed as exposed.";

impl PrivateKeyInput {
    /// Refuses the retired option without reading anything else. Called before
    /// any vault or configuration is opened, so the refusal does not depend on
    /// the environment being set up.
    pub fn reject_legacy(&self) -> anyhow::Result<()> {
        if self.legacy_private_key.is_some() {
            anyhow::bail!(LEGACY_PRIVATE_KEY_MESSAGE);
        }
        Ok(())
    }

    /// Reads and base64-decodes the private key. Errors never contain key bytes.
    pub fn read(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.reject_legacy()?;
        let source = select_source(
            self.private_key_file.as_deref(),
            self.private_key_fd,
            "--private-key-file",
            "--private-key-fd",
            "Private key (base64, hidden): ",
        )?;
        let text = read_secret(&source)?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trim_ascii(&text))
            .map(Zeroizing::new)
            .map_err(|_| anyhow::anyhow!("private key is not valid base64"))
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Import a key from a private key into the vault")]
pub struct KeyImportCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
    #[command(flatten)]
    private_key: PrivateKeyInput,
    #[arg(short = 'a', long = "algorithm", default_value = "ed25519")]
    algorithm: String,
    #[arg(short = 'e', long = "extractable")]
    extractable: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "List all keys in the vault")]
pub struct KeyLsCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a key from the vault")]
pub struct KeyRmCmd {
    #[arg(short = 'n', long = "name")]
    name: String,
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len { s.to_string() } else { format!("{}...", &s[..max_len - 3]) }
}

fn print_header() {
    println!(
        "  {:<30} {:<12} {:<12} {:<20} {}",
        "Name".cyan().bold(),
        "Algorithm".cyan().bold(),
        "Extractable".cyan().bold(),
        "Created".cyan().bold(),
        "Public Key".cyan().bold(),
    );
    println!("  {}", "─".repeat(120).dimmed());
}

async fn print_secret(secret: &Secret) -> anyhow::Result<()> {
    let metadata = secret.metadata();
    let secret_id =
        metadata.secret_id.as_ref().ok_or_else(|| anyhow::anyhow!("Secret has no ID"))?;
    let public_key =
        if let Secret::KeyPair { keypair } = secret { keypair.public_key().await? } else { None };

    println!(
        "  {:<30} {:<12} {:<12} {:<20} {}",
        truncate(&secret_id.to_string(), 30),
        metadata.algorithm.to_string(),
        if metadata.extractable { "Yes".green() } else { "No".red() },
        metadata.created_at.format("%Y-%m-%d %H:%M"),
        if let Some(pk) = public_key {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_slice())
        } else {
            "".to_string()
        }
    );

    Ok(())
}

impl KeyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        if let KeyAction::Import(cmd) = &self.action {
            // Read the key before touching the vault, so a refused or
            // unreadable input changes nothing.
            let private_key = cmd.private_key.read()?;
            let vault = SecretVaultBuilder::from_env().await?;
            return cmd.run(&vault, &private_key).await;
        }
        let vault = SecretVaultBuilder::from_env().await?;
        match &self.action {
            KeyAction::Add(cmd) => cmd.run(&vault).await,
            KeyAction::Import(_) => anyhow::bail!("key import is handled before the vault opens"),
            KeyAction::Ls(cmd) => cmd.run(&vault).await,
            KeyAction::Rm(cmd) => cmd.run(&vault).await,
        }
    }
}

impl KeyAddCmd {
    pub async fn run(&self, vault: &SecretVault) -> anyhow::Result<()> {
        let algo: Algorithm = self.algorithm.parse().context("Invalid algorithm")?;
        let secret_id = self.name.as_str().into();
        let spec = SecretSpec::new(algo).extractable(self.extractable);
        vault.generate_secret(&spec, &secret_id).await?;
        vault.flush().await?;
        let secret = vault.get(&secret_id).await?;

        println!("\n{} {}\n", "OK".green().bold(), "Key generated successfully".green());

        print_header();
        print_secret(&secret).await?;
        println!();
        Ok(())
    }
}

impl KeyImportCmd {
    pub async fn run(&self, vault: &SecretVault, private_key_bytes: &[u8]) -> anyhow::Result<()> {
        let algo: Algorithm = self.algorithm.parse().context("Invalid algorithm")?;
        let secret_id = self.name.as_str().into();
        let metadata = Metadata::new(Some(&secret_id), algo, self.extractable);
        let secret =
            Secret::from_raw_data(private_key_bytes, metadata, AutoCryptoFactory {}.new_crypto()?)
                .await?;
        vault.put(&secret, StoreMode::CreateOrReplace).await?;
        vault.flush().await?;
        let secret = vault.get(&secret_id).await?;

        println!("\n{} {}\n", "OK".green().bold(), "Key imported successfully".green());

        print_header();
        print_secret(&secret).await?;
        println!();
        Ok(())
    }
}

impl KeyLsCmd {
    pub async fn run(&self, vault: &SecretVault) -> anyhow::Result<()> {
        let records = vault.list_metadata().await?;

        if records.is_empty() {
            println!("\n{}\n", "No keys found".yellow());
            return Ok(());
        }

        println!("\n{} {} ({})\n", "OK".green().bold(), "Keys:".green(), records.len());

        print_header();

        for meta in &records {
            let secret_id =
                meta.secret_id.as_ref().ok_or_else(|| anyhow::anyhow!("Secret has no ID"))?;
            let secret = vault.get(secret_id).await?;
            print_secret(&secret).await?;
        }

        println!();
        Ok(())
    }
}

impl KeyRmCmd {
    pub async fn run(&self, vault: &SecretVault) -> anyhow::Result<()> {
        let secret_id = self.name.as_str().into();
        vault.delete(&secret_id).await?;
        vault.flush().await?;

        println!("\n{} Key '{}' removed\n", "OK".green().bold(), self.name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        action: KeyAction,
    }

    const KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn import(args: &[&str]) -> KeyImportCmd {
        let mut argv = vec!["key", "import", "-n", "k"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).map(|cli| cli.action) {
            Ok(KeyAction::Import(cmd)) => cmd,
            Ok(_) => panic!("not an import"),
            Err(error) => panic!("parse: {error}"),
        }
    }

    #[test]
    fn legacy_private_key_argument_is_a_hard_error_that_does_not_echo_it() {
        for flag in ["-k", "--private-key"] {
            let cmd = import(&[flag, KEY_B64]);
            let error = cmd.private_key.read().expect_err("legacy option must be refused");
            let text = format!("{error:#}");
            assert!(text.contains("--private-key-file"), "{text}");
            assert!(!text.contains(KEY_B64), "{text}");
        }
    }

    #[test]
    fn private_key_is_read_from_a_protected_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key");
        let mut file = std::fs::File::create(&path).expect("create");
        writeln!(file, "{KEY_B64}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let cmd = import(&["--private-key-file", path.to_str().expect("utf8")]);
        let key = cmd.private_key.read().expect("read");
        assert_eq!(&key[..], &(0u8..32).collect::<Vec<_>>()[..]);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = cmd.private_key.read().expect_err("world-readable file must be refused");
        assert!(!format!("{error:#}").contains(KEY_B64));
    }

    #[test]
    fn invalid_base64_error_does_not_echo_the_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key");
        let secret_like = "not*base64*secret*material";
        std::fs::write(&path, secret_like).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let cmd = import(&["--private-key-file", path.to_str().expect("utf8")]);
        let text = format!("{:#}", cmd.private_key.read().expect_err("invalid"));
        assert_eq!(text, "private key is not valid base64");
    }

    #[test]
    fn file_and_descriptor_are_mutually_exclusive() {
        let parsed = Cli::try_parse_from([
            "key",
            "import",
            "-n",
            "k",
            "--private-key-file",
            "/x",
            "--private-key-fd",
            "3",
        ]);
        assert!(parsed.is_err());
    }
}
