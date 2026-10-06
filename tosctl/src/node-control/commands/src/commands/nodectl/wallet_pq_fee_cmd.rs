// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{
    InitialCodeArgs, PathBuf, SecretId, Zeroizing, bounded_public_file, open_vault_file,
    public_hash, secret_input,
};
use contracts::wallet_v5r2_manifest::{InitialRecoveryManifest, MAX_MANIFEST_BYTES, SeedProfile};

#[derive(clap::Args, Clone)]
#[command(
    about = "Restore initial fee custody from native mnemonic; no signing-state recovery or readiness"
)]
pub struct PqRestoreFeeInitialCmd {
    #[arg(long)]
    vault_file: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    recovery_manifest: PathBuf,
    /// Independently authenticated basechain wallet account ID, in hex.
    #[arg(long)]
    expected_wallet: String,
    #[command(flatten)]
    code: InitialCodeArgs,
    /// Existing public tree cache. Without this, rebuild the complete H20 tree.
    #[arg(long)]
    fee_tree_cache: Option<PathBuf>,
    /// Save the verified public tree to a new file; existing files are refused.
    #[arg(long)]
    write_fee_tree_cache: Option<PathBuf>,
    #[arg(long, conflicts_with = "mnemonic_fd")]
    mnemonic_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "mnemonic_file")]
    mnemonic_fd: Option<i32>,
    /// Exact password bytes; absent means empty, never trimmed.
    #[arg(long, conflicts_with = "password_fd")]
    password_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "password_file")]
    password_fd: Option<i32>,
    #[arg(long, conflicts_with = "vault_key_fd")]
    vault_key_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "vault_key_file")]
    vault_key_fd: Option<i32>,
}

impl PqRestoreFeeInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.record_id.trim().is_empty(), "record ID must not be empty");
        let fds = [self.mnemonic_fd, self.password_fd, self.vault_key_fd];
        for i in 0..fds.len() {
            for j in 0..i {
                anyhow::ensure!(
                    fds[i].is_none() || fds[i] != fds[j],
                    "secret inputs require distinct file descriptors"
                );
            }
        }
        let expected = public_hash(&self.expected_wallet)?;
        let encoded = bounded_public_file(&self.recovery_manifest, MAX_MANIFEST_BYTES)?;
        let (manifest, _) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, self.code.load()?, expected)?;
        anyhow::ensure!(
            manifest.derivation().fee_seed_profile == SeedProfile::NativeMnemonic,
            "fee recovery requires declared native mnemonic profile"
        );
        let cache = self.fee_tree_cache.clone();
        let key = manifest.initial_fee_public_key()?;
        // Public validation precedes secret collection and persistent custody.
        let tree = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            match cache {
                None => Ok(None),
                Some(path) => {
                    anyhow::ensure!(
                        std::fs::metadata(&path)?.is_file(),
                        "fee cache must be a file"
                    );
                    let file = std::fs::File::open(path)?;
                    anyhow::ensure!(
                        file.metadata()?.len() == 64 * 1024 * 1024 + 68,
                        "fee cache size mismatch"
                    );
                    Ok(Some(wallet_pq_signer::fee::FeeTree::read_cache(file, &key)?))
                }
            }
        })
        .await??;
        let phrase_source = secret_input::select_source(
            self.mnemonic_file.as_deref(),
            self.mnemonic_fd,
            "--mnemonic-file",
            "--mnemonic-fd",
            "TOS mnemonic (hidden): ",
        )?;
        let phrase = secret_input::read_secret(&phrase_source)?;
        let phrase =
            std::str::from_utf8(&phrase).map_err(|_| anyhow::anyhow!("mnemonic is not UTF-8"))?;
        let password = match (&self.password_file, self.password_fd) {
            (None, None) => Zeroizing::new(Vec::new()),
            _ => secret_input::read_secret_exact(&secret_input::select_source(
                self.password_file.as_deref(),
                self.password_fd,
                "--password-file",
                "--password-fd",
                "Password (hidden): ",
            )?)?,
        };
        let password =
            std::str::from_utf8(&password).map_err(|_| anyhow::anyhow!("password is not UTF-8"))?;
        let mut master = Zeroizing::new(
            tos_native_mnemonic::private_seed(phrase, password)
                .map_err(|_| anyhow::anyhow!("native mnemonic or password rejected"))?,
        );
        let mut checked = Zeroizing::new(*master);
        let output = self.write_fee_tree_cache.clone();
        let (manifest, path) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let tree = match tree {
                Some(tree) => tree,
                None => {
                    let mut rebuilding = Zeroizing::new(*checked);
                    manifest.rebuild_initial_fee_tree_and_wipe(
                        &mut *rebuilding,
                        SeedProfile::NativeMnemonic,
                    )?
                }
            };
            let path = tree.authentication_path(0)?;
            manifest.verify_initial_fee_master_and_wipe(
                &mut *checked,
                SeedProfile::NativeMnemonic,
                0,
                &path,
            )?;
            if let Some(output) = output {
                #[cfg(unix)]
                tree.save_cache_new(&output)?;
                #[cfg(not(unix))]
                {
                    let _ = output;
                    anyhow::bail!("durable fee cache publication requires Unix");
                }
            }
            Ok((manifest, path))
        })
        .await??;
        let vault =
            open_vault_file(&self.vault_file, self.vault_key_file.as_deref(), self.vault_key_fd)
                .await?;
        let public_key = manifest
            .restore_initial_fee_master_to_vault(
                &vault,
                &SecretId::new(self.record_id.as_str()),
                &mut *master,
                SeedProfile::NativeMnemonic,
                0,
                &path,
            )
            .await?;
        println!(
            "{}",
            serde_json::json!({"status":"fee_key_record_restored",
            "record_id":self.record_id,"public_key":hex::encode(public_key),
            "initial_wallet":hex::encode(expected)})
        );
        Ok(())
    }
}
