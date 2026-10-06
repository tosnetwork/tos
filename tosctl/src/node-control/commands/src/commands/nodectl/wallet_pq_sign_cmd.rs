// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{
    Path, PathBuf, SecretId, bounded_public_file,
    inspect::{InitialProofArgs, now},
    open_vault_file,
};
use contracts::wallet_v5r2_vault::VaultKey;
use std::io::Write;

#[derive(clap::Args, Clone)]
#[command(
    about = "Sign approved V5 actions with proven initial PQ state and global policy; no broadcast"
)]
pub struct PqSignPrimaryInitialCmd {
    #[command(flatten)]
    proof: InitialProofArgs,
    /// Exact owner-approved strict V5 OutList BOC, including recipients and amounts.
    #[arg(long)]
    actions: PathBuf,
    /// Absolute Unix deadline; at most one hour after the proven wallet time.
    #[arg(long)]
    valid_until: u32,
    #[arg(long)]
    vault_file: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long, conflicts_with = "vault_key_fd")]
    vault_key_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "vault_key_file")]
    vault_key_fd: Option<i32>,
    /// New directory for signed SUB3 body and its public binding report.
    #[arg(long)]
    output_dir: PathBuf,
}

impl PqSignPrimaryInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.record_id.trim().is_empty(), "record ID must not be empty");
        let actions = chain_block::read_single_root_boc(bounded_public_file(
            &self.actions,
            4 * 1024 * 1024,
        )?)?;
        contracts::wallet_v5r2::validate_actions(&actions)?;
        let proof = self.proof.read(&[48]).await?;
        let request =
            proof.view.primary_request(&proof.wallet, now()?, self.valid_until, actions.clone())?;
        // Reserve a new output location before opening custody. Uncertain partial
        // output is retained, never silently overwritten or automatically retried.
        std::fs::create_dir(&self.output_dir)?;
        let storage =
            open_vault_file(&self.vault_file, self.vault_key_file.as_deref(), self.vault_key_fd)
                .await?;
        let id = SecretId::new(&self.record_id);
        let submission = VaultKey { vault: &storage, id: &id }
            .sign_primary(&proof.view, &proof.wallet, now, self.valid_until, actions.clone())
            .await?;
        drop(storage);
        // A slow signing operation must not publish an expired authorization.
        proof.view.primary_request(&proof.wallet, now()?, self.valid_until, actions.clone())?;
        let checkpoint = &proof.wallet.evidence().checkpoint;
        let report = serde_json::json!({
            "status": "primary_submission_signed",
            "suite": "ML-DSA-44",
            "wallet": proof.wallet.evidence().account.address,
            "module": proof.module.evidence().account.address,
            "checkpoint": {"seqno": checkpoint.seqno,
                "root_hash": checkpoint.root_hash, "file_hash": checkpoint.file_hash},
            "epoch": proof.view.epoch(), "nonce": proof.view.primary_nonce(),
            "valid_until": self.valid_until,
            "actions_hash": actions.repr_hash().to_hex_string(),
            "request_hash": request.cell().repr_hash().to_hex_string(),
            "auth_digest": hex::encode(request.digest()),
            "submission_hash": submission.repr_hash().to_hex_string(),
            "scope": "signed internal module body; not fee authorization, broadcast, nonce reservation or delivery"
        });
        for (name, bytes) in [
            ("submission.boc", chain_block::write_boc(&submission)?),
            ("binding.json", serde_json::to_vec_pretty(&report)?),
        ] {
            let path = self.output_dir.join(name);
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            anyhow::ensure!(
                bounded_public_file(&path, bytes.len())? == bytes,
                "signed output readback mismatch"
            );
        }
        std::fs::File::open(&self.output_dir)?.sync_all()?;
        let parent = self
            .output_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        println!("{report}");
        Ok(())
    }
}
