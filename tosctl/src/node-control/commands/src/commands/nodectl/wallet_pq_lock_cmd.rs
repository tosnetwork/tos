// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::sign::write_submission;
use super::{
    PathBuf, SecretId,
    inspect::{InitialProofArgs, now},
    open_vault_file,
};
use contracts::{wallet_v5r2::AuthAction, wallet_v5r2_vault::VaultKey};

#[derive(clap::Args, Clone)]
#[command(about = "Sign an SLH lock of PRIMARY from proven initial wallet state; no broadcast")]
pub struct PqLockPrimaryInitialCmd {
    #[command(flatten)]
    proof: InitialProofArgs,
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

impl PqLockPrimaryInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.record_id.trim().is_empty(), "record ID must not be empty");
        let proof = self.proof.read(&[]).await?;
        let request =
            proof.view.rescue_request(now()?, self.valid_until, AuthAction::LockPrimary)?;
        // Reserve a new output location before opening custody. Uncertain partial
        // output is retained, never silently overwritten or automatically retried.
        std::fs::create_dir(&self.output_dir)?;
        let storage =
            open_vault_file(&self.vault_file, self.vault_key_file.as_deref(), self.vault_key_fd)
                .await?;
        let id = SecretId::new(&self.record_id);
        let submission = VaultKey { vault: &storage, id: &id }
            .sign_rescue(&proof.view, now, self.valid_until, AuthAction::LockPrimary)
            .await?;
        drop(storage);
        // A slow signing operation must not publish an expired authorization.
        proof.view.rescue_request(now()?, self.valid_until, AuthAction::LockPrimary)?;
        let checkpoint = &proof.wallet.evidence().checkpoint;
        let report = serde_json::json!({
            "status": "rescue_lock_submission_signed",
            "suite": "SLH-DSA-SHA2-128s",
            "wallet": proof.wallet.evidence().account.address,
            "module": proof.module.evidence().account.address,
            "checkpoint": {"seqno": checkpoint.seqno,
                "root_hash": checkpoint.root_hash, "file_hash": checkpoint.file_hash},
            "epoch": proof.view.epoch(), "nonce": proof.view.rescue_nonce(),
            "valid_until": self.valid_until,
            "action": "lock_primary",
            "request_hash": request.cell().repr_hash().to_hex_string(),
            "auth_digest": hex::encode(request.digest()),
            "submission_hash": submission.repr_hash().to_hex_string(),
            "scope": "signed internal module body; not fee authorization, broadcast, nonce reservation or delivery"
        });
        write_submission(&self.output_dir, &submission, &report)?;
        println!("{report}");
        Ok(())
    }
}
