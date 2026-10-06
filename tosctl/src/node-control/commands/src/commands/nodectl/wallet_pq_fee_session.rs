// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! A process-held fee journal. No broadcast or fee affordability assertion.
use super::{
    Path, PathBuf, SecretId, bounded_public_file,
    inspect::{InitialContext, InitialProofArgs, now},
    open_vault_file,
};
use contracts::{
    lms_fee_journal::{FeeJournal, SignedFeeMessage},
    wallet_v5r2::AuthAction,
    wallet_v5r2_fee::{FeeBinding, FeeClass, FeeIntent, FeePayload},
    wallet_v5r2_vault::VaultKey,
};
use std::io::{BufRead, Read, Write};

#[derive(clap::Args, Clone)]
#[command(
    about = "Hold an initial rescue-fee journal session; JSON-line status/lock/retry/quit, no broadcast"
)]
pub struct PqFeeSessionInitialCmd {
    #[command(flatten)]
    proof: InitialProofArgs,
    /// Existing absolute, owner-only mode-0700 journal directory.
    #[arg(long)]
    journal_dir: PathBuf,
    #[arg(long)]
    fee_tree_cache: PathBuf,
    #[arg(long)]
    fee_vault_file: PathBuf,
    #[arg(long)]
    fee_record_id: String,
    /// Protected file containing the fee Vault encryption key as hex.
    #[arg(long)]
    fee_vault_key_file: PathBuf,
    #[arg(long)]
    rescue_vault_file: PathBuf,
    #[arg(long)]
    rescue_record_id: String,
    #[arg(long)]
    rescue_vault_key_file: PathBuf,
}

#[derive(serde::Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Lock { valid_for_seconds: u32, value_nanotos: String, output_dir: PathBuf },
    Retry { intent: PathBuf, output_dir: PathBuf },
    Quit,
}

fn fee_clock() -> u32 {
    match now() {
        Ok(time) => time,
        // Every fee path requires valid_until > now, impossible at this value.
        Err(_) => u32::MAX,
    }
}

fn put(directory: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path = directory.join(name);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    anyhow::ensure!(
        bounded_public_file(&path, bytes.len())? == bytes,
        "fee output readback mismatch"
    );
    std::fs::File::open(directory)?.sync_all()?;
    let parent = directory.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn export(directory: &Path, signed: &SignedFeeMessage) -> anyhow::Result<serde_json::Value> {
    use chain_block::{
        ExternalInboundMessageHeader, Message, MsgAddressExt, Serializable, SliceData,
    };
    let destination = format!("0:{}", hex::encode(signed.vault()));
    let message = Message::with_ext_in_header_and_body(
        ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, destination.parse()?),
        SliceData::load_cell(signed.body().clone())?,
    );
    let root = message.serialize()?;
    let report = serde_json::json!({
        "status": "fee_message_cached", "vault": destination,
        "leaf": signed.intent().leaf(), "intent_hash": hex::encode(signed.intent().digest()),
        "body_hash": signed.body().repr_hash().to_hex_string(),
        "message_hash": root.repr_hash().to_hex_string(),
        "scope": "cached signature and exact external message only; admission, affordability, broadcast and delivery are unconfirmed"
    });
    put(directory, "message.boc", &chain_block::write_boc(&root)?)?;
    put(directory, "binding.json", &serde_json::to_vec_pretty(&report)?)?;
    Ok(report)
}

impl PqFeeSessionInitialCmd {
    pub async fn run(
        &self,
        cancellation: common::task_cancellation::CancellationCtx,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.fee_record_id.trim().is_empty() && !self.rescue_record_id.trim().is_empty(),
            "record IDs must not be empty"
        );
        let context = self.proof.context()?;
        let view = context.fee().await?;
        let key = *view.fee_public_key();
        let tree_file = self.fee_tree_cache.clone();
        let tree = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let file = std::fs::File::open(tree_file)?;
            anyhow::ensure!(
                file.metadata()?.is_file() && file.metadata()?.len() == 64 * 1024 * 1024 + 68,
                "fee tree cache size/type mismatch"
            );
            Ok(wallet_pq_signer::fee::FeeTree::read_cache(file, &key)?)
        })
        .await??;
        let view = context.fee().await?;
        let mut journal = FeeJournal::open_proven(&self.journal_dir, &view, now()?)?;
        println!(
            "{}",
            serde_json::json!({"status":"fee_session_open", "scope":"new signatures remain subject to next-slot recovery and fresh proofs"})
        );
        std::io::stdout().flush()?;
        // A dedicated standard thread owns only stdin, never custody or journal.
        // Unlike a Tokio blocking task, an idle stdin read cannot delay runtime
        // shutdown after cancellation. The bounded channel permits one queued line.
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        std::thread::Builder::new().name("fee-session-input".into()).spawn(move || {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            loop {
                let mut line = Vec::new();
                match (&mut input).take(8193).read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if sender.blocking_send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.blocking_send(Err(error));
                        break;
                    }
                }
            }
        })?;
        let mut cancelled = cancellation.subscribe();
        while !cancellation.is_cancelled() {
            let line = tokio::select! {
                biased;
                _ = cancelled.changed() => break,
                next = receiver.recv() => match next { Some(line) => line?, None => break },
            };
            anyhow::ensure!(
                line.len() <= 8192 && line.last() == Some(&b'\n'),
                "fee session requires bounded complete JSON lines"
            );
            let request: Request = serde_json::from_slice(&line)?;
            if matches!(request, Request::Quit) {
                break;
            }
            let result = tokio::select! {
                biased;
                _ = cancelled.changed() => break,
                result = self.process(request, &context, &mut journal, &tree) => result,
            };
            let report = match result {
                Ok(value) => value,
                Err(error) => {
                    serde_json::json!({"status":"request_refused", "reason":error.to_string(), "scope":"preserve journal and any partial output; refusal is not proof of failed delivery"})
                }
            };
            println!("{report}");
            std::io::stdout().flush()?;
        }
        Ok(())
    }

    async fn process(
        &self,
        request: Request,
        context: &InitialContext,
        journal: &mut FeeJournal,
        tree: &wallet_pq_signer::fee::FeeTree,
    ) -> anyhow::Result<serde_json::Value> {
        let view = context.fee().await?;
        match request {
            Request::Status => {
                let plan = journal.preview_proven(&view, now()?)?;
                Ok(
                    serde_json::json!({"status":"leaf_available", "leaf":plan.leaf, "proven_time":view.proven_time(), "scope":"reservation capacity only; not signing or payment readiness"}),
                )
            }
            Request::Retry { intent, output_dir } => {
                let intent = FeeIntent::from_cached_cell(
                    chain_block::read_single_root_boc(bounded_public_file(
                        &intent,
                        4 * 1024 * 1024,
                    )?)?,
                    view.route().epoch0,
                )?;
                let signed = journal.retry_proven_fee(&view, now()?, &intent)?;
                std::fs::create_dir(&output_dir)?;
                put(&output_dir, "pending-intent.boc", &chain_block::write_boc(intent.cell())?)?;
                export(&output_dir, &signed)
            }
            Request::Lock { valid_for_seconds, value_nanotos, output_dir } => {
                anyhow::ensure!((1..=3600).contains(&valid_for_seconds), "fee TTL out of range");
                anyhow::ensure!(
                    !value_nanotos.is_empty() && value_nanotos.bytes().all(|b| b.is_ascii_digit()),
                    "value must be exact decimal nanoTOS"
                );
                let value = value_nanotos.parse::<u128>()?;
                anyhow::ensure!(value > 0, "fee value must be positive");
                journal.preview_proven(&view, now()?)?;
                let proof = context.read(&[]).await?;
                let deadline = now()?
                    .checked_add(valid_for_seconds)
                    .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?;
                proof.view.rescue_request(now()?, deadline, AuthAction::LockPrimary)?;
                std::fs::create_dir(&output_dir)?;
                let rescue = open_vault_file(
                    &self.rescue_vault_file,
                    Some(&self.rescue_vault_key_file),
                    None,
                )
                .await?;
                let id = SecretId::new(&self.rescue_record_id);
                let submission = VaultKey { vault: &rescue, id: &id }
                    .sign_rescue(&proof.view, now, deadline, AuthAction::LockPrimary)
                    .await?;
                drop(rescue);
                let view = context.fee().await?;
                let plan = journal.preview_proven(&view, now()?)?;
                proof.view.rescue_request(now()?, deadline, AuthAction::LockPrimary)?;
                let intent = FeeIntent::new(
                    FeeBinding {
                        vault: view.route().vault,
                        config_hash: *view.config_hash(),
                        epoch0: view.route().epoch0,
                        leaf: plan.leaf,
                        valid_until: deadline,
                        value,
                    },
                    FeePayload::from_submission(FeeClass::RescueAuth, submission.clone())?,
                    view.proven_time(),
                )?;
                // Persist the complete intent before any stateful fee signature.
                put(&output_dir, "pending-intent.boc", &chain_block::write_boc(intent.cell())?)?;
                let fee =
                    open_vault_file(&self.fee_vault_file, Some(&self.fee_vault_key_file), None)
                        .await?;
                let id = SecretId::new(&self.fee_record_id);
                let signed = journal
                    .sign_proven_fee_from_vault_tree(
                        &fee,
                        &id,
                        &view,
                        fee_clock,
                        deadline,
                        value,
                        FeePayload::from_submission(FeeClass::RescueAuth, submission)?,
                        tree,
                    )
                    .await?;
                drop(fee);
                anyhow::ensure!(
                    signed.intent().digest() == intent.digest(),
                    "fee signing changed the persisted intent"
                );
                let signed = journal.retry_proven_fee(&view, now()?, &intent)?;
                export(&output_dir, &signed)
            }
            Request::Quit => anyhow::bail!("session already closing"),
        }
    }
}
