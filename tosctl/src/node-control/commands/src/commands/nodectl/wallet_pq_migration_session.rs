// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Migration composes two process-held journals with exact funded POP receipts.
use super::super::inspect::absolute_path_argument;
use super::super::pop_receipt::{PopHistoryOptions, RetainedPopFiles};
use super::*;
use contracts::{lms_fee_schedule::Continuity, wallet_v5r2_wallet_state::MigrationEvidence};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SuccessorCustody {
    journal_dir: PathBuf,
    fee_tree_cache: PathBuf,
    fee_vault_file: PathBuf,
    fee_record_id: String,
    fee_vault_key_file: PathBuf,
    rescue_vault_file: PathBuf,
    rescue_record_id: String,
    rescue_vault_key_file: PathBuf,
    primary_vault_file: PathBuf,
    primary_record_id: String,
    primary_vault_key_file: PathBuf,
}

pub(super) struct HeldSuccessor {
    pub command: PqFeeSessionInitialCmd,
    pub context: InitialContext,
    pub journal: FeeJournal,
    pub tree: wallet_pq_signer::fee::FeeTree,
    predecessor_epoch: u64,
    predecessor_retired: u16,
}

impl HeldSuccessor {
    pub async fn open(
        current: &PqFeeSessionInitialCmd,
        manifest: PathBuf,
        pin: String,
        custody: SuccessorCustody,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            [&custody.fee_record_id, &custody.rescue_record_id, &custody.primary_record_id]
                .iter()
                .all(|id| !id.trim().is_empty()),
            "successor record IDs must not be empty"
        );
        let context =
            current.proof.context()?.with_successor(current.proof.successor(&manifest, &pin)?);
        let predecessor = context.read(&[]).await?;
        let mut command = current.clone();
        command.successor_manifest = Some(manifest);
        command.expected_template_wallet = Some(pin);
        command.journal_dir = custody.journal_dir;
        command.fee_tree_cache = custody.fee_tree_cache;
        command.fee_vault_file = custody.fee_vault_file;
        command.fee_record_id = custody.fee_record_id;
        command.fee_vault_key_file = custody.fee_vault_key_file;
        command.rescue_vault_file = custody.rescue_vault_file;
        command.rescue_record_id = custody.rescue_record_id;
        command.rescue_vault_key_file = custody.rescue_vault_key_file;
        command.primary_vault_file = Some(custody.primary_vault_file);
        command.primary_record_id = Some(custody.primary_record_id);
        command.primary_vault_key_file = Some(custody.primary_vault_key_file);
        let (tree, journal) = command.open_fee_route(&context).await?;
        Ok(Self {
            command,
            context,
            journal,
            tree,
            predecessor_epoch: predecessor.view.epoch(),
            predecessor_retired: predecessor.view.retired(),
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationInput {
    primary_pop: RetainedPopFiles,
    rescue_pop: RetainedPopFiles,
    history: PopHistoryOptions,
    valid_for_seconds: u32,
    value_nanotos: String,
    output_dir: PathBuf,
}

impl PqFeeSessionInitialCmd {
    /// Promotion changes only local routing. The wallet's authenticated installed
    /// tuple, not a signed request or a relayer's receipt, is the authority gate.
    /// Both journals stay held across all proof/export work and the final swap.
    pub(super) async fn promote(
        &mut self,
        current: &mut InitialContext,
        current_journal: &mut FeeJournal,
        current_tree: &mut wallet_pq_signer::fee::FeeTree,
        attached: &mut Option<HeldSuccessor>,
        retired_journals: &mut Vec<FeeJournal>,
        output_dir: PathBuf,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(self.successor_manifest.is_none(), "promotion requires the current route");
        // Keep retained locks bounded. Restarting preserves each journal's
        // durable reservations and deliberately reinstates its restore barrier.
        require_rotation_capacity(retired_journals.len())?;
        anyhow::ensure!(output_dir.is_absolute(), "promotion output must be an absolute path");
        let held =
            attached.as_ref().ok_or_else(|| anyhow::anyhow!("successor session not attached"))?;
        let manifest = held
            .command
            .successor_manifest
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing successor manifest"))?;
        let pin = held
            .command
            .expected_template_wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing successor template pin"))?;
        let mut command = held.command.clone();
        command.proof = held.command.proof.with_installed(manifest.clone(), pin.clone())?;
        command.successor_manifest = None;
        command.expected_template_wallet = None;
        let context = command.proof.context()?;
        let proposed = held
            .context
            .successor()
            .ok_or_else(|| anyhow::anyhow!("missing attached successor"))?;
        let installed =
            context.installed().ok_or_else(|| anyhow::anyhow!("missing installed successor"))?;
        anyhow::ensure!(
            installed.module_init().repr_hash() == proposed.module_init().repr_hash()
                && installed.metadata().repr_hash() == proposed.metadata().repr_hash()
                && installed.vault_init().repr_hash() == proposed.vault_init().repr_hash(),
            "attached successor enrollment changed"
        );
        // This read invokes bind_successor against the exact wallet/module proof.
        // It must fail while the tuple is merely proposed or partially deployed.
        let proof = context.read(&[]).await?;
        anyhow::ensure!(
            proof.view.epoch() > held.predecessor_epoch
                && proof.view.retired() & held.predecessor_retired == held.predecessor_retired,
            "installed successor regressed epoch or retirement"
        );
        let (vault, fee) = context.fee_at_live_wallet(&proof.wallet).await?;
        // An exhausted or restoring journal still belongs to the installed
        // route. Promotion never creates continuity or authorizes a fee leaf.
        let capacity = match held.journal.preview_proven(&fee, now()?) {
            Ok(plan) => serde_json::json!({"leaf": plan.leaf}),
            Err(error) => serde_json::json!({"unavailable": error.to_string()}),
        };
        let (exported, files) = command.proof.installed_export(&context, &output_dir)?;
        command.proof = exported;
        let checkpoint = &proof.wallet.evidence().checkpoint;
        let report = serde_json::json!({
            "status": "installed_route_promoted",
            "wallet": proof.wallet.evidence().account.address,
            "module": proof.module.evidence().account.address,
            "vault": vault.evidence().account.address,
            "epoch": proof.view.epoch(), "retired": proof.view.retired(),
            "checkpoint": {"seqno": checkpoint.seqno, "root_hash": checkpoint.root_hash,
                "file_hash": checkpoint.file_hash},
            "fee_capacity": capacity,
            "scope": "authenticated installed tuple and retained local journal ownership; no broadcast, current funding/readiness, recipient delivery or remote-device revocation claim"
        });
        let resume = serde_json::json!({
            "schema": "TOS-WALLET-V5R2-INSTALLED-CLI-v1",
            "proof_arguments": command.proof.proof_arguments()?,
            "fee_session_arguments": command.resume_arguments()?,
            "scope": "public enrollment and local custody paths only; preserve encrypted backups and all journals separately; reopening always enforces the restore barrier"
        });
        std::fs::create_dir(&output_dir)?;
        for (name, bytes) in files {
            put(&output_dir, name, &bytes)?;
        }
        put(&output_dir, "resume.json", &serde_json::to_vec_pretty(&resume)?)?;
        put(&output_dir, "installation.json", &serde_json::to_vec_pretty(&report)?)?;
        // Reconstruct the persisted files before any ownership changes. A partial
        // or uncertain export leaves both sessions attached and unchanged.
        let exported_context = command.proof.context()?;
        let exported_installed = exported_context
            .installed()
            .ok_or_else(|| anyhow::anyhow!("missing exported installed successor"))?;
        anyhow::ensure!(
            exported_installed.module_init().repr_hash() == installed.module_init().repr_hash()
                && exported_installed.metadata().repr_hash() == installed.metadata().repr_hash()
                && exported_installed.vault_init().repr_hash()
                    == installed.vault_init().repr_hash(),
            "installed export readback changed route"
        );
        let held =
            attached.take().ok_or_else(|| anyhow::anyhow!("successor session disappeared"))?;
        let previous = std::mem::replace(current_journal, held.journal);
        retired_journals.push(previous);
        *current_tree = held.tree;
        *current = exported_context;
        *self = command;
        Ok(report)
    }

    fn resume_arguments(&self) -> anyhow::Result<Vec<String>> {
        let mut args = self.proof.proof_arguments()?;
        for (name, value) in [
            ("--journal-dir", &self.journal_dir),
            ("--fee-tree-cache", &self.fee_tree_cache),
            ("--fee-vault-file", &self.fee_vault_file),
            ("--fee-vault-key-file", &self.fee_vault_key_file),
            ("--rescue-vault-file", &self.rescue_vault_file),
            ("--rescue-vault-key-file", &self.rescue_vault_key_file),
        ] {
            args.extend([name.into(), absolute_path_argument(value)?]);
        }
        args.extend([
            "--fee-record-id".into(),
            self.fee_record_id.clone(),
            "--rescue-record-id".into(),
            self.rescue_record_id.clone(),
        ]);
        match (&self.primary_vault_file, &self.primary_record_id, &self.primary_vault_key_file) {
            (Some(file), Some(id), Some(key)) => args.extend([
                "--primary-vault-file".into(),
                absolute_path_argument(file)?,
                "--primary-record-id".into(),
                id.clone(),
                "--primary-vault-key-file".into(),
                absolute_path_argument(key)?,
            ]),
            (None, None, None) => (),
            _ => anyhow::bail!("incomplete primary custody"),
        }
        Ok(args)
    }

    pub(super) async fn migrate(
        &self,
        current: &InitialContext,
        current_journal: &mut FeeJournal,
        current_tree: &wallet_pq_signer::fee::FeeTree,
        held: &mut HeldSuccessor,
        input: MigrationInput,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!((1..=3600).contains(&input.valid_for_seconds), "fee TTL out of range");
        // History can grow after attachment. Refuse before any migration fee
        // signature, while the wallet still uses the current enrollment.
        self.proof.require_fee_history_capacity()?;
        let value = decimal_amount(&input.value_nanotos)?;
        let source_fee = current.fee().await?;
        current_journal.preview_proven(&source_fee, now()?)?;
        let successor = held
            .context
            .successor()
            .ok_or_else(|| anyhow::anyhow!("missing successor enrollment"))?;
        let policy = if successor.policy() == RescuePolicy::Ready { &[48][..] } else { &[][..] };
        let proof = current.read(policy).await?;
        let module = held.context.pop_module_at(proof.wallet.evidence().checkpoint.clone()).await?;
        // Bind historical account proof to this same live wallet checkpoint.
        // A second Live selector could observe a later block during acquisition.
        let (vault, fee) = held.context.fee_at_live_wallet(&proof.wallet).await?;
        held.journal.preview_proven(&fee, now()?)?;
        let primary =
            input.primary_pop.verify_at(&held.context, &vault, &module, &input.history).await?;
        let rescue =
            input.rescue_pop.verify_at(&held.context, &vault, &module, &input.history).await?;
        let primary_receipts = primary.receipts();
        let rescue_receipts = rescue.receipts();
        // This value comes only from the journal held by this process. No JSON
        // field or chain counter is accepted as a local continuity assertion.
        held.journal.preview_proven(&fee, now()?)?;
        let continuity = held.journal.observed_continuity(fee.proven_time())?;
        let evidence = MigrationEvidence {
            primary_request: &primary.request,
            primary_receipts: &primary_receipts,
            primary_external: &primary.external,
            rescue_request: &rescue.request,
            rescue_receipts: &rescue_receipts,
            rescue_external: &rescue.external,
            vault: &vault,
            fee_continuity: Continuity::Intact(continuity),
            policy: Some(&proof.wallet),
        };
        let deadline = now()?
            .checked_add(input.valid_for_seconds)
            .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?;
        let request = proof.view.migration_request(now()?, deadline, successor, &evidence)?;
        std::fs::create_dir(&input.output_dir)?;
        put(&input.output_dir, "migration-request.boc", &chain_block::write_boc(request.cell())?)?;
        put(
            &input.output_dir,
            "successor-module-init.boc",
            &chain_block::write_boc(successor.module_init())?,
        )?;
        put(
            &input.output_dir,
            "successor-vault-init.boc",
            &chain_block::write_boc(successor.vault_init())?,
        )?;
        let custody =
            open_vault_file(&self.rescue_vault_file, Some(&self.rescue_vault_key_file), None)
                .await?;
        let id = SecretId::new(&self.rescue_record_id);
        let submission = VaultKey { vault: &custody, id: &id }
            .sign_migration(&proof.view, now, deadline, successor, &evidence)
            .await?;
        drop(custody);
        // Neither journal can service another request during this operation.
        // Recheck local reservations/freshness after the asynchronous secret load.
        held.journal.preview_proven(&fee, now()?)?;
        proof.view.migration_request(now()?, deadline, successor, &evidence)?;
        let source_fee = current.fee().await?;
        let plan = current_journal.preview_proven(&source_fee, now()?)?;
        let payload = FeePayload::from_submission(FeeClass::RescueAuth, submission.clone())?;
        let intent = FeeIntent::new(
            FeeBinding {
                vault: source_fee.route().vault,
                config_hash: *source_fee.config_hash(),
                epoch0: source_fee.route().epoch0,
                leaf: plan.leaf,
                valid_until: deadline,
                value,
            },
            FeePayload::from_submission(FeeClass::RescueAuth, submission)?,
            source_fee.proven_time(),
        )?;
        put(&input.output_dir, "pending-intent.boc", &chain_block::write_boc(intent.cell())?)?;
        let custody =
            open_vault_file(&self.fee_vault_file, Some(&self.fee_vault_key_file), None).await?;
        let id = SecretId::new(&self.fee_record_id);
        // Revalidate migration readiness before consuming the source fee leaf.
        held.journal.preview_proven(&fee, now()?)?;
        proof.view.migration_request(now()?, deadline, successor, &evidence)?;
        let signed = current_journal
            .sign_proven_fee_from_vault_tree(
                &custody,
                &id,
                &source_fee,
                fee_clock,
                deadline,
                value,
                payload,
                current_tree,
            )
            .await?;
        drop(custody);
        anyhow::ensure!(
            signed.intent().digest() == intent.digest(),
            "fee signing changed the persisted intent"
        );
        let signed = current_journal.retry_proven_fee(&source_fee, now()?, &intent)?;
        export(&input.output_dir, &signed)
    }
}
