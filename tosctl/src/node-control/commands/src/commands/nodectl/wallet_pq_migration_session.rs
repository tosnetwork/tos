// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Migration composes two process-held journals with exact funded POP receipts.
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
        Ok(Self { command, context, journal, tree })
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
    pub(super) async fn migrate(
        &self,
        current: &InitialContext,
        current_journal: &mut FeeJournal,
        current_tree: &wallet_pq_signer::fee::FeeTree,
        held: &mut HeldSuccessor,
        input: MigrationInput,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!((1..=3600).contains(&input.valid_for_seconds), "fee TTL out of range");
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
        // A live successor read is required. Historical capacity is insufficient;
        // the SDK also requires this read to match the wallet/receipt checkpoint.
        let (vault, fee) = held.context.fee_snapshot().await?;
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
