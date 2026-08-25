use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

use anyhow::Context;
use chain_block::{
    Coins, Deserializable, Message, MsgAddressInt, base64_decode, base64_encode,
    read_single_root_boc, write_boc,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_account::{
    AGENT_CANCEL_SEQNO_OPCODE, AGENT_NATIVE_SEND_OPCODE, AGENT_TASK_SEND_OPCODE,
};

const SCHEMA: &str = "tos.agent-account.controller-journal.v2";
const JOURNAL_FILE: &str = "controller-actions.json";
const LOCK_FILE: &str = "controller-actions.lock";
const MAX_JOURNAL_BYTES: u64 = 32 << 20;
// Serialized bytes are the authoritative storage bound. This separate count
// prevents a hostile file full of tiny records from making validation
// unbounded without imposing a small global active-action cap across wallets.
const MAX_TOTAL_RECORDS: usize = 4096;
const MAX_RETAINED_RESOLVED_RECORDS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControllerActionStatus {
    Claimed,
    Signed,
    Broadcasting,
    Resolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerActionClaim {
    pub account: String,
    pub network_global_id: i32,
    /// Lowercase 32-byte hex identifier from finalized Agent Account state.
    pub deployment_id: String,
    /// Monotonic controller-key generation from finalized Agent Account state.
    pub controller_epoch: u64,
    pub seqno: u32,
    pub target: String,
    pub value_atomic: u64,
    /// Exact outbound task body. Empty only for bodyless native sends and
    /// cancellations. It is independently verified from the signed BOC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
    pub action_kind: String,
    pub idempotency_key: String,
    pub action_identity: String,
    pub valid_until: u32,
}

/// Exact, Agreement-bound authorization issued by the Owner Economic Action
/// Authority for one custody payment. The Action Authority key is pinned by
/// custody configuration; the key carried here is only an audit commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicActionAuthorization {
    pub schema_version: u16,
    pub authority_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub source_account: String,
    pub network_id: String,
    pub network_global_id: i32,
    pub stable_action_id: String,
    pub exact_request_digest: String,
    pub writer_generation: u64,
    pub writer_fence_digest: String,
    pub policy_revision: u64,
    pub mandate_digest: String,
    pub approval_digest_or_zero: String,
    pub agreement_body_digest: String,
    pub obligation_instance_id: String,
    pub destination: String,
    pub amount_atomic: u64,
    pub expires_at_unix: u64,
    pub public_key: String,
    pub proof: String,
}

/// Generic owner-authorized contract effect. This keeps escrow acceptance and
/// stablecoin funding behind the same writer-generation high-water boundary as
/// Agreement payments without making custody interpret the Agreement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicEffectAuthorization {
    pub schema_version: u16,
    pub authority_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub source_account: String,
    pub network_id: String,
    pub network_global_id: i32,
    pub action_kind: String,
    pub stable_action_id: String,
    pub exact_request_digest: String,
    pub writer_generation: u64,
    pub writer_fence_digest: String,
    pub policy_revision: u64,
    pub mandate_digest: String,
    pub approval_digest_or_zero: String,
    pub agreement_body_digest: String,
    pub obligation_id: String,
    pub destination: String,
    pub amount_nanotos: u64,
    pub body_hash: String,
    pub state_init_hash_or_zero: String,
    pub expires_at_unix: u64,
    pub public_key: String,
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerActionRecord {
    #[serde(flatten)]
    pub claim: ControllerActionClaim,
    pub status: ControllerActionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_signed_boc_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_signed_boc_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_boc_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_authorization: Option<EconomicActionAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_effect_authorization: Option<EconomicEffectAuthorization>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct JournalDocument {
    schema: String,
    #[serde(default)]
    high_water: std::collections::BTreeMap<String, FinalizedHighWater>,
    #[serde(default)]
    economic_authority_high_water: std::collections::BTreeMap<String, EconomicAuthorityHighWater>,
    records: Vec<ControllerActionRecord>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct FinalizedHighWater {
    controller_epoch: u64,
    seqno: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct EconomicAuthorityHighWater {
    authority_id: String,
    public_key: String,
    writer_generation: u64,
    #[serde(default)]
    writer_fence_digest: String,
}

pub struct AgentAccountCustodyJournal {
    directory_fd: File,
}

impl AgentAccountCustodyJournal {
    pub fn open(directory: impl AsRef<Path>) -> anyhow::Result<Self> {
        let directory = directory.as_ref();
        if !directory.is_absolute() {
            anyhow::bail!("Agent Account custody journal path must be absolute");
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!("Agent Account custody journal must be a real directory");
        }
        #[cfg(not(unix))]
        anyhow::bail!("Agent Account custody journal requires Unix openat semantics");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            let directory_fd = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory)?;
            let opened = directory_fd.metadata()?;
            if !opened.is_dir()
                || opened.permissions().mode() & 0o777 != 0o700
                || opened.uid() != unsafe { libc::geteuid() }
                || opened.dev() != metadata.dev()
                || opened.ino() != metadata.ino()
            {
                anyhow::bail!(
                    "Agent Account custody journal directory changed or is not private mode 0700"
                );
            }
            let journal = Self { directory_fd };
            let lock = journal.openat_file(
                LOCK_FILE,
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            validate_private_regular_file(&lock, true, LOCK_FILE)?;
            drop(lock);
            journal.with_document(|_| Ok(()))?;
            Ok(journal)
        }
    }

    pub fn claim_primary(
        &self,
        claim: ControllerActionClaim,
        now: u64,
    ) -> anyhow::Result<(ControllerActionRecord, bool)> {
        validate_claim(&claim)?;
        if now == 0 {
            anyhow::bail!("custody claim requires a Unix time");
        }
        self.with_document(|document| admit_claim(document, claim, None, now))
    }

    /// Admit one direct payment only after independently verifying the exact
    /// Action Authority proof and enforcing its owner/Agent writer generation
    /// at the custody boundary. A stale coordinator cannot regain authority by
    /// replaying an otherwise valid old proof after takeover.
    pub fn claim_economic_payment(
        &self,
        claim: ControllerActionClaim,
        authorization: EconomicActionAuthorization,
        expected_authority_id: &str,
        expected_authority_public_key: [u8; 32],
        now: u64,
    ) -> anyhow::Result<(ControllerActionRecord, bool)> {
        validate_claim(&claim)?;
        validate_economic_authorization(
            &authorization,
            expected_authority_id,
            expected_authority_public_key,
            now,
        )?;
        let idempotency = authorization
            .stable_action_id
            .strip_prefix("sha256:")
            .context("economic action identity has no sha256 prefix")?;
        if claim.action_kind != "agent-native-send"
            || claim.account != authorization.source_account
            || claim.network_global_id != authorization.network_global_id
            || claim.target != authorization.destination
            || claim.value_atomic != authorization.amount_atomic
            || claim.action_identity != authorization.stable_action_id
            || claim.idempotency_key != idempotency
            || u64::from(claim.valid_until) > authorization.expires_at_unix
        {
            anyhow::bail!("custody claim does not match its economic authorization");
        }
        self.with_document(|document| {
            let authority_key = economic_authority_key(&authorization.owner_id, &authorization.agent_id);
            let public_key_text = format!("ed25519:{}", hex::encode(expected_authority_public_key));
            if let Some(high) = document.economic_authority_high_water.get(&authority_key) {
                if high.authority_id != expected_authority_id || high.public_key != public_key_text {
                    anyhow::bail!("custody Action Authority identity changed; explicit owner recovery is required");
                }
                if authorization.writer_generation < high.writer_generation {
                    anyhow::bail!("stale writer generation cannot authorize a custody payment");
                }
                if authorization.writer_generation == high.writer_generation
                    && !high.writer_fence_digest.is_empty()
                    && authorization.writer_fence_digest != high.writer_fence_digest
                {
                    anyhow::bail!("writer generation equivocates between authority fences");
                }
            }
            document.economic_authority_high_water.insert(
                authority_key,
                EconomicAuthorityHighWater {
                    authority_id: expected_authority_id.to_owned(),
                    public_key: public_key_text,
                    writer_generation: authorization.writer_generation,
                    writer_fence_digest: authorization.writer_fence_digest.clone(),
                },
            );
            admit_claim(document, claim, Some(authorization), now)
        })
    }

    /// Admit an exact task-body effect under the same pinned authority and
    /// monotonic writer generation used for payments.
    pub fn claim_economic_effect(
        &self,
        claim: ControllerActionClaim,
        authorization: EconomicEffectAuthorization,
        expected_authority_id: &str,
        expected_authority_public_key: [u8; 32],
        now: u64,
    ) -> anyhow::Result<(ControllerActionRecord, bool)> {
        validate_claim(&claim)?;
        validate_economic_effect_authorization(
            &authorization,
            expected_authority_id,
            expected_authority_public_key,
            now,
        )?;
        let idempotency = authorization
            .stable_action_id
            .strip_prefix("sha256:")
            .context("economic effect identity has no sha256 prefix")?;
        if claim.action_kind != "agent-task-send"
            || claim.account != authorization.source_account
            || claim.network_global_id != authorization.network_global_id
            || claim.target != authorization.destination
            || claim.value_atomic != authorization.amount_nanotos
            || claim.body_hash.as_deref() != Some(authorization.body_hash.as_str())
            || claim.action_identity != authorization.stable_action_id
            || claim.idempotency_key != idempotency
            || u64::from(claim.valid_until) > authorization.expires_at_unix
            || authorization.state_init_hash_or_zero != format!("sha256:{}", "0".repeat(64))
        {
            anyhow::bail!("custody claim does not match its economic effect authorization");
        }
        self.with_document(|document| {
            admit_economic_high_water(
                document,
                &authorization.owner_id,
                &authorization.agent_id,
                &authorization.authority_id,
                &authorization.public_key,
                authorization.writer_generation,
                &authorization.writer_fence_digest,
                expected_authority_id,
                expected_authority_public_key,
            )?;
            let generation = generation_key(&claim);
            if let Some(target) = document.records.iter_mut().find(|record| {
                generation_key(&record.claim) == generation
                    && record.claim.idempotency_key == claim.idempotency_key
            }) {
                if target.claim == claim
                    && target.economic_effect_authorization.as_ref() == Some(&authorization)
                {
                    return Ok((target.clone(), false));
                }
                if target.economic_effect_authorization.as_ref() == Some(&authorization)
                    && same_unsigned_claim(&target.claim, &claim)
                {
                    return Ok((target.clone(), false));
                }
                let same_effect_takeover = target.status != ControllerActionStatus::Broadcasting
                    && target.status != ControllerActionStatus::Resolved
                    && target.cancellation_identity.is_none()
                    && target.cancellation_boc_base64.is_none()
                    && target.economic_authorization.is_none()
                    && target.economic_effect_authorization.as_ref().is_some_and(|prior| {
                        authorization.writer_generation > prior.writer_generation
                            && same_economic_effect(prior, &authorization)
                    })
                    && same_unsigned_claim(&target.claim, &claim);
                if !same_effect_takeover {
                    anyhow::bail!("changed economic effect conflicts with custody journal");
                }
                if target.status == ControllerActionStatus::Claimed {
                    if target.exact_signed_boc_base64.is_some()
                        || target.exact_signed_boc_digest.is_some()
                    {
                        anyhow::bail!("unsigned custody action contains signed bytes");
                    }
                    target.claim = claim;
                } else if target.status != ControllerActionStatus::Signed
                    || target.exact_signed_boc_base64.is_none()
                    || target.exact_signed_boc_digest.is_none()
                {
                    anyhow::bail!("economic effect cannot be taken over in its current state");
                }
                target.economic_effect_authorization = Some(authorization);
                target.updated_at_unix = now;
                return Ok((target.clone(), false));
            }
            let (record, created) = admit_claim(document, claim, None, now)?;
            let target = document
                .records
                .iter_mut()
                .find(|candidate| candidate.claim == record.claim)
                .context("new economic effect custody record disappeared")?;
            if let Some(existing) = &target.economic_effect_authorization {
                if existing != &authorization {
                    anyhow::bail!("changed economic effect conflicts with custody journal");
                }
            } else if target.economic_authorization.is_some() {
                anyhow::bail!("custody action is already a payment");
            } else {
                target.economic_effect_authorization = Some(authorization);
            }
            Ok((target.clone(), created))
        })
    }

    pub fn find_primary(
        &self,
        account: &str,
        network_global_id: i32,
        deployment_id: &str,
        controller_epoch: u64,
        idempotency_key: &str,
    ) -> anyhow::Result<Option<ControllerActionRecord>> {
        validate_generation(account, network_global_id, deployment_id)?;
        if !valid_idempotency_key(idempotency_key) {
            anyhow::bail!("invalid controller action lookup");
        }
        let generation = generation_key_parts(account, network_global_id, deployment_id);
        self.with_document(|document| {
            Ok(document
                .records
                .iter()
                .find(|record| {
                    generation_key(&record.claim) == generation
                        && record.claim.controller_epoch == controller_epoch
                        && record.claim.idempotency_key == idempotency_key
                })
                .cloned())
        })
    }

    pub fn attach_signed_boc(
        &self,
        claim: &ControllerActionClaim,
        boc_base64: &str,
        digest: &str,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        if boc_base64.is_empty() || boc_base64.len() > 128 << 10 || !valid_digest(digest) {
            anyhow::bail!("invalid exact signed BOC record");
        }
        validate_signed_boc(claim, boc_base64, Some(digest), ExpectedAction::Primary)?;
        self.mutate_exact(claim, |record| {
            if let Some(existing) = &record.exact_signed_boc_digest {
                if existing != digest
                    || record.exact_signed_boc_base64.as_deref() != Some(boc_base64)
                {
                    anyhow::bail!("changed signed BOC conflicts with custody journal");
                }
                return Ok(());
            }
            if record.status != ControllerActionStatus::Claimed {
                anyhow::bail!("custody record is not awaiting a signature");
            }
            record.exact_signed_boc_base64 = Some(boc_base64.to_owned());
            record.exact_signed_boc_digest = Some(digest.to_owned());
            record.status = ControllerActionStatus::Signed;
            record.updated_at_unix = now;
            Ok(())
        })
    }

    pub fn authorize_cancellation(
        &self,
        claim: &ControllerActionClaim,
        cancellation_identity: &str,
        cancellation_boc_base64: &str,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        if !valid_digest(cancellation_identity)
            || cancellation_boc_base64.is_empty()
            || cancellation_boc_base64.len() > 128 << 10
        {
            anyhow::bail!("invalid owner-authorized cancellation");
        }
        validate_signed_boc(claim, cancellation_boc_base64, None, ExpectedAction::Cancellation)?;
        self.mutate_exact(claim, |record| {
            if let Some(existing) = &record.cancellation_identity {
                if existing != cancellation_identity
                    || record.cancellation_boc_base64.as_deref() != Some(cancellation_boc_base64)
                {
                    anyhow::bail!("only one exact cancellation may race a primary action");
                }
                return Ok(());
            }
            if record.status == ControllerActionStatus::Resolved {
                anyhow::bail!("resolved action cannot be cancelled");
            }
            record.cancellation_identity = Some(cancellation_identity.to_owned());
            record.cancellation_boc_base64 = Some(cancellation_boc_base64.to_owned());
            record.updated_at_unix = now;
            Ok(())
        })
    }

    pub fn begin_broadcast(
        &self,
        claim: &ControllerActionClaim,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        self.mutate_exact(claim, |record| {
            if record.status == ControllerActionStatus::Broadcasting {
                anyhow::bail!("ambiguous broadcast must be resolved from finalized state");
            }
            if record.status != ControllerActionStatus::Signed {
                anyhow::bail!("only a durable signed action may be broadcast");
            }
            record.status = ControllerActionStatus::Broadcasting;
            record.updated_at_unix = now;
            Ok(())
        })
    }

    pub fn reconcile_finalized_state(
        &self,
        account: &str,
        network_global_id: i32,
        deployment_id: &str,
        controller_epoch: u64,
        finalized_seqno: u32,
        now: u64,
    ) -> anyhow::Result<()> {
        validate_generation(account, network_global_id, deployment_id)?;
        let generation = generation_key_parts(account, network_global_id, deployment_id);
        self.with_document(|document| {
            if document.records.iter().any(|record| {
                record.claim.account == account
                    && record.claim.network_global_id == network_global_id
                    && generation_key(&record.claim) != generation
                    && record.status != ControllerActionStatus::Resolved
            }) {
                anyhow::bail!(
                    "Agent Account deployment/network generation changed; explicit owner recovery is required"
                );
            }
            if let Some(high) = document.high_water.get(&generation) {
                if (controller_epoch, finalized_seqno) < (high.controller_epoch, high.seqno) {
                    anyhow::bail!(
                        "Agent Account finalized controller epoch/seqno rolled back; refusing replay"
                    );
                }
            }
            document.high_water.insert(
                generation.clone(),
                FinalizedHighWater { controller_epoch, seqno: finalized_seqno },
            );
            for record in &mut document.records {
                if generation_key(&record.claim) == generation
                    && record.status != ControllerActionStatus::Resolved
                    && (controller_epoch, finalized_seqno)
                        > (record.claim.controller_epoch, record.claim.seqno)
                {
                    record.status = ControllerActionStatus::Resolved;
                    record.exact_signed_boc_base64 = None;
                    record.cancellation_boc_base64 = None;
                    record.updated_at_unix = now;
                }
            }
            compact_records(document);
            Ok(())
        })
    }

    /// Retire an inactive, non-frozen deployment generation during the
    /// explicit owner replacement flow. The caller proves that chain state
    /// before invoking this method; the durable high-water entry is retained
    /// so an identical-StateInit rollback still fails closed.
    pub fn retire_generation(
        &self,
        account: &str,
        network_global_id: i32,
        deployment_id: &str,
        now: u64,
    ) -> anyhow::Result<()> {
        validate_generation(account, network_global_id, deployment_id)?;
        let generation = generation_key_parts(account, network_global_id, deployment_id);
        self.with_document(|document| {
            if document.records.iter().any(|record| {
                generation_key(&record.claim) == generation
                    && record.status != ControllerActionStatus::Resolved
                    && now < u64::from(record.claim.valid_until)
            }) {
                anyhow::bail!(
                    "cannot retire Agent Account generation while a controller signature is still valid"
                );
            }
            for record in &mut document.records {
                if generation_key(&record.claim) == generation
                    && record.status != ControllerActionStatus::Resolved
                {
                    record.status = ControllerActionStatus::Resolved;
                    record.exact_signed_boc_base64 = None;
                    record.cancellation_boc_base64 = None;
                    record.updated_at_unix = now;
                }
            }
            compact_records(document);
            Ok(())
        })
    }

    fn mutate_exact(
        &self,
        claim: &ControllerActionClaim,
        change: impl FnOnce(&mut ControllerActionRecord) -> anyhow::Result<()>,
    ) -> anyhow::Result<ControllerActionRecord> {
        self.with_document(|document| {
            let record = document
                .records
                .iter_mut()
                .find(|record| record.claim == *claim)
                .context("controller action claim not found")?;
            change(record)?;
            Ok(record.clone())
        })
    }

    fn with_document<T>(
        &self,
        operation: impl FnOnce(&mut JournalDocument) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let lock = self.openat_file(
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        validate_private_regular_file(&lock, true, LOCK_FILE)?;
        lock.lock_exclusive()?;
        let mut document = match self.openat_file(
            JOURNAL_FILE,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => {
                validate_private_regular_file(&file, false, JOURNAL_FILE)?;
                let metadata = file.metadata()?;
                if metadata.len() == 0 || metadata.len() > MAX_JOURNAL_BYTES {
                    anyhow::bail!("invalid Agent Account custody journal file");
                }
                let mut raw = Vec::with_capacity(metadata.len() as usize);
                file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut raw)?;
                let parsed: JournalDocument =
                    serde_json::from_slice(&raw).context("decode Agent Account custody journal")?;
                if parsed.schema != SCHEMA {
                    anyhow::bail!("unknown Agent Account custody journal schema");
                }
                validate_document(&parsed)?;
                parsed
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                JournalDocument { schema: SCHEMA.to_owned(), ..Default::default() }
            }
            Err(error) => return Err(error.into()),
        };
        let original = document.clone();
        let result = operation(&mut document)?;
        if document != original {
            self.persist(&document)?;
        }
        FileExt::unlock(&lock)?;
        Ok(result)
    }

    fn persist(&self, document: &JournalDocument) -> anyhow::Result<()> {
        let raw = serde_json::to_vec(document)?;
        if raw.len() as u64 > MAX_JOURNAL_BYTES {
            anyhow::bail!("Agent Account custody journal exceeds size limit");
        }
        let temporary = format!(
            ".controller-actions.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        );
        let mut file = self.openat_file(
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        let write_result = file.write_all(&raw).and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = write_result {
            let temporary_c = c_filename(&temporary)?;
            // SAFETY: validated directory descriptor and NUL-free filename.
            unsafe {
                libc::unlinkat(self.directory_fd.as_raw_fd(), temporary_c.as_ptr(), 0);
            }
            return Err(error.into());
        }
        let temporary_c = c_filename(&temporary)?;
        let journal_c = c_filename(JOURNAL_FILE)?;
        // SAFETY: both names are validated, NUL-free C strings and both
        // directory descriptors remain open for the duration of renameat.
        let renamed = unsafe {
            libc::renameat(
                self.directory_fd.as_raw_fd(),
                temporary_c.as_ptr(),
                self.directory_fd.as_raw_fd(),
                journal_c.as_ptr(),
            )
        };
        if renamed != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: same validated directory/name pair as above. Best effort.
            unsafe {
                libc::unlinkat(self.directory_fd.as_raw_fd(), temporary_c.as_ptr(), 0);
            }
            return Err(error.into());
        }
        self.directory_fd.sync_all()?;
        Ok(())
    }

    fn openat_file(&self, name: &str, flags: i32, mode: libc::mode_t) -> std::io::Result<File> {
        let name = c_filename(name).map_err(std::io::Error::other)?;
        // SAFETY: `name` is NUL-terminated and the returned owned descriptor is
        // converted to `File` exactly once.
        let fd = unsafe {
            libc::openat(
                self.directory_fd.as_raw_fd(),
                name.as_ptr(),
                flags,
                libc::c_uint::from(mode),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned file descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn same_unsigned_claim(left: &ControllerActionClaim, right: &ControllerActionClaim) -> bool {
    left.account == right.account
        && left.network_global_id == right.network_global_id
        && left.deployment_id == right.deployment_id
        && left.controller_epoch == right.controller_epoch
        && left.seqno == right.seqno
        && left.target == right.target
        && left.value_atomic == right.value_atomic
        && left.body_hash == right.body_hash
        && left.action_kind == right.action_kind
        && left.idempotency_key == right.idempotency_key
        && left.action_identity == right.action_identity
}

fn same_economic_effect(
    left: &EconomicEffectAuthorization,
    right: &EconomicEffectAuthorization,
) -> bool {
    left.schema_version == right.schema_version
        && left.authority_id == right.authority_id
        && left.owner_id == right.owner_id
        && left.agent_id == right.agent_id
        && left.source_account == right.source_account
        && left.network_id == right.network_id
        && left.network_global_id == right.network_global_id
        && left.action_kind == right.action_kind
        && left.stable_action_id == right.stable_action_id
        && left.exact_request_digest == right.exact_request_digest
        && left.agreement_body_digest == right.agreement_body_digest
        && left.obligation_id == right.obligation_id
        && left.destination == right.destination
        && left.amount_nanotos == right.amount_nanotos
        && left.body_hash == right.body_hash
        && left.state_init_hash_or_zero == right.state_init_hash_or_zero
        && left.public_key == right.public_key
}

fn validate_claim(claim: &ControllerActionClaim) -> anyhow::Result<()> {
    validate_generation(&claim.account, claim.network_global_id, &claim.deployment_id)?;
    if claim.network_global_id == 0
        || claim.action_kind.is_empty()
        || claim.action_kind.len() > 64
        || !valid_idempotency_key(&claim.idempotency_key)
        || !valid_digest(&claim.action_identity)
        || claim.target.is_empty()
        || claim.target.len() > 128
        || claim.value_atomic == 0
        || claim.valid_until == 0
        || claim.body_hash.as_ref().is_some_and(|value| !valid_cell_digest(value))
        || (claim.action_kind == "agent-native-send" && claim.body_hash.is_some())
        || (claim.action_kind == "agent-task-send" && claim.body_hash.is_none())
    {
        anyhow::bail!("invalid controller action claim");
    }
    Ok(())
}

fn admit_claim(
    document: &mut JournalDocument,
    claim: ControllerActionClaim,
    economic_authorization: Option<EconomicActionAuthorization>,
    now: u64,
) -> anyhow::Result<(ControllerActionRecord, bool)> {
    let generation = generation_key(&claim);
    if document.records.iter().any(|record| {
        record.claim.account == claim.account
            && record.claim.network_global_id == claim.network_global_id
            && generation_key(&record.claim) != generation
            && record.status != ControllerActionStatus::Resolved
    }) {
        anyhow::bail!(
            "Agent Account deployment/network generation changed; explicit owner recovery is required"
        );
    }
    if let Some(high) = document.high_water.get(&generation)
        && (claim.controller_epoch, claim.seqno) < (high.controller_epoch, high.seqno)
    {
        anyhow::bail!(
            "Agent Account controller epoch/seqno rollback requires explicit owner recovery"
        );
    }
    if let Some(record) = document.records.iter().find(|record| {
        generation_key(&record.claim) == generation
            && record.claim.idempotency_key == claim.idempotency_key
    }) {
        if record.claim != claim || record.economic_authorization != economic_authorization {
            anyhow::bail!("controller action identity was reused with different semantics");
        }
        return Ok((record.clone(), false));
    }
    for record in &document.records {
        if generation_key(&record.claim) != generation
            || record.status == ControllerActionStatus::Resolved
        {
            continue;
        }
        if record.claim == claim && record.economic_authorization == economic_authorization {
            return Ok((record.clone(), false));
        }
        anyhow::bail!("another primary controller action already owns this Agent Account sequence");
    }
    if document.records.len() >= MAX_TOTAL_RECORDS {
        anyhow::bail!("Agent Account custody journal has too many records");
    }
    document.high_water.entry(generation).or_insert(FinalizedHighWater {
        controller_epoch: claim.controller_epoch,
        seqno: claim.seqno,
    });
    let record = ControllerActionRecord {
        claim,
        status: ControllerActionStatus::Claimed,
        exact_signed_boc_base64: None,
        exact_signed_boc_digest: None,
        cancellation_identity: None,
        cancellation_boc_base64: None,
        economic_authorization,
        economic_effect_authorization: None,
        created_at_unix: now,
        updated_at_unix: now,
    };
    document.records.push(record.clone());
    compact_records(document);
    Ok((record, true))
}

fn admit_economic_high_water(
    document: &mut JournalDocument,
    owner_id: &str,
    agent_id: &str,
    authority_id: &str,
    public_key: &str,
    writer_generation: u64,
    writer_fence_digest: &str,
    expected_authority_id: &str,
    expected_public_key: [u8; 32],
) -> anyhow::Result<()> {
    let authority_key = economic_authority_key(owner_id, agent_id);
    let expected_key = format!("ed25519:{}", hex::encode(expected_public_key));
    if authority_id != expected_authority_id || public_key != expected_key {
        anyhow::bail!("economic action is not issued by the pinned authority");
    }
    if let Some(high) = document.economic_authority_high_water.get(&authority_key) {
        if high.authority_id != expected_authority_id || high.public_key != expected_key {
            anyhow::bail!(
                "custody Action Authority identity changed; explicit owner recovery is required"
            );
        }
        if writer_generation < high.writer_generation {
            anyhow::bail!("stale writer generation cannot authorize a custody effect");
        }
        if writer_generation == high.writer_generation
            && !high.writer_fence_digest.is_empty()
            && writer_fence_digest != high.writer_fence_digest
        {
            anyhow::bail!("writer generation equivocates between authority fences");
        }
    }
    document.economic_authority_high_water.insert(
        authority_key,
        EconomicAuthorityHighWater {
            authority_id: expected_authority_id.to_owned(),
            public_key: expected_key,
            writer_generation,
            writer_fence_digest: writer_fence_digest.to_owned(),
        },
    );
    Ok(())
}

fn validate_economic_authorization(
    authorization: &EconomicActionAuthorization,
    expected_authority_id: &str,
    expected_public_key: [u8; 32],
    now: u64,
) -> anyhow::Result<()> {
    if authorization.authority_id != expected_authority_id
        || authorization.public_key != format!("ed25519:{}", hex::encode(expected_public_key))
        || now == 0
        || now >= authorization.expires_at_unix
    {
        anyhow::bail!("economic authorization is expired or not issued by the pinned authority");
    }
    let preimage = economic_authorization_preimage(authorization)?;
    let digest = Sha256::digest(preimage);
    let proof_hex = authorization
        .proof
        .strip_prefix("ed25519:")
        .context("economic authorization proof has no Ed25519 prefix")?;
    let proof_bytes = hex::decode(proof_hex).context("decode economic authorization proof")?;
    let signature = Signature::from_slice(&proof_bytes)
        .context("economic authorization proof must be 64 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(&expected_public_key)
        .context("invalid pinned economic authority public key")?;
    verifying_key
        .verify(digest.as_slice(), &signature)
        .context("economic authorization proof is invalid")?;
    Ok(())
}

fn economic_authorization_preimage(
    authorization: &EconomicActionAuthorization,
) -> anyhow::Result<Vec<u8>> {
    let digests = [
        &authorization.stable_action_id,
        &authorization.exact_request_digest,
        &authorization.writer_fence_digest,
        &authorization.mandate_digest,
        &authorization.approval_digest_or_zero,
        &authorization.agreement_body_digest,
        &authorization.obligation_instance_id,
    ];
    if authorization.schema_version != 1
        || authorization.authority_id.is_empty()
        || authorization.authority_id.len() > 256
        || authorization.owner_id.is_empty()
        || authorization.owner_id.len() > 256
        || authorization.agent_id.is_empty()
        || authorization.agent_id.len() > 256
        || authorization.source_account.is_empty()
        || authorization.source_account.len() > 256
        || authorization.network_id.is_empty()
        || authorization.network_id.len() > 128
        || authorization.network_global_id == 0
        || authorization.writer_generation == 0
        || authorization.policy_revision == 0
        || authorization.destination.is_empty()
        || authorization.destination.len() > 256
        || authorization.amount_atomic == 0
        || authorization.expires_at_unix == 0
        || digests.iter().any(|value| !valid_digest(value))
    {
        anyhow::bail!("economic authorization body is invalid");
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"TOS-EAA\0");
    output.extend_from_slice(&authorization.schema_version.to_be_bytes());
    for value in [
        &authorization.authority_id,
        &authorization.owner_id,
        &authorization.agent_id,
        &authorization.source_account,
        &authorization.network_id,
    ] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.network_global_id.to_be_bytes());
    for value in [&authorization.stable_action_id, &authorization.exact_request_digest] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.writer_generation.to_be_bytes());
    write_lp32(&mut output, authorization.writer_fence_digest.as_bytes())?;
    output.extend_from_slice(&authorization.policy_revision.to_be_bytes());
    for value in [
        &authorization.mandate_digest,
        &authorization.approval_digest_or_zero,
        &authorization.agreement_body_digest,
        &authorization.obligation_instance_id,
        &authorization.destination,
    ] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.amount_atomic.to_be_bytes());
    output.extend_from_slice(&authorization.expires_at_unix.to_be_bytes());
    Ok(output)
}

fn validate_economic_effect_authorization(
    authorization: &EconomicEffectAuthorization,
    expected_authority_id: &str,
    expected_public_key: [u8; 32],
    now: u64,
) -> anyhow::Result<()> {
    if authorization.authority_id != expected_authority_id
        || authorization.public_key != format!("ed25519:{}", hex::encode(expected_public_key))
        || now == 0
        || now >= authorization.expires_at_unix
    {
        anyhow::bail!("economic effect is expired or not issued by the pinned authority");
    }
    let preimage = economic_effect_authorization_preimage(authorization)?;
    let digest = Sha256::digest(preimage);
    let proof_hex = authorization
        .proof
        .strip_prefix("ed25519:")
        .context("economic effect proof has no Ed25519 prefix")?;
    let signature =
        Signature::from_slice(&hex::decode(proof_hex).context("decode economic effect proof")?)
            .context("economic effect proof must be 64 bytes")?;
    VerifyingKey::from_bytes(&expected_public_key)
        .context("invalid pinned economic authority public key")?
        .verify(digest.as_slice(), &signature)
        .context("economic effect authorization proof is invalid")?;
    Ok(())
}

fn economic_effect_authorization_preimage(
    authorization: &EconomicEffectAuthorization,
) -> anyhow::Result<Vec<u8>> {
    let digests = [
        &authorization.stable_action_id,
        &authorization.exact_request_digest,
        &authorization.writer_fence_digest,
        &authorization.mandate_digest,
        &authorization.approval_digest_or_zero,
        &authorization.agreement_body_digest,
    ];
    let no_state_init = format!("sha256:{}", "0".repeat(64));
    if authorization.schema_version != 1
        || authorization.authority_id.is_empty()
        || authorization.authority_id.len() > 256
        || authorization.owner_id.is_empty()
        || authorization.owner_id.len() > 256
        || authorization.agent_id.is_empty()
        || authorization.agent_id.len() > 256
        || authorization.source_account.is_empty()
        || authorization.source_account.len() > 256
        || authorization.network_id.is_empty()
        || authorization.network_id.len() > 128
        || authorization.network_global_id == 0
        || !valid_lower_token(&authorization.action_kind)
        || authorization.writer_generation == 0
        || authorization.policy_revision == 0
        || authorization.obligation_id.is_empty()
        || authorization.obligation_id.len() > 256
        || authorization.destination.is_empty()
        || authorization.destination.len() > 256
        || authorization.amount_nanotos == 0
        || !valid_cell_digest(&authorization.body_hash)
        || !(valid_cell_digest(&authorization.state_init_hash_or_zero)
            || authorization.state_init_hash_or_zero == no_state_init)
        || authorization.expires_at_unix == 0
        || digests.iter().any(|value| !valid_digest(value))
    {
        anyhow::bail!("economic effect authorization body is invalid");
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"TOS-CEA\0");
    output.extend_from_slice(&authorization.schema_version.to_be_bytes());
    for value in [
        &authorization.authority_id,
        &authorization.owner_id,
        &authorization.agent_id,
        &authorization.source_account,
        &authorization.network_id,
    ] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.network_global_id.to_be_bytes());
    for value in [
        &authorization.action_kind,
        &authorization.stable_action_id,
        &authorization.exact_request_digest,
    ] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.writer_generation.to_be_bytes());
    write_lp32(&mut output, authorization.writer_fence_digest.as_bytes())?;
    output.extend_from_slice(&authorization.policy_revision.to_be_bytes());
    for value in [
        &authorization.mandate_digest,
        &authorization.approval_digest_or_zero,
        &authorization.agreement_body_digest,
        &authorization.obligation_id,
        &authorization.destination,
    ] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.amount_nanotos.to_be_bytes());
    for value in [&authorization.body_hash, &authorization.state_init_hash_or_zero] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    output.extend_from_slice(&authorization.expires_at_unix.to_be_bytes());
    Ok(output)
}

fn write_lp32(output: &mut Vec<u8>, value: &[u8]) -> anyhow::Result<()> {
    let length = u32::try_from(value.len()).context("economic authorization field is too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn economic_authority_key(owner_id: &str, agent_id: &str) -> String {
    format!("{}:{owner_id}:{}:{agent_id}", owner_id.len(), agent_id.len())
}

fn validate_generation(
    account: &str,
    network_global_id: i32,
    deployment_id: &str,
) -> anyhow::Result<()> {
    if account.is_empty()
        || account.len() > 128
        || network_global_id == 0
        || deployment_id.len() != 64
        || !deployment_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        anyhow::bail!("invalid Agent Account deployment generation");
    }
    Ok(())
}

fn generation_key(claim: &ControllerActionClaim) -> String {
    generation_key_parts(&claim.account, claim.network_global_id, &claim.deployment_id)
}

fn generation_key_parts(account: &str, network_global_id: i32, deployment_id: &str) -> String {
    format!("{network_global_id}:{}:{account}:{deployment_id}", account.len())
}

fn compact_records(document: &mut JournalDocument) {
    let mut active = Vec::new();
    let mut resolved = Vec::new();
    for mut record in document.records.drain(..) {
        if record.status == ControllerActionStatus::Resolved {
            // Terminal records retain identities and timestamps, not replayable
            // signatures. The generation high-water mark preserves rollback
            // protection after old terminal records are pruned.
            record.exact_signed_boc_base64 = None;
            record.cancellation_boc_base64 = None;
            resolved.push(record);
        } else {
            active.push(record);
        }
    }
    resolved.sort_by_key(|record| record.updated_at_unix);
    let keep_from = resolved.len().saturating_sub(MAX_RETAINED_RESOLVED_RECORDS);
    document.records.extend(resolved.drain(keep_from..));
    document.records.extend(active);
}

#[derive(Clone, Copy)]
enum ExpectedAction {
    Primary,
    Cancellation,
}

fn validate_signed_boc(
    claim: &ControllerActionClaim,
    encoded: &str,
    expected_digest: Option<&str>,
    expected_action: ExpectedAction,
) -> anyhow::Result<()> {
    let bytes = base64_decode(encoded).context("decode signed Agent Account BOC")?;
    if bytes.len() > 96 << 10 {
        anyhow::bail!("signed Agent Account BOC exceeds decoded size limit");
    }
    if base64_encode(bytes.clone()) != encoded {
        anyhow::bail!("signed Agent Account BOC uses non-canonical base64");
    }
    if let Some(expected) = expected_digest {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if actual != expected {
            anyhow::bail!("signed Agent Account BOC digest mismatch");
        }
    }
    let root = read_single_root_boc(bytes.clone()).context("parse signed Agent Account BOC")?;
    if write_boc(&root)? != bytes {
        anyhow::bail!("signed Agent Account BOC uses non-canonical serialization");
    }
    let message =
        Message::construct_from_cell(root).context("parse external Agent Account message")?;
    let header = message
        .ext_in_header()
        .context("stored Agent Account BOC is not an external inbound message")?;
    if header.dst.to_string() != claim.account {
        anyhow::bail!("stored Agent Account BOC destination does not match custody claim");
    }
    let mut body = message.body().cloned().context("stored Agent Account BOC has no body")?;
    body.move_by(512).context("stored Agent Account BOC has a truncated signature")?;
    let opcode = body.get_next_u32()?;
    let expected_opcode = match expected_action {
        ExpectedAction::Cancellation => AGENT_CANCEL_SEQNO_OPCODE,
        ExpectedAction::Primary if claim.action_kind == "agent-task-send" => AGENT_TASK_SEND_OPCODE,
        ExpectedAction::Primary if claim.action_kind == "agent-native-send" => {
            AGENT_NATIVE_SEND_OPCODE
        }
        ExpectedAction::Primary => anyhow::bail!("unsupported controller action kind"),
    };
    if opcode != expected_opcode
        || body.get_next_i32()? != claim.network_global_id
        || body.get_next_u64()? != claim.controller_epoch
        || body.get_next_u32()? != claim.seqno
        || body.get_next_u32()? != claim.valid_until
    {
        anyhow::bail!("stored Agent Account BOC does not match custody claim");
    }
    if matches!(expected_action, ExpectedAction::Primary) {
        let target = MsgAddressInt::construct_from(&mut body)
            .context("stored Agent Account BOC has an invalid target")?;
        let value = Coins::construct_from(&mut body)
            .context("stored Agent Account BOC has an invalid value")?
            .as_u128();
        if target.to_string() != claim.target || value != u128::from(claim.value_atomic) {
            anyhow::bail!("stored Agent Account BOC target/value does not match custody claim");
        }
        let expected_refs = usize::from(claim.action_kind == "agent-task-send");
        if body.remaining_bits() != 0 || body.remaining_references() != expected_refs {
            anyhow::bail!("stored Agent Account BOC has unexpected trailing action data");
        }
        if claim.action_kind == "agent-task-send" {
            let task_body = body.checked_drain_reference()?;
            let actual = format!("tvm-cell-sha256:{}", hex::encode(task_body.hash(0)));
            if claim.body_hash.as_deref() != Some(actual.as_str()) {
                anyhow::bail!("stored Agent Account task body differs from custody claim");
            }
        }
    } else if body.remaining_bits() != 0 || body.remaining_references() != 0 {
        anyhow::bail!("stored Agent Account cancellation BOC has unexpected trailing data");
    }
    Ok(())
}

fn validate_document(document: &JournalDocument) -> anyhow::Result<()> {
    if document.records.len() > MAX_TOTAL_RECORDS {
        anyhow::bail!("Agent Account custody journal contains too many records");
    }
    for record in &document.records {
        validate_claim(&record.claim)?;
        if let Some(authorization) = &record.economic_authorization {
            let authority_key =
                economic_authority_key(&authorization.owner_id, &authorization.agent_id);
            let high = document
                .economic_authority_high_water
                .get(&authority_key)
                .context("economic action has no durable authority high-water record")?;
            let encoded_key = high
                .public_key
                .strip_prefix("ed25519:")
                .context("stored economic authority key has no Ed25519 prefix")?;
            let key: [u8; 32] = hex::decode(encoded_key)
                .context("decode stored economic authority key")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored economic authority key must be 32 bytes"))?;
            validate_economic_authorization(
                authorization,
                &high.authority_id,
                key,
                record.created_at_unix,
            )?;
            if authorization.writer_generation > high.writer_generation
                || (record.status != ControllerActionStatus::Resolved
                    && authorization.writer_generation == high.writer_generation
                    && !high.writer_fence_digest.is_empty()
                    && authorization.writer_fence_digest != high.writer_fence_digest)
                || record.claim.account != authorization.source_account
                || record.claim.network_global_id != authorization.network_global_id
                || record.claim.target != authorization.destination
                || record.claim.value_atomic != authorization.amount_atomic
                || record.claim.action_identity != authorization.stable_action_id
            {
                anyhow::bail!("economic action does not match durable authority state");
            }
        }
        if let Some(authorization) = &record.economic_effect_authorization {
            if record.economic_authorization.is_some() {
                anyhow::bail!("custody record cannot be both payment and generic effect");
            }
            let authority_key =
                economic_authority_key(&authorization.owner_id, &authorization.agent_id);
            let high = document
                .economic_authority_high_water
                .get(&authority_key)
                .context("economic effect has no durable authority high-water record")?;
            let key: [u8; 32] = hex::decode(
                high.public_key
                    .strip_prefix("ed25519:")
                    .context("stored authority key is malformed")?,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored authority key must be 32 bytes"))?;
            validate_economic_effect_authorization(
                authorization,
                &high.authority_id,
                key,
                record.created_at_unix,
            )?;
            if authorization.writer_generation > high.writer_generation
                || (record.status != ControllerActionStatus::Resolved
                    && authorization.writer_generation == high.writer_generation
                    && !high.writer_fence_digest.is_empty()
                    && authorization.writer_fence_digest != high.writer_fence_digest)
                || record.claim.account != authorization.source_account
                || record.claim.network_global_id != authorization.network_global_id
                || record.claim.target != authorization.destination
                || record.claim.value_atomic != authorization.amount_nanotos
                || record.claim.body_hash.as_deref() != Some(authorization.body_hash.as_str())
                || record.claim.action_identity != authorization.stable_action_id
            {
                anyhow::bail!("economic effect does not match durable authority state");
            }
        }
        match (&record.exact_signed_boc_base64, &record.exact_signed_boc_digest) {
            (Some(boc), Some(digest)) => {
                validate_signed_boc(&record.claim, boc, Some(digest), ExpectedAction::Primary)?;
            }
            (None, None)
                if record.status == ControllerActionStatus::Claimed
                    || record.status == ControllerActionStatus::Resolved => {}
            (None, Some(_)) if record.status == ControllerActionStatus::Resolved => {}
            _ => anyhow::bail!("incomplete signed BOC fields in Agent Account custody journal"),
        }
        if let Some(boc) = &record.cancellation_boc_base64 {
            if record.cancellation_identity.is_none() {
                anyhow::bail!("cancellation BOC is missing its authorization identity");
            }
            validate_signed_boc(&record.claim, boc, None, ExpectedAction::Cancellation)?;
        } else if record.cancellation_identity.is_some()
            && record.status != ControllerActionStatus::Resolved
        {
            anyhow::bail!("cancellation identity is missing its exact BOC");
        }
    }
    Ok(())
}

fn c_filename(name: &str) -> anyhow::Result<CString> {
    if name.is_empty() || name.as_bytes().contains(&b'/') {
        anyhow::bail!("invalid custody journal filename");
    }
    CString::new(name.as_bytes()).context("custody journal filename contains NUL")
}

fn validate_private_regular_file(
    file: &File,
    allow_empty: bool,
    label: &str,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || (!allow_empty && metadata.len() == 0)
    {
        anyhow::bail!("invalid private Agent Account custody file: {label}");
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_cell_digest(value: &str) -> bool {
    value.len() == 80
        && value.starts_with("tvm-cell-sha256:")
        && value[16..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && value[16..].bytes().any(|b| b != b'0')
}
fn valid_lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && byte.is_ascii_digit())
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}
fn valid_idempotency_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Cell, MsgAddressInt, base64_encode, write_boc};
    use ed25519_dalek::{Signer, SigningKey};

    fn claim(seqno: u32, marker: char) -> ControllerActionClaim {
        ControllerActionClaim {
            account: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap().to_string(),
            network_global_id: 42,
            deployment_id: "55".repeat(32),
            controller_epoch: 3,
            seqno,
            target: MsgAddressInt::with_standart(None, 0, [0x22; 32].into()).unwrap().to_string(),
            value_atomic: 1,
            body_hash: None,
            action_kind: "agent-native-send".into(),
            idempotency_key: "1".repeat(64),
            action_identity: format!("sha256:{}", marker.to_string().repeat(64)),
            valid_until: 2000,
        }
    }

    fn signed_boc(claim: &ControllerActionClaim, cancellation: bool) -> (String, String) {
        let account = claim.account.parse::<MsgAddressInt>().unwrap();
        let payload = if cancellation {
            crate::AgentAccountContract::build_cancel_seqno_payload(
                claim.network_global_id,
                claim.controller_epoch,
                claim.seqno,
                claim.valid_until,
            )
            .unwrap()
        } else {
            crate::AgentAccountContract::build_native_send_payload(
                claim.network_global_id,
                claim.controller_epoch,
                claim.seqno,
                claim.valid_until,
                &claim.target.parse::<MsgAddressInt>().unwrap(),
                claim.value_atomic,
            )
            .unwrap()
        };
        let signed =
            crate::AgentAccountContract::build_signed_controller_message(payload, &[0x44; 64])
                .unwrap();
        let message =
            crate::AgentAccountContract::build_external_controller_message(account, signed)
                .unwrap();
        let bytes = write_boc(&message).unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        (base64_encode(bytes), digest)
    }

    fn signed_task_boc(claim: &ControllerActionClaim, body: Cell) -> (String, String) {
        let account = claim.account.parse::<MsgAddressInt>().unwrap();
        let payload = crate::AgentAccountContract::build_task_send_payload(
            claim.network_global_id,
            claim.controller_epoch,
            claim.seqno,
            claim.valid_until,
            &claim.target.parse::<MsgAddressInt>().unwrap(),
            claim.value_atomic,
            body,
        )
        .unwrap();
        let signed =
            crate::AgentAccountContract::build_signed_controller_message(payload, &[0x44; 64])
                .unwrap();
        let message =
            crate::AgentAccountContract::build_external_controller_message(account, signed)
                .unwrap();
        let bytes = write_boc(&message).unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        (base64_encode(bytes), digest)
    }

    fn economic_authorization(
        claim: &ControllerActionClaim,
        generation: u64,
        key: &SigningKey,
    ) -> EconomicActionAuthorization {
        let mut authorization = EconomicActionAuthorization {
            schema_version: 1,
            authority_id: "authority:owner".into(),
            owner_id: "owner:1".into(),
            agent_id: "agent:buyer".into(),
            source_account: claim.account.clone(),
            network_id: "tos:testnet".into(),
            network_global_id: claim.network_global_id,
            stable_action_id: claim.action_identity.clone(),
            exact_request_digest: format!("sha256:{}", "2".repeat(64)),
            writer_generation: generation,
            writer_fence_digest: format!("sha256:{}", "3".repeat(64)),
            policy_revision: 4,
            mandate_digest: format!("sha256:{}", "4".repeat(64)),
            approval_digest_or_zero: format!("sha256:{}", "0".repeat(64)),
            agreement_body_digest: format!("sha256:{}", "5".repeat(64)),
            obligation_instance_id: format!("sha256:{}", "6".repeat(64)),
            destination: claim.target.clone(),
            amount_atomic: claim.value_atomic,
            expires_at_unix: u64::from(claim.valid_until),
            public_key: format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes())),
            proof: String::new(),
        };
        let digest = Sha256::digest(economic_authorization_preimage(&authorization).unwrap());
        authorization.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));
        authorization
    }

    fn economic_effect_authorization(
        claim: &ControllerActionClaim,
        generation: u64,
        key: &SigningKey,
    ) -> EconomicEffectAuthorization {
        let mut authorization = EconomicEffectAuthorization {
            schema_version: 1,
            authority_id: "authority:owner".into(),
            owner_id: "owner:1".into(),
            agent_id: "agent:buyer".into(),
            source_account: claim.account.clone(),
            network_id: "tos:testnet".into(),
            network_global_id: claim.network_global_id,
            action_kind: "escrow.accept".into(),
            stable_action_id: claim.action_identity.clone(),
            exact_request_digest: format!("sha256:{}", "2".repeat(64)),
            writer_generation: generation,
            writer_fence_digest: format!("sha256:{}", "3".repeat(64)),
            policy_revision: 4,
            mandate_digest: format!("sha256:{}", "4".repeat(64)),
            approval_digest_or_zero: format!("sha256:{}", "0".repeat(64)),
            agreement_body_digest: format!("sha256:{}", "5".repeat(64)),
            obligation_id: "payment:one".into(),
            destination: claim.target.clone(),
            amount_nanotos: claim.value_atomic,
            body_hash: claim.body_hash.clone().unwrap(),
            state_init_hash_or_zero: format!("sha256:{}", "0".repeat(64)),
            expires_at_unix: u64::from(claim.valid_until),
            public_key: format!("ed25519:{}", hex::encode(key.verifying_key().to_bytes())),
            proof: String::new(),
        };
        let digest =
            Sha256::digest(economic_effect_authorization_preimage(&authorization).unwrap());
        authorization.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));
        authorization
    }
    #[test]
    fn exact_retry_conflict_broadcast_and_recovery_are_durable() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let a = claim(3, 'a');
        assert!(journal.claim_primary(a.clone(), 10).unwrap().1);
        assert!(!journal.claim_primary(a.clone(), 11).unwrap().1);
        assert!(journal.claim_primary(claim(3, 'b'), 11).is_err());
        let (boc, digest) = signed_boc(&a, false);
        journal.attach_signed_boc(&a, &boc, &digest, 12).unwrap();
        journal.begin_broadcast(&a, 13).unwrap();
        assert!(journal.begin_broadcast(&a, 14).is_err());
        let reopened =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let mut next = claim(4, 'd');
        next.idempotency_key = "2".repeat(64);
        assert!(reopened.claim_primary(next.clone(), 15).is_err());
        reopened
            .reconcile_finalized_state(
                &a.account,
                a.network_global_id,
                &a.deployment_id,
                a.controller_epoch,
                4,
                16,
            )
            .unwrap();
        assert!(reopened.claim_primary(next, 17).unwrap().1);
        assert!(
            reopened
                .reconcile_finalized_state(
                    &a.account,
                    a.network_global_id,
                    &a.deployment_id,
                    a.controller_epoch,
                    2,
                    18,
                )
                .is_err()
        );
    }
    #[test]
    fn one_cancellation_only_and_changed_boc_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let a = claim(0, 'a');
        journal.claim_primary(a.clone(), 1).unwrap();
        let mut substituted = a.clone();
        substituted.target =
            MsgAddressInt::with_standart(None, 0, [0x33; 32].into()).unwrap().to_string();
        let (substituted_boc, substituted_digest) = signed_boc(&substituted, false);
        assert!(journal.attach_signed_boc(&a, &substituted_boc, &substituted_digest, 2).is_err());
        let (boc, digest) = signed_boc(&a, false);
        journal.attach_signed_boc(&a, &boc, &digest, 3).unwrap();
        assert!(journal.attach_signed_boc(&a, "Ym9jMg==", &digest, 4).is_err());
        let cancel = format!("sha256:{}", "c".repeat(64));
        let (cancel_boc, _) = signed_boc(&a, true);
        journal.authorize_cancellation(&a, &cancel, &cancel_boc, 5).unwrap();
        assert!(
            journal
                .authorize_cancellation(&a, &format!("sha256:{}", "d".repeat(64)), "eA==", 5)
                .is_err()
        );
    }

    #[test]
    fn explicit_generation_retirement_releases_an_abandoned_action() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let old = claim(0, 'a');
        journal.claim_primary(old.clone(), 1).unwrap();
        assert!(
            journal
                .retire_generation(&old.account, old.network_global_id, &old.deployment_id, 1_999,)
                .is_err()
        );
        journal
            .retire_generation(&old.account, old.network_global_id, &old.deployment_id, 2_000)
            .unwrap();
        let record = journal
            .find_primary(
                &old.account,
                old.network_global_id,
                &old.deployment_id,
                old.controller_epoch,
                &old.idempotency_key,
            )
            .unwrap()
            .unwrap();
        assert_eq!(record.status, ControllerActionStatus::Resolved);
        assert_eq!(
            journal.claim_primary(old, 3).unwrap().0.status,
            ControllerActionStatus::Resolved
        );
        let mut fresh = claim(0, 'b');
        fresh.deployment_id = "66".repeat(32);
        journal
            .reconcile_finalized_state(
                &fresh.account,
                fresh.network_global_id,
                &fresh.deployment_id,
                fresh.controller_epoch,
                fresh.seqno,
                4,
            )
            .unwrap();
        assert!(journal.claim_primary(fresh, 5).unwrap().1);
    }

    #[test]
    fn rejects_symlinked_lock_and_generation_or_epoch_rollback() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            symlink("attacker-controlled", directory.path().join(LOCK_FILE)).unwrap();
            assert!(
                AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).is_err()
            );
            fs::remove_file(directory.path().join(LOCK_FILE)).unwrap();
        }

        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let a = claim(5, 'a');
        journal
            .reconcile_finalized_state(
                &a.account,
                a.network_global_id,
                &a.deployment_id,
                a.controller_epoch,
                a.seqno,
                10,
            )
            .unwrap();
        assert!(
            journal
                .reconcile_finalized_state(
                    &a.account,
                    a.network_global_id,
                    &a.deployment_id,
                    a.controller_epoch - 1,
                    u32::MAX,
                    11,
                )
                .is_err()
        );
        journal.claim_primary(a.clone(), 12).unwrap();
        let mut changed_generation = a;
        changed_generation.deployment_id = "66".repeat(32);
        assert!(journal.claim_primary(changed_generation, 13).is_err());
    }

    #[test]
    fn economic_payment_is_agreement_bound_and_writer_fenced() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x63; 32]);
        let first = claim(0, '1');
        let auth = economic_authorization(&first, 7, &key);
        assert!(
            journal
                .claim_economic_payment(
                    first.clone(),
                    auth.clone(),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    10,
                )
                .unwrap()
                .1
        );
        assert!(
            !journal
                .claim_economic_payment(
                    first.clone(),
                    auth,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .unwrap()
                .1
        );
        let mut changed = economic_authorization(&first, 7, &key);
        changed.amount_atomic += 1;
        assert!(
            journal
                .claim_economic_payment(
                    first.clone(),
                    changed,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .is_err()
        );

        // A generation is a fencing epoch, not merely a counter. Once the
        // custody boundary has admitted one authority-issued fence for that
        // epoch, another fence at the same generation is equivocation even
        // when its signature is otherwise valid.
        let mut equivocated = economic_authorization(&first, 7, &key);
        equivocated.writer_fence_digest = format!("sha256:{}", "9".repeat(64));
        let digest = Sha256::digest(economic_authorization_preimage(&equivocated).unwrap());
        equivocated.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));
        assert!(
            journal
                .claim_economic_payment(
                    first.clone(),
                    equivocated,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .is_err()
        );

        journal
            .reconcile_finalized_state(
                &first.account,
                first.network_global_id,
                &first.deployment_id,
                first.controller_epoch,
                1,
                12,
            )
            .unwrap();
        let mut takeover = claim(1, '7');
        takeover.idempotency_key = "7".repeat(64);
        let takeover_auth = economic_authorization(&takeover, 8, &key);
        journal
            .claim_economic_payment(
                takeover,
                takeover_auth,
                "authority:owner",
                key.verifying_key().to_bytes(),
                13,
            )
            .unwrap();
        assert!(
            journal
                .claim_economic_payment(
                    first,
                    economic_authorization(&claim(0, '1'), 7, &key),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    14,
                )
                .is_err()
        );
    }

    #[test]
    fn economic_effect_binds_task_body_and_rejects_stale_writer() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x64; 32]);
        let mut effect = claim(0, '8');
        effect.idempotency_key = "8".repeat(64);
        effect.action_kind = "agent-task-send".into();
        effect.body_hash = Some(format!("tvm-cell-sha256:{}", "8".repeat(64)));
        let authorization = economic_effect_authorization(&effect, 10, &key);
        assert!(
            journal
                .claim_economic_effect(
                    effect.clone(),
                    authorization.clone(),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    10,
                )
                .unwrap()
                .1
        );
        assert!(
            !journal
                .claim_economic_effect(
                    effect.clone(),
                    authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .unwrap()
                .1
        );
        let mut substituted = effect.clone();
        substituted.body_hash = Some(format!("tvm-cell-sha256:{}", "9".repeat(64)));
        assert!(
            journal
                .claim_economic_effect(
                    substituted.clone(),
                    economic_effect_authorization(&substituted, 10, &key),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    12,
                )
                .is_err()
        );
        let mut stale = effect;
        stale.idempotency_key = "a".repeat(64);
        stale.action_identity = format!("sha256:{}", "a".repeat(64));
        stale.seqno = 1;
        journal
            .reconcile_finalized_state(
                &stale.account,
                stale.network_global_id,
                &stale.deployment_id,
                stale.controller_epoch,
                1,
                13,
            )
            .unwrap();
        assert!(
            journal
                .claim_economic_effect(
                    stale.clone(),
                    economic_effect_authorization(&stale, 9, &key),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    14,
                )
                .is_err()
        );
    }

    #[test]
    fn higher_writer_recovers_only_the_exact_unfinished_effect() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let body = Cell::default();
        let mut effect = claim(0, 'b');
        effect.idempotency_key = "b".repeat(64);
        effect.action_kind = "agent-task-send".into();
        effect.body_hash = Some(format!("tvm-cell-sha256:{}", hex::encode(body.hash(0))));
        let first = economic_effect_authorization(&effect, 20, &key);
        journal
            .claim_economic_effect(
                effect.clone(),
                first,
                "authority:owner",
                key.verifying_key().to_bytes(),
                10,
            )
            .unwrap();

        let mut refreshed_claim = effect.clone();
        refreshed_claim.valid_until += 100;
        let mut takeover = economic_effect_authorization(&refreshed_claim, 21, &key);
        takeover.exact_request_digest = format!("sha256:{}", "2".repeat(64));
        let digest = Sha256::digest(economic_effect_authorization_preimage(&takeover).unwrap());
        takeover.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));
        let (recovered, created) = journal
            .claim_economic_effect(
                refreshed_claim.clone(),
                takeover.clone(),
                "authority:owner",
                key.verifying_key().to_bytes(),
                11,
            )
            .unwrap();
        assert!(!created);
        assert_eq!(recovered.claim.valid_until, refreshed_claim.valid_until);
        assert_eq!(recovered.economic_effect_authorization.as_ref().unwrap().writer_generation, 21);

        let (boc, boc_digest) = signed_task_boc(&refreshed_claim, body);
        journal.attach_signed_boc(&refreshed_claim, &boc, &boc_digest, 12).unwrap();
        let mut later_claim = refreshed_claim.clone();
        later_claim.valid_until += 100;
        let later = economic_effect_authorization(&later_claim, 22, &key);
        let (recovered_signed, _) = journal
            .claim_economic_effect(
                later_claim.clone(),
                later,
                "authority:owner",
                key.verifying_key().to_bytes(),
                13,
            )
            .unwrap();
        assert_eq!(recovered_signed.status, ControllerActionStatus::Signed);
        assert_eq!(recovered_signed.claim.valid_until, refreshed_claim.valid_until);
        assert_eq!(recovered_signed.exact_signed_boc_digest.as_deref(), Some(boc_digest.as_str()));

        let stale = economic_effect_authorization(&later_claim, 21, &key);
        assert!(
            journal
                .claim_economic_effect(
                    later_claim.clone(),
                    stale,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    14,
                )
                .is_err()
        );
        let mut changed = later_claim;
        changed.target =
            MsgAddressInt::with_standart(None, 0, [0x33; 32].into()).unwrap().to_string();
        let changed_authorization = economic_effect_authorization(&changed, 23, &key);
        assert!(
            journal
                .claim_economic_effect(
                    changed,
                    changed_authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    15,
                )
                .is_err()
        );
    }
}
