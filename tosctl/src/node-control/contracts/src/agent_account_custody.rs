use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

use anyhow::Context;
use chain_block::{
    Cell, Coins, Deserializable, Message, MsgAddressInt, base64_decode, base64_encode,
    read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::{
    client_json_rpc::{MAX_EXACT_BOC_BYTES, validate_exact_boc_before_broadcast},
    data_models::RelayNetworkDomainPin,
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
const ECONOMIC_ACTION_TOMBSTONE_SCHEMA: &str = "tos.agent-account.economic-action-tombstone.v1";
const ECONOMIC_ACTION_TOMBSTONE_PREFIX: &str = "economic-action-";
const MAX_JOURNAL_BYTES: u64 = 32 << 20;
const MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES: u64 = 2 << 20;
// This is an owner/custody-domain lifetime budget, not merely a hot-cache
// threshold. Each admitted identity reserves the complete per-file maximum so
// every exact retry and valid state transition retains space after admission.
const MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES: u64 = 512 << 20;
// One private custody directory is the rollback-resistant replay domain for
// its owner. Permanent replay fences are never deleted merely to reclaim
// space, so admission must stop before an unbounded number can be created.
const MAX_ECONOMIC_ACTION_TOMBSTONES: usize = 65_536;
const MAX_CUSTODY_DIRECTORY_ENTRIES: usize = MAX_ECONOMIC_ACTION_TOMBSTONES + 64;
// Serialized bytes are the authoritative storage bound. This separate count
// prevents a hostile file full of tiny records from making validation
// unbounded without imposing a small global active-action cap across wallets.
const MAX_TOTAL_RECORDS: usize = 4096;
const MAX_RETAINED_RESOLVED_RECORDS: usize = 1024;
const MAX_EXACT_BOC_BASE64_BYTES: usize = MAX_EXACT_BOC_BYTES.div_ceil(3) * 4;

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
    /// Required for every economic/relay action. Legacy manual controller
    /// actions may omit it but are not production relay authorizations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_domain: Option<RelayNetworkDomainPin>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_domain: Option<RelayNetworkDomainPin>,
    pub stable_action_id: String,
    pub exact_request_digest: String,
    /// Required by schema v3. This binds custody and later transaction
    /// evidence to the complete canonical AgreementPaymentRequestV3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_payment_request_digest: Option<String>,
    /// Optional only for ordinary schema-v3 payments. Sponsorship requires
    /// this all-or-none triple so the Action Authority signs the exact
    /// selected finality descriptor and frozen observation capability before
    /// custody admits the top-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsorship_finality_profile_cbor_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsorship_release_profile_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsorship_corroboration_snapshot_identity: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_domain: Option<RelayNetworkDomainPin>,
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
    /// Replayable, bounded evidence durably stored before a resolver writes
    /// stdout. It is deliberately generic at the custody layer: the caller
    /// verifies the chain-specific witness, while custody binds it to the one
    /// exact claim and signed BOC and rejects any conflicting winner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_winner_resolution: Option<ControllerActionResolutionEvidence>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerActionResolutionEvidence {
    pub evidence_kind: String,
    pub evidence_digest: String,
    pub evidence: serde_json::Value,
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

/// Permanent owner/Agent semantic replay identity. The bounded hot controller
/// journal may discard old terminal BOC material, but it may never discard the
/// fact that this stable action already selected one exact source sequence and
/// effect. One file per stable action keeps exact retries independent, while a
/// hard custody-domain ceiling prevents unbounded permanent-ledger growth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicActionTombstone {
    schema: String,
    initial_authorization_digest: String,
    current_authorization_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_resolution_digest: Option<String>,
    record: ControllerActionRecord,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EconomicTombstoneUsage {
    count: usize,
    persistent_bytes: u64,
}

pub struct AgentAccountCustodyJournal {
    directory_fd: File,
}

impl AgentAccountCustodyJournal {
    /// Return the one durable controller action selected by an idempotency key.
    /// Resolution commands use this instead of reconstructing a claim from
    /// mutable CLI inputs. Duplicate keys are corruption and fail closed.
    pub fn action_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> anyhow::Result<ControllerActionRecord> {
        if idempotency_key.len() != 64
            || !idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!("invalid controller action idempotency key");
        }
        self.with_document(|document| {
            let mut matching = document
                .records
                .iter()
                .filter(|record| record.claim.idempotency_key == idempotency_key);
            let record = matching.next().context("controller action was not found")?.clone();
            if matching.next().is_some() {
                anyhow::bail!("duplicate controller action idempotency key");
            }
            Ok(record)
        })
    }

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
        let network_domain = authorization
            .network_domain
            .as_ref()
            .context("economic authorization has no full network-domain pin")?;
        let sponsorship = authorization.sponsorship_finality_profile_cbor_digest.is_some();
        let expected_body_hash = if sponsorship {
            let body = crate::AgentAccountContract::build_sponsorship_payment_commitment(
                authorization
                    .agreement_payment_request_digest
                    .as_deref()
                    .context("sponsorship authorization has no AgreementPaymentRequest digest")?,
                &authorization.stable_action_id,
            )?;
            Some(format!("tvm-cell-sha256:{}", hex::encode(body.hash(0))))
        } else {
            None
        };
        let validity_matches = if sponsorship {
            u64::from(claim.valid_until) == authorization.expires_at_unix
        } else {
            u64::from(claim.valid_until) <= authorization.expires_at_unix
        };
        if claim.action_kind != if sponsorship { "agent-task-send" } else { "agent-native-send" }
            || claim.body_hash != expected_body_hash
            || claim.account != authorization.source_account
            || claim.network_global_id != authorization.network_global_id
            || claim.network_domain.as_ref() != Some(network_domain)
            || claim.target != authorization.destination
            || claim.value_atomic != authorization.amount_atomic
            || claim.action_identity != authorization.stable_action_id
            || claim.idempotency_key != idempotency
            || !validity_matches
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
            if let Some(tombstone) =
                self.read_economic_action_tombstone(&authorization.stable_action_id)?
            {
                let mut stored = tombstone.record;
                let prior = stored
                    .economic_authorization
                    .as_ref()
                    .context("stable action belongs to a non-payment economic effect")?;
                if stored.claim != claim || !same_economic_payment(prior, &authorization) {
                    anyhow::bail!(
                        "economic stable action was already bound to a different source or effect"
                    );
                }
                if prior != &authorization {
                    if stored.status == ControllerActionStatus::Resolved
                        || authorization.writer_generation <= prior.writer_generation
                    {
                        anyhow::bail!(
                            "terminal or non-increasing economic authorization cannot replace a stable action"
                        );
                    }
                    stored.economic_authorization = Some(authorization);
                    stored.updated_at_unix = now;
                    self.persist_economic_action_tombstone(&stored)?;
                }
                restore_hot_economic_record(document, &stored)?;
                return Ok((stored, false));
            }
            let (record, created) = admit_claim(document, claim, Some(authorization), now)?;
            self.persist_economic_action_tombstone(&record)?;
            Ok((record, created))
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
        let network_domain = authorization
            .network_domain
            .as_ref()
            .context("economic effect has no full network-domain pin")?;
        if claim.action_kind != "agent-task-send"
            || claim.account != authorization.source_account
            || claim.network_global_id != authorization.network_global_id
            || claim.network_domain.as_ref() != Some(network_domain)
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
            if let Some(tombstone) =
                self.read_economic_action_tombstone(&authorization.stable_action_id)?
            {
                let mut stored = tombstone.record;
                let prior = stored
                    .economic_effect_authorization
                    .as_ref()
                    .context("stable action belongs to an economic payment")?;
                if stored.claim != claim || !same_economic_effect(prior, &authorization) {
                    anyhow::bail!(
                        "economic stable action was already bound to a different source or effect"
                    );
                }
                if prior != &authorization {
                    if stored.status == ControllerActionStatus::Resolved
                        || authorization.writer_generation <= prior.writer_generation
                    {
                        anyhow::bail!(
                            "terminal or non-increasing economic authorization cannot replace a stable action"
                        );
                    }
                    stored.economic_effect_authorization = Some(authorization);
                    stored.updated_at_unix = now;
                    self.persist_economic_action_tombstone(&stored)?;
                }
                restore_hot_economic_record(document, &stored)?;
                return Ok((stored, false));
            }
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
            let output = target.clone();
            self.persist_economic_action_tombstone(&output)?;
            Ok((output, created))
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

    /// Find one economic payment by the owner-wide stable action identity.
    /// This supports crash recovery after chain finalization without requiring
    /// a live RPC or current Provider account merely to rediscover the frozen
    /// controller generation. Duplicate identities are treated as corruption,
    /// never as first-wins.
    pub fn find_economic_payment_by_stable_action(
        &self,
        stable_action_id: &str,
    ) -> anyhow::Result<Option<ControllerActionRecord>> {
        if !valid_digest(stable_action_id) {
            anyhow::bail!("invalid economic payment lookup");
        }
        self.with_document(|document| {
            let mut matches = document.records.iter().filter(|record| {
                record
                    .economic_authorization
                    .as_ref()
                    .is_some_and(|authorization| authorization.stable_action_id == stable_action_id)
            });
            let first = matches.next().cloned();
            if matches.next().is_some() {
                anyhow::bail!("custody journal repeats an economic stable action identity");
            }
            let tombstone = self.read_economic_action_tombstone(stable_action_id)?;
            match (first, tombstone) {
                (Some(hot), Some(tombstone)) => {
                    let stored = tombstone.record;
                    if stored.economic_authorization.is_none()
                        || hot.claim != stored.claim
                        || !same_optional_economic_payment(
                            hot.economic_authorization.as_ref(),
                            stored.economic_authorization.as_ref(),
                        )
                    {
                        anyhow::bail!("custody hot journal conflicts with its semantic tombstone");
                    }
                    Ok(Some(
                        if action_status_rank(&stored.status) >= action_status_rank(&hot.status) {
                            stored
                        } else {
                            hot
                        },
                    ))
                }
                (None, Some(tombstone)) if tombstone.record.economic_authorization.is_some() => {
                    Ok(Some(tombstone.record))
                }
                (None, Some(_)) => {
                    anyhow::bail!("stable action belongs to a non-payment economic effect")
                }
                (Some(hot), None) => Ok(Some(hot)),
                (None, None) => Ok(None),
            }
        })
    }

    pub fn attach_signed_boc(
        &self,
        claim: &ControllerActionClaim,
        boc_base64: &str,
        digest: &str,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        if boc_base64.is_empty()
            || boc_base64.len() > MAX_EXACT_BOC_BASE64_BYTES
            || !valid_digest(digest)
        {
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
            || cancellation_boc_base64.len() > MAX_EXACT_BOC_BASE64_BYTES
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

    /// Enter or resume the broadcast of the one exact BOC already attached to
    /// this claim. This is intentionally narrower than `begin_broadcast`:
    /// callers may use it only when replaying the same custody-journaled BOC.
    /// A crash before the first socket write therefore cannot strand a Signed
    /// record, while a crash after the durable Broadcasting transition can
    /// only resend identical bytes for the same account sequence.
    pub fn begin_or_resume_exact_broadcast(
        &self,
        claim: &ControllerActionClaim,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        self.mutate_exact(claim, |record| match record.status {
            ControllerActionStatus::Signed => {
                if record.exact_signed_boc_base64.is_none()
                    || record.exact_signed_boc_digest.is_none()
                {
                    anyhow::bail!("signed action has no exact BOC");
                }
                record.status = ControllerActionStatus::Broadcasting;
                record.updated_at_unix = now;
                Ok(())
            }
            ControllerActionStatus::Broadcasting => {
                if record.exact_signed_boc_base64.is_none()
                    || record.exact_signed_boc_digest.is_none()
                {
                    anyhow::bail!("broadcasting action has no exact BOC");
                }
                Ok(())
            }
            _ => anyhow::bail!(
                "only a durable signed or already-broadcasting exact action may be resumed"
            ),
        })
    }

    pub fn reconcile_finalized_state(
        &self,
        account: &str,
        network_global_id: i32,
        deployment_id: &str,
        controller_epoch: u64,
        finalized_seqno: u32,
        _now: u64,
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
            if document.records.iter().any(|record| {
                generation_key(&record.claim) == generation
                    && record.status != ControllerActionStatus::Resolved
                    && (controller_epoch, finalized_seqno)
                        > (record.claim.controller_epoch, record.claim.seqno)
            }) {
                anyhow::bail!(
                    "controller sequence advanced while an exact action is unresolved; provide exact winner/effect proof before changing custody state"
                );
            }
            document.high_water.insert(
                generation.clone(),
                FinalizedHighWater { controller_epoch, seqno: finalized_seqno },
            );
            compact_records(document);
            Ok(())
        })
    }

    /// Atomically bind a caller-verified exact winner to one custody claim,
    /// advance the generation high-water mark, and retain replayable evidence
    /// before any caller-visible output. This performs no network operation.
    pub fn resolve_exact_winner(
        &self,
        claim: &ControllerActionClaim,
        exact_signed_boc_digest: &str,
        finalized_controller_epoch: u64,
        finalized_seqno: u32,
        resolution: ControllerActionResolutionEvidence,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        validate_claim(claim)?;
        validate_resolution_evidence(&resolution)?;
        if !valid_digest(exact_signed_boc_digest) || now == 0 {
            anyhow::bail!("exact winner resolution input is invalid");
        }
        let generation = generation_key(claim);
        self.with_document(|document| {
            if let Some(high) = document.high_water.get(&generation) {
                if (finalized_controller_epoch, finalized_seqno)
                    < (high.controller_epoch, high.seqno)
                {
                    anyhow::bail!(
                        "Agent Account finalized controller epoch/seqno rolled back; refusing replay"
                    );
                }
            }
            let position = document
                .records
                .iter()
                .position(|record| record.claim == *claim)
                .context("exact custody winner claim was not found")?;
            let record = &document.records[position];
            if record.exact_signed_boc_digest.as_deref() != Some(exact_signed_boc_digest) {
                anyhow::bail!("exact winner differs from the custody-signed BOC");
            }
            if record.status == ControllerActionStatus::Resolved {
                if record.exact_winner_resolution.as_ref() != Some(&resolution) {
                    anyhow::bail!("resolved custody action conflicts with different winner evidence");
                }
                return Ok(record.clone());
            }
            if record.status != ControllerActionStatus::Broadcasting {
                anyhow::bail!("only an ambiguously broadcast exact action may be resolved");
            }
            if (finalized_controller_epoch, finalized_seqno)
                <= (claim.controller_epoch, claim.seqno)
            {
                anyhow::bail!("finalized state has not consumed the exact custody sequence");
            }
            if document.records.iter().enumerate().any(|(index, candidate)| {
                index != position
                    && generation_key(&candidate.claim) == generation
                    && candidate.status != ControllerActionStatus::Resolved
                    && (finalized_controller_epoch, finalized_seqno)
                        > (candidate.claim.controller_epoch, candidate.claim.seqno)
            }) {
                anyhow::bail!(
                    "finalized state advanced across another unresolved exact custody action"
                );
            }
            let record = &mut document.records[position];
            record.status = ControllerActionStatus::Resolved;
            record.exact_winner_resolution = Some(resolution);
            record.updated_at_unix = now;
            document.high_water.insert(
                generation,
                FinalizedHighWater {
                    controller_epoch: finalized_controller_epoch,
                    seqno: finalized_seqno,
                },
            );
            let output = record.clone();
            if is_economic_record(&output) {
                self.persist_economic_action_tombstone(&output)?;
            }
            compact_records(document);
            Ok(output)
        })
    }

    /// Atomically terminalize one exact signed economic action after an
    /// independently verified, expiry-mature absence proof. Unlike
    /// `resolve_exact_winner`, the checkpoint is allowed to retain the signed
    /// sequence because the exact message was not included. The proof bytes
    /// and digest are persisted before caller output for crash-safe replay.
    pub fn resolve_exact_absence(
        &self,
        claim: &ControllerActionClaim,
        exact_signed_boc_digest: &str,
        checkpoint_controller_epoch: u64,
        checkpoint_seqno: u32,
        resolution: ControllerActionResolutionEvidence,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        validate_claim(claim)?;
        validate_resolution_evidence(&resolution)?;
        if !valid_digest(exact_signed_boc_digest) || now == 0 {
            anyhow::bail!("exact absence resolution input is invalid");
        }
        let generation = generation_key(claim);
        self.with_document(|document| {
            if let Some(high) = document.high_water.get(&generation) {
                if (checkpoint_controller_epoch, checkpoint_seqno)
                    < (high.controller_epoch, high.seqno)
                {
                    anyhow::bail!(
                        "Agent Account absence checkpoint rolled back below custody high-water"
                    );
                }
            }
            if (checkpoint_controller_epoch, checkpoint_seqno)
                < (claim.controller_epoch, claim.seqno)
            {
                anyhow::bail!("Agent Account absence checkpoint predates the exact signed action");
            }
            let position = document
                .records
                .iter()
                .position(|record| record.claim == *claim)
                .context("exact custody absence claim was not found")?;
            let record = &document.records[position];
            if record.exact_signed_boc_digest.as_deref() != Some(exact_signed_boc_digest) {
                anyhow::bail!("absence claim differs from the custody-signed BOC");
            }
            if record.status == ControllerActionStatus::Resolved {
                if record.exact_winner_resolution.as_ref() != Some(&resolution) {
                    anyhow::bail!(
                        "resolved custody action conflicts with different absence evidence"
                    );
                }
                return Ok(record.clone());
            }
            if record.status != ControllerActionStatus::Signed
                && record.status != ControllerActionStatus::Broadcasting
            {
                anyhow::bail!(
                    "only an exact signed or ambiguously broadcast action may resolve absent"
                );
            }
            let record = &mut document.records[position];
            record.status = ControllerActionStatus::Resolved;
            record.exact_winner_resolution = Some(resolution);
            record.updated_at_unix = now;
            document.high_water.insert(
                generation,
                FinalizedHighWater {
                    controller_epoch: checkpoint_controller_epoch,
                    seqno: checkpoint_seqno,
                },
            );
            let output = record.clone();
            if is_economic_record(&output) {
                self.persist_economic_action_tombstone(&output)?;
            }
            compact_records(document);
            Ok(output)
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
            for record in document.records.iter().filter(|record| {
                generation_key(&record.claim) == generation && is_economic_record(record)
            }) {
                self.persist_economic_action_tombstone(record)?;
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
            let output = record.clone();
            if is_economic_record(&output) {
                self.persist_economic_action_tombstone(&output)?;
            }
            Ok(output)
        })
    }

    fn read_economic_action_tombstone(
        &self,
        stable_action_id: &str,
    ) -> anyhow::Result<Option<EconomicActionTombstone>> {
        let filename = economic_action_tombstone_filename(stable_action_id)?;
        let file = match self.openat_file(
            &filename,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_private_regular_file(&file, false, &filename)?;
        let metadata = file.metadata()?;
        if metadata.len() == 0 || metadata.len() > MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES {
            anyhow::bail!("invalid economic stable-action tombstone file");
        }
        let mut raw = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES + 1).read_to_end(&mut raw)?;
        let tombstone: EconomicActionTombstone =
            serde_json::from_slice(&raw).context("decode economic stable-action tombstone")?;
        validate_economic_action_tombstone(&tombstone, stable_action_id)?;
        Ok(Some(tombstone))
    }

    fn persist_economic_action_tombstone(
        &self,
        record: &ControllerActionRecord,
    ) -> anyhow::Result<()> {
        let (stable_action_id, authorization_digest) = economic_record_identity(record)?;
        let filename = economic_action_tombstone_filename(stable_action_id)?;
        let mut permanent_record = record.clone();
        if permanent_record.status == ControllerActionStatus::Resolved {
            permanent_record.exact_signed_boc_base64 = None;
            permanent_record.cancellation_boc_base64 = None;
        }
        let terminal_resolution_digest = permanent_record
            .exact_winner_resolution
            .as_ref()
            .map(|resolution| {
                controller_resolution_evidence_digest(
                    &resolution.evidence_kind,
                    &resolution.evidence,
                )
            })
            .transpose()?;
        let mut candidate = EconomicActionTombstone {
            schema: ECONOMIC_ACTION_TOMBSTONE_SCHEMA.to_owned(),
            initial_authorization_digest: authorization_digest.clone(),
            current_authorization_digest: authorization_digest,
            terminal_resolution_digest,
            record: permanent_record,
        };
        if let Some(existing) = self.read_economic_action_tombstone(stable_action_id)? {
            candidate.initial_authorization_digest = existing.initial_authorization_digest.clone();
            validate_economic_tombstone_transition(&existing, &candidate)?;
            if candidate == existing {
                return Ok(());
            }
        } else {
            // Reserve capacity before the first durable representation of a
            // new semantic action. Exact retries and transitions of an
            // existing action remain available even when the ledger is full.
            enforce_economic_tombstone_capacity(self.economic_action_tombstone_usage()?, true)?;
        }
        let raw = serde_json::to_vec(&candidate)?;
        if raw.is_empty() || raw.len() as u64 > MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES {
            anyhow::bail!("economic stable-action tombstone exceeds size limit");
        }
        self.persist_named_file(&filename, &raw)
    }

    fn persist_named_file(&self, filename: &str, raw: &[u8]) -> anyhow::Result<()> {
        let temporary = format!(
            ".{filename}.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        );
        let mut file = self.openat_file(
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        let write_result = file.write_all(raw).and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = write_result {
            unlinkat_best_effort(&self.directory_fd, &temporary);
            return Err(error.into());
        }
        let temporary_c = c_filename(&temporary)?;
        let filename_c = c_filename(filename)?;
        // SAFETY: both names are validated and both descriptors remain open.
        if unsafe {
            libc::renameat(
                self.directory_fd.as_raw_fd(),
                temporary_c.as_ptr(),
                self.directory_fd.as_raw_fd(),
                filename_c.as_ptr(),
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            unlinkat_best_effort(&self.directory_fd, &temporary);
            return Err(error.into());
        }
        self.directory_fd.sync_all()?;
        Ok(())
    }

    fn economic_action_tombstone_usage(&self) -> anyhow::Result<EconomicTombstoneUsage> {
        #[cfg(not(unix))]
        anyhow::bail!("Agent Account custody tombstones require Unix openat semantics");
        #[cfg(unix)]
        {
            struct DirectoryStream(*mut libc::DIR);
            impl Drop for DirectoryStream {
                fn drop(&mut self) {
                    // SAFETY: fdopendir returned this unique DIR pointer and
                    // ownership has not been transferred elsewhere.
                    unsafe { libc::closedir(self.0) };
                }
            }

            // Open "." relative to the pinned custody descriptor. This creates
            // an independent directory stream for every scan without ever
            // resolving the caller-supplied pathname again.
            let dot = c_filename(".")?;
            // SAFETY: the retained descriptor is open for the journal lifetime
            // and `dot` is a validated, NUL-terminated relative name.
            let scan_fd = unsafe {
                libc::openat(
                    self.directory_fd.as_raw_fd(),
                    dot.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if scan_fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: scan_fd is a newly opened directory descriptor. On
            // success fdopendir owns it; on failure we close it below.
            let stream = unsafe { libc::fdopendir(scan_fd) };
            if stream.is_null() {
                let error = std::io::Error::last_os_error();
                // SAFETY: fdopendir did not take ownership on failure.
                unsafe { libc::close(scan_fd) };
                return Err(error.into());
            }
            let stream = DirectoryStream(stream);
            let mut usage = EconomicTombstoneUsage::default();
            let mut scanned = 0usize;
            loop {
                errno::set_errno(errno::Errno(0));
                // SAFETY: the stream remains owned and open for this loop.
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = errno::errno();
                    if error.0 != 0 {
                        anyhow::bail!("read pinned custody directory: {error}");
                    }
                    break;
                }
                // SAFETY: POSIX dirent::d_name is NUL-terminated for a
                // successful readdir result and remains valid until the next
                // call on this stream.
                let name_bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name_bytes == b"." || name_bytes == b".." {
                    continue;
                }
                scanned = scanned.checked_add(1).context("custody entry count overflows")?;
                if scanned > MAX_CUSTODY_DIRECTORY_ENTRIES {
                    anyhow::bail!("Agent Account custody directory entry capacity is exceeded");
                }
                let name = std::str::from_utf8(name_bytes)
                    .context("custody directory contains a non-UTF-8 name")?;
                if !name.starts_with(ECONOMIC_ACTION_TOMBSTONE_PREFIX) {
                    continue;
                }
                let raw = name
                    .strip_prefix(ECONOMIC_ACTION_TOMBSTONE_PREFIX)
                    .and_then(|value| value.strip_suffix(".json"))
                    .context("custody directory contains a malformed economic tombstone name")?;
                if raw.len() != 64
                    || !raw
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    anyhow::bail!("custody directory contains a malformed economic tombstone name");
                }
                let filename = c_filename(name)?;
                // SAFETY: stat is initialized by a successful fstatat call;
                // the pinned directory descriptor and filename remain valid.
                let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe {
                    libc::fstatat(
                        self.directory_fd.as_raw_fd(),
                        filename.as_ptr(),
                        &mut metadata,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let size = u64::try_from(metadata.st_size)
                    .context("economic tombstone has a negative byte size")?;
                if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                    || metadata.st_mode & 0o777 != 0o600
                    || metadata.st_uid != unsafe { libc::geteuid() }
                    || metadata.st_nlink != 1
                    || size == 0
                    || size > MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES
                {
                    anyhow::bail!("invalid private economic stable-action tombstone file");
                }
                usage.count =
                    usage.count.checked_add(1).context("economic tombstone count overflows")?;
                usage.persistent_bytes = usage
                    .persistent_bytes
                    .checked_add(size)
                    .context("economic tombstone byte count overflows")?;
                enforce_economic_tombstone_capacity(usage, false)?;
            }
            Ok(usage)
        }
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
        // Reject an already-overfull permanent ledger before loading hot
        // state or executing an operation. This is both a startup bound and a
        // guard against out-of-band file injection.
        enforce_economic_tombstone_capacity(self.economic_action_tombstone_usage()?, false)?;
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
        // Backfill every legacy economic record into the permanent semantic
        // registry before an operation can compact it. If a prior crash made
        // the write-ahead tombstone newer than the hot journal, restore that
        // exact state instead of authorizing or signing another effect.
        for record in document.records.clone().into_iter().filter(is_economic_record) {
            let (stable_action_id, _) = economic_record_identity(&record)?;
            if let Some(tombstone) = self.read_economic_action_tombstone(stable_action_id)? {
                restore_hot_economic_record(&mut document, &tombstone.record)?;
                if let Some(current) = document.records.iter().find(|candidate| {
                    economic_record_identity(candidate)
                        .ok()
                        .is_some_and(|(candidate_id, _)| candidate_id == stable_action_id)
                }) {
                    self.persist_economic_action_tombstone(current)?;
                }
            } else {
                self.persist_economic_action_tombstone(&record)?;
            }
        }
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

fn economic_action_tombstone_filename(stable_action_id: &str) -> anyhow::Result<String> {
    let raw = stable_action_id
        .strip_prefix("sha256:")
        .context("economic stable action has no sha256 prefix")?;
    if raw.len() != 64
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("economic stable action is not a canonical SHA-256 digest");
    }
    Ok(format!("{ECONOMIC_ACTION_TOMBSTONE_PREFIX}{raw}.json"))
}

fn enforce_economic_tombstone_capacity(
    usage: EconomicTombstoneUsage,
    creating_new: bool,
) -> anyhow::Result<()> {
    if usage.count > MAX_ECONOMIC_ACTION_TOMBSTONES
        || usage.persistent_bytes > MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES
    {
        anyhow::bail!("Agent Account custody permanent replay ledger exceeds its hard capacity");
    }
    let reserved_count = usage
        .count
        .checked_add(usize::from(creating_new))
        .context("economic tombstone reservation count overflows")?;
    if reserved_count > MAX_ECONOMIC_ACTION_TOMBSTONES {
        anyhow::bail!(
            "Agent Account custody permanent replay ledger reached its {}-action capacity",
            MAX_ECONOMIC_ACTION_TOMBSTONES
        );
    }
    let worst_case_reserved_bytes = u64::try_from(reserved_count)?
        .checked_mul(MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES)
        .context("economic tombstone byte reservation overflows")?;
    if worst_case_reserved_bytes > MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES {
        anyhow::bail!(
            "Agent Account custody permanent replay ledger reached its {}-byte aggregate capacity",
            MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES
        );
    }
    Ok(())
}

fn unlinkat_best_effort(directory: &File, filename: &str) {
    let Ok(filename) = c_filename(filename) else {
        return;
    };
    // SAFETY: the directory descriptor remains open and the name is validated.
    unsafe {
        libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0);
    }
}

fn is_economic_record(record: &ControllerActionRecord) -> bool {
    record.economic_authorization.is_some() || record.economic_effect_authorization.is_some()
}

fn action_status_rank(status: &ControllerActionStatus) -> u8 {
    match status {
        ControllerActionStatus::Claimed => 0,
        ControllerActionStatus::Signed => 1,
        ControllerActionStatus::Broadcasting => 2,
        ControllerActionStatus::Resolved => 3,
    }
}

fn economic_record_identity(record: &ControllerActionRecord) -> anyhow::Result<(&str, String)> {
    match (&record.economic_authorization, &record.economic_effect_authorization) {
        (Some(authorization), None) => Ok((
            &authorization.stable_action_id,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(economic_authorization_preimage(authorization)?))
            ),
        )),
        (None, Some(authorization)) => Ok((
            &authorization.stable_action_id,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(economic_effect_authorization_preimage(authorization)?))
            ),
        )),
        _ => anyhow::bail!("economic tombstone record must contain exactly one authorization"),
    }
}

fn embedded_authority(record: &ControllerActionRecord) -> anyhow::Result<(&str, &str, u64, &str)> {
    match (&record.economic_authorization, &record.economic_effect_authorization) {
        (Some(authorization), None) => Ok((
            &authorization.authority_id,
            &authorization.public_key,
            authorization.writer_generation,
            &authorization.writer_fence_digest,
        )),
        (None, Some(authorization)) => Ok((
            &authorization.authority_id,
            &authorization.public_key,
            authorization.writer_generation,
            &authorization.writer_fence_digest,
        )),
        _ => anyhow::bail!("economic tombstone record must contain exactly one authorization"),
    }
}

fn embedded_owner_agent(record: &ControllerActionRecord) -> anyhow::Result<(&str, &str)> {
    match (&record.economic_authorization, &record.economic_effect_authorization) {
        (Some(authorization), None) => Ok((&authorization.owner_id, &authorization.agent_id)),
        (None, Some(authorization)) => Ok((&authorization.owner_id, &authorization.agent_id)),
        _ => anyhow::bail!("economic tombstone record must contain exactly one authorization"),
    }
}

fn validate_economic_action_tombstone(
    tombstone: &EconomicActionTombstone,
    expected_stable_action_id: &str,
) -> anyhow::Result<()> {
    if tombstone.schema != ECONOMIC_ACTION_TOMBSTONE_SCHEMA
        || !valid_digest(&tombstone.initial_authorization_digest)
        || !valid_digest(&tombstone.current_authorization_digest)
    {
        anyhow::bail!("invalid economic stable-action tombstone envelope");
    }
    let (stable_action_id, current_authorization_digest) =
        economic_record_identity(&tombstone.record)?;
    if stable_action_id != expected_stable_action_id
        || tombstone.current_authorization_digest != current_authorization_digest
    {
        anyhow::bail!("economic tombstone identity or authorization digest mismatch");
    }
    let terminal_digest = tombstone
        .record
        .exact_winner_resolution
        .as_ref()
        .map(|resolution| {
            controller_resolution_evidence_digest(&resolution.evidence_kind, &resolution.evidence)
        })
        .transpose()?;
    if terminal_digest != tombstone.terminal_resolution_digest
        || (terminal_digest.is_some()
            && tombstone.record.status != ControllerActionStatus::Resolved)
    {
        anyhow::bail!("economic tombstone has invalid terminal evidence binding");
    }

    let (owner_id, agent_id) = embedded_owner_agent(&tombstone.record)?;
    let (authority_id, public_key, writer_generation, writer_fence_digest) =
        embedded_authority(&tombstone.record)?;
    let public_key: [u8; 32] = hex::decode(
        public_key
            .strip_prefix("ed25519:")
            .context("economic tombstone authority key has no Ed25519 prefix")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("economic tombstone authority key must be 32 bytes"))?;
    let mut document = JournalDocument { schema: SCHEMA.to_owned(), ..Default::default() };
    document.economic_authority_high_water.insert(
        economic_authority_key(owner_id, agent_id),
        EconomicAuthorityHighWater {
            authority_id: authority_id.to_owned(),
            public_key: format!("ed25519:{}", hex::encode(public_key)),
            writer_generation,
            writer_fence_digest: writer_fence_digest.to_owned(),
        },
    );
    document.records.push(tombstone.record.clone());
    validate_document(&document)
}

fn validate_economic_tombstone_transition(
    existing: &EconomicActionTombstone,
    candidate: &EconomicActionTombstone,
) -> anyhow::Result<()> {
    let (existing_id, _) = economic_record_identity(&existing.record)?;
    let (candidate_id, _) = economic_record_identity(&candidate.record)?;
    validate_economic_action_tombstone(existing, existing_id)?;
    validate_economic_action_tombstone(candidate, candidate_id)?;
    if existing_id != candidate_id
        || existing.record.claim != candidate.record.claim
        || existing.initial_authorization_digest != candidate.initial_authorization_digest
        || action_status_rank(&candidate.record.status)
            < action_status_rank(&existing.record.status)
        || candidate.record.created_at_unix != existing.record.created_at_unix
        || candidate.record.updated_at_unix < existing.record.updated_at_unix
    {
        anyhow::bail!("economic stable-action tombstone cannot change or regress its frozen claim");
    }
    match (
        &existing.record.economic_authorization,
        &candidate.record.economic_authorization,
        &existing.record.economic_effect_authorization,
        &candidate.record.economic_effect_authorization,
    ) {
        (Some(left), Some(right), None, None) if same_economic_payment(left, right) => {
            if left != right
                && (existing.record.status == ControllerActionStatus::Resolved
                    || right.writer_generation <= left.writer_generation)
            {
                anyhow::bail!("economic payment authorization replacement is stale or terminal");
            }
        }
        (None, None, Some(left), Some(right)) if same_economic_effect(left, right) => {
            if left != right
                && (existing.record.status == ControllerActionStatus::Resolved
                    || right.writer_generation <= left.writer_generation)
            {
                anyhow::bail!("economic effect authorization replacement is stale or terminal");
            }
        }
        _ => anyhow::bail!("economic stable action changed its owner, Agent, or semantic effect"),
    }
    if existing.record.exact_signed_boc_digest.is_some()
        && existing.record.exact_signed_boc_digest != candidate.record.exact_signed_boc_digest
        || existing.record.exact_signed_boc_base64.is_some()
            && candidate.record.status != ControllerActionStatus::Resolved
            && existing.record.exact_signed_boc_base64 != candidate.record.exact_signed_boc_base64
        || existing.record.cancellation_identity.is_some()
            && existing.record.cancellation_identity != candidate.record.cancellation_identity
        || existing.record.cancellation_boc_base64.is_some()
            && candidate.record.status != ControllerActionStatus::Resolved
            && existing.record.cancellation_boc_base64 != candidate.record.cancellation_boc_base64
        || existing.terminal_resolution_digest.is_some()
            && existing.terminal_resolution_digest != candidate.terminal_resolution_digest
    {
        anyhow::bail!("economic stable action changed signed bytes or terminal evidence");
    }
    Ok(())
}

fn restore_hot_economic_record(
    document: &mut JournalDocument,
    permanent: &ControllerActionRecord,
) -> anyhow::Result<()> {
    restore_economic_authority_high_water(document, permanent)?;
    let (stable_action_id, _) = economic_record_identity(permanent)?;
    let matching: Vec<_> = document
        .records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            economic_record_identity(record)
                .ok()
                .and_then(|(candidate, _)| (candidate == stable_action_id).then_some(index))
        })
        .collect();
    if matching.len() > 1 {
        anyhow::bail!("custody journal repeats an owner-wide economic stable action");
    }
    if let Some(index) = matching.first().copied() {
        let hot = &document.records[index];
        if hot.claim != permanent.claim
            || !same_optional_economic_payment(
                hot.economic_authorization.as_ref(),
                permanent.economic_authorization.as_ref(),
            ) && !same_optional_economic_effect(
                hot.economic_effect_authorization.as_ref(),
                permanent.economic_effect_authorization.as_ref(),
            )
        {
            anyhow::bail!("custody hot journal conflicts with permanent semantic action");
        }
        let hot_generation = economic_record_writer_generation(hot)?;
        let permanent_generation = economic_record_writer_generation(permanent)?;
        if action_status_rank(&permanent.status) > action_status_rank(&hot.status)
            || permanent_generation > hot_generation
        {
            document.records[index] = permanent.clone();
        }
        return Ok(());
    }
    if permanent.status == ControllerActionStatus::Resolved {
        return Ok(());
    }
    if document.records.iter().any(|record| {
        generation_key(&record.claim) == generation_key(&permanent.claim)
            && record.status != ControllerActionStatus::Resolved
    }) {
        anyhow::bail!("permanent economic action conflicts with an active controller sequence");
    }
    if document.records.len() >= MAX_TOTAL_RECORDS {
        anyhow::bail!("Agent Account custody journal has too many active records");
    }
    document.records.push(permanent.clone());
    Ok(())
}

fn restore_economic_authority_high_water(
    document: &mut JournalDocument,
    permanent: &ControllerActionRecord,
) -> anyhow::Result<()> {
    let (owner_id, agent_id) = embedded_owner_agent(permanent)?;
    let (authority_id, public_key, writer_generation, writer_fence_digest) =
        embedded_authority(permanent)?;
    let key = economic_authority_key(owner_id, agent_id);
    if let Some(high) = document.economic_authority_high_water.get(&key) {
        if high.authority_id != authority_id || high.public_key != public_key {
            anyhow::bail!("permanent economic action conflicts with the pinned Action Authority");
        }
        if writer_generation < high.writer_generation {
            if permanent.status != ControllerActionStatus::Resolved {
                anyhow::bail!("stale nonterminal economic tombstone cannot be restored");
            }
            return Ok(());
        }
        if writer_generation == high.writer_generation
            && !high.writer_fence_digest.is_empty()
            && high.writer_fence_digest != writer_fence_digest
        {
            anyhow::bail!("economic tombstone equivocates at one writer generation");
        }
    }
    document.economic_authority_high_water.insert(
        key,
        EconomicAuthorityHighWater {
            authority_id: authority_id.to_owned(),
            public_key: public_key.to_owned(),
            writer_generation,
            writer_fence_digest: writer_fence_digest.to_owned(),
        },
    );
    Ok(())
}

fn economic_record_writer_generation(record: &ControllerActionRecord) -> anyhow::Result<u64> {
    match (&record.economic_authorization, &record.economic_effect_authorization) {
        (Some(authorization), None) => Ok(authorization.writer_generation),
        (None, Some(authorization)) => Ok(authorization.writer_generation),
        _ => anyhow::bail!("economic record must have exactly one authorization"),
    }
}

fn same_optional_economic_payment(
    left: Option<&EconomicActionAuthorization>,
    right: Option<&EconomicActionAuthorization>,
) -> bool {
    matches!((left, right), (Some(left), Some(right)) if same_economic_payment(left, right))
}

fn same_optional_economic_effect(
    left: Option<&EconomicEffectAuthorization>,
    right: Option<&EconomicEffectAuthorization>,
) -> bool {
    matches!((left, right), (Some(left), Some(right)) if same_economic_effect(left, right))
}

fn same_unsigned_claim(left: &ControllerActionClaim, right: &ControllerActionClaim) -> bool {
    left.account == right.account
        && left.network_global_id == right.network_global_id
        && left.network_domain == right.network_domain
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

fn same_economic_payment(
    left: &EconomicActionAuthorization,
    right: &EconomicActionAuthorization,
) -> bool {
    left.schema_version == right.schema_version
        && left.authority_id == right.authority_id
        && left.owner_id == right.owner_id
        && left.agent_id == right.agent_id
        && left.source_account == right.source_account
        && left.network_id == right.network_id
        && left.network_global_id == right.network_global_id
        && left.network_domain == right.network_domain
        && left.stable_action_id == right.stable_action_id
        && left.exact_request_digest == right.exact_request_digest
        && left.agreement_payment_request_digest == right.agreement_payment_request_digest
        && left.sponsorship_finality_profile_cbor_digest
            == right.sponsorship_finality_profile_cbor_digest
        && left.sponsorship_release_profile_digest == right.sponsorship_release_profile_digest
        && left.sponsorship_corroboration_snapshot_identity
            == right.sponsorship_corroboration_snapshot_identity
        && left.policy_revision == right.policy_revision
        && left.mandate_digest == right.mandate_digest
        && left.approval_digest_or_zero == right.approval_digest_or_zero
        && left.agreement_body_digest == right.agreement_body_digest
        && left.obligation_instance_id == right.obligation_instance_id
        && left.destination == right.destination
        && left.amount_atomic == right.amount_atomic
        && left.expires_at_unix == right.expires_at_unix
        && left.public_key == right.public_key
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
        && left.network_domain == right.network_domain
        && left.action_kind == right.action_kind
        && left.stable_action_id == right.stable_action_id
        && left.exact_request_digest == right.exact_request_digest
        && left.policy_revision == right.policy_revision
        && left.mandate_digest == right.mandate_digest
        && left.approval_digest_or_zero == right.approval_digest_or_zero
        && left.agreement_body_digest == right.agreement_body_digest
        && left.obligation_id == right.obligation_id
        && left.destination == right.destination
        && left.amount_nanotos == right.amount_nanotos
        && left.body_hash == right.body_hash
        && left.state_init_hash_or_zero == right.state_init_hash_or_zero
        && left.expires_at_unix == right.expires_at_unix
        && left.public_key == right.public_key
}

fn validate_claim(claim: &ControllerActionClaim) -> anyhow::Result<()> {
    validate_generation(&claim.account, claim.network_global_id, &claim.deployment_id)?;
    if let Some(network) = &claim.network_domain {
        validate_network_domain(network)?;
        let source = claim
            .account
            .parse::<MsgAddressInt>()
            .context("controller claim source account is invalid")?;
        if network.global_id != claim.network_global_id
            || network.workchain_id != source.workchain_id()
        {
            anyhow::bail!("controller claim network pin conflicts with its global ID or workchain");
        }
    }
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
        exact_winner_resolution: None,
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
    let network_domain = authorization
        .network_domain
        .as_ref()
        .context("economic authorization has no full network-domain pin")?;
    validate_network_domain(network_domain)?;
    let payment_request_digest_valid = match authorization.schema_version {
        2 => {
            authorization.agreement_payment_request_digest.is_none()
                && authorization.sponsorship_finality_profile_cbor_digest.is_none()
                && authorization.sponsorship_release_profile_digest.is_none()
                && authorization.sponsorship_corroboration_snapshot_identity.is_none()
        }
        3 => authorization
            .agreement_payment_request_digest
            .as_ref()
            .is_some_and(|value| valid_digest(value)),
        _ => false,
    };
    let sponsorship_binding_valid = match (
        &authorization.sponsorship_finality_profile_cbor_digest,
        &authorization.sponsorship_release_profile_digest,
        &authorization.sponsorship_corroboration_snapshot_identity,
    ) {
        (None, None, None) => true,
        (Some(finality), Some(release), Some(snapshot)) => {
            valid_digest(finality) && valid_digest(release) && valid_digest(snapshot)
        }
        _ => false,
    };
    if !payment_request_digest_valid
        || !sponsorship_binding_valid
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
        || authorization.network_id != network_domain.network_id
        || authorization.network_global_id != network_domain.global_id
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
    write_network_domain(&mut output, network_domain)?;
    for value in [&authorization.stable_action_id, &authorization.exact_request_digest] {
        write_lp32(&mut output, value.as_bytes())?;
    }
    if let Some(value) = &authorization.agreement_payment_request_digest {
        write_lp32(&mut output, value.as_bytes())?;
    }
    if let (Some(finality), Some(release), Some(snapshot)) = (
        &authorization.sponsorship_finality_profile_cbor_digest,
        &authorization.sponsorship_release_profile_digest,
        &authorization.sponsorship_corroboration_snapshot_identity,
    ) {
        write_lp32(&mut output, finality.as_bytes())?;
        write_lp32(&mut output, release.as_bytes())?;
        write_lp32(&mut output, snapshot.as_bytes())?;
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
    let network_domain = authorization
        .network_domain
        .as_ref()
        .context("economic effect has no full network-domain pin")?;
    validate_network_domain(network_domain)?;
    if authorization.schema_version != 2
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
        || authorization.network_id != network_domain.network_id
        || authorization.network_global_id != network_domain.global_id
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
    write_network_domain(&mut output, network_domain)?;
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

fn write_network_domain(
    output: &mut Vec<u8>,
    network: &RelayNetworkDomainPin,
) -> anyhow::Result<()> {
    write_lp32(output, network.network_id.as_bytes())?;
    output.extend_from_slice(&network.global_id.to_be_bytes());
    write_lp32(output, network.zero_state_root_hash.as_bytes())?;
    write_lp32(output, network.zero_state_file_hash.as_bytes())?;
    output.extend_from_slice(&network.workchain_id.to_be_bytes());
    Ok(())
}

fn validate_network_domain(network: &RelayNetworkDomainPin) -> anyhow::Result<()> {
    if network.network_id.is_empty()
        || network.network_id.len() > 128
        || !network.network_id.bytes().all(|byte| byte.is_ascii_graphic())
        || network.global_id == 0
        || !valid_digest(&network.zero_state_root_hash)
        || !valid_digest(&network.zero_state_file_hash)
    {
        anyhow::bail!("invalid full TOS network-domain pin");
    }
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

/// Canonical task-body identity used by claims, signed-BOC custody, and
/// finalized-effect reconciliation. Representation hash is intentional: it
/// commits to the complete TVM cell including its level/exotic semantics.
pub fn agent_account_task_body_hash(body: &Cell) -> String {
    format!("tvm-cell-sha256:{}", hex::encode(body.repr_hash()))
}

fn validate_signed_boc(
    claim: &ControllerActionClaim,
    encoded: &str,
    expected_digest: Option<&str>,
    expected_action: ExpectedAction,
) -> anyhow::Result<()> {
    let bytes = base64_decode(encoded).context("decode signed Agent Account BOC")?;
    validate_exact_boc_before_broadcast(&bytes)
        .context("signed Agent Account BOC failed the shared exact-BOC gate")?;
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
            let actual = agent_account_task_body_hash(&task_body);
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
        if let Some(resolution) = &record.exact_winner_resolution {
            validate_resolution_evidence(resolution)?;
            if record.status != ControllerActionStatus::Resolved {
                anyhow::bail!("nonterminal custody record contains exact winner evidence");
            }
        }
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
                || record.claim.network_domain != authorization.network_domain
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
                || record.claim.network_domain != authorization.network_domain
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

pub fn controller_resolution_evidence_digest(
    evidence_kind: &str,
    evidence: &serde_json::Value,
) -> anyhow::Result<String> {
    if evidence_kind.is_empty()
        || evidence_kind.len() > 128
        || evidence_kind.bytes().any(|byte| byte.is_ascii_control())
    {
        anyhow::bail!("exact winner evidence kind is invalid");
    }
    let encoded = serde_json::to_vec(evidence)?;
    if encoded.is_empty() || encoded.len() > 1 << 20 {
        anyhow::bail!("exact winner evidence has invalid size");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"tos.agent-account.exact-winner-resolution.v1\0");
    hasher.update((evidence_kind.len() as u16).to_be_bytes());
    hasher.update(evidence_kind.as_bytes());
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_resolution_evidence(
    resolution: &ControllerActionResolutionEvidence,
) -> anyhow::Result<()> {
    let digest =
        controller_resolution_evidence_digest(&resolution.evidence_kind, &resolution.evidence)?;
    if resolution.evidence_digest != digest {
        anyhow::bail!("exact winner evidence digest is inconsistent");
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

    #[test]
    fn task_body_identity_uses_representation_hash_for_ordinary_and_exotic_cells() {
        for body in [Cell::default(), Cell::default().as_library_cell()] {
            assert_eq!(
                agent_account_task_body_hash(&body),
                format!("tvm-cell-sha256:{}", hex::encode(body.repr_hash()))
            );
        }
    }

    fn claim(seqno: u32, marker: char) -> ControllerActionClaim {
        ControllerActionClaim {
            account: MsgAddressInt::with_standart(None, -1, [0x11; 32].into()).unwrap().to_string(),
            network_global_id: 42,
            network_domain: Some(RelayNetworkDomainPin {
                network_id: "tos:testnet".into(),
                global_id: 42,
                zero_state_root_hash: format!("sha256:{}", "a".repeat(64)),
                zero_state_file_hash: format!("sha256:{}", "b".repeat(64)),
                workchain_id: -1,
            }),
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

    #[test]
    fn permanent_replay_ledger_reserves_capacity_only_for_new_actions() {
        let fully_reserved = usize::try_from(
            MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES / MAX_ECONOMIC_ACTION_TOMBSTONE_BYTES,
        )
        .unwrap();
        let usage = EconomicTombstoneUsage {
            count: fully_reserved,
            persistent_bytes: u64::try_from(fully_reserved).unwrap(),
        };
        enforce_economic_tombstone_capacity(usage, false)
            .expect("existing actions remain readable and transitionable at reserved capacity");
        assert!(
            enforce_economic_tombstone_capacity(usage, true).is_err(),
            "a new semantic action must reserve its worst-case bytes before side-effect state"
        );
        assert!(
            enforce_economic_tombstone_capacity(
                EconomicTombstoneUsage {
                    count: 1,
                    persistent_bytes: MAX_ECONOMIC_ACTION_TOMBSTONE_TOTAL_BYTES + 1,
                },
                false,
            )
            .is_err(),
            "an aggregate-byte-overfull ledger must fail closed at load"
        );
    }

    #[cfg(unix)]
    #[test]
    fn permanent_replay_ledger_scan_stays_on_the_pinned_directory_after_path_swap() {
        use std::os::unix::fs::PermissionsExt;

        fn write_private(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let parent = tempfile::tempdir().unwrap();
        let original = parent.path().join("custody");
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = AgentAccountCustodyJournal::open(original.canonicalize().unwrap()).unwrap();

        let pinned = parent.path().join("pinned-custody");
        fs::rename(&original, &pinned).unwrap();
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(
            &pinned.join(format!("{ECONOMIC_ACTION_TOMBSTONE_PREFIX}{}.json", "a".repeat(64))),
            b"{}",
        );
        write_private(
            &original.join(format!("{ECONOMIC_ACTION_TOMBSTONE_PREFIX}{}.json", "b".repeat(64))),
            b"replacement-path-data-must-not-be-counted",
        );

        assert_eq!(
            journal.economic_action_tombstone_usage().unwrap(),
            EconomicTombstoneUsage { count: 1, persistent_bytes: 2 }
        );
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
            schema_version: 2,
            authority_id: "authority:owner".into(),
            owner_id: "owner:1".into(),
            agent_id: "agent:buyer".into(),
            source_account: claim.account.clone(),
            network_id: "tos:testnet".into(),
            network_global_id: claim.network_global_id,
            network_domain: claim.network_domain.clone(),
            stable_action_id: claim.action_identity.clone(),
            exact_request_digest: format!("sha256:{}", "2".repeat(64)),
            agreement_payment_request_digest: None,
            sponsorship_finality_profile_cbor_digest: None,
            sponsorship_release_profile_digest: None,
            sponsorship_corroboration_snapshot_identity: None,
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
            schema_version: 2,
            authority_id: "authority:owner".into(),
            owner_id: "owner:1".into(),
            agent_id: "agent:buyer".into(),
            source_account: claim.account.clone(),
            network_id: "tos:testnet".into(),
            network_global_id: claim.network_global_id,
            network_domain: claim.network_domain.clone(),
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
    fn custody_v2_preimages_match_the_go_protocol_vectors() {
        let action = EconomicActionAuthorization {
            schema_version: 2,
            authority_id: "authority:owner".into(),
            owner_id: "owner:1".into(),
            agent_id: "agent:buyer".into(),
            source_account: "-1:source".into(),
            network_id: "tos:testnet".into(),
            network_global_id: 42,
            network_domain: Some(RelayNetworkDomainPin {
                network_id: "tos:testnet".into(),
                global_id: 42,
                zero_state_root_hash: format!("sha256:{}", "a".repeat(64)),
                zero_state_file_hash: format!("sha256:{}", "b".repeat(64)),
                workchain_id: -1,
            }),
            stable_action_id: format!("sha256:{}", "1".repeat(64)),
            exact_request_digest: format!("sha256:{}", "2".repeat(64)),
            agreement_payment_request_digest: None,
            sponsorship_finality_profile_cbor_digest: None,
            sponsorship_release_profile_digest: None,
            sponsorship_corroboration_snapshot_identity: None,
            writer_generation: 7,
            writer_fence_digest: format!("sha256:{}", "3".repeat(64)),
            policy_revision: 4,
            mandate_digest: format!("sha256:{}", "4".repeat(64)),
            approval_digest_or_zero: format!("sha256:{}", "0".repeat(64)),
            agreement_body_digest: format!("sha256:{}", "5".repeat(64)),
            obligation_instance_id: format!("sha256:{}", "6".repeat(64)),
            destination: "0:destination".into(),
            amount_atomic: 50,
            expires_at_unix: 1_800_000_060,
            public_key: String::new(),
            proof: String::new(),
        };
        assert_eq!(
            hex::encode(Sha256::digest(economic_authorization_preimage(&action).unwrap())),
            "8b2d089f841741ea4157783d141107b49420b98bbe5cae5c0aa74591b14e0502"
        );
        let mut v3 = action.clone();
        v3.schema_version = 3;
        v3.agreement_payment_request_digest = Some(format!("sha256:{}", "7".repeat(64)));
        let v3_preimage = economic_authorization_preimage(&v3).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&v3_preimage)),
            "007e848255182c6b9129c98138275540a9551ac8d0d742e8544ee0d0c51af749"
        );
        v3.sponsorship_finality_profile_cbor_digest = Some(format!("sha256:{}", "8".repeat(64)));
        v3.sponsorship_release_profile_digest = Some(format!("sha256:{}", "9".repeat(64)));
        v3.sponsorship_corroboration_snapshot_identity = Some(format!("sha256:{}", "a".repeat(64)));
        assert_eq!(
            hex::encode(Sha256::digest(economic_authorization_preimage(&v3).unwrap())),
            "bf8b0b09ec57d200f745e2f170abe10c8c3bc6fd3b78e442829d9ef105524ce2"
        );
        v3.sponsorship_finality_profile_cbor_digest = None;
        v3.sponsorship_release_profile_digest = None;
        v3.sponsorship_corroboration_snapshot_identity = None;
        v3.sponsorship_finality_profile_cbor_digest = Some(format!("sha256:{}", "8".repeat(64)));
        assert!(economic_authorization_preimage(&v3).is_err());
        v3.sponsorship_finality_profile_cbor_digest = None;
        v3.agreement_payment_request_digest = None;
        assert!(economic_authorization_preimage(&v3).is_err());

        let effect = EconomicEffectAuthorization {
            schema_version: 2,
            authority_id: "authority:one".into(),
            owner_id: "owner:one".into(),
            agent_id: "agent:buyer".into(),
            source_account: format!("0:{}", "1".repeat(64)),
            network_id: "tos:test".into(),
            network_global_id: -3,
            network_domain: Some(RelayNetworkDomainPin {
                network_id: "tos:test".into(),
                global_id: -3,
                zero_state_root_hash: format!("sha256:{}", "a".repeat(64)),
                zero_state_file_hash: format!("sha256:{}", "b".repeat(64)),
                workchain_id: 0,
            }),
            action_kind: "escrow.accept".into(),
            stable_action_id: format!("sha256:{}", "2".repeat(64)),
            exact_request_digest: format!("sha256:{}", "3".repeat(64)),
            writer_generation: 4,
            writer_fence_digest: format!("sha256:{}", "4".repeat(64)),
            policy_revision: 5,
            mandate_digest: format!("sha256:{}", "5".repeat(64)),
            approval_digest_or_zero: format!("sha256:{}", "0".repeat(64)),
            agreement_body_digest: format!("sha256:{}", "6".repeat(64)),
            obligation_id: "payment:one".into(),
            destination: format!("0:{}", "7".repeat(64)),
            amount_nanotos: 100_000_000,
            body_hash: format!("tvm-cell-sha256:{}", "8".repeat(64)),
            state_init_hash_or_zero: format!("sha256:{}", "0".repeat(64)),
            expires_at_unix: 2_000_000_060,
            public_key: String::new(),
            proof: String::new(),
        };
        assert_eq!(
            hex::encode(Sha256::digest(economic_effect_authorization_preimage(&effect).unwrap())),
            "fe281488a120f3a60e0d7584f5f9a286071df82e7a477acd990d067fc3f8ca47"
        );
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
        assert!(
            reopened
                .reconcile_finalized_state(
                    &a.account,
                    a.network_global_id,
                    &a.deployment_id,
                    a.controller_epoch,
                    4,
                    16,
                )
                .is_err(),
            "seqno advancement alone must not choose the primary over a cancellation or unrelated winner"
        );
        assert!(reopened.claim_primary(next, 17).is_err());
        let unresolved = reopened
            .find_primary(
                &a.account,
                a.network_global_id,
                &a.deployment_id,
                a.controller_epoch,
                &a.idempotency_key,
            )
            .unwrap()
            .unwrap();
        assert_eq!(unresolved.status, ControllerActionStatus::Broadcasting);
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
    fn exact_payment_broadcast_resume_survives_both_crash_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().canonicalize().unwrap();
        let journal = AgentAccountCustodyJournal::open(path.clone()).unwrap();
        let action = claim(9, 'e');
        journal.claim_primary(action.clone(), 10).unwrap();
        let (boc, digest) = signed_boc(&action, false);
        journal.attach_signed_boc(&action, &boc, &digest, 11).unwrap();

        // Recovery before the durable boundary advances the already-signed
        // action; no new BOC or sequence can be introduced.
        let first = journal.begin_or_resume_exact_broadcast(&action, 12).unwrap();
        assert_eq!(first.status, ControllerActionStatus::Broadcasting);
        assert_eq!(first.exact_signed_boc_base64.as_deref(), Some(boc.as_str()));
        assert_eq!(first.exact_signed_boc_digest.as_deref(), Some(digest.as_str()));

        // Recovery after the boundary, including after a process restart,
        // returns the same immutable bytes so the transport may safely resend
        // that exact transaction.
        let reopened = AgentAccountCustodyJournal::open(path).unwrap();
        let resumed = reopened.begin_or_resume_exact_broadcast(&action, 13).unwrap();
        assert_eq!(resumed.status, ControllerActionStatus::Broadcasting);
        assert_eq!(resumed.exact_signed_boc_base64, first.exact_signed_boc_base64);
        assert_eq!(resumed.exact_signed_boc_digest, first.exact_signed_boc_digest);
        assert_eq!(resumed.claim.seqno, first.claim.seqno);
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
    fn custody_rejects_decoded_boc_over_64k_before_persistence() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let action = claim(0, 'a');
        journal.claim_primary(action.clone(), 1).unwrap();
        let oversized = base64_encode(vec![0_u8; MAX_EXACT_BOC_BYTES + 1]);
        assert!(
            journal
                .attach_signed_boc(&action, &oversized, &format!("sha256:{}", "f".repeat(64)), 2,)
                .is_err()
        );
        let record = journal
            .find_primary(
                &action.account,
                action.network_global_id,
                &action.deployment_id,
                action.controller_epoch,
                &action.idempotency_key,
            )
            .unwrap()
            .unwrap();
        assert_eq!(record.status, ControllerActionStatus::Claimed);
        assert!(record.exact_signed_boc_base64.is_none());
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
        let mut other_genesis = economic_authorization(&first, 7, &key);
        other_genesis.network_domain.as_mut().unwrap().zero_state_file_hash =
            format!("sha256:{}", "c".repeat(64));
        let digest = Sha256::digest(economic_authorization_preimage(&other_genesis).unwrap());
        other_genesis.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));
        assert!(
            journal
                .claim_economic_payment(
                    first.clone(),
                    other_genesis,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .is_err(),
            "a valid authority signature for another genesis must not match the custody claim"
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

        assert!(
            journal
                .reconcile_finalized_state(
                    &first.account,
                    first.network_global_id,
                    &first.deployment_id,
                    first.controller_epoch,
                    1,
                    12,
                )
                .is_err()
        );
        journal
            .retire_generation(&first.account, first.network_global_id, &first.deployment_id, 2_000)
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
    fn sponsorship_payment_requires_exact_task_send_request_commitment() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x72; 32]);
        let mut native = claim(0, 'd');
        native.idempotency_key = "d".repeat(64);
        let mut authorization = economic_authorization(&native, 3, &key);
        authorization.schema_version = 3;
        authorization.agreement_payment_request_digest = Some(format!("sha256:{}", "7".repeat(64)));
        authorization.sponsorship_finality_profile_cbor_digest =
            Some(format!("sha256:{}", "8".repeat(64)));
        authorization.sponsorship_release_profile_digest =
            Some(format!("sha256:{}", "9".repeat(64)));
        authorization.sponsorship_corroboration_snapshot_identity =
            Some(format!("sha256:{}", "a".repeat(64)));
        let digest = Sha256::digest(economic_authorization_preimage(&authorization).unwrap());
        authorization.proof = format!("ed25519:{}", hex::encode(key.sign(&digest).to_bytes()));

        assert!(
            journal
                .claim_economic_payment(
                    native.clone(),
                    authorization.clone(),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    10,
                )
                .is_err(),
            "a bodyless native send cannot fulfill a sponsorship PaymentRequest"
        );

        let commitment = crate::AgentAccountContract::build_sponsorship_payment_commitment(
            authorization.agreement_payment_request_digest.as_deref().unwrap(),
            &authorization.stable_action_id,
        )
        .unwrap();
        let mut bound = native;
        bound.action_kind = "agent-task-send".into();
        bound.body_hash = Some(format!("tvm-cell-sha256:{}", hex::encode(commitment.hash(0))));
        let mut shorter = bound.clone();
        shorter.valid_until -= 1;
        assert!(
            journal
                .claim_economic_payment(
                    shorter,
                    authorization.clone(),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .is_err(),
            "a sponsorship transaction expiry must exactly match its PaymentRequest authorization"
        );
        assert!(
            journal
                .claim_economic_payment(
                    bound.clone(),
                    authorization.clone(),
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .unwrap()
                .1
        );
        let (signed, signed_digest) = signed_task_boc(&bound, commitment);
        journal.attach_signed_boc(&bound, &signed, &signed_digest, 12).unwrap();

        let mut changed = bound;
        changed.body_hash = Some(format!("tvm-cell-sha256:{}", "f".repeat(64)));
        assert!(
            journal
                .claim_economic_payment(
                    changed,
                    authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    13,
                )
                .is_err()
        );
    }

    #[test]
    fn exact_winner_resolution_is_atomic_replayable_and_conflict_safe() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x64; 32]);
        let mut payment = claim(0, '8');
        payment.idempotency_key = "8".repeat(64);
        journal
            .claim_economic_payment(
                payment.clone(),
                economic_authorization(&payment, 9, &key),
                "authority:owner",
                key.verifying_key().to_bytes(),
                100,
            )
            .unwrap();
        let (boc, boc_digest) = signed_boc(&payment, false);
        journal.attach_signed_boc(&payment, &boc, &boc_digest, 101).unwrap();
        journal.begin_broadcast(&payment, 102).unwrap();
        let recovered = journal.action_by_idempotency_key(&payment.idempotency_key).unwrap();
        assert_eq!(recovered.claim, payment);
        assert_eq!(recovered.status, ControllerActionStatus::Broadcasting);
        assert!(journal.action_by_idempotency_key("not-a-canonical-action-id").is_err());

        let evidence = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-finalized.v1",
            "stable_action_id": payment.action_identity,
            "transaction_hash": format!("sha256:{}", "9".repeat(64)),
        });
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: "tosctl.agent-account.agreement-payment-finalized.v1".into(),
            evidence_digest: controller_resolution_evidence_digest(
                "tosctl.agent-account.agreement-payment-finalized.v1",
                &evidence,
            )
            .unwrap(),
            evidence,
        };
        let resolved = journal
            .resolve_exact_winner(
                &payment,
                &boc_digest,
                payment.controller_epoch,
                1,
                resolution.clone(),
                103,
            )
            .unwrap();
        assert_eq!(resolved.status, ControllerActionStatus::Resolved);
        assert_eq!(resolved.exact_winner_resolution.as_ref(), Some(&resolution));

        // A crash after the durable transition can reopen the journal and
        // recover exactly the same evidence without a chain query.
        drop(journal);
        let reopened =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let replay = reopened
            .find_economic_payment_by_stable_action(&payment.action_identity)
            .unwrap()
            .unwrap();
        assert_eq!(replay.status, ControllerActionStatus::Resolved);
        assert_eq!(replay.exact_winner_resolution.as_ref(), Some(&resolution));
        assert!(replay.exact_signed_boc_base64.is_none());
        reopened
            .resolve_exact_winner(
                &payment,
                &boc_digest,
                payment.controller_epoch,
                1,
                resolution.clone(),
                104,
            )
            .unwrap();

        let changed_evidence = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-finalized.v1",
            "stable_action_id": payment.action_identity,
            "transaction_hash": format!("sha256:{}", "a".repeat(64)),
        });
        let changed = ControllerActionResolutionEvidence {
            evidence_kind: resolution.evidence_kind.clone(),
            evidence_digest: controller_resolution_evidence_digest(
                &resolution.evidence_kind,
                &changed_evidence,
            )
            .unwrap(),
            evidence: changed_evidence,
        };
        assert!(
            reopened
                .resolve_exact_winner(
                    &payment,
                    &boc_digest,
                    payment.controller_epoch,
                    1,
                    changed,
                    105,
                )
                .is_err()
        );
    }

    #[test]
    fn exact_absence_resolution_is_atomic_replayable_and_conflict_safe() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let mut payment = claim(0, '9');
        payment.idempotency_key = "9".repeat(64);
        journal
            .claim_economic_payment(
                payment.clone(),
                economic_authorization(&payment, 10, &key),
                "authority:owner",
                key.verifying_key().to_bytes(),
                200,
            )
            .unwrap();
        let (boc, boc_digest) = signed_boc(&payment, false);
        journal.attach_signed_boc(&payment, &boc, &boc_digest, 201).unwrap();

        let evidence = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1",
            "sponsorship_stable_action_id": payment.action_identity,
            "state": "corroborated_sponsorship_absent",
            "proof_bundle_digest": format!("sha256:{}", "b".repeat(64)),
        });
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind:
                "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1".into(),
            evidence_digest: controller_resolution_evidence_digest(
                "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1",
                &evidence,
            )
            .unwrap(),
            evidence,
        };
        let resolved = journal
            .resolve_exact_absence(
                &payment,
                &boc_digest,
                payment.controller_epoch,
                payment.seqno,
                resolution.clone(),
                202,
            )
            .unwrap();
        assert_eq!(resolved.status, ControllerActionStatus::Resolved);
        assert_eq!(resolved.exact_winner_resolution.as_ref(), Some(&resolution));

        drop(journal);
        let reopened =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let replay = reopened
            .find_economic_payment_by_stable_action(&payment.action_identity)
            .unwrap()
            .unwrap();
        assert_eq!(replay.status, ControllerActionStatus::Resolved);
        assert_eq!(replay.exact_winner_resolution.as_ref(), Some(&resolution));
        assert!(replay.exact_signed_boc_base64.is_none());
        reopened
            .resolve_exact_absence(
                &payment,
                &boc_digest,
                payment.controller_epoch,
                payment.seqno,
                resolution.clone(),
                203,
            )
            .unwrap();

        let changed_evidence = serde_json::json!({
            "schema": "tosctl.agent-account.agreement-payment-sponsorship-component-absence.v1",
            "sponsorship_stable_action_id": payment.action_identity,
            "state": "corroborated_sponsorship_absent",
            "proof_bundle_digest": format!("sha256:{}", "c".repeat(64)),
        });
        let changed = ControllerActionResolutionEvidence {
            evidence_kind: resolution.evidence_kind.clone(),
            evidence_digest: controller_resolution_evidence_digest(
                &resolution.evidence_kind,
                &changed_evidence,
            )
            .unwrap(),
            evidence: changed_evidence,
        };
        assert!(
            reopened
                .resolve_exact_absence(
                    &payment,
                    &boc_digest,
                    payment.controller_epoch,
                    payment.seqno,
                    changed,
                    204,
                )
                .is_err()
        );
        assert!(
            reopened
                .resolve_exact_absence(
                    &payment,
                    &format!("sha256:{}", "d".repeat(64)),
                    payment.controller_epoch,
                    payment.seqno,
                    resolution,
                    205,
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
        assert!(
            journal
                .reconcile_finalized_state(
                    &stale.account,
                    stale.network_global_id,
                    &stale.deployment_id,
                    stale.controller_epoch,
                    1,
                    13,
                )
                .is_err()
        );
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

        let refreshed_claim = effect.clone();
        let mut takeover = economic_effect_authorization(&refreshed_claim, 21, &key);
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
        assert!(
            journal
                .claim_economic_effect(
                    later_claim.clone(),
                    later,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    13,
                )
                .is_err(),
            "takeover cannot change the frozen source expiry after stable-action admission"
        );
        let same_claim_later = economic_effect_authorization(&refreshed_claim, 22, &key);
        let (recovered_signed, _) = journal
            .claim_economic_effect(
                refreshed_claim.clone(),
                same_claim_later,
                "authority:owner",
                key.verifying_key().to_bytes(),
                14,
            )
            .unwrap();
        assert_eq!(recovered_signed.status, ControllerActionStatus::Signed);
        assert_eq!(recovered_signed.claim.valid_until, refreshed_claim.valid_until);
        assert_eq!(recovered_signed.exact_signed_boc_digest.as_deref(), Some(boc_digest.as_str()));

        let stale = economic_effect_authorization(&refreshed_claim, 21, &key);
        assert!(
            journal
                .claim_economic_effect(
                    refreshed_claim.clone(),
                    stale,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    14,
                )
                .is_err()
        );
        let mut changed = refreshed_claim;
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

    #[test]
    fn permanent_payment_tombstone_survives_hot_compaction_and_source_rotation() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().canonicalize().unwrap();
        let journal = AgentAccountCustodyJournal::open(path.clone()).unwrap();
        let key = SigningKey::from_bytes(&[0x72; 32]);
        let mut payment = claim(0, 'c');
        payment.idempotency_key = "c".repeat(64);
        let authorization = economic_authorization(&payment, 30, &key);
        journal
            .claim_economic_payment(
                payment.clone(),
                authorization.clone(),
                "authority:owner",
                key.verifying_key().to_bytes(),
                10,
            )
            .unwrap();
        let (boc, digest) = signed_boc(&payment, false);
        journal.attach_signed_boc(&payment, &boc, &digest, 11).unwrap();
        journal.begin_broadcast(&payment, 12).unwrap();
        journal
            .resolve_exact_winner(
                &payment,
                &digest,
                payment.controller_epoch,
                payment.seqno + 1,
                ControllerActionResolutionEvidence {
                    evidence_kind: "test.finalized.v1".into(),
                    evidence_digest: controller_resolution_evidence_digest(
                        "test.finalized.v1",
                        &serde_json::json!({"stable_action_id": payment.action_identity}),
                    )
                    .unwrap(),
                    evidence: serde_json::json!({"stable_action_id": payment.action_identity}),
                },
                13,
            )
            .unwrap();

        // Simulate more than the bounded hot terminal retention window. These
        // records are deliberately non-economic: the assertion is that the
        // old economic identity lives in its permanent per-action registry,
        // not that every unrelated test record creates another registry file.
        journal
            .with_document(|document| {
                for index in 0..=MAX_RETAINED_RESOLVED_RECORDS {
                    let mut later = claim(u32::try_from(index + 2).unwrap(), 'd');
                    let identity =
                        format!("{:064x}", u64::try_from(index).unwrap().saturating_add(10_000));
                    later.idempotency_key = identity.clone();
                    later.action_identity = format!("sha256:{identity}");
                    document.records.push(ControllerActionRecord {
                        claim: later,
                        status: ControllerActionStatus::Resolved,
                        exact_signed_boc_base64: None,
                        exact_signed_boc_digest: None,
                        cancellation_identity: None,
                        cancellation_boc_base64: None,
                        economic_authorization: None,
                        economic_effect_authorization: None,
                        exact_winner_resolution: None,
                        created_at_unix: 100 + u64::try_from(index).unwrap(),
                        updated_at_unix: 100 + u64::try_from(index).unwrap(),
                    });
                }
                compact_records(document);
                assert!(
                    document
                        .records
                        .iter()
                        .all(|record| { record.claim.action_identity != payment.action_identity })
                );
                Ok(())
            })
            .unwrap();
        drop(journal);

        let reopened = AgentAccountCustodyJournal::open(path).unwrap();
        let recovered = reopened
            .find_economic_payment_by_stable_action(&payment.action_identity)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.status, ControllerActionStatus::Resolved);
        assert_eq!(recovered.claim, payment);
        assert!(recovered.exact_winner_resolution.is_some());

        let mut other_account = payment.clone();
        other_account.account =
            MsgAddressInt::with_standart(None, -1, [0x33; 32].into()).unwrap().to_string();
        let other_authorization = economic_authorization(&other_account, 31, &key);
        assert!(
            reopened
                .claim_economic_payment(
                    other_account,
                    other_authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    14,
                )
                .is_err(),
            "the same stable payment cannot move to another source account"
        );

        let mut other_deployment = payment.clone();
        other_deployment.deployment_id = "66".repeat(32);
        let other_deployment_authorization = economic_authorization(&other_deployment, 32, &key);
        assert!(
            reopened
                .claim_economic_payment(
                    other_deployment,
                    other_deployment_authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    15,
                )
                .is_err(),
            "the same stable payment cannot move to another deployment"
        );
    }

    #[test]
    fn permanent_effect_tombstone_rejects_cross_account_replay_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().canonicalize().unwrap();
        let journal = AgentAccountCustodyJournal::open(path.clone()).unwrap();
        let key = SigningKey::from_bytes(&[0x73; 32]);
        let body = Cell::default();
        let mut effect = claim(0, 'e');
        effect.idempotency_key = "e".repeat(64);
        effect.action_kind = "agent-task-send".into();
        effect.body_hash = Some(format!("tvm-cell-sha256:{}", hex::encode(body.hash(0))));
        let authorization = economic_effect_authorization(&effect, 40, &key);
        journal
            .claim_economic_effect(
                effect.clone(),
                authorization,
                "authority:owner",
                key.verifying_key().to_bytes(),
                10,
            )
            .unwrap();
        drop(journal);

        let reopened = AgentAccountCustodyJournal::open(path).unwrap();
        let mut moved = effect;
        moved.account =
            MsgAddressInt::with_standart(None, -1, [0x44; 32].into()).unwrap().to_string();
        let moved_authorization = economic_effect_authorization(&moved, 41, &key);
        assert!(
            reopened
                .claim_economic_effect(
                    moved,
                    moved_authorization,
                    "authority:owner",
                    key.verifying_key().to_bytes(),
                    11,
                )
                .is_err(),
            "generic economic effects share the same permanent owner-wide replay boundary"
        );
    }
}
