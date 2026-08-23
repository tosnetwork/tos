use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "tos.agent-account.controller-journal.v1";
const JOURNAL_FILE: &str = "controller-actions.json";
const LOCK_FILE: &str = "controller-actions.lock";
const MAX_JOURNAL_BYTES: u64 = 32 << 20;

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
    pub seqno: u32,
    pub action_kind: String,
    pub idempotency_key: String,
    pub action_identity: String,
    pub valid_until: u32,
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
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct JournalDocument {
    schema: String,
    #[serde(default)]
    high_water_seqno: std::collections::BTreeMap<String, u32>,
    records: Vec<ControllerActionRecord>,
}

pub struct AgentAccountCustodyJournal {
    directory: PathBuf,
}

impl AgentAccountCustodyJournal {
    pub fn open(directory: impl AsRef<Path>) -> anyhow::Result<Self> {
        let directory = directory.as_ref();
        if !directory.is_absolute() {
            anyhow::bail!("Agent Account custody journal path must be absolute");
        }
        fs::create_dir_all(directory)?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!("Agent Account custody journal must be a real directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if metadata.permissions().mode() & 0o777 != 0o700 {
                anyhow::bail!("Agent Account custody journal directory must have mode 0700");
            }
            let lock_path = directory.join(LOCK_FILE);
            let _ = OpenOptions::new().create(true).write(true).mode(0o600).open(lock_path)?;
        }
        let journal = Self { directory: directory.to_path_buf() };
        journal.with_document(|_| Ok(()))?;
        Ok(journal)
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
        self.with_document(|document| {
            if let Some(high) = document.high_water_seqno.get(&claim.account) {
                if claim.seqno < *high {
                    anyhow::bail!(
                        "Agent Account seqno rollback/redeployment requires explicit owner recovery"
                    );
                }
            }
            if let Some(record) = document.records.iter().find(|record| {
                record.claim.account == claim.account
                    && record.claim.idempotency_key == claim.idempotency_key
            }) {
                if record.claim.action_kind != claim.action_kind
                    || record.claim.network_global_id != claim.network_global_id
                    || record.claim.action_identity != claim.action_identity
                {
                    anyhow::bail!("controller action identity was reused with different semantics");
                }
                return Ok((record.clone(), false));
            }
            for record in &mut document.records {
                if record.claim.account != claim.account
                    || record.status == ControllerActionStatus::Resolved
                {
                    continue;
                }
                if record.claim == claim {
                    return Ok((record.clone(), false));
                }
                anyhow::bail!(
                    "another primary controller action already owns this Agent Account sequence"
                );
            }
            document
                .high_water_seqno
                .entry(claim.account.clone())
                .and_modify(|v| *v = (*v).max(claim.seqno))
                .or_insert(claim.seqno);
            let record = ControllerActionRecord {
                claim,
                status: ControllerActionStatus::Claimed,
                exact_signed_boc_base64: None,
                exact_signed_boc_digest: None,
                cancellation_identity: None,
                cancellation_boc_base64: None,
                created_at_unix: now,
                updated_at_unix: now,
            };
            document.records.push(record.clone());
            Ok((record, true))
        })
    }

    pub fn find_primary(
        &self,
        account: &str,
        idempotency_key: &str,
    ) -> anyhow::Result<Option<ControllerActionRecord>> {
        if account.is_empty() || !valid_idempotency_key(idempotency_key) {
            anyhow::bail!("invalid controller action lookup");
        }
        self.with_document(|document| {
            Ok(document
                .records
                .iter()
                .find(|record| {
                    record.claim.account == account
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

    pub fn resolve(
        &self,
        claim: &ControllerActionClaim,
        now: u64,
    ) -> anyhow::Result<ControllerActionRecord> {
        self.mutate_exact(claim, |record| {
            record.status = ControllerActionStatus::Resolved;
            record.updated_at_unix = now;
            Ok(())
        })
    }

    pub fn reconcile_finalized_seqno(
        &self,
        account: &str,
        finalized_seqno: u32,
        now: u64,
    ) -> anyhow::Result<()> {
        self.with_document(|document| {
            if let Some(high) = document.high_water_seqno.get(account) {
                if finalized_seqno < *high { anyhow::bail!("Agent Account finalized seqno rolled back; refusing replay after redeployment"); }
            }
            for record in &mut document.records {
                if record.claim.account == account && record.status != ControllerActionStatus::Resolved && finalized_seqno > record.claim.seqno {
                    record.status = ControllerActionStatus::Resolved; record.updated_at_unix = now;
                }
            }
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
        let lock_path = self.directory.join(LOCK_FILE);
        let lock = OpenOptions::new().create(true).read(true).write(true).open(&lock_path)?;
        lock.lock_exclusive()?;
        let path = self.directory.join(JOURNAL_FILE);
        let mut document = if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > MAX_JOURNAL_BYTES
            {
                anyhow::bail!("invalid Agent Account custody journal file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    anyhow::bail!("Agent Account custody journal file must have mode 0600");
                }
            }
            let mut raw = Vec::with_capacity(metadata.len() as usize);
            File::open(&path)?.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut raw)?;
            let parsed: JournalDocument =
                serde_json::from_slice(&raw).context("decode Agent Account custody journal")?;
            if parsed.schema != SCHEMA {
                anyhow::bail!("unknown Agent Account custody journal schema");
            }
            parsed
        } else {
            JournalDocument { schema: SCHEMA.to_owned(), ..Default::default() }
        };
        let result = operation(&mut document)?;
        self.persist(&path, &document)?;
        FileExt::unlock(&lock)?;
        Ok(result)
    }

    fn persist(&self, path: &Path, document: &JournalDocument) -> anyhow::Result<()> {
        let raw = serde_json::to_vec(document)?;
        if raw.len() as u64 > MAX_JOURNAL_BYTES {
            anyhow::bail!("Agent Account custody journal exceeds size limit");
        }
        let temporary = self.directory.join(format!(
            ".controller-actions.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

fn validate_claim(claim: &ControllerActionClaim) -> anyhow::Result<()> {
    if claim.account.is_empty()
        || claim.account.len() > 128
        || claim.network_global_id == 0
        || claim.action_kind.is_empty()
        || claim.action_kind.len() > 64
        || !valid_idempotency_key(&claim.idempotency_key)
        || !valid_digest(&claim.action_identity)
        || claim.valid_until == 0
    {
        anyhow::bail!("invalid controller action claim");
    }
    Ok(())
}
fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_idempotency_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claim(seqno: u32, marker: char) -> ControllerActionClaim {
        ControllerActionClaim {
            account: "-1:abc".into(),
            network_global_id: 42,
            seqno,
            action_kind: "agent-native-send".into(),
            idempotency_key: "1".repeat(64),
            action_identity: format!("sha256:{}", marker.to_string().repeat(64)),
            valid_until: 2000,
        }
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
        journal.attach_signed_boc(&a, "Ym9j", &format!("sha256:{}", "c".repeat(64)), 12).unwrap();
        journal.begin_broadcast(&a, 13).unwrap();
        assert!(journal.begin_broadcast(&a, 14).is_err());
        let reopened =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let mut next = claim(4, 'd');
        next.idempotency_key = "2".repeat(64);
        assert!(reopened.claim_primary(next.clone(), 15).is_err());
        reopened.reconcile_finalized_seqno(&a.account, 4, 16).unwrap();
        assert!(reopened.claim_primary(next, 17).unwrap().1);
        assert!(reopened.reconcile_finalized_seqno(&a.account, 2, 18).is_err());
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
        let digest = format!("sha256:{}", "b".repeat(64));
        journal.attach_signed_boc(&a, "Ym9j", &digest, 2).unwrap();
        assert!(journal.attach_signed_boc(&a, "Ym9jMg==", &digest, 3).is_err());
        let cancel = format!("sha256:{}", "c".repeat(64));
        journal.authorize_cancellation(&a, &cancel, "Y2FuY2Vs", 4).unwrap();
        assert!(
            journal
                .authorize_cancellation(&a, &format!("sha256:{}", "d".repeat(64)), "eA==", 5)
                .is_err()
        );
    }
}
