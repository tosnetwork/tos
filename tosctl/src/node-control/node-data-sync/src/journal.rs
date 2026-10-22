use crate::{
    model::{FullId, hash},
    safe_io::Root,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreeIdentity {
    pub device: u64,
    pub inode: u64,
}
impl TreeIdentity {
    pub fn read(path: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        ensure!(meta.file_type().is_dir(), "tree must be a real directory");
        Ok(Self { device: meta.dev(), inode: meta.ino() })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Staged,
    ForwardOnly,
    Exchanged,
    StartIssued,
    CatchingUp,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub version: u8,
    pub operation: String,
    pub generation: String,
    pub old: TreeIdentity,
    pub new: TreeIdentity,
    pub installed: String,
    pub staged: String,
    pub preservation_sha256: String,
    pub corroboration_sha256: Option<String>,
    pub target_anchor: FullId,
    pub phase: Phase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    OldRefreshRequired,
    NewContinueOnly,
}
impl Journal {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 2
                && self.operation.len() == 32
                && self.operation.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid restore journal identity"
        );
        hash(&self.generation)?;
        hash(&self.preservation_sha256)?;
        if let Some(hash_value) = &self.corroboration_sha256 {
            hash(hash_value)?;
        }
        self.target_anchor.masterchain()?;
        ensure!(
            self.old.device == self.new.device && self.old.inode != self.new.inode,
            "exchange requires distinct trees on one filesystem"
        );
        ensure!(
            Path::new(&self.installed).is_absolute()
                && Path::new(&self.staged).is_absolute()
                && !Path::new(&self.installed).starts_with(&self.staged)
                && !Path::new(&self.staged).starts_with(&self.installed),
            "invalid journal roots"
        );
        Ok(())
    }
    pub fn write(&self, operation: &Root) -> Result<()> {
        self.validate()?;
        ensure!(
            !operation.path.starts_with(&self.installed)
                && !operation.path.starts_with(&self.staged),
            "journal must survive root replacement outside both trees"
        );
        operation.replace("restore.json", &serde_json::to_vec(self)?)
    }
    pub fn read(operation: &Root) -> Result<Self> {
        let result: Self = serde_json::from_slice(&operation.bytes("restore.json", 1 << 20)?)?;
        result.validate()?;
        Ok(result)
    }
    pub fn reference_binding(&self) -> String {
        crate::model::sha256(
            format!("TOS_NODE_EXPOSURE_V1\0{}{}", self.generation, self.preservation_sha256)
                .as_bytes(),
        )
    }
    pub fn authorize(
        &mut self,
        operation: &Root,
        approval: &crate::references::Corroborated,
    ) -> Result<()> {
        let receipt = approval.receipt()?;
        ensure!(
            receipt.binding_sha256 == self.reference_binding()
                && receipt.frontier.seqno >= self.target_anchor.seqno,
            "reference approval belongs to another preservation revision or precedes its safety anchor"
        );
        let bytes = serde_json::to_vec(&receipt)?;
        operation.replace("corroboration.json", &bytes)?;
        self.corroboration_sha256 = Some(crate::model::sha256(&bytes));
        self.write(operation)
    }
    pub fn check_references(
        &self,
        operation: &Root,
        fresh: bool,
    ) -> Result<crate::references::ReferenceReceipt> {
        let digest = self
            .corroboration_sha256
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restore has no corroboration approval"))?;
        let bytes = operation.bytes("corroboration.json", 1 << 20)?;
        ensure!(&crate::model::sha256(&bytes) == digest, "restore corroboration receipt changed");
        let receipt: crate::references::ReferenceReceipt = serde_json::from_slice(&bytes)?;
        receipt.validate(&receipt.network, &receipt.frontier, &self.reference_binding())?;
        ensure!(
            receipt.frontier.seqno >= self.target_anchor.seqno,
            "reference frontier precedes safety anchor"
        );
        if fresh {
            receipt.ensure_fresh()?;
        }
        Ok(receipt)
    }
    pub fn forward_only(&mut self, operation: &Root) -> Result<()> {
        ensure!(
            self.phase == Phase::Staged,
            "forward-only boundary cannot be cleared or re-entered"
        );
        self.check_references(operation, true)?;
        self.phase = Phase::ForwardOnly;
        self.write(operation)
    }
    pub fn recovery(&self) -> Result<Recovery> {
        self.validate()?;
        let installed = TreeIdentity::read(Path::new(&self.installed))?;
        let staged = TreeIdentity::read(Path::new(&self.staged))?;
        if installed == self.old && staged == self.new {
            return Ok(Recovery::OldRefreshRequired);
        }
        ensure!(
            self.phase != Phase::Staged,
            "replacement exposed before durable forward-only boundary"
        );
        ensure!(installed == self.new && staged == self.old, "restore tree identity is ambiguous");
        ensure!(self.corroboration_sha256.is_some(), "replacement exposed without corroboration");
        Ok(Recovery::NewContinueOnly)
    }
    pub fn exchange(&mut self, operation: &Root) -> Result<()> {
        // The durable no-rollback record must precede any exposure, not just start().
        ensure!(self.phase == Phase::ForwardOnly, "exchange requires durable FORWARD_ONLY");
        let durable = Self::read(operation)?;
        ensure!(durable == *self, "forward-only record is not durable for these trees");
        ensure!(
            self.recovery()? == Recovery::OldRefreshRequired,
            "replacement is already installed"
        );
        self.check_references(operation, true)?;
        atomic_exchange(Path::new(&self.installed), Path::new(&self.staged))?;
        self.phase = Phase::Exchanged;
        self.write(operation)
    }
    pub fn advance(&mut self, operation: &Root, next: Phase) -> Result<()> {
        let allowed = matches!(
            (self.phase, next),
            (Phase::ForwardOnly, Phase::Exchanged)
                | (Phase::Exchanged, Phase::StartIssued)
                | (Phase::StartIssued, Phase::CatchingUp)
                | (Phase::CatchingUp, Phase::Complete)
        );
        ensure!(allowed, "invalid or backward restore transition");
        ensure!(self.recovery()? == Recovery::NewContinueOnly, "new tree is not installed");
        self.phase = next;
        self.write(operation)
    }
}
fn atomic_exchange(a: &Path, b: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let a_name = CString::new(a.as_os_str().as_bytes())?;
    let b_name = CString::new(b.as_os_str().as_bytes())?;
    // SAFETY: terminated absolute paths live through the synchronous atomic syscall.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a_name.as_ptr(),
            libc::AT_FDCWD,
            b_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    ensure!(result == 0, "atomic root exchange failed: {}", std::io::Error::last_os_error());
    for path in [a, b] {
        std::fs::File::open(path.parent().ok_or_else(|| anyhow::anyhow!("missing root parent"))?)?
            .sync_all()?;
    }
    Ok(())
}
