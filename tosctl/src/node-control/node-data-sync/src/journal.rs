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
            self.version == 1
                && self.operation.len() == 32
                && self.operation.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid restore journal identity"
        );
        hash(&self.generation)?;
        hash(&self.preservation_sha256)?;
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
    pub fn forward_only(&mut self, operation: &Root) -> Result<()> {
        ensure!(
            self.phase == Phase::Staged,
            "forward-only boundary cannot be cleared or re-entered"
        );
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
