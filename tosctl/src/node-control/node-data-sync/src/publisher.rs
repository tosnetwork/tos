//! Provenance of the dedicated publisher secret remains private throughout capture.
use crate::safe_io::Root;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub struct PublisherSecret {
    parent: Root,
    path: PathBuf,
    file: File,
    key: SigningKey,
}
impl PublisherSecret {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let parent = Root::open(path.parent().context("publisher parent")?)?;
        let name = path.file_name().and_then(|n| n.to_str()).context("publisher filename")?;
        let file = parent.read(name, 32)?;
        let seed: [u8; 32] = parent
            .bytes(name, 32)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("publisher seed must contain exactly 32 bytes"))?;
        let result = Self { parent, path, file, key: SigningKey::from_bytes(&seed) };
        result.attached()?;
        Ok(result)
    }
    fn attached(&self) -> Result<()> {
        self.parent.attached()?;
        let name = self.path.file_name().and_then(|n| n.to_str()).context("publisher filename")?;
        let current = self.parent.read(name, 32)?;
        let held = self.file.metadata()?;
        let now = current.metadata()?;
        ensure!(
            held.dev() == now.dev() && held.ino() == now.ino(),
            "publisher secret was replaced"
        );
        ensure!(
            now.uid() == unsafe { libc::geteuid() }
                && now.mode() & 0o077 == 0
                && now.nlink() == 1
                && now.len() == 32,
            "publisher secret must be an owned private single-link 32-byte file"
        );
        ensure!(
            self.parent.bytes(name, 32)? == self.key.to_bytes(),
            "publisher secret changed while held"
        );
        Ok(())
    }
    /// Repeated after service quiescence, before any capture or public object writes.
    pub fn validate(&self, database: &Path, catalog: &Path, operation: &Path) -> Result<()> {
        self.attached()?;
        for root in [database, catalog, operation] {
            let root = prospective_root(root)?;
            ensure!(
                !self.path.starts_with(&root),
                "publisher secret overlaps source, catalog or operation tree"
            );
        }
        Ok(())
    }
    pub(crate) fn reject_input(&self, input: &File) -> Result<()> {
        self.attached()?;
        let a = self.file.metadata()?;
        let b = input.metadata()?;
        ensure!(a.dev() != b.dev() || a.ino() != b.ino(), "publisher secret aliases capture input");
        Ok(())
    }
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}
fn prospective_root(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    if absolute.try_exists()? {
        ensure!(absolute.canonicalize()? == absolute, "publisher boundary is not canonical");
        Ok(absolute)
    } else {
        let parent = Root::open(absolute.parent().context("publisher boundary parent")?)?;
        let name = absolute.file_name().context("publisher boundary name")?;
        ensure!(absolute == parent.path.join(name), "ambiguous publisher boundary");
        Ok(absolute)
    }
}
