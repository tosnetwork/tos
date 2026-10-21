use crate::{
    cas::{ObjectWriter, Objects},
    model::{MANIFEST_LIMIT, SignedManifest, hash},
    safe_io::Root,
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadOwnership {
    lease: String,
    generation: String,
    request_sha256: String,
}

pub struct Catalog {
    root: Root,
    trusted: [u8; 32],
}
impl Catalog {
    pub fn open(path: &Path, trusted: [u8; 32]) -> Result<Self> {
        Ok(Self { root: Root::open(path)?, trusted })
    }
    pub fn create(path: &Path, trusted: [u8; 32]) -> Result<Self> {
        Ok(Self { root: Root::create(path)?, trusted })
    }
    fn atomic_metadata(&self, path: &str, bytes: &[u8]) -> Result<()> {
        // An interrupted write stays unreachable and can be pruned, never partially visible.
        let temporary = format!("incoming/{:032x}.zst", rand::random::<u128>());
        self.root.write_new(&temporary, bytes)?;
        self.root.rename(&temporary, path)
    }
    pub fn list(&self) -> Result<Vec<(String, SignedManifest)>> {
        self.list_locked()
    }
    fn list_locked(&self) -> Result<Vec<(String, SignedManifest)>> {
        let mut result = Vec::new();
        for name in names(&self.root.path.join("generations"))? {
            let digest = name.strip_suffix(".json").context("unknown catalog entry")?;
            hash(digest)?;
            let signed = SignedManifest::parse(
                &self.root.bytes(&format!("generations/{name}"), MANIFEST_LIMIT)?,
                &self.trusted,
            )?;
            ensure!(signed.verify(&self.trusted)? == digest, "catalog name and generation differ");
            result.push((digest.to_owned(), signed));
        }
        result.sort_by_key(|(digest, value)| (value.manifest.created_utc, digest.clone()));
        Ok(result)
    }
    pub fn latest(&self) -> Result<Option<SignedManifest>> {
        match self.root.path.join("latest.json").symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(Some(SignedManifest::parse(
                &self.root.bytes("latest.json", MANIFEST_LIMIT)?,
                &self.trusted,
            )?)),
        }
    }
    fn save_locked(&self, value: &SignedManifest) -> Result<String> {
        let digest = value.verify(&self.trusted)?;
        for (_, previous) in self.list_locked()? {
            ensure!(
                previous.manifest.network == value.manifest.network,
                "catalog contains another network"
            );
        }
        let name = format!("generations/{digest}.json");
        if self.root.path.join(&name).try_exists()? {
            ensure!(
                self.root.bytes(&name, MANIFEST_LIMIT)? == value.bytes()?,
                "generation identity conflict"
            );
        } else {
            self.atomic_metadata(&name, &value.bytes()?)?;
        }
        Ok(digest)
    }
    /// Pin a completed preparation before releasing its capture lock. Only one may await publication.
    pub fn prepare(&self, value: &SignedManifest, writer: &ObjectWriter<'_>) -> Result<String> {
        let objects = writer.objects();
        ensure!(objects.root_path() == self.root.path, "catalog and object store differ");
        verify_generation(value, objects, &self.trusted)?;
        let _lock = self.root.lock("catalog.lock")?;
        let digest = value.verify(&self.trusted)?;
        for name in names(&self.root.path.join("leases"))? {
            ensure!(
                !name.starts_with("p-") || name == format!("p-{digest}"),
                "another completed preparation awaits publication"
            );
        }
        self.save_locked(value)?;
        self.atomic_metadata(&format!("complete/{digest}"), digest.as_bytes())?;
        self.atomic_metadata(&format!("leases/p-{digest}"), digest.as_bytes())?;
        Ok(digest)
    }
    /// HTTP publication remains a separate operation after creation and verification.
    pub fn publish(
        &self,
        value: &SignedManifest,
        objects: &Objects,
        references: &crate::references::ReferencePolicy,
    ) -> Result<String> {
        ensure!(objects.root_path() == self.root.path, "catalog and object store differ");
        let _capture = objects.writer()?;
        verify_generation(value, objects, &self.trusted)?;
        let _lock = self.root.lock("catalog.lock")?;
        if let Some(previous) = self.latest()? {
            let old = &previous.manifest;
            let new = &value.manifest;
            ensure!(
                new.network == old.network
                    && new.created_utc >= old.created_utc
                    && new.frontier.seqno >= old.frontier.seqno,
                "latest publication would regress network, time or frontier"
            );
            ensure!(
                new.frontier.seqno != old.frontier.seqno || new.frontier == old.frontier,
                "same-height publication changes full block id"
            );
        }
        let digest = value.verify(&self.trusted)?;
        let approval =
            references.corroborate(&value.manifest.network, &value.manifest.frontier, &digest)?;
        let receipt = approval.receipt()?;
        self.save_locked(value)?;
        self.atomic_metadata(
            &format!("publications/{digest}.json"),
            &serde_json::to_vec(&receipt)?,
        )?;
        approval.receipt()?;
        self.atomic_metadata(&format!("complete/{digest}"), digest.as_bytes())?;
        self.atomic_metadata("latest.json", &value.bytes()?)?;
        let lease = format!("leases/p-{digest}");
        if self.root.path.join(&lease).try_exists()? {
            self.root.unlink(&lease)?;
        }
        Ok(digest)
    }
    /// Register the exact signed manifest and lease before transferring its first object.
    pub fn begin_download(
        &self,
        value: &SignedManifest,
        writer: &ObjectWriter<'_>,
        operation: &str,
    ) -> Result<String> {
        self.begin_download_impl(value, writer, operation, None)
    }
    pub fn begin_owned_download(
        &self,
        value: &SignedManifest,
        writer: &ObjectWriter<'_>,
        operation: &str,
        record: &Root,
    ) -> Result<String> {
        self.begin_download_impl(value, writer, operation, Some(record))
    }
    fn begin_download_impl(
        &self,
        value: &SignedManifest,
        writer: &ObjectWriter<'_>,
        operation: &str,
        record: Option<&Root>,
    ) -> Result<String> {
        hash(operation)?;
        ensure!(
            writer.objects().root_path() == self.root.path,
            "cache catalog and object store differ"
        );
        let _lock = self.root.lock("catalog.lock")?;
        let digest = value.verify(&self.trusted)?;
        if let Some(record) = record {
            ensure!(
                crate::model::sha256(&record.bytes("operation-id", 32)?) == operation,
                "download operation id mismatch"
            );
            let ownership = DownloadOwnership {
                lease: operation.to_owned(),
                generation: digest.clone(),
                request_sha256: crate::model::sha256(
                    &record.bytes("request.json", MANIFEST_LIMIT)?,
                ),
            };
            record.write_new("download.json", &serde_json::to_vec(&ownership)?)?;
        }
        let digest = self.save_locked(value)?;
        ensure!(
            crate::safe_io::absent(&self.root.path.join(format!("leases/r-{operation}")))?,
            "receiver lease already exists"
        );
        self.atomic_metadata(&format!("leases/r-{operation}"), digest.as_bytes())?;
        Ok(digest)
    }
    /// Abort only an authenticated pre-journal receiver; never touch the installed node.
    pub fn abort_download(
        &self,
        value: &SignedManifest,
        objects: &Objects,
        operation: &str,
        record: &Root,
    ) -> Result<()> {
        ensure!(objects.root_path() == self.root.path, "cache catalog and object store differ");
        ensure!(
            crate::safe_io::absent(&record.path.join("restore.json"))?,
            "journaled restore cannot use preparation abort"
        );
        let bytes = record.bytes("download.json", MANIFEST_LIMIT)?;
        let ownership: DownloadOwnership = serde_json::from_slice(&bytes)?;
        let digest = value.verify(&self.trusted)?;
        ensure!(
            ownership.lease == operation
                && ownership.generation == digest
                && crate::model::sha256(&record.bytes("operation-id", 32)?) == operation
                && ownership.request_sha256
                    == crate::model::sha256(&record.bytes("request.json", MANIFEST_LIMIT)?),
            "preparation abort binding mismatch"
        );
        // Authenticate the record before opening any writable cache descriptor.
        let _writer = objects.writer()?;
        let _lock = self.root.lock("catalog.lock")?;
        let lease = format!("leases/r-{operation}");
        if !crate::safe_io::absent(&self.root.path.join(&lease))? {
            ensure!(
                self.root.bytes(&lease, 64)? == digest.as_bytes(),
                "preparation lease binding mismatch"
            );
        }
        publish_abort_receipt(record, operation, &bytes, |root, path, bytes| {
            root.write_new(path, bytes)
        })?;
        if !crate::safe_io::absent(&self.root.path.join(&lease))? {
            self.root.unlink(&lease)?;
        }
        Ok(())
    }
    /// Pin a fully downloaded receiver generation while its writer still excludes pruning.
    pub fn hold_download(
        &self,
        value: &SignedManifest,
        writer: &ObjectWriter<'_>,
        operation: &str,
    ) -> Result<String> {
        hash(operation)?;
        let objects = writer.objects();
        ensure!(objects.root_path() == self.root.path, "cache catalog and object store differ");
        verify_generation(value, objects, &self.trusted)?;
        let _lock = self.root.lock("catalog.lock")?;
        let digest = self.save_locked(value)?;
        self.atomic_metadata(&format!("complete/{digest}"), digest.as_bytes())?;
        ensure!(
            self.root.bytes(&format!("leases/r-{operation}"), 64)? == digest.as_bytes(),
            "completed download does not match its durable lease"
        );
        Ok(digest)
    }
    pub fn lease(&self, operation: &str, generation: &str) -> Result<()> {
        hash(operation)?;
        hash(generation)?;
        let _lock = self.root.lock("catalog.lock")?;
        ensure!(
            self.list_locked()?.iter().any(|(id, _)| id == generation),
            "lease generation unavailable"
        );
        ensure!(
            crate::safe_io::absent(&self.root.path.join(format!("leases/r-{operation}")))?,
            "receiver lease already exists"
        );
        self.atomic_metadata(&format!("leases/r-{operation}"), generation.as_bytes())
    }
    pub fn release(&self, operation: &str) -> Result<()> {
        hash(operation)?;
        let _lock = self.root.lock("catalog.lock")?;
        self.root.unlink(&format!("leases/r-{operation}"))
    }
    /// Reachability, preparation leases and receiver leases all protect objects.
    pub fn prune(&self) -> Result<Vec<String>> {
        let _capture = self.root.lock("capture.lock")?;
        let _lock = self.root.lock("catalog.lock")?;
        let list = self.list_locked()?;
        let mut retained = BTreeSet::new();
        for (id, _) in list.iter().rev() {
            if self.root.path.join(format!("complete/{id}")).try_exists()? {
                ensure!(
                    self.root.bytes(&format!("complete/{id}"), 64)? == id.as_bytes(),
                    "completed generation marker is corrupt"
                );
                if retained.len() < 2 {
                    retained.insert(id.clone());
                }
            }
        }
        if let Some(latest) = self.latest()? {
            let id = latest.verify(&self.trusted)?;
            ensure!(list.iter().any(|(known, _)| known == &id), "latest pointer has no generation");
            retained.insert(id);
        }
        for name in names(&self.root.path.join("leases"))? {
            let suffix = name
                .strip_prefix("r-")
                .or_else(|| name.strip_prefix("p-"))
                .context("unknown lease kind")?;
            hash(suffix)?;
            let bytes = self.root.bytes(&format!("leases/{name}"), 64)?;
            let id = std::str::from_utf8(&bytes)?;
            hash(id)?;
            ensure!(list.iter().any(|(known, _)| known == id), "lease generation is missing");
            retained.insert(id.to_owned());
        }
        let mut protected = BTreeSet::new();
        let mut partials = BTreeSet::new();
        for (id, signed) in &list {
            if retained.contains(id) {
                for object in &signed.manifest.files {
                    protected.insert(Objects::object_name(object)?);
                    partials.insert(format!(
                        "{}-{}.part",
                        object.compressed_sha256, object.compressed_size
                    ));
                }
            }
        }
        let mut deleted = Vec::new();
        for (id, _) in list {
            if !retained.contains(&id) {
                self.root.unlink(&format!("generations/{id}.json"))?;
                if self.root.path.join(format!("complete/{id}")).try_exists()? {
                    self.root.unlink(&format!("complete/{id}"))?;
                }
                if self.root.path.join(format!("publications/{id}.json")).try_exists()? {
                    self.root.unlink(&format!("publications/{id}.json"))?;
                }
                deleted.push(id);
            }
        }
        for name in names(&self.root.path.join("objects"))? {
            let base = name.strip_suffix(".zst").context("unknown content object")?;
            let parts: Vec<_> = base.split('-').collect();
            ensure!(parts.len() == 3, "unknown content-addressed object name");
            hash(parts[0])?;
            hash(parts[2])?;
            let size: u64 = parts[1].parse()?;
            ensure!(
                size.to_string() == parts[1] && size <= crate::model::RAW_LIMIT,
                "invalid content object size key"
            );
            if !protected.contains(&format!("objects/{name}")) {
                self.root.unlink(&format!("objects/{name}"))?;
            }
        }
        for name in names(&self.root.path.join("incoming"))? {
            if partials.contains(&name) {
                continue;
            }
            if let Some(base) = name.strip_suffix(".part") {
                let (digest, size) = base.split_once('-').context("unknown partial object name")?;
                hash(digest)?;
                let size: u64 = size.parse()?;
                ensure!(size <= crate::model::TRANSFER_LIMIT, "invalid partial object size");
            } else {
                let base = name.strip_suffix(".zst").context("unknown incoming object name")?;
                ensure!(
                    base.len() == 32 && base.bytes().all(|b| b.is_ascii_hexdigit()),
                    "unknown incoming object name"
                );
            }
            self.root.unlink(&format!("incoming/{name}"))?;
        }
        Ok(deleted)
    }
}
fn names(path: &Path) -> Result<Vec<String>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
        Ok(m) => ensure!(m.file_type().is_dir(), "catalog directory is a link or special file"),
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(result.len() < 100_000, "catalog count limit");
        let entry = entry?;
        ensure!(entry.file_type()?.is_file(), "catalog entry is a link or special file");
        result.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-text catalog entry"))?,
        );
    }
    result.sort();
    Ok(result)
}
pub fn verify_generation(
    value: &SignedManifest,
    objects: &Objects,
    trusted: &[u8; 32],
) -> Result<()> {
    value.verify(trusted)?;
    for object in &value.manifest.files {
        objects.check(object)?;
    }
    let metadata = |path: &str| -> Result<Vec<u8>> {
        let object = value
            .manifest
            .files
            .iter()
            .find(|o| o.path == path)
            .context("generation metadata missing")?;
        objects.bytes(object, MANIFEST_LIMIT)
    };
    crate::metadata::validate(
        &value.manifest,
        &metadata("metadata/zero-state.boc")?,
        &metadata("metadata/tip-block.boc")?,
    )?;
    let chain = crate::records::ChainRecords::parse(&metadata("state-records.cbor")?)?;
    ensure!(chain.frontier()? == value.manifest.frontier, "StateDb and manifest frontiers differ");
    ensure!(
        chain.gc()? == value.manifest.retained_from,
        "StateDb and manifest retained range differ"
    );
    ensure!(
        chain.forks()? == value.manifest.approved_forks,
        "StateDb and manifest fork records differ"
    );
    Ok(())
}

// The final name is authoritative only after fsynced temporary bytes are renamed.
fn publish_abort_receipt(
    record: &Root,
    operation: &str,
    bytes: &[u8],
    write: impl FnOnce(&Root, &str, &[u8]) -> Result<()>,
) -> Result<()> {
    hash(operation)?;
    let final_name = "preparation-aborted.json";
    let temporary = format!("preparation-aborted.{operation}.pending");
    let complete = !crate::safe_io::absent(&record.path.join(final_name))?;
    if complete {
        ensure!(
            record.bytes(final_name, MANIFEST_LIMIT)? == bytes,
            "abort receipt binding mismatch"
        );
    }
    if !crate::safe_io::absent(&record.path.join(&temporary))? {
        // This exact name belongs to the authenticated operation, never a wildcard.
        record.read(&temporary, MANIFEST_LIMIT)?;
        record.unlink(&temporary)?;
    }
    if !complete {
        write(record, &temporary, bytes)?;
        record.rename(&temporary, final_name)?;
    }
    Ok(())
}

#[cfg(test)]
mod abort_receipt_tests {
    use super::*;
    #[test]
    fn interrupted_receipt_has_no_partial_final_and_retry_removes_owned_temporary() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let root = Root::open(tmp.path())?;
        let operation = "ab".repeat(32);
        let bytes = b"complete authenticated receipt";
        let result = publish_abort_receipt(&root, &operation, bytes, |root, path, bytes| {
            root.write_new(path, &bytes[..7])?;
            anyhow::bail!("injected write interruption")
        });
        assert!(result.is_err());
        assert!(
            !root.path.join("preparation-aborted.json").exists(),
            "partial receipt was published at final name"
        );
        let temporary = format!("preparation-aborted.{operation}.pending");
        assert_eq!(root.bytes(&temporary, 1024)?, &bytes[..7]);
        root.write_new("unrelated.pending", b"retain")?;
        publish_abort_receipt(&root, &operation, bytes, |root, path, bytes| {
            root.write_new(path, bytes)
        })?;
        assert_eq!(root.bytes("preparation-aborted.json", 1024)?, bytes);
        assert!(!root.path.join(&temporary).exists(), "owned temporary survived retry");
        assert_eq!(root.bytes("unrelated.pending", 100)?, b"retain");
        root.write_new(&temporary, b"interrupted leftover")?;
        publish_abort_receipt(&root, &operation, bytes, |_, _, _| {
            anyhow::bail!("complete receipt was rewritten")
        })?;
        assert!(
            !root.path.join(&temporary).exists(),
            "owned temporary survived complete-receipt retry"
        );
        root.replace("preparation-aborted.json", b"different")?;
        assert!(
            publish_abort_receipt(&root, &operation, bytes, |root, path, bytes| root
                .write_new(path, bytes))
            .is_err(),
            "mismatched final receipt was accepted"
        );
        Ok(())
    }
}
