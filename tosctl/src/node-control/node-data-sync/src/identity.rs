use crate::{
    model::sha256,
    paths::LOCAL_CONFIGS,
    safe_io::{Root, copy_hash},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub const IDENTITY_FILE_LIMIT: u64 = 64 << 20;
pub const IDENTITY_TOTAL_LIMIT: u64 = 1 << 30;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateFile {
    pub source: PathBuf,
    pub stored: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub format: u8,
    pub files: Vec<PrivateFile>,
    pub protected_files: Vec<PathBuf>,
    pub directories: Vec<PathBuf>,
}
impl Identity {
    pub fn capture(
        db: &Path,
        work: &Path,
        working_directory: &Path,
        operator: &Path,
        global_config: &Path,
        service_files: &[PathBuf],
        backup: &Root,
    ) -> Result<Self> {
        let db = fs::canonicalize(db)?;
        let work = fs::canonicalize(work)?;
        let working_directory = fs::canonicalize(working_directory)?;
        let mut sources =
            vec![db.join("config.json"), operator.to_owned(), global_config.to_owned()];
        ensure!(
            !service_files.is_empty() && service_files.len() <= 64,
            "service definition inventory is missing or oversized"
        );
        sources.extend_from_slice(service_files);
        for name in LOCAL_CONFIGS {
            sources.push(db.join(name));
        }
        let mut protected_files = sources.clone();
        for path in &protected_files {
            ensure!(
                ![
                    "celldb",
                    "files",
                    "archive",
                    "static",
                    "state",
                    "tmp",
                    "import",
                    "consensus",
                    "catchains"
                ]
                .iter()
                .any(|name| path.starts_with(db.join(name))),
                "private config overlaps chain, recovery or signing-state data"
            );
        }
        let mut directories = Vec::new();
        for name in ["keyring", "keys"] {
            let base = if name == "keyring" { &db } else { &work };
            let path = base.join(name);
            match path.symlink_metadata() {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && name == "keys" => {}
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    inventory_tree(&path, &mut sources)?;
                    directories.push(path);
                }
            }
        }
        let config = Root::open(&db)?.bytes("config.json", IDENTITY_FILE_LIMIT)?;
        let config: serde_json::Value = serde_json::from_slice(&config)?;
        for id in registered_keys(&config)? {
            let path = format!("keyring/{}", id.to_ascii_uppercase());
            Root::open(&db)?
                .read(&path, IDENTITY_FILE_LIMIT)
                .context("required registered key is missing")?;
        }
        for reference in seed_references(&config)? {
            let source =
                if reference.is_absolute() { reference } else { working_directory.join(reference) };
            let resolved =
                fs::canonicalize(&source).context("referenced signing seed is absent")?;
            ensure!(
                !["celldb", "files", "archive", "static", "state", "tmp", "import"]
                    .iter()
                    .any(|p| resolved.starts_with(db.join(p))),
                "signing seed overlaps chain or recovery data"
            );
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = source.symlink_metadata()?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o077 == 0,
                "configured consensus seed is not an owned private regular file"
            );
            ensure!(
                metadata.len() == 32,
                "configured consensus seed is not a protected 32-byte file"
            );
            protected_files.push(source.clone());
            sources.push(source);
        }
        let mut unique = BTreeSet::new();
        let mut files = Vec::new();
        let mut total = 0_u64;
        for source in sources {
            ensure!(source.is_absolute(), "identity source must be absolute");
            ensure!(
                fs::canonicalize(source.parent().context("identity parent")?)?
                    == source.parent().context("identity parent")?,
                "identity parent contains a symlink or noncanonical component"
            );
            if !unique.insert(source.clone()) {
                continue;
            }
            let stored = format!("files/{:06}", files.len());
            let optional = LOCAL_CONFIGS.iter().any(|name| source == db.join(name));
            match fs::symlink_metadata(&source) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && optional => {
                    files.push(PrivateFile { source, stored, size: None, sha256: None })
                }
                Err(e) => return Err(e.into()),
                Ok(metadata) => {
                    ensure!(
                        metadata.file_type().is_file(),
                        "non-regular identity file: {}",
                        source.display()
                    );
                    let parent = Root::open(source.parent().context("identity source parent")?)?;
                    let name =
                        source.file_name().and_then(|s| s.to_str()).context("identity filename")?;
                    let input = parent.read(name, IDENTITY_FILE_LIMIT)?;
                    let mut output = backup.create_file(&stored)?;
                    let (size, digest) = copy_hash(input, &mut output, IDENTITY_FILE_LIMIT)?;
                    total = total.checked_add(size).context("identity size overflow")?;
                    ensure!(total <= IDENTITY_TOTAL_LIMIT, "identity backup total limit");
                    output.sync_all()?;
                    backup.sync_parent(&stored)?;
                    files.push(PrivateFile {
                        source,
                        stored,
                        size: Some(size),
                        sha256: Some(digest),
                    });
                }
            }
        }
        let identity = Self { format: 1, files, protected_files, directories };
        backup.write_new("identity.json", &serde_json::to_vec(&identity)?)?;
        identity.verify(backup)?;
        Ok(identity)
    }
    pub fn verify(&self, backup: &Root) -> Result<()> {
        ensure!(self.format == 1 && self.files.len() <= 100_000, "unsupported identity inventory");
        ensure!(
            self.directories.len() <= 2 && self.directories.iter().all(|path| path.is_absolute()),
            "invalid identity directory inventory"
        );
        let protected: BTreeSet<_> = self.protected_files.iter().collect();
        ensure!(protected.len() == self.protected_files.len(), "duplicate protected configuration");
        ensure!(
            protected.iter().all(|path| self.files.iter().any(|file| &file.source == *path)),
            "protected configuration is absent from backup inventory"
        );
        let mut paths = BTreeSet::new();
        let mut total = 0_u64;
        for (index, file) in self.files.iter().enumerate() {
            ensure!(
                file.source.is_absolute() && paths.insert(&file.source),
                "duplicate or relative identity source"
            );
            ensure!(file.stored == format!("files/{index:06}"), "invalid private bundle path");
            match (&file.size, &file.sha256) {
                (None, None) => ensure!(
                    crate::safe_io::absent(&backup.path.join(&file.stored))?,
                    "absent identity file has stored bytes"
                ),
                (Some(size), Some(digest)) => {
                    ensure!(*size <= IDENTITY_FILE_LIMIT, "identity file limit");
                    let bytes = backup.bytes(&file.stored, *size)?;
                    ensure!(
                        bytes.len() as u64 == *size && sha256(&bytes) == *digest,
                        "identity backup digest mismatch"
                    );
                    total = total.checked_add(*size).context("identity size overflow")?;
                }
                _ => anyhow::bail!("identity absence and digest disagree"),
            }
        }
        ensure!(total <= IDENTITY_TOTAL_LIMIT, "identity total limit");
        Ok(())
    }
    pub fn verify_sources(&self) -> Result<()> {
        for file in &self.files {
            match file.size {
                Some(size) => {
                    let parent =
                        Root::open(file.source.parent().context("identity source parent")?)?;
                    let name = file
                        .source
                        .file_name()
                        .and_then(|s| s.to_str())
                        .context("identity name")?;
                    ensure!(
                        crate::safe_io::file_hash(parent.read(name, size)?, size)?
                            == (size, file.sha256.clone().context("identity digest")?),
                        "own identity/config changed during preparation"
                    );
                }
                None => ensure!(
                    crate::safe_io::absent(&file.source)?,
                    "absent local config appeared during preparation"
                ),
            }
        }
        Ok(())
    }
    /// Only database-root local files are overlaid. External files remain at their own locations.
    pub fn overlay(&self, old_db: &Path, replacement: &Root, backup: &Root) -> Result<()> {
        self.verify(backup)?;
        let old_db = fs::canonicalize(old_db)?;
        for directory in &self.directories {
            if let Ok(relative) = directory.strip_prefix(&old_db) {
                use std::os::unix::fs::DirBuilderExt;
                ensure!(
                    matches!(relative.to_str(), Some("keyring" | "keys")),
                    "unexpected private directory"
                );
                fs::DirBuilder::new().mode(0o700).create(replacement.path.join(relative))?;
                replacement.sync()?;
            } else {
                ensure!(
                    directory.symlink_metadata()?.file_type().is_dir(),
                    "external private directory changed"
                );
            }
        }
        for file in &self.files {
            if let Ok(relative) = file.source.strip_prefix(&old_db) {
                let relative = relative.to_str().context("non-text identity path")?;
                ensure!(
                    self.protected_files.contains(&file.source)
                        || relative.starts_with("keyring/")
                        || relative.starts_with("keys/"),
                    "unexpected local identity overlay"
                );
                if let Some(size) = file.size {
                    replacement.write_new(relative, &backup.bytes(&file.stored, size)?)?;
                } else {
                    ensure!(
                        crate::safe_io::absent(&replacement.path.join(relative))?,
                        "replacement supplied an absent local config"
                    );
                }
            } else if let Some(size) = file.size {
                let parent = Root::open(file.source.parent().context("external identity parent")?)?;
                let name = file
                    .source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("external identity name")?;
                ensure!(
                    sha256(&parent.bytes(name, size)?)
                        == file.sha256.as_deref().context("missing external digest")?,
                    "external identity changed after backup"
                );
            }
        }
        Ok(())
    }
}
fn inventory_tree(path: &Path, sources: &mut Vec<PathBuf>) -> Result<()> {
    let root = Root::open(path).context("required identity directory is missing or unsafe")?;
    for file in crate::trees::inventory(&root)? {
        ensure!(sources.len() < 100_000, "identity inventory count limit");
        sources.push(path.join(file.path));
    }
    Ok(())
}
pub fn seed_references(config: &serde_json::Value) -> Result<Vec<PathBuf>> {
    let Some(pq) = config.pointer("/extraconfig/pq_consensus") else {
        return Ok(vec![]);
    };
    if pq.is_null() {
        return Ok(vec![]);
    }
    ensure!(pq.is_object(), "invalid signing custody configuration");
    let mut sources = Vec::new();
    let mut push = |value: &serde_json::Value| -> Result<()> {
        let path = value.as_str().context("signing seed reference is not a string")?;
        if !path.is_empty() {
            sources.push(PathBuf::from(path));
        }
        Ok(())
    };
    if let Some(primary) = pq.get("consensus_key_file") {
        push(primary)?;
    }
    if let Some(keys) = pq.get("keys") {
        for key in keys.as_array().context("scheduled signing keys are not an array")? {
            push(
                key.get("consensus_key_file")
                    .context("scheduled signing key has no custody reference")?,
            )?;
        }
    }
    Ok(sources)
}

/// Public ids that the native configuration registers as locally held keys.
/// Remote control clients and full-node slave servers are intentionally not local keys.
pub fn registered_keys(config: &serde_json::Value) -> Result<BTreeSet<String>> {
    use base64::Engine;
    let mut keys = BTreeSet::new();
    let mut insert = |value: &serde_json::Value| -> Result<()> {
        let text = value.as_str().context("registered key id is not a string")?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(text)?;
        ensure!(bytes.len() == 32, "registered key id length");
        if bytes != [0; 32] {
            keys.insert(hex::encode(bytes));
        }
        Ok(())
    };
    for (collection, field) in [
        ("adnl", "id"),
        ("dht", "id"),
        ("liteservers", "id"),
        ("control", "id"),
        ("fullnodemasters", "adnl"),
        ("collators", "adnl_id"),
    ] {
        if let Some(values) = config.get(collection) {
            for value in values.as_array().context("invalid local key collection")? {
                insert(value.get(field).context("missing registered key id")?)?;
            }
        }
    }
    if let Some(fullnode) = config.get("fullnode") {
        insert(fullnode)?;
    }
    if let Some(validators) = config.get("validators") {
        for validator in validators.as_array().context("invalid validator key list")? {
            insert(validator.get("id").context("missing validator key id")?)?;
            for (field, key) in [("temp_keys", "key"), ("adnl_addrs", "id")] {
                if let Some(values) = validator.get(field) {
                    for value in values.as_array().context("invalid validator key schedule")? {
                        insert(value.get(key).context("missing scheduled key id")?)?;
                    }
                }
            }
        }
    }
    Ok(keys)
}
