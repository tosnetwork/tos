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
    io::Write,
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
    /// Permission bits of the copied source, present exactly when its bytes are.
    pub mode: Option<u32>,
}
/// One directory of an identity tree, including empty ones and the tree root itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PrivateDirectory {
    pub path: PathBuf,
    pub mode: u32,
}
/// Identity trees: name, whether it lives in the database root (otherwise the work root),
/// and whether it must exist.
const IDENTITY_TREES: [(&str, bool, bool); 3] =
    [("keyring", true, true), ("console-client", true, false), ("keys", false, false)];
const IDENTITY_ENTRY_LIMIT: usize = 100_000;
/// Identity and configuration of one node, captured privately before its database root is
/// replaced, and restored into the replacement.
///
/// Contract for the database-local trees (`keyring`, `console-client`, and `keys` when the
/// work root is the database root): every directory, including empty ones, and every
/// regular file is recorded with its permission bits; the replacement recreates exactly
/// that set with exactly those bits. Every recorded entry must belong to the database
/// root's owner and group, carry no special bits and not be writable by other accounts;
/// the replacement is handed to that same owner and group, so ownership is preserved too.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub format: u8,
    pub files: Vec<PrivateFile>,
    pub protected_files: Vec<PathBuf>,
    /// The identity trees present, by absolute path.
    pub roots: Vec<PathBuf>,
    pub directories: Vec<PrivateDirectory>,
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
        // Every file below the node's tree is reached through this held descriptor.
        let database = Root::open(&db)?;
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
        // Database-local identity entries, and seeds, belong to the account that runs the
        // node, which owns the database root.
        let owner = database.owner()?;
        let (seed_owner, _) = owner;
        let mut roots = Vec::new();
        let mut directories = Vec::new();
        let mut local_files = BTreeSet::new();
        for (name, local, required) in IDENTITY_TREES {
            let base = if local { &db } else { &work };
            let path = base.join(name);
            let parent = database.open_anchored(base)?;
            match crate::trees::optional_directory(&parent, name)
                .context("required identity directory is missing or unsafe")?
            {
                None if !required => {}
                None => anyhow::bail!("required identity directory is missing: {}", path.display()),
                Some(tree) => {
                    let in_database = path.starts_with(&db);
                    for entry in crate::trees::private_tree(
                        &tree,
                        IDENTITY_ENTRY_LIMIT,
                        IDENTITY_TOTAL_LIMIT,
                    )? {
                        let full = if entry.path.is_empty() {
                            path.clone()
                        } else {
                            path.join(&entry.path)
                        };
                        if in_database {
                            check_local_entry(&full, entry.mode, (entry.uid, entry.gid), owner)?;
                        }
                        if entry.directory {
                            directories.push(PrivateDirectory { path: full, mode: entry.mode });
                        } else {
                            ensure!(
                                sources.len() < IDENTITY_ENTRY_LIMIT,
                                "identity inventory count limit"
                            );
                            if in_database {
                                local_files.insert(full.clone());
                            }
                            sources.push(full);
                        }
                    }
                    roots.push(path);
                }
            }
        }
        let config = database.bytes("config.json", IDENTITY_FILE_LIMIT)?;
        let config: serde_json::Value = serde_json::from_slice(&config)?;
        for id in registered_keys(&config)? {
            let path = format!("keyring/{}", id.to_ascii_uppercase());
            database
                .read(&path, IDENTITY_FILE_LIMIT)
                .context("required registered key is missing")?;
        }
        let mut seeds = std::collections::BTreeMap::new();
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
            // Opened once, below the held tree. The checks run on this descriptor and the
            // backup is copied from it, so a seed replaced by name afterwards is never read.
            let (parent, name) = anchored_file(&database, &source)?;
            let seed = parent
                .read(name, 32)
                .context("configured consensus seed is not an owned private regular file")?;
            check_seed(&seed, seed_owner)?;
            protected_files.push(source.clone());
            seeds.insert(source.clone(), seed);
            sources.push(source);
        }
        #[cfg(test)]
        before_identity_copy();
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
            if let Some(seed) = seeds.remove(&source) {
                // Rechecked on the same descriptor just before its bytes are copied.
                check_seed(&seed, seed_owner)?;
                let mode = descriptor_mode(&seed)?;
                if local_files.contains(&source) {
                    check_local_entry(&source, mode, descriptor_owner(&seed)?, owner)?;
                }
                let mut output = backup.create_file(&stored)?;
                let (size, digest) = copy_hash(seed, &mut output, 32)?;
                ensure!(size == 32, "configured consensus seed changed length while held");
                total = total.checked_add(size).context("identity size overflow")?;
                output.sync_all()?;
                backup.sync_parent(&stored)?;
                files.push(PrivateFile {
                    source,
                    stored,
                    size: Some(size),
                    sha256: Some(digest),
                    mode: Some(mode),
                });
                continue;
            }
            let optional = LOCAL_CONFIGS.iter().any(|name| source == db.join(name));
            let (parent, name) = anchored_file(&database, &source)?;
            match parent.kind(name)? {
                None if optional => {
                    files.push(PrivateFile { source, stored, size: None, sha256: None, mode: None })
                }
                None => anyhow::bail!("identity file is missing: {}", source.display()),
                Some(kind) => {
                    ensure!(
                        kind == crate::safe_io::Kind::File,
                        "non-regular identity file: {}",
                        source.display()
                    );
                    let input = parent.read(name, IDENTITY_FILE_LIMIT)?;
                    // Mode and owner come from the same descriptor whose bytes are copied.
                    let mode = descriptor_mode(&input)?;
                    if local_files.contains(&source) {
                        check_local_entry(&source, mode, descriptor_owner(&input)?, owner)?;
                    }
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
                        mode: Some(mode),
                    });
                }
            }
        }
        ensure!(seeds.is_empty(), "a checked consensus seed was not backed up");
        let identity = Self { format: 2, files, protected_files, roots, directories };
        backup.write_new("identity.json", &serde_json::to_vec(&identity)?)?;
        identity.verify(backup)?;
        Ok(identity)
    }
    pub fn verify(&self, backup: &Root) -> Result<()> {
        ensure!(
            self.format == 2 && self.files.len() <= IDENTITY_ENTRY_LIMIT,
            "unsupported identity inventory"
        );
        let roots: BTreeSet<_> = self.roots.iter().collect();
        ensure!(
            roots.len() == self.roots.len()
                && self.roots.len() <= IDENTITY_TREES.len()
                && self.roots.iter().all(|root| {
                    root.is_absolute()
                        && root.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
                            IDENTITY_TREES.iter().any(|(tree, _, _)| *tree == name)
                        })
                }),
            "invalid identity tree inventory"
        );
        ensure!(self.directories.len() <= IDENTITY_ENTRY_LIMIT, "identity directory count limit");
        let mut directories = BTreeSet::new();
        for directory in &self.directories {
            ensure!(
                directory.path.is_absolute()
                    && directory.mode <= 0o7777
                    && directories.insert(&directory.path),
                "invalid or duplicate identity directory"
            );
        }
        for directory in &self.directories {
            let parent = directory.path.parent().context("identity directory parent")?;
            ensure!(
                roots.contains(&directory.path)
                    || (roots.iter().any(|root| directory.path.starts_with(root))
                        && directories.contains(&parent.to_path_buf())),
                "identity directory is outside its tree or lacks its parent"
            );
        }
        ensure!(
            self.roots.iter().all(|root| directories.contains(root)),
            "identity tree root has no recorded directory"
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
            if roots.iter().any(|root| file.source.starts_with(root)) {
                let parent = file.source.parent().context("identity file parent")?;
                ensure!(
                    directories.contains(&parent.to_path_buf()),
                    "identity tree file has no recorded directory"
                );
            }
            match (&file.size, &file.sha256, &file.mode) {
                (None, None, None) => ensure!(
                    crate::safe_io::absent(&backup.path.join(&file.stored))?,
                    "absent identity file has stored bytes"
                ),
                (Some(size), Some(digest), Some(mode)) => {
                    ensure!(*size <= IDENTITY_FILE_LIMIT, "identity file limit");
                    ensure!(*mode <= 0o7777, "invalid identity file mode");
                    let bytes = backup.bytes(&file.stored, *size)?;
                    ensure!(
                        bytes.len() as u64 == *size && sha256(&bytes) == *digest,
                        "identity backup digest mismatch"
                    );
                    total = total.checked_add(*size).context("identity size overflow")?;
                }
                _ => anyhow::bail!("identity absence, digest and mode disagree"),
            }
        }
        ensure!(total <= IDENTITY_TOTAL_LIMIT, "identity total limit");
        Ok(())
    }
    /// Recheck every source below the held database descriptor `database`: bytes and mode of
    /// every file, and the complete directory and file set of every identity tree.
    pub fn verify_sources(&self, database: &Root) -> Result<()> {
        for file in &self.files {
            let (parent, name) = anchored_file(database, &file.source)?;
            match file.size {
                Some(size) => {
                    let input = parent.read(name, size)?;
                    ensure!(
                        Some(descriptor_mode(&input)?) == file.mode,
                        "own identity/config mode changed during preparation"
                    );
                    ensure!(
                        crate::safe_io::file_hash(input, size)?
                            == (size, file.sha256.clone().context("identity digest")?),
                        "own identity/config changed during preparation"
                    );
                }
                None => ensure!(
                    parent.kind(name)?.is_none(),
                    "absent local config appeared during preparation"
                ),
            }
        }
        for root in &self.roots {
            let tree = database.open_anchored(root)?;
            let mut seen_directories = BTreeSet::new();
            let mut seen_files = BTreeSet::new();
            for entry in
                crate::trees::private_tree(&tree, IDENTITY_ENTRY_LIMIT, IDENTITY_TOTAL_LIMIT)?
            {
                let full =
                    if entry.path.is_empty() { root.clone() } else { root.join(&entry.path) };
                if entry.directory {
                    seen_directories.insert(PrivateDirectory { path: full, mode: entry.mode });
                } else {
                    seen_files.insert(full);
                }
            }
            let recorded_directories: BTreeSet<_> =
                self.directories.iter().filter(|d| d.path.starts_with(root)).cloned().collect();
            let recorded_files: BTreeSet<_> = self
                .files
                .iter()
                .filter(|f| f.source.starts_with(root))
                .map(|f| f.source.clone())
                .collect();
            ensure!(
                seen_directories == recorded_directories && seen_files == recorded_files,
                "own identity tree changed during preparation: {}",
                root.display()
            );
        }
        Ok(())
    }
    /// Only database-root local entries are overlaid. External files remain at their own
    /// locations. Every recorded local directory, including empty ones, is recreated first,
    /// then every local file, each with its recorded permission bits.
    pub fn overlay(&self, old_db: &Path, replacement: &Root, backup: &Root) -> Result<()> {
        self.verify(backup)?;
        let old_db = fs::canonicalize(old_db)?;
        let local_tree = |relative: &Path| {
            relative
                .components()
                .next()
                .and_then(|c| c.as_os_str().to_str())
                .is_some_and(|first| IDENTITY_TREES.iter().any(|(name, _, _)| *name == first))
        };
        let mut directories: Vec<_> = self.directories.iter().collect();
        directories.sort_by(|a, b| a.path.cmp(&b.path));
        for directory in directories {
            if let Ok(relative) = directory.path.strip_prefix(&old_db) {
                use std::os::unix::fs::DirBuilderExt;
                ensure!(local_tree(relative), "unexpected private directory");
                ensure!(directory.mode <= 0o777, "private directory carries special bits");
                fs::DirBuilder::new().mode(0o700).create(replacement.path.join(relative))?;
                replacement
                    .open_child(relative.to_str().context("non-text identity path")?)?
                    .set_mode(directory.mode)?;
                replacement.sync()?;
            } else {
                ensure!(
                    directory.path.symlink_metadata()?.file_type().is_dir(),
                    "external private directory changed"
                );
            }
        }
        for file in &self.files {
            if let Ok(relative) = file.source.strip_prefix(&old_db) {
                ensure!(
                    self.protected_files.contains(&file.source) || local_tree(relative),
                    "unexpected local identity overlay"
                );
                let relative = relative.to_str().context("non-text identity path")?;
                match (file.size, file.mode) {
                    (Some(size), Some(mode)) => {
                        use std::os::unix::fs::PermissionsExt;
                        ensure!(mode <= 0o777, "private file carries special bits");
                        let bytes = backup.bytes(&file.stored, size)?;
                        let mut output = replacement.create_file(relative)?;
                        output.write_all(&bytes)?;
                        output.set_permissions(fs::Permissions::from_mode(mode))?;
                        output.sync_all()?;
                        replacement.sync_parent(relative)?;
                        ensure!(
                            descriptor_mode(&output)? == mode,
                            "private file mode was not applied"
                        );
                    }
                    _ => ensure!(
                        crate::safe_io::absent(&replacement.path.join(relative))?,
                        "replacement supplied an absent local config"
                    ),
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
fn descriptor_mode(file: &fs::File) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.mode() & 0o7777)
}
fn descriptor_owner(file: &fs::File) -> Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.uid(), metadata.gid()))
}
/// A database-local identity entry is kept with its exact bits and handed back to the
/// database owner, so it must already belong to that owner and group, carry no special
/// bits, and not be writable by other accounts.
fn check_local_entry(path: &Path, mode: u32, actual: (u32, u32), owner: (u32, u32)) -> Result<()> {
    ensure!(
        actual == owner,
        "identity entry {} belongs to {}:{}, not to the database owner {}:{}",
        path.display(),
        actual.0,
        actual.1,
        owner.0,
        owner.1
    );
    ensure!(
        mode & 0o7000 == 0 && mode & 0o002 == 0,
        "identity entry {} has special or world-writable mode {mode:o}",
        path.display()
    );
    Ok(())
}
/// Owner, mode, link count and length of a consensus seed, read from its open descriptor.
fn check_seed(seed: &fs::File, owner: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = seed.metadata()?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o077 == 0,
        "configured consensus seed is not an owned private regular file"
    );
    ensure!(metadata.len() == 32, "configured consensus seed is not a protected 32-byte file");
    Ok(())
}
#[cfg(test)]
thread_local! {
    static BEFORE_IDENTITY_COPY: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}
/// Test-only step between the seed checks and the backup copy.
#[cfg(test)]
fn before_identity_copy() {
    BEFORE_IDENTITY_COPY.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
}
/// The parent of `source`, opened below the held database when it lies inside it.
fn anchored_file<'a>(database: &Root, source: &'a Path) -> Result<(Root, &'a str)> {
    let parent = database.open_anchored(source.parent().context("identity source parent")?)?;
    let name = source.file_name().and_then(|s| s.to_str()).context("identity filename")?;
    Ok((parent, name))
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

#[cfg(test)]
mod seed_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn seed_replaced_after_its_checks_is_never_copied() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().canonicalize()?;
        let db = Root::create(&base.join("db"))?;
        db.write_new(
            "config.json",
            br#"{"extraconfig":{"pq_consensus":{"consensus_key_file":"seed"}}}"#,
        )?;
        db.ensure_directory("keyring")?;
        let seed = db.path.join("seed");
        fs::write(&seed, [7_u8; 32])?;
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600))?;
        for name in ["operator.json", "global.json", "unit.service"] {
            fs::write(base.join(name), b"{}")?;
        }
        let backup = Root::create(&base.join("backup"))?;
        // Between the seed checks and the copy, the seed is replaced by name with a
        // world-readable file of another length and other bytes.
        let replaced = seed.clone();
        BEFORE_IDENTITY_COPY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let staged = replaced.with_extension("staged");
                fs::write(&staged, [9_u8; 64]).expect("stage replacement");
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o644))
                    .expect("replacement mode");
                fs::rename(&staged, &replaced).expect("replace seed");
            }));
        });
        let captured = Identity::capture(
            &db.path,
            &base,
            &db.path,
            &base.join("operator.json"),
            &base.join("global.json"),
            &[base.join("unit.service")],
            &backup,
        );
        BEFORE_IDENTITY_COPY.with(|hook| *hook.borrow_mut() = None);
        // The held descriptor now names an unlinked inode: its recheck refuses before any
        // byte is copied, and the replacement is never opened.
        let error = captured.err().context("a seed replaced after its checks was backed up")?;
        let text = format!("{error:#}");
        assert!(
            text.contains("configured consensus seed is not an owned private regular file"),
            "wrong refusal: {text}"
        );
        if let Some(files) = crate::trees::optional_directory(&backup, "files")? {
            for file in crate::trees::inventory(&files)? {
                assert_ne!(
                    files.bytes(&file.path, 64)?,
                    [9_u8; 64],
                    "the replacement was copied into the backup"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tree_contract_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Node {
        _temporary: tempfile::TempDir,
        base: PathBuf,
        db: Root,
        work: PathBuf,
    }
    /// A node whose identity trees hold files of several modes and an empty nested
    /// directory; `keys_in_database` puts the work root (and its `keys`) in the database.
    fn node(keys_in_database: bool) -> Result<Node> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().canonicalize()?;
        let db = Root::create(&base.join("db"))?;
        let work =
            if keys_in_database { db.path.clone() } else { Root::create(&base.join("work"))?.path };
        db.write_new("config.json", b"{}")?;
        db.write_new("keyring/KEY", b"transport key")?;
        db.write_new("console-client/client", b"console private key")?;
        db.write_new("console-client/client.pub", b"console public key")?;
        db.write_new("console-client/server.pub", b"server public key")?;
        db.ensure_directory("console-client/empty/inner")?;
        let keys = Root::open(&work)?;
        keys.write_new("keys/pq-consensus.seed", &[7; 32])?;
        let mode =
            |path: &Path, mode: u32| fs::set_permissions(path, fs::Permissions::from_mode(mode));
        mode(&db.path.join("console-client/client.pub"), 0o644)?;
        mode(&db.path.join("console-client/server.pub"), 0o640)?;
        mode(&db.path.join("console-client/empty"), 0o750)?;
        mode(&db.path.join("console-client/empty/inner"), 0o710)?;
        mode(&db.path.join("console-client"), 0o751)?;
        mode(&db.path.join("keyring"), 0o700)?;
        for name in ["operator.json", "global.json", "unit.service"] {
            fs::write(base.join(name), b"{}")?;
        }
        Ok(Node { _temporary: temporary, base, db, work })
    }
    fn capture(node: &Node, backup: &str) -> Result<(Identity, Root)> {
        let backup = Root::create(&node.base.join(backup))?;
        let identity = Identity::capture(
            &node.db.path,
            &node.work,
            &node.db.path,
            &node.base.join("operator.json"),
            &node.base.join("global.json"),
            &[node.base.join("unit.service")],
            &backup,
        )?;
        Ok((identity, backup))
    }
    /// Every entry of a tree with kind, bits, owner, group and bytes.
    fn listing(root: &Path) -> Result<Vec<(String, bool, u32, u32, u32, Vec<u8>)>> {
        let tree = Root::open(root)?;
        crate::trees::private_tree(&tree, 1000, 1 << 20)?
            .into_iter()
            .map(|e| {
                let bytes = if e.directory { vec![] } else { tree.bytes(&e.path, e.size)? };
                Ok((e.path, e.directory, e.mode, e.uid, e.gid, bytes))
            })
            .collect()
    }
    #[test]
    fn identity_trees_keep_bytes_modes_owner_and_empty_directories() -> Result<()> {
        for keys_in_database in [false, true] {
            let node = node(keys_in_database)?;
            let (identity, backup) = capture(&node, "backup")?;
            let replacement = Root::create(&node.base.join("replacement"))?;
            identity.overlay(&node.db.path, &replacement, &backup)?;
            replacement.hand_over(node.db.owner()?)?;
            let mut trees = vec!["keyring", "console-client"];
            if keys_in_database {
                trees.push("keys");
            } else {
                assert!(!replacement.path.join("keys").exists(), "external keys were copied in");
            }
            for tree in trees {
                assert_eq!(
                    listing(&replacement.path.join(tree))?,
                    listing(&node.db.path.join(tree))?,
                    "{tree} was not preserved exactly (keys in database: {keys_in_database})"
                );
            }
            identity.verify_sources(&node.db)?;
        }
        Ok(())
    }
    #[test]
    fn a_changed_identity_tree_is_detected_before_exposure() -> Result<()> {
        let changes: [(&str, fn(&Node) -> Result<()>); 4] = [
            ("file mode", |n| {
                Ok(fs::set_permissions(
                    n.db.path.join("console-client/client.pub"),
                    fs::Permissions::from_mode(0o600),
                )?)
            }),
            ("directory mode", |n| {
                Ok(fs::set_permissions(
                    n.db.path.join("console-client/empty"),
                    fs::Permissions::from_mode(0o700),
                )?)
            }),
            ("new file", |n| n.db.write_new("console-client/extra", b"x")),
            ("new empty directory", |n| n.db.ensure_directory("keyring/new")),
        ];
        for (label, change) in changes {
            let node = node(false)?;
            let (identity, _backup) = capture(&node, "backup")?;
            change(&node)?;
            let error = identity.verify_sources(&node.db).expect_err(label);
            assert!(
                format!("{error:#}").contains("changed during preparation"),
                "{label}: {error:#}"
            );
        }
        Ok(())
    }
    #[test]
    fn a_local_identity_entry_of_another_owner_or_unsafe_mode_refuses() -> Result<()> {
        for (label, mode) in [("world-writable", 0o666), ("setgid directory", 0o2750)] {
            let node = node(false)?;
            let path = if mode == 0o2750 {
                node.db.path.join("console-client/empty")
            } else {
                node.db.path.join("console-client/client")
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            let error = capture(&node, "backup").err().context(label)?;
            assert!(
                format!("{error:#}").contains("special or world-writable"),
                "{label}: {error:#}"
            );
        }
        let Some(other) = crate::safe_io::ownership_tests::other_owner() else {
            eprintln!("SKIP: no second owner is available to this test process");
            return Ok(());
        };
        let node = node(false)?;
        let target = std::ffi::CString::new(
            node.db.path.join("console-client/client").as_os_str().as_encoded_bytes(),
        )?;
        // SAFETY: a terminated path in a private temporary directory.
        ensure!(unsafe { libc::chown(target.as_ptr(), other.0, other.1) } == 0, "chown");
        let error = capture(&node, "backup").err().context("foreign owner accepted")?;
        assert!(format!("{error:#}").contains("not to the database owner"), "{error:#}");
        Ok(())
    }
}
