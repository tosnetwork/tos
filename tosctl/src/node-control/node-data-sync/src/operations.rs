//! Administrative trusted-data recovery. The donor never supplies identity or local StateDb bytes.
use crate::{
    capture,
    cas::Objects,
    catalog::{Catalog, verify_generation},
    context::{NodeContext, read_bytes},
    generation,
    identity::Identity,
    journal::{Journal, Phase, Recovery, TreeIdentity},
    model::{FullId, MANIFEST_LIMIT, SignedManifest, approved_forks, sha256},
    records::{self, ChainRecords},
    safe_io::Root,
    service::{Frozen, operation_lock},
    trees, worker,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub context: NodeContext,
    pub manifest: PathBuf,
    pub cache: PathBuf,
    pub publisher_key: String,
    pub source_url: Option<String>,
}
#[derive(Serialize)]
pub struct Preparation {
    pub generation: String,
    pub network: crate::model::Network,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
    pub database: PathBuf,
    pub warning: &'static str,
    pub local_config_presence: std::collections::BTreeMap<String, bool>,
    pub preserved_classes: Vec<&'static str>,
}
fn trusted(text: &str) -> Result<[u8; 32]> {
    crate::model::hash(text)?;
    hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("publisher key length"))
}
fn selected(request: &RestoreRequest) -> Result<(SignedManifest, [u8; 32])> {
    request.context.validate_paths()?;
    request.context.service().validate()?;
    let key = trusted(&request.publisher_key)?;
    let signed = SignedManifest::parse(&read_bytes(&request.manifest, MANIFEST_LIMIT)?, &key)?;
    let (network, policy) = request.context.policy()?;
    ensure!(signed.manifest.network == network, "dump belongs to another held network");
    ensure!(
        signed.manifest.approved_forks == approved_forks(&policy)?,
        "dump differs from locally approved fork policy"
    );
    ensure!(
        signed.manifest.source_build == request.context.engine_sha256,
        "dump requires another installed build"
    );
    ensure!(
        signed.manifest.permanent_cells == request.context.service().permanent_cells()?,
        "dump requires another cell-storage mode"
    );
    Ok((signed, key))
}
pub fn preflight(request: &RestoreRequest) -> Result<Preparation> {
    let (signed, key) = selected(request)?;
    let raw = signed
        .manifest
        .files
        .iter()
        .try_fold(0_u64, |n, o| n.checked_add(o.size).context("raw size overflow"))?;
    let compressed = signed.manifest.files.iter().try_fold(0_u64, |n, o| {
        n.checked_add(o.compressed_size).context("transfer size overflow")
    })?;
    let mut local_config_presence = std::collections::BTreeMap::new();
    for name in crate::paths::LOCAL_CONFIGS {
        let path = request.context.database.join(name);
        let present = match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                ensure!(metadata.file_type().is_file(), "local config is a link or special file");
                true
            }
        };
        local_config_presence.insert(name.to_owned(), present);
    }
    Ok(Preparation {
        local_config_presence,
        preserved_classes: vec![
            "config.json",
            "keyring",
            "work-root keys",
            "primary and scheduled consensus seeds",
            "operator/vault/service configuration",
            "consensus",
            "catchains",
            "local StateDb records and full-id safety anchors",
            "old tmp/import remains only with old CellDb",
        ],
        generation: signed.verify(&key)?,
        network: signed.manifest.network,
        raw_bytes: raw,
        compressed_bytes: compressed,
        database: request.context.database.clone(),
        warning: "Trusted publisher data; own identity, sessions, local safety anchors and old recovery material must be preserved. Offline inspection and native ancestry checks run after stopping, before FORWARD_ONLY. No rollback is available after replacement exposure.",
    })
}
fn separate(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "private operation, node database and public object cache must be disjoint"
    );
    Ok(())
}
fn operation_directory(context: &NodeContext, path: &Path) -> Result<Root> {
    let absolute = std::path::absolute(path)?;
    ensure!(
        !absolute.starts_with(&context.database) && !context.database.starts_with(&absolute),
        "operation must be outside installed tree"
    );
    let root = Root::create(&absolute)?;
    ensure!(
        TreeIdentity::read(&root.path)?.device == TreeIdentity::read(&context.database)?.device,
        "staging and installed tree must share a filesystem"
    );
    Ok(root)
}
fn metadata(signed: &SignedManifest, objects: &Objects, path: &str) -> Result<Vec<u8>> {
    let object = signed
        .manifest
        .files
        .iter()
        .find(|o| o.path == path)
        .context("generation metadata absent")?;
    objects.bytes(object, MANIFEST_LIMIT)
}
fn chain(signed: &SignedManifest, objects: &Objects) -> Result<ChainRecords> {
    ChainRecords::parse(&metadata(signed, objects, "state-records.cbor")?)
}
fn required(old: &ChainRecords, local: &records::LocalRecords) -> Result<BTreeSet<FullId>> {
    let mut anchors = local.safety_anchors()?;
    anchors.extend([old.gc()?, old.init()?, old.frontier()?]);
    Ok(anchors)
}
/// Back up complete offline identity/config using the same inventory as restoration.
pub fn backup(context: &NodeContext, destination: &Path) -> Result<Identity> {
    context.validate_paths()?;
    let _operation = operation_lock(&context.database)?;
    let _frozen = context.service().freeze()?;
    let backup = operation_directory(context, destination)?;
    Identity::capture(
        &context.database,
        &context.work_root,
        &context.working_directory,
        &context.operator_config,
        &context.global_config,
        &context.preservation_files()?,
        &backup,
    )
}

pub fn create(
    context: &NodeContext,
    operation_path: &Path,
    store: &Path,
    publisher: &crate::publisher::PublisherSecret,
) -> Result<String> {
    context.validate_paths()?;
    publisher.validate(&context.database, store, operation_path)?;
    context.source_role()?;
    let _lock = operation_lock(&context.database)?;
    let service = context.service();
    let permanent = service.permanent_cells()?;
    let public = Root::open(store)?;
    separate(&public.path, &context.database)?;
    separate(&public.path, &std::path::absolute(operation_path)?)?;
    let operation = operation_directory(context, operation_path)?;
    ensure!(
        context.budget_roots.iter().any(|root| store.starts_with(root)),
        "catalog is outside task allocation inventory"
    );
    let reserve = crate::budget::reservation(trees::allocated_bytes(&context.database)?, 0, 0)?;
    let _monitor = crate::budget::Monitor::start(
        &context.budget_roots,
        &operation,
        reserve,
        &context.disk_policy,
    )?;
    let image = Root::create(&operation.path.join("image"))?;
    let started = Instant::now();
    let capture_started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let frozen = service.stop()?;
    // Repeat role checks after quiescence: configuration may have changed while stop settled.
    context.source_role()?;
    service.require_mode(permanent)?;
    publisher.validate(&context.database, store, operation_path)?;
    let copied =
        capture::cold_image_checked(&frozen, &Root::open(&context.database)?, &image, publisher)?;
    service.start_in_mode(frozen, permanent)?;
    operation.write_new(
        "capture.json",
        &serde_json::to_vec(&crate::model::CaptureReceipt {
            method: "cold_copy".to_owned(),
            started_utc: capture_started,
            finished_utc: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            copied_bytes: copied,
            elapsed_millis: u64::try_from(started.elapsed().as_millis())?,
        })?,
    )?;
    worker::validate(context, &image, &operation, vec![], permanent)?;
    let checked = Root::open(&operation.path.join("checked"))?;
    let objects = Objects::open(store)?;
    let signing_key = publisher.signing_key();
    let catalog = Catalog::open(store, signing_key.verifying_key().to_bytes())?;
    let (_, policy) = context.policy()?;
    let signed = generation::assemble(
        &image,
        &checked,
        generation::GenerationPolicy {
            global_config: &policy,
            global_id: context.global_id,
            references: &context.references,
        },
        &objects,
        signing_key,
        &catalog,
    )?;
    operation.write_new("generation.json", &signed.bytes()?)?;
    signed.verify(&signing_key.verifying_key().to_bytes())
}

/// Complete all transport and verification before stopping the target.
pub fn restore(request: &RestoreRequest, operation_path: &Path) -> Result<Journal> {
    let preparation = preflight(request)?;
    let (signed, key) = selected(request)?;
    ensure!(
        signed.verify(&key)? == preparation.generation,
        "selected generation changed during preflight"
    );
    let objects = Objects::open(&request.cache)?;
    let catalog = Catalog::open(&request.cache, key)?;
    separate(objects.root_path(), &request.context.database)?;
    separate(objects.root_path(), &std::path::absolute(operation_path)?)?;
    let operation = operation_directory(&request.context, operation_path)?;
    let _lock = operation_lock(&request.context.database)?;
    ensure!(
        request.context.budget_roots.iter().any(|root| request.cache.starts_with(root)),
        "cache is outside task allocation inventory"
    );
    let reserve = crate::budget::reservation(
        preparation.raw_bytes,
        preparation.compressed_bytes,
        trees::allocated_bytes(&request.context.database)?,
    )?;
    let _monitor = crate::budget::Monitor::start(
        &request.context.budget_roots,
        &operation,
        reserve,
        &request.context.disk_policy,
    )?;
    operation.write_new("request.json", &serde_json::to_vec(request)?)?;
    operation.write_new("generation.json", &signed.bytes()?)?;
    let operation_id = format!("{:032x}", rand::random::<u128>());
    let lease = sha256(operation_id.as_bytes());
    operation.write_new("operation-id", operation_id.as_bytes())?;
    {
        let writer = objects.writer()?;
        catalog.begin_owned_download(&signed, &writer, &lease, &operation)?;
        for object in &signed.manifest.files {
            if objects.check(object).is_err() {
                let source = request
                    .source_url
                    .as_deref()
                    .context("object is absent or corrupt and no source URL was supplied")?;
                writer.fetch(source, object, std::time::Duration::from_secs(300))?;
            }
        }
        verify_generation(&signed, &objects, &key)?;
        catalog.hold_download(&signed, &writer, &lease)?;
    }
    request.context.service().require_mode(signed.manifest.permanent_cells)?;
    let frozen = request.context.service().stop()?;
    request.context.service().require_mode(signed.manifest.permanent_cells)?;
    let service_files = request.context.preservation_files()?;
    let mut journal = stage(
        request,
        &signed,
        &objects,
        &operation,
        StoppedTarget {
            operation_id: &operation_id,
            frozen: &frozen,
            service_files: &service_files,
        },
        None,
    )?;
    crate::budget::check_active()?;
    request.context.validate_paths()?;
    let approval = request.context.references.corroborate(
        &signed.manifest.network,
        &signed.manifest.frontier,
        &journal.reference_binding(),
    )?;
    journal.authorize(&operation, &approval)?;
    request.context.service().require_mode(signed.manifest.permanent_cells)?;
    journal.forward_only(&operation)?;
    journal.exchange(&operation)?;
    drop(frozen);
    start_installed(&request.context, &operation, &mut journal)?;
    Ok(journal)
}
struct StoppedTarget<'a> {
    operation_id: &'a str,
    frozen: &'a Frozen,
    service_files: &'a [PathBuf],
}
fn stage(
    request: &RestoreRequest,
    signed: &SignedManifest,
    objects: &Objects,
    operation: &Root,
    target: StoppedTarget<'_>,
    previous: Option<&Journal>,
) -> Result<Journal> {
    let space = Root::open(&request.context.database)?.space()?;
    stage_with_space(request, signed, objects, operation, target, previous, space)
}
fn stage_with_space(
    request: &RestoreRequest,
    signed: &SignedManifest,
    objects: &Objects,
    operation: &Root,
    target: StoppedTarget<'_>,
    previous: Option<&Journal>,
    space: crate::budget::Space,
) -> Result<Journal> {
    let StoppedTarget { operation_id, frozen, service_files } = target;
    ensure!(frozen.root == request.context.database, "preservation lock belongs to another root");
    let own = Root::open(&request.context.database)?;
    let mut private_names = vec![
        "consensus".to_owned(),
        "catchains".to_owned(),
        "adnl".to_owned(),
        "overlays".to_owned(),
    ];
    for entry in fs::read_dir(&own.path)? {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(|name| name.starts_with("dht-")) {
            private_names.push(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("transport path is not text"))?,
            );
        }
    }
    let mut private_bytes = 0_u64;
    for name in &private_names {
        if !crate::safe_io::absent(&own.path.join(name))? {
            for file in trees::inventory(&Root::open(&own.path.join(name))?)? {
                private_bytes = private_bytes
                    .checked_add(file.size)
                    .context("private preservation size overflow")?;
                ensure!(
                    private_bytes <= crate::model::RAW_LIMIT,
                    "private preservation exceeds tree ceiling"
                );
            }
        }
    }
    let raw = signed.manifest.files.iter().try_fold(0_u64, |sum, file| {
        sum.checked_add(file.size).context("manifest raw size overflow")
    })?;
    let reserve = crate::budget::reservation(raw, 0, private_bytes)?;
    crate::budget::admit(
        &request.context.disk_policy,
        &[crate::budget::allocated(&request.context.budget_roots)?],
        reserve,
        space,
    )?;
    let store = node_store::OfflineStore::open_existing(&own.path.join("state"))?;
    let (old, local) = records::export(&store)?;
    drop(store);
    let anchors = required(&old, &local)?;
    let donor = chain(signed, objects)?;
    ensure!(
        anchors.iter().all(|a| a.seqno <= signed.manifest.frontier.seqno),
        "dump predates target safety anchor"
    );
    let revision = format!("stage-{:032x}", rand::random::<u128>());
    let revision_root = Root::create(&operation.path.join(&revision))?;
    let backup = Root::create(&revision_root.path.join("private"))?;
    let identity = Identity::capture(
        &own.path,
        &request.context.work_root,
        &request.context.working_directory,
        &request.context.operator_config,
        &request.context.global_config,
        service_files,
        &backup,
    )?;
    let replacement = Root::create(&revision_root.path.join("replacement"))?;
    let payload = Root::create(&revision_root.path.join("payload"))?;
    // Only chain files are extracted here. There is no raw donor StateDb or donor local overlay.
    for object in signed.manifest.files.iter().filter(|o| o.path.starts_with("chain/")) {
        objects.materialize_native(object, &payload, &own)?;
    }
    capture::install_chain_roots(&payload, &replacement)?;
    replacement.sync()?;
    // Native validation uses a separate image with fresh validation identity and fresh recovery dir.
    records::install(&replacement.path.join("state"), &donor, &local)?;
    let image = Root::create(&revision_root.path.join("image"))?;
    let stage_frozen = Frozen::acquire(&replacement.path)?;
    capture::cold_image(&stage_frozen, &replacement, &image)?;
    drop(stage_frozen);
    let checked = worker::validate(
        &request.context,
        &image,
        &revision_root,
        anchors.iter().cloned().collect(),
        signed.manifest.permanent_cells,
    )?;
    let evidence = checked.ancestors.into_iter().collect();
    records::reconcile_forks(&signed.manifest.approved_forks, &donor, &old.forks()?, &evidence)?;
    records::reconcile_anchors(&donor, &anchors, &evidence)?;
    identity.overlay(&own.path, &replacement, &backup)?;
    let mut local_trees = Vec::new();
    for name in &private_names {
        local_trees.push(trees::preserve(&own, name, Some(&replacement))?);
    }
    for name in ["tmp", "import"] {
        local_trees.push(trees::preserve(&own, name, None)?);
    }
    let signing: serde_json::Value =
        serde_json::from_slice(&own.bytes("config.json", MANIFEST_LIMIT)?)?;
    if signing.get("validators").and_then(|v| v.as_array()).is_some_and(|v| !v.is_empty())
        || signing.pointer("/extraconfig/pq_consensus").is_some_and(|v| !v.is_null())
    {
        ensure!(
            own.path.join("consensus").symlink_metadata()?.file_type().is_dir(),
            "existing validator signing history is missing"
        );
    }
    // Recovery material remains in the complete old root. Never copy old tmp/import into replacement.
    ensure!(
        !replacement.path.join("tmp").try_exists()?
            && !replacement.path.join("import").try_exists()?,
        "old recovery context leaked into replacement"
    );
    fs::create_dir(replacement.path.join("tmp"))?;
    replacement.sync()?;
    let store = node_store::OfflineStore::open_existing(&replacement.path.join("state"))?;
    let (_, actual) = records::export(&store)?;
    ensure!(actual == local, "local StateDb preservation mismatch");
    drop(store);
    identity.verify_sources()?;
    replacement.sync()?;
    let preservation = serde_json::to_vec(
        &serde_json::json!({"identity":identity,"local_records":local,"anchors":anchors,"local_trees":local_trees}),
    )?;
    ensure!(preservation.len() as u64 <= MANIFEST_LIMIT, "private preservation receipt size limit");
    revision_root.write_new("preservation.json", &preservation)?;
    let journal = Journal {
        version: 2,
        corroboration_sha256: None,
        operation: operation_id.to_owned(),
        generation: signed.verify(&trusted(&request.publisher_key)?)?,
        old: TreeIdentity::read(&own.path)?,
        new: TreeIdentity::read(&replacement.path)?,
        installed: own.path.to_str().context("installed path")?.to_owned(),
        staged: replacement.path.to_str().context("stage path")?.to_owned(),
        preservation_sha256: sha256(&preservation),
        target_anchor: old.frontier()?,
        phase: previous.map_or(Phase::Staged, |_| Phase::ForwardOnly),
    };
    journal.write(operation)?;
    Ok(journal)
}
fn start_installed(context: &NodeContext, operation: &Root, journal: &mut Journal) -> Result<()> {
    ensure!(
        journal.recovery()? == Recovery::NewContinueOnly,
        "cannot start old installed tree as recovered replacement"
    );
    if journal.phase == Phase::ForwardOnly {
        journal.advance(operation, Phase::Exchanged)?;
    }
    if journal.phase == Phase::Exchanged {
        journal.advance(operation, Phase::StartIssued)?;
    }
    let request: RestoreRequest =
        serde_json::from_slice(&operation.bytes("request.json", MANIFEST_LIMIT)?)?;
    let signed = SignedManifest::parse(
        &operation.bytes("generation.json", MANIFEST_LIMIT)?,
        &trusted(&request.publisher_key)?,
    )?;
    context.service().require_mode(signed.manifest.permanent_cells)?;
    let frozen = context.service().freeze()?;
    journal.check_references(operation, true)?;
    context.service().start_in_mode(frozen, signed.manifest.permanent_cells)?;
    if journal.phase == Phase::StartIssued {
        journal.advance(operation, Phase::CatchingUp)?;
    }
    Ok(())
}
pub enum RecoveryOutcome {
    Installed(Box<(NodeContext, Journal)>),
    Aborted,
}
pub fn recover(operation_path: &Path) -> Result<RecoveryOutcome> {
    let operation = Root::open(operation_path)?;
    let request: RestoreRequest =
        serde_json::from_slice(&operation.bytes("request.json", MANIFEST_LIMIT)?)?;
    request.context.validate_paths()?;
    separate(&operation.path, &request.context.database)?;
    separate(&request.cache, &request.context.database)?;
    separate(&request.cache, &operation.path)?;
    if crate::safe_io::absent(&operation.path.join("restore.json"))? {
        let _monitor = crate::budget::Monitor::start(
            &request.context.budget_roots,
            &operation,
            0,
            &request.context.disk_policy,
        )?;
        let _lock = operation_lock(&request.context.database)?;
        let key = trusted(&request.publisher_key)?;
        let signed =
            SignedManifest::parse(&operation.bytes("generation.json", MANIFEST_LIMIT)?, &key)?;
        let id = sha256(&operation.bytes("operation-id", 32)?);
        let objects = Objects::open(&request.cache)?;
        let catalog = Catalog::open(&request.cache, key)?;
        catalog.abort_download(&signed, &objects, &id, &operation)?;
        // Normal reachability pruning retains every other lease and published generation.
        catalog.prune()?;
        return Ok(RecoveryOutcome::Aborted);
    }
    let mut journal = Journal::read(&operation)?;
    let signed_probe = SignedManifest::parse(
        &operation.bytes("generation.json", MANIFEST_LIMIT)?,
        &trusted(&request.publisher_key)?,
    )?;
    let raw = signed_probe
        .manifest
        .files
        .iter()
        .try_fold(0_u64, |n, f| n.checked_add(f.size).context("recovery size overflow"))?;
    let reserve = if journal.recovery()? == Recovery::OldRefreshRequired {
        crate::budget::reservation(raw, 0, trees::allocated_bytes(&request.context.database)?)?
    } else {
        0
    };
    let _monitor = crate::budget::Monitor::start(
        &request.context.budget_roots,
        &operation,
        reserve,
        &request.context.disk_policy,
    )?;
    let _lock = operation_lock(&request.context.database)?;
    ensure!(
        Path::new(&journal.installed) == request.context.database,
        "journal and selected service root differ"
    );
    let key = trusted(&request.publisher_key)?;
    let signed = SignedManifest::parse(&operation.bytes("generation.json", MANIFEST_LIMIT)?, &key)?;
    let (network, policy) = request.context.policy()?;
    ensure!(
        signed.verify(&key)? == journal.generation
            && signed.manifest.network == network
            && signed.manifest.approved_forks == approved_forks(&policy)?
            && signed.manifest.source_build == request.context.engine_sha256
            && signed.manifest.permanent_cells == request.context.service().permanent_cells()?,
        "recovery generation differs from held policy, build or storage mode"
    );
    if journal.recovery()? == Recovery::NewContinueOnly {
        journal.check_references(&operation, false)?;
    }
    let frozen = request.context.service().stop()?;
    request.context.service().require_mode(signed.manifest.permanent_cells)?;
    match journal.recovery()? {
        Recovery::OldRefreshRequired => {
            // The old root could have booted and signed: capture its latest local state, never reuse a stale overlay.
            let objects = Objects::open(&request.cache)?;
            verify_generation(&signed, &objects, &key)?;
            journal = stage(
                &request,
                &signed,
                &objects,
                &operation,
                StoppedTarget {
                    operation_id: &journal.operation,
                    frozen: &frozen,
                    service_files: &request.context.preservation_files()?,
                },
                Some(&journal),
            )?;
            let approval = request.context.references.corroborate(
                &network,
                &signed.manifest.frontier,
                &journal.reference_binding(),
            )?;
            journal.authorize(&operation, &approval)?;
            request.context.service().require_mode(signed.manifest.permanent_cells)?;
            journal.exchange(&operation)?;
        }
        Recovery::NewContinueOnly => {
            // A boot may have advanced this tree. Corroborate its current coherent frontier;
            // never replace it with the original snapshot or overlay old signing records.
            let store =
                node_store::OfflineStore::open_existing(&request.context.database.join("state"))?;
            let (current, _) = records::export(&store)?;
            drop(store);
            let approval = request.context.references.corroborate(
                &network,
                &current.frontier()?,
                &journal.reference_binding(),
            )?;
            journal.authorize(&operation, &approval)?;
        }
    }
    drop(frozen);
    start_installed(&request.context, &operation, &mut journal)?;
    Ok(RecoveryOutcome::Installed(Box::new((request.context, journal))))
}

/// Completion releases only the receiver lease, never the retained old root or its recovery context.
pub fn complete(operation_path: &Path) -> Result<()> {
    let operation = Root::open(operation_path)?;
    let request: RestoreRequest =
        serde_json::from_slice(&operation.bytes("request.json", MANIFEST_LIMIT)?)?;
    let _lock = operation_lock(&request.context.database)?;
    let mut journal = Journal::read(&operation)?;
    if journal.phase == Phase::CatchingUp {
        journal.advance(&operation, Phase::Complete)?;
    }
    ensure!(
        journal.phase == Phase::Complete && journal.recovery()? == Recovery::NewContinueOnly,
        "restore is not completed on the replacement tree"
    );
    Catalog::open(&request.cache, trusted(&request.publisher_key)?)?
        .release(&sha256(journal.operation.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires engine-created generation and a private network namespace; run the native fixture CI step"]
    fn native_stage_preserves_own_context_and_never_overlays_recovery_material() -> Result<()> {
        let fixture = PathBuf::from(
            std::env::var("NODE_SYNC_NATIVE_FIXTURE")
                .context("NODE_SYNC_NATIVE_FIXTURE is required")?,
        )
        .canonicalize()?;
        let source = PathBuf::from(
            std::env::var("NODE_SYNC_NATIVE_SOURCE")
                .context("NODE_SYNC_NATIVE_SOURCE is required")?,
        )
        .canonicalize()?;
        let engine = PathBuf::from(
            std::env::var("NODE_SYNC_NATIVE_ENGINE")
                .context("NODE_SYNC_NATIVE_ENGINE is required")?,
        )
        .canonicalize()?;
        let worker = PathBuf::from(
            std::env::var("NODE_SYNC_NATIVE_WORKER")
                .context("NODE_SYNC_NATIVE_WORKER is required")?,
        )
        .canonicalize()?;
        let parent =
            Root::create(&fixture.join(format!("preservation-{:032x}", rand::random::<u128>())))?;
        let own = Root::create(&parent.path.join("own"))?;
        let stopped_image = fixture.join("image");
        let stopped = Frozen::acquire(&stopped_image)?;
        capture::cold_image(&stopped, &Root::open(&stopped_image)?, &own)?;
        drop(stopped);
        let installed_worker = parent.path.join("validation-worker");
        fs::copy(&worker, &installed_worker)?;
        let worker = installed_worker;
        let mut local_store = node_store::OfflineStore::open_existing(&own.path.join("state"))?;
        local_store.write(&[(node_store::StateKey::PendingObserverCleanup, Some(vec![]))])?;
        drop(local_store);
        let source_root = Root::open(&source)?;
        trees::copy_file(&source_root, "config.json", &own, "config.json", MANIFEST_LIMIT)?;
        trees::copy_optional_tree(&source_root, "keyring", &own)?;
        own.write_new("custom-overlays.json", b"{\"local\":true}")?;
        own.write_new(
            "tmp/persistent-state/target-only.celldb-rollback.receipt",
            b"belongs only to the original cells",
        )?;
        own.write_new("consensus/session/own-vote", b"own newest signed vote")?;
        own.write_new("catchains/own-journal", b"own session journal")?;
        parent.write_new("operator.json", b"{}")?;
        parent.write_new("fixture.service", b"fixture definition bytes")?;
        let engine_sha256 =
            crate::safe_io::file_hash(crate::context::read_file(&engine, 1 << 30)?, 1 << 30)?.1;
        let worker_sha256 =
            crate::safe_io::file_hash(crate::context::read_file(&worker, 1 << 30)?, 1 << 30)?.1;
        let mut context = NodeContext {
            unit: "fixture.service".to_owned(),
            user_manager: true,
            database: own.path.clone(),
            engine,
            engine_sha256,
            validation_worker: worker,
            validation_worker_sha256: worker_sha256,
            global_config: source.join("config.global.json"),
            global_id: 3,
            work_root: parent.path.clone(),
            working_directory: parent.path.clone(),
            operator_config: parent.path.join("operator.json"),
            node_name: "fixture".to_owned(),
            budget_roots: vec![fixture.clone()],
            disk_policy: crate::budget::DiskPolicy {
                max_owned_bytes: 64 << 30,
                shutdown_free_bytes: Some(4 << 30),
            },
            vault_config_files: vec![],
            references: crate::references::ReferencePolicy { sources: vec![] },
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let objects = Objects::open(&fixture.join("catalog"))?;
        let signed = Catalog::open(objects.root_path(), key.verifying_key().to_bytes())?
            .latest()?
            .context("published native generation")?;
        let references = crate::test_references::References::new(
            &signed.manifest.network,
            &signed.manifest.frontier,
            crate::test_references::Mode::Agree,
        )?;
        context.references = references.policy.clone();
        let request = RestoreRequest {
            context,
            manifest: fixture.join("unused.json"),
            cache: objects.root_path().to_owned(),
            publisher_key: hex::encode(key.verifying_key().to_bytes()),
            source_url: None,
        };
        let operation = Root::create(&parent.path.join("operation"))?;
        let frozen = Frozen::acquire(&own.path)?;
        let staged = stage_with_space(
            &request,
            &signed,
            &objects,
            &operation,
            StoppedTarget {
                operation_id: &"12".repeat(16),
                frozen: &frozen,
                service_files: &[parent.path.join("fixture.service")],
            },
            None,
            crate::budget::Space { capacity: 128 << 30, free: 100 << 30 },
        );
        assert!(staged.is_ok(), "native stage preservation failed: {staged:?}");
        let mut journal = staged?;
        let replacement = Root::open(Path::new(&journal.staged))?;
        assert_eq!(
            replacement.bytes("config.json", MANIFEST_LIMIT)?,
            own.bytes("config.json", MANIFEST_LIMIT)?
        );
        assert_eq!(replacement.bytes("custom-overlays.json", 100)?, b"{\"local\":true}");
        assert!(!replacement.path.join("collators-list.json").exists());
        assert!(
            replacement.path.join("consensus/session/own-vote").is_file(),
            "own signing history was not preserved"
        );
        assert_eq!(
            replacement.bytes("consensus/session/own-vote", 100)?,
            b"own newest signed vote"
        );
        assert_eq!(replacement.bytes("catchains/own-journal", 100)?, b"own session journal");
        assert!(
            fs::read_dir(replacement.path.join("tmp"))?.next().is_none(),
            "old recovery was overlaid onto imported cells"
        );
        assert!(own.path.join("tmp/persistent-state/target-only.celldb-rollback.receipt").exists());
        let approval = references.policy.corroborate(
            &signed.manifest.network,
            &signed.manifest.frontier,
            &journal.reference_binding(),
        )?;
        journal.authorize(&operation, &approval)?;
        journal.forward_only(&operation)?;
        journal.exchange(&operation)?;
        drop(frozen);
        let installed = Root::open(&request.context.database)?;
        installed
            .replace("consensus/session/own-vote", b"signed after exchange before start-issued")?;
        assert_eq!(journal.recovery()?, Recovery::NewContinueOnly);
        assert_eq!(
            installed.bytes("consensus/session/own-vote", 100)?,
            b"signed after exchange before start-issued"
        );
        assert!(journal.exchange(&operation).is_err(), "interrupted recovery permitted rollback");
        println!("NATIVE_STAGE_PRESERVATION_OK");
        Ok(())
    }
}
