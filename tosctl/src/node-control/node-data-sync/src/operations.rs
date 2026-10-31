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

/// Which target a request installs into.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// Same-node fast rejoin: an existing node keeps its own identity, signing history and
    /// local StateDb records; only chain data is replaced.
    #[default]
    Restore,
    /// A new non-validating node that has never run: it has its own identity and no local
    /// records, and receives chain data from the signed catalog.
    Bootstrap,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub context: NodeContext,
    pub manifest: PathBuf,
    pub cache: PathBuf,
    pub publisher_key: String,
    pub source_url: Option<String>,
    #[serde(default)]
    pub lane: Lane,
}
#[derive(Serialize)]
pub struct Preparation {
    pub lane: Lane,
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
fn restore_storage(request: &RestoreRequest, operation: Option<&Path>) -> Result<()> {
    request.context.validate_paths()?;
    ensure!(
        !request
            .context
            .budget_roots
            .iter()
            .any(|root| root.starts_with(&request.context.database)),
        "restore allocation roots must remain outside the exchanged database; select stable parent roots"
    );
    let mut paths = vec![request.cache.as_path()];
    if let Some(operation) = operation {
        paths.push(operation);
    }
    crate::budget::require_paths(
        &request.context.budget_roots,
        &Root::open(&request.context.database)?,
        &paths,
    )
}
/// Ownership of the cache, operation and budget roots, against the described service account.
/// Preparation abort does not use it: that path never describes the service before it has
/// authenticated the operation, and it only removes the bound stage through descriptors.
fn restore_owners(request: &RestoreRequest, operation: Option<&Path>) -> Result<()> {
    let account = request.context.service().account()?;
    account.require_private(&request.cache)?;
    account.require_budget(&request.context.budget_roots)?;
    if let Some(operation) = operation {
        require_operation_owner(&account, operation)?;
    }
    Ok(())
}
/// The target check before the exchange. A restore target is an existing node. A bootstrap
/// target must still be a database that has never run, with its service inactive and no
/// validator or signing material anywhere, the database root, the work root or the
/// configured signing references.
fn require_unexchanged_target(request: &RestoreRequest, expected: Option<bool>) -> Result<()> {
    let service = request.context.service();
    match request.lane {
        Lane::Restore => {
            service.require_restore_target(expected)?;
            ensure!(
                trees::optional_directory(&Root::open(&request.context.database)?, "state")?
                    .is_some(),
                "StateDb directory is missing: restore needs an existing node with its own local records; install a new node with tosctl node sync bootstrap"
            );
            Ok(())
        }
        Lane::Bootstrap => {
            service.require_selected_mode(expected)?;
            service.require_inactive().context(
                "bootstrap target service must be inactive; bootstrap never stops or replaces a running node",
            )?;
            crate::paths::new_node_root(&request.context.database)?;
            require_no_signing_material(&request.context)
        }
    }
}
/// A new node must hold no validator binding or key: no validator registration or signing
/// custody in `config.json`, no enabled election binding, no referenced signing seed, and
/// no key file in the work-root key directory. An empty or absent database `keys/` alone
/// proves none of this.
fn require_no_signing_material(context: &NodeContext) -> Result<()> {
    context
        .source_role()
        .context("bootstrap refuses a validator target; recover a validator with restore")?;
    let config: serde_json::Value = serde_json::from_slice(
        &Root::open(&context.database)?.bytes("config.json", MANIFEST_LIMIT)?,
    )?;
    ensure!(
        crate::identity::seed_references(&config)?.is_empty(),
        "bootstrap refuses a target that references a signing seed"
    );
    let work = Root::open(&context.work_root)?;
    if let Some(keys) = trees::optional_directory(&work, "keys")
        .context("work-root key directory is a link or special file")?
    {
        let entries = trees::private_tree(&keys, 1024, 64 << 20)?;
        ensure!(
            entries.iter().all(|entry| entry.directory),
            "bootstrap refuses a target whose work-root key directory holds key files: {}",
            keys.path.display()
        );
    }
    Ok(())
}
fn selected(request: &RestoreRequest) -> Result<(SignedManifest, [u8; 32])> {
    restore_storage(request, None)?;
    require_unexchanged_target(request, None)?;
    restore_owners(request, None)?;
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
        lane: request.lane,
        generation: signed.verify(&key)?,
        network: signed.manifest.network,
        raw_bytes: raw,
        compressed_bytes: compressed,
        database: request.context.database.clone(),
        warning: match request.lane {
            Lane::Restore => {
                "Trusted publisher data; own identity, sessions, local safety anchors and old recovery material must be preserved. Offline inspection and native ancestry checks run after stopping, before FORWARD_ONLY. No rollback is available after replacement exposure."
            }
            Lane::Bootstrap => {
                "Trusted publisher data for a new non-validating node; its own identity and console keys are preserved, and it has no local records. The target must stay inactive; native validation must prove descent from the held zero state and init block before FORWARD_ONLY. No rollback is available after replacement exposure."
            }
        },
    })
}
fn separate(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "private operation, node database and public object cache must be disjoint"
    );
    Ok(())
}
/// A new operation is created by the invoker inside a directory only the invoker controls;
/// an existing one must still be the invoker's.
fn require_operation_owner(account: &crate::service::Account, path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    account.require_private(absolute.parent().context("operation parent")?)?;
    if !crate::safe_io::absent(&absolute)? {
        account.require_private(&absolute)?;
    }
    Ok(())
}
fn operation_directory(context: &NodeContext, path: &Path) -> Result<Root> {
    let absolute = std::path::absolute(path)?;
    ensure!(
        !absolute.starts_with(&context.database) && !context.database.starts_with(&absolute),
        "operation must be outside installed tree"
    );
    require_operation_owner(&context.service().account()?, &absolute)?;
    crate::budget::require_paths(
        &context.budget_roots,
        &Root::open(&context.database)?,
        &[&absolute],
    )?;
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
    crate::budget::require_paths(
        &context.budget_roots,
        &Root::open(&context.database)?,
        &[store, operation_path],
    )?;
    let _lock = operation_lock(&context.database)?;
    let service = context.service();
    let permanent = service.permanent_cells()?;
    let account = service.account()?;
    account.require_private(store)?;
    account.require_budget(&context.budget_roots)?;
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
    // Everything that needs no stopped node is checked before the stop.
    capture::precheck_roots(&Root::open(&context.database)?)?;
    service.validate()?;
    let attached = TreeIdentity::read(&context.database)?;
    let started = Instant::now();
    let capture_started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // From the stop command on, every failure either restarts the source or reports that it
    // did not, with the distinct source-left-stopped exit status. Only a frozen source is
    // ever restarted: without the freeze its quiescence and lock are unproven.
    let frozen = service.stop_command().and_then(|()| service.freeze()).map_err(|error| {
        left_stopped(&service, "the stop could not be confirmed and frozen", &error)
    })?;
    let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<u64> {
        // Repeat role checks after quiescence: configuration may have changed while stop settled.
        context.source_role()?;
        service.require_mode(permanent)?;
        publisher.validate(&context.database, store, operation_path)?;
        #[cfg(all(test, feature = "native-lifecycle-tests"))]
        crate::test_hooks::boundary("before-capture")?;
        capture::cold_image_checked(&frozen, &Root::open(&context.database)?, &image, publisher)
    }))
    .unwrap_or_else(|panic| Err(anyhow::anyhow!("capture panicked: {}", panic_text(&panic))));
    let restarted = restart_source(context, &service, frozen, permanent, &attached);
    let copied = match (captured, restarted) {
        (Ok(copied), Ok(())) => copied,
        (Err(error), Ok(())) => {
            return Err(error.context(format!(
                "capture failed after the source was stopped; the source service {} was restarted",
                context.unit
            )));
        }
        (Ok(_), Err(stopped)) => return Err(stopped.into()),
        (Err(error), Err(stopped)) => {
            return Err(anyhow::Error::new(stopped).context(format!("capture failed: {error:#}")));
        }
    };
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

/// Restart the source this command stopped, through the same unit and manager scope, only
/// after rechecking immediately before the start that it is still a non-validating source
/// in the frozen storage mode, on the same database root, under the same held lock. Any
/// mismatch, or a failed start, leaves it stopped and is reported as such.
fn restart_source(
    context: &NodeContext,
    service: &crate::service::Service,
    frozen: Frozen,
    permanent: bool,
    attached: &TreeIdentity,
) -> std::result::Result<(), crate::service::SourceLeftStopped> {
    let recheck = (|| -> Result<()> {
        context.source_role().context("role or signing custody changed while stopped")?;
        service.require_mode(permanent).context("storage mode or unit changed while stopped")?;
        ensure!(
            TreeIdentity::read(&context.database)? == *attached,
            "database root was replaced while stopped"
        );
        frozen.check_held(&context.database).context("held lock changed while stopped")
    })();
    if let Err(error) = recheck {
        drop(frozen);
        return Err(left_stopped(service, "the restart recheck refused", &error));
    }
    service
        .start_in_mode(frozen, permanent)
        .map_err(|error| left_stopped(service, "the restart failed", &error))
}
fn left_stopped(
    service: &crate::service::Service,
    reason: &str,
    error: &anyhow::Error,
) -> crate::service::SourceLeftStopped {
    let (state, command) = service
        .abort_guidance()
        .unwrap_or_else(|guidance| ("unknown".to_owned(), format!("unavailable: {guidance:#}")));
    crate::service::SourceLeftStopped(format!(
        "the source service {} was stopped by this command and was NOT restarted: {reason}: {error:#}; observed state={state}; review the cause, then restart it with: {command}",
        service.unit
    ))
}
fn panic_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-text panic payload".to_owned()
    }
}

/// Complete all transport and verification before stopping the target.
pub fn restore(request: &RestoreRequest, operation_path: &Path) -> Result<Journal> {
    let preparation = preflight(request)?;
    let (signed, key) = selected(request)?;
    ensure!(
        signed.verify(&key)? == preparation.generation,
        "selected generation changed during preflight"
    );
    restore_storage(request, Some(operation_path))?;
    restore_owners(request, Some(operation_path))?;
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
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    crate::test_hooks::boundary("after-download")?;
    require_unexchanged_target(request, Some(signed.manifest.permanent_cells))?;
    prepare_stop(request, &signed, &operation, &operation_id)?;
    let frozen = quiesce(request)?;
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    crate::test_hooks::boundary("after-stop-before-stage")?;
    require_unexchanged_target(request, Some(signed.manifest.permanent_cells))?;
    let service_files = request.context.preservation_files()?;
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    crate::test_hooks::boundary("before-stage")?;
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
    authorize_references(request, &operation, &mut journal, &signed.manifest.frontier)?;
    require_unexchanged_target(request, Some(signed.manifest.permanent_cells))?;
    expose_staged(&operation, &mut journal)?;
    drop(frozen);
    start_installed(&request.context, &operation, &mut journal)?;
    Ok(journal)
}
/// A restore stops the existing node. A bootstrap never stops anything: its new target must
/// already be inactive, and is only frozen.
fn quiesce(request: &RestoreRequest) -> Result<Frozen> {
    let service = request.context.service();
    match request.lane {
        Lane::Restore => service.stop(),
        Lane::Bootstrap => service.freeze().context(
            "bootstrap target service must be inactive; bootstrap never stops or replaces a running node",
        ),
    }
}
/// Fixed name of the private StateDb capture inside an operation directory. There is at
/// most one: a leftover from an interrupted run is removed before the next capture, and
/// a capture is never resumed or read again, so it never becomes authoritative.
const STATE_CAPTURE: &str = "state-capture";
/// Files the native library writes when it opens and recovers the capture: a new
/// manifest and options file and its info log.
const STATE_CAPTURE_METADATA: u64 = 64 << 20;
/// Space for one capture of `state`: the copy, a table flushed from its write-ahead logs
/// while the copy recovers, and native metadata. Checked arithmetic throughout.
fn state_capture_reservation(state: &Root) -> Result<u64> {
    let (mut copy, mut logs) = (0_u64, 0_u64);
    for file in trees::inventory(state)? {
        copy = copy.checked_add(file.size).context("StateDb capture size overflow")?;
        if file.path.ends_with(".log") {
            logs = logs.checked_add(file.size).context("StateDb log size overflow")?;
        }
    }
    copy.checked_add(logs)
        .and_then(|n| n.checked_add(STATE_CAPTURE_METADATA))
        .context("StateDb capture reservation overflow")
}
fn discard_state_capture(operation: &Root) -> Result<()> {
    if operation.kind(STATE_CAPTURE)?.is_some() {
        operation.remove_tree(STATE_CAPTURE).context("remove leftover StateDb capture")?;
    }
    Ok(())
}
/// Read the installed tree's local records without ever opening it by name as the invoker.
///
/// The native library resolves paths itself and writes while it opens a database, so it
/// never sees the installed tree, whose entries the service account can replace. `state`
/// is opened below the held installed-root descriptor and copied, file by file through
/// descriptors, into a private directory of the invoker's operation; only that copy is
/// opened. A link, a replaced directory, another mount or a hard link refuses.
///
/// Consistency: the service is stopped, its native writer has shut down and no process
/// holds a writable descriptor on the tree (checked when it was frozen). Under that
/// cooperative-node model the copy, which includes the write-ahead logs and every other
/// database file, is the database as the node left it. Per-file size and change stamps
/// refuse a change they can detect; they do not make the copy transactionally consistent
/// against a concurrent writer, and they do not exclude a deliberate same-account writer.
fn export_installed(
    installed: &Root,
    operation: &Root,
    policy: &crate::budget::DiskPolicy,
    budget_roots: &[PathBuf],
) -> Result<(ChainRecords, records::LocalRecords)> {
    discard_state_capture(operation)?;
    let state =
        trees::optional_directory(installed, "state")?.context("StateDb directory is missing")?;
    let reserve = state_capture_reservation(&state)?;
    crate::budget::admit(
        policy,
        &[crate::budget::allocated(budget_roots)?],
        reserve,
        operation.space()?,
    )
    .context("disk refusal before the private StateDb capture")?;
    let capture = Root::create(&operation.path.join(STATE_CAPTURE))?;
    let exported = (|| {
        trees::copy_tree(&state, &capture, "")?;
        capture.sync()?;
        let store = node_store::OfflineStore::open_existing(&capture.path)?;
        records::export(&store)
    })();
    // Removed on success and on failure; a crash leaves it for the next discard.
    let removed = operation.remove_tree(STATE_CAPTURE);
    match (exported, removed) {
        (Ok(exported), Ok(())) => Ok(exported),
        (Ok(_), Err(error)) => Err(error.context("remove private StateDb capture")),
        (Err(error), Ok(())) => Err(error.context("private StateDb capture")),
        (Err(error), Err(cleanup)) => {
            Err(error
                .context(format!("private StateDb capture; its removal also failed: {cleanup:#}")))
        }
    }
}
/// What the installed tree contributes to a staged replacement.
struct TargetRecords {
    /// Local StateDb records preserved into the replacement.
    local: records::LocalRecords,
    /// Blocks the imported frontier must descend from, proven by native validation.
    anchors: BTreeSet<FullId>,
    /// Fork history the installed tree already holds.
    old_forks: Vec<FullId>,
    /// The journal's safety anchor: reference approval may not precede it.
    anchor: FullId,
}
/// A restore target contributes its own records and safety anchors. A bootstrap target has
/// never run, so it has no records; the imported chain must instead descend from the
/// locally held zero state and init block of the configured network.
fn target_records(request: &RestoreRequest, own: &Root, operation: &Root) -> Result<TargetRecords> {
    match request.lane {
        Lane::Restore => {
            let (old, local) = export_installed(
                own,
                operation,
                &request.context.disk_policy,
                &request.context.budget_roots,
            )?;
            Ok(TargetRecords {
                anchors: required(&old, &local)?,
                old_forks: old.forks()?,
                anchor: old.frontier()?,
                local,
            })
        }
        Lane::Bootstrap => {
            ensure!(
                own.kind("state")?.is_none(),
                "bootstrap target has local StateDb records; it is not a new node"
            );
            let (network, _) = request.context.policy()?;
            Ok(TargetRecords {
                local: records::LocalRecords::never_run(),
                anchors: BTreeSet::from([network.zero.clone(), network.init.clone()]),
                old_forks: vec![],
                anchor: network.init,
            })
        }
    }
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
    match request.lane {
        Lane::Restore => {
            crate::paths::restore_root(&own.path, request.context.service().keys_location()?)?
        }
        Lane::Bootstrap => {
            crate::paths::new_node_root(&own.path)?;
            require_no_signing_material(&request.context)?;
        }
    }
    let mut private_names = vec![
        "consensus".to_owned(),
        "catchains".to_owned(),
        "adnl".to_owned(),
        "overlays".to_owned(),
        "error".to_owned(),
    ];
    for name in own.names()? {
        if name.starts_with("dht-") {
            private_names.push(name);
        }
    }
    let mut private_bytes = 0_u64;
    for name in &private_names {
        if let Some(tree) = trees::optional_directory(&own, name)? {
            for file in trees::inventory(&tree)? {
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
    let state_reserve = match request.lane {
        Lane::Restore => {
            let state = trees::optional_directory(&own, "state")?
                .context("StateDb directory is missing")?;
            state_capture_reservation(&state)?
        }
        Lane::Bootstrap => 0,
    };
    let reserve = crate::budget::reservation(raw, 0, private_bytes)?
        .checked_add(state_reserve)
        .context("task reservation overflow")?;
    crate::budget::admit(
        &request.context.disk_policy,
        &[crate::budget::allocated(&request.context.budget_roots)?],
        reserve,
        space,
    )?;
    let target = target_records(request, &own, operation)?;
    let (local, anchors) = (target.local, target.anchors);
    let donor = chain(signed, objects)?;
    ensure!(
        anchors.iter().all(|a| a.seqno <= signed.manifest.frontier.seqno),
        "dump predates target safety anchor"
    );
    let revision = if previous.is_none() {
        read_stop(request, signed, operation, operation_id)?.stage
    } else {
        format!("stage-{:032x}", rand::random::<u128>())
    };
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
    records::reconcile_forks(
        &signed.manifest.approved_forks,
        &donor,
        &target.old_forks,
        &evidence,
    )?;
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
            own.kind("consensus")? == Some(crate::safe_io::Kind::Directory),
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
    // The replacement becomes the installed tree: it takes the installed root's owner,
    // which the service description checked is the service account.
    replacement.hand_over(own.owner()?)?;
    identity.verify_sources(&own)?;
    replacement.sync()?;
    let preservation = serde_json::to_vec(
        &serde_json::json!({"identity":identity,"local_records":local,"anchors":anchors,"local_trees":local_trees}),
    )?;
    ensure!(preservation.len() as u64 <= MANIFEST_LIMIT, "private preservation receipt size limit");
    revision_root.write_new("preservation.json", &preservation)?;
    let phase = match previous.map(|journal| journal.phase) {
        None | Some(Phase::Staged) => Phase::Staged,
        Some(Phase::ForwardOnly) => Phase::ForwardOnly,
        Some(_) => anyhow::bail!("old-tree refresh has invalid journal phase"),
    };
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
        target_anchor: target.anchor,
        phase,
    };
    journal.write(operation)?;
    Ok(journal)
}
// Every potentially blocking corroboration is followed by the same exposure guard.
fn exposure_check(boundary: &str) -> Result<()> {
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    crate::test_hooks::boundary(boundary)?;
    crate::budget::check_active().with_context(|| format!("disk refusal before {boundary}"))
}
fn authorize_references(
    request: &RestoreRequest,
    operation: &Root,
    journal: &mut Journal,
    frontier: &FullId,
) -> Result<()> {
    let approval = request.context.references.corroborate(
        &request.context.policy()?.0,
        frontier,
        &journal.reference_binding(),
    )?;
    exposure_check("restore-authorize")?;
    journal.authorize(operation, &approval)
}
fn expose_staged(operation: &Root, journal: &mut Journal) -> Result<()> {
    if journal.phase == Phase::Staged {
        exposure_check("restore-forward-only")?;
        journal.forward_only(operation)?;
    }
    exposure_check("restore-exchange")?;
    journal.exchange(operation)
}
fn start_installed(context: &NodeContext, operation: &Root, journal: &mut Journal) -> Result<()> {
    exposure_check("restore-start-installed")?;
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
    context.service().require_restore_target(Some(signed.manifest.permanent_cells))?;
    let frozen = context.service().freeze()?;
    journal.check_references(operation, true)?;
    context.service().start_restore(frozen, signed.manifest.permanent_cells)?;
    if journal.phase == Phase::StartIssued {
        journal.advance(operation, Phase::CatchingUp)?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AbortReport {
    pub lane: Lane,
    pub service_state: String,
    pub restart_command: String,
    pub removed_stage: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopPreparation {
    operation: String,
    generation: String,
    request_sha256: String,
    installed: TreeIdentity,
    stage: String,
}
fn prepare_stop(
    request: &RestoreRequest,
    signed: &SignedManifest,
    operation: &Root,
    id: &str,
) -> Result<()> {
    let stop = StopPreparation {
        operation: id.to_owned(),
        generation: signed.verify(&trusted(&request.publisher_key)?)?,
        request_sha256: sha256(&operation.bytes("request.json", MANIFEST_LIMIT)?),
        installed: TreeIdentity::read(&request.context.database)?,
        stage: format!("stage-{:032x}", rand::random::<u128>()),
    };
    ensure!(
        crate::safe_io::absent(&operation.path.join("stop-preparation.json"))?,
        "stop preparation already exists"
    );
    operation.replace("stop-preparation.json", &serde_json::to_vec(&stop)?)
}
fn read_stop(
    request: &RestoreRequest,
    signed: &SignedManifest,
    operation: &Root,
    id: &str,
) -> Result<StopPreparation> {
    let stop: StopPreparation =
        serde_json::from_slice(&operation.bytes("stop-preparation.json", MANIFEST_LIMIT)?)?;
    ensure!(
        stop.operation == id
            && stop.generation == signed.verify(&trusted(&request.publisher_key)?)?
            && stop.request_sha256 == sha256(&operation.bytes("request.json", MANIFEST_LIMIT)?),
        "stop preparation binding mismatch"
    );
    let suffix = stop.stage.strip_prefix("stage-").context("invalid owned stage")?;
    ensure!(
        suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid owned stage"
    );
    ensure!(
        TreeIdentity::read(&request.context.database)? == stop.installed,
        "installed root differs from pre-stop identity; preparation abort refused"
    );
    Ok(stop)
}
fn classify_preparation(
    request: &RestoreRequest,
    signed: &SignedManifest,
    operation: &Root,
) -> Result<Option<StopPreparation>> {
    let stop = if crate::safe_io::absent(&operation.path.join("stop-preparation.json"))? {
        None
    } else {
        let id = String::from_utf8(operation.bytes("operation-id", 32)?)?;
        Some(read_stop(request, signed, operation, &id)?)
    };
    for entry in fs::read_dir(&operation.path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-text operation entry"))?;
        if name.starts_with("stage-") {
            let stage = Root::open(&entry.path())?;
            let bytes = trees::allocated_bytes(&stage.path)?;
            ensure!(
                crate::safe_io::absent(&stage.path.join("preservation.json"))?,
                "stage {name} has later-phase evidence ({bytes} allocated bytes); journal missing, retain for inspection; node may be stopped"
            );
            ensure!(
                stop.as_ref().is_some_and(|s| s.stage == name),
                "unbound stage {name} ({bytes} allocated bytes); retain for inspection; node may be stopped"
            );
        }
    }
    Ok(stop)
}
fn cleanup_stage(request: &RestoreRequest, operation: &Root, stop: &StopPreparation) -> Result<()> {
    // Check again at deletion time, not just while classifying the interrupted operation.
    ensure!(
        TreeIdentity::read(&request.context.database)? == stop.installed,
        "installed root changed before staging cleanup"
    );
    if !crate::safe_io::absent(&operation.path.join(&stop.stage))? {
        crate::service::refuse_writers(&operation.path.join(&stop.stage))?;
        operation.remove_tree(&stop.stage)?;
    }
    Ok(())
}
pub enum RecoveryOutcome {
    Installed(Box<(NodeContext, Journal)>),
    Aborted(AbortReport),
}
pub fn recover(operation_path: &Path) -> Result<RecoveryOutcome> {
    let operation = Root::open(operation_path)?;
    let request: RestoreRequest =
        serde_json::from_slice(&operation.bytes("request.json", MANIFEST_LIMIT)?)?;
    restore_storage(&request, Some(&operation.path))?;
    separate(&operation.path, &request.context.database)?;
    separate(&request.cache, &request.context.database)?;
    separate(&request.cache, &operation.path)?;
    if crate::safe_io::absent(&operation.path.join("restore.json"))? {
        let authenticated = (|| -> Result<_> {
            let key = trusted(&request.publisher_key)?;
            let signed =
                SignedManifest::parse(&operation.bytes("generation.json", MANIFEST_LIMIT)?, &key)?;
            let id = sha256(&operation.bytes("operation-id", 32)?);
            let objects = Objects::open(&request.cache)?;
            let catalog = Catalog::open(&request.cache, key)?;
            catalog.verify_preparation(&signed, &objects, &id, &operation)?;
            Ok(())
        })();
        authenticated
            .context("Preparation binding is unverified; retain operation for inspection")?;
        let (service_state, restart_command) = request.context.service().abort_guidance()?;
        let guidance = format!(
            "Preparation recovery: selected service state={service_state}; command={restart_command}. Do not restart until original-tree identity is confirmed; retain ambiguous staging for inspection"
        );
        let result: Result<RecoveryOutcome> = (|| {
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
            let stop = classify_preparation(&request, &signed, &operation)?;
            catalog.abort_download(&signed, &objects, &id, &operation)?;
            discard_state_capture(&operation)?;
            // Normal reachability pruning retains every other lease and published generation.
            let removed_stage = if let Some(stop) = stop {
                cleanup_stage(&request, &operation, &stop)?;
                Some(stop.stage)
            } else {
                None
            };
            catalog.prune()?;
            let (service_state, restart_command) = request.context.service().abort_guidance()?;
            Ok(RecoveryOutcome::Aborted(AbortReport {
                lane: request.lane,
                service_state,
                restart_command,
                removed_stage,
            }))
        })();
        return result.context(guidance);
    }
    let mut journal = Journal::read(&operation)?;
    restore_owners(&request, Some(&operation.path))?;
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
    // The journal, not the tree's contents, says which tree is installed. Only an unexchanged
    // bootstrap target is checked as a new node; an installed replacement is checked as the
    // existing node it now is, and never treated as new again.
    let unexchanged = journal.recovery()? == Recovery::OldRefreshRequired;
    let check_installed = || -> Result<()> {
        if unexchanged {
            require_unexchanged_target(&request, Some(signed.manifest.permanent_cells))
        } else {
            request.context.service().require_restore_target(Some(signed.manifest.permanent_cells))
        }
    };
    check_installed()?;
    if !unexchanged {
        journal.check_references(&operation, false)?;
    }
    let frozen = if unexchanged { quiesce(&request)? } else { request.context.service().stop()? };
    check_installed()?;
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
            authorize_references(&request, &operation, &mut journal, &signed.manifest.frontier)?;
            check_installed()?;
            expose_staged(&operation, &mut journal)?;
        }
        Recovery::NewContinueOnly => {
            // A boot may have advanced this tree. Corroborate its current coherent frontier;
            // never replace it with the original snapshot or overlay old signing records.
            let (current, _) = export_installed(
                &Root::open(&request.context.database)?,
                &operation,
                &request.context.disk_policy,
                &request.context.budget_roots,
            )?;
            authorize_references(&request, &operation, &mut journal, &current.frontier()?)?;
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
    restore_storage(&request, Some(&operation.path))?;
    let _lock = operation_lock(&request.context.database)?;
    let mut journal = Journal::read(&operation)?;
    let key = trusted(&request.publisher_key)?;
    let signed = SignedManifest::parse(&operation.bytes("generation.json", MANIFEST_LIMIT)?, &key)?;
    ensure!(
        operation.bytes("operation-id", 32)? == journal.operation.as_bytes(),
        "completed operation identity mismatch"
    );
    let objects = Objects::open(&request.cache)?;
    let catalog = Catalog::open(&request.cache, key)?;
    let operation_id = sha256(journal.operation.as_bytes());
    let (_, generation) = catalog.verify_receiver(&signed, &objects, &operation_id, &operation)?;
    ensure!(
        generation == journal.generation
            && Path::new(&journal.installed) == request.context.database,
        "completed receiver context binding mismatch"
    );
    if journal.phase == Phase::CatchingUp {
        journal.advance(&operation, Phase::Complete)?;
    }
    ensure!(
        journal.phase == Phase::Complete && journal.recovery()? == Recovery::NewContinueOnly,
        "restore is not completed on the replacement tree"
    );
    catalog.release_completed(&signed, &objects, &operation_id, &operation)?;
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    crate::test_hooks::boundary("after-completion-lease-release")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stopped_fixture_request(root: &Root) -> Result<RestoreRequest> {
        let database = Root::create(&root.path.join("database"))?;
        Ok(RestoreRequest {
            context: NodeContext {
                unit: "floria-p2-selected@fixture.service".to_owned(),
                user_manager: true,
                database: database.path.clone(),
                engine: root.path.join("engine"),
                engine_sha256: "00".repeat(32),
                validation_worker: root.path.join("worker"),
                validation_worker_sha256: "00".repeat(32),
                global_config: root.path.join("global.json"),
                global_id: 3,
                work_root: root.path.clone(),
                working_directory: database.path,
                operator_config: root.path.join("operator.json"),
                node_name: "own".to_owned(),
                budget_roots: vec![root.path.clone()],
                disk_policy: crate::budget::DiskPolicy {
                    max_owned_bytes: 1 << 30,
                    shutdown_free_bytes: Some(1),
                },
                vault_config_files: vec![],
                references: crate::references::ReferencePolicy { sources: vec![] },
            },
            manifest: root.path.join("generation.json"),
            cache: root.path.join("cache"),
            publisher_key: "00".repeat(32),
            source_url: None,
            lane: Lane::Restore,
        })
    }
    /// A tree of one installed database with a native (versionless) StateDb, an unrelated
    /// populated native database as the decoy, and a private operation directory.
    struct CaptureFixture {
        _temporary: tempfile::TempDir,
        base: PathBuf,
        installed: Root,
        operation: Root,
        decoy: PathBuf,
        policy: crate::budget::DiskPolicy,
    }
    fn capture_fixture() -> Result<CaptureFixture> {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().canonicalize()?;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755))?;
        let installed = Root::create(&base.join("installed"))?;
        drop(node_store::OfflineStore::create_staging(&installed.path.join("state"))?);
        let decoy = base.join("decoy");
        drop(node_store::OfflineStore::create_staging(&decoy)?);
        fs::write(decoy.join("marker"), b"unrelated database")?;
        let operation = Root::create(&base.join("operation"))?;
        let policy =
            crate::budget::DiskPolicy { max_owned_bytes: 1 << 30, shutdown_free_bytes: Some(1) };
        Ok(CaptureFixture { _temporary: temporary, base, installed, operation, decoy, policy })
    }
    /// Names, sizes, inodes, owners and modification times of every entry of a directory.
    fn listing(path: &Path) -> Result<Vec<(String, u64, u64, u32, i64, i64)>> {
        use std::os::unix::fs::MetadataExt;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            entries.push((
                entry.file_name().to_string_lossy().into_owned(),
                metadata.len(),
                metadata.ino(),
                metadata.uid(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ));
        }
        entries.sort();
        Ok(entries)
    }
    fn export(fixture: &CaptureFixture, installed: &Root) -> Result<()> {
        export_installed(installed, &fixture.operation, &fixture.policy, &[fixture.base.clone()])
            .map(|_| ())
    }
    fn refused(fixture: &CaptureFixture, installed: &Root, reason: &str) -> Result<()> {
        refused_beside(fixture, installed, reason, &fixture.decoy)
    }
    fn refused_beside(
        fixture: &CaptureFixture,
        installed: &Root,
        reason: &str,
        decoy: &Path,
    ) -> Result<()> {
        let before = listing(decoy)?;
        let error = export(fixture, installed).err().context("swapped StateDb was read")?;
        let text = format!("{error:#}");
        assert!(text.contains(reason), "wrong refusal, expected {reason:?}: {text}");
        assert_eq!(listing(decoy)?, before, "a write landed in the decoy database");
        assert!(
            fixture.operation.kind(STATE_CAPTURE)?.is_none(),
            "a refused capture was left behind"
        );
        Ok(())
    }
    #[test]
    fn private_state_capture_never_writes_the_installed_tree() -> Result<()> {
        let fixture = capture_fixture()?;
        let state = fixture.installed.path.join("state");
        let before = listing(&state)?;
        // A leftover capture from an interrupted run is discarded, never read.
        fixture.operation.write_new(&format!("{STATE_CAPTURE}/CURRENT"), b"stale")?;
        let error = export(&fixture, &fixture.installed).err().context("versionless accepted")?;
        // The native library opened and refused the private copy, not the installed tree.
        assert!(format!("{error:#}").contains("StateDb version"), "wrong refusal: {error:#}");
        assert_eq!(listing(&state)?, before, "the invoker wrote into the installed StateDb");
        assert!(fixture.operation.kind(STATE_CAPTURE)?.is_none(), "capture left behind");
        Ok(())
    }
    #[test]
    fn swapped_state_symlink_refuses_and_leaves_the_decoy() -> Result<()> {
        let fixture = capture_fixture()?;
        let state = fixture.installed.path.join("state");
        fs::rename(&state, fixture.base.join("state.real"))?;
        std::os::unix::fs::symlink(&fixture.decoy, &state)?;
        refused(&fixture, &fixture.installed, "local tree is a symlink or special file: state")
    }
    #[test]
    fn swapped_intermediate_directory_refuses_and_leaves_the_decoy() -> Result<()> {
        let fixture = capture_fixture()?;
        // The installed root is held; then its own path is replaced by a symlink to another
        // tree whose real `state` directory is an unrelated database. A lookup by name
        // would resolve through the replaced component into that database.
        let held = fixture.installed.duplicate()?;
        let elsewhere = fixture.base.join("elsewhere");
        fs::create_dir(&elsewhere)?;
        drop(node_store::OfflineStore::create_staging(&elsewhere.join("state"))?);
        fs::rename(&fixture.installed.path, fixture.base.join("installed.real"))?;
        std::os::unix::fs::symlink(&elsewhere, &fixture.installed.path)?;
        refused_beside(
            &fixture,
            &held,
            "root path was exchanged or replaced",
            &elsewhere.join("state"),
        )
    }
    #[test]
    fn hard_linked_state_file_refuses_and_leaves_the_decoy() -> Result<()> {
        let fixture = capture_fixture()?;
        fs::hard_link(fixture.decoy.join("marker"), fixture.installed.path.join("state/marker"))?;
        refused(
            &fixture,
            &fixture.installed,
            "tree contains a link or special file: marker (links=2)",
        )
    }
    /// Re-executes itself in a private user and mount namespace, where it may mount.
    #[test]
    #[ignore = "mounts in a private namespace; run by the native CI step"]
    fn foreign_mount_on_state_refuses_and_leaves_the_mounted_tree() -> Result<()> {
        const INNER: &str = "NODE_SYNC_MOUNT_CONTROL_INNER";
        if std::env::var_os(INNER).is_none() {
            let output = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--mount", "--"])
                .arg(std::env::current_exe()?)
                .args([
                    "--exact",
                    "operations::tests::foreign_mount_on_state_refuses_and_leaves_the_mounted_tree",
                    "--ignored",
                    "--nocapture",
                ])
                .env(INNER, "1")
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("FOREIGN_MOUNT_REFUSAL_INNER_OK"),
                "mount control failed: {stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!("\nFOREIGN_MOUNT_REFUSAL_OK");
            return Ok(());
        }
        let fixture = capture_fixture()?;
        let state = fixture.installed.path.join("state");
        let target = std::ffi::CString::new(state.as_os_str().as_encoded_bytes())?;
        // SAFETY: terminated constant strings and path; a private namespace's mount table.
        let mounted = unsafe {
            libc::mount(c"tmpfs".as_ptr(), target.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null())
        };
        ensure!(mounted == 0, "tmpfs mount: {}", std::io::Error::last_os_error());
        fs::write(state.join("CURRENT"), b"MANIFEST-000001\n")?;
        let mounted_before = listing(&state)?;
        let decoy_before = listing(&fixture.decoy)?;
        let error = export(&fixture, &fixture.installed).err().context("mount accepted")?;
        let text = format!("{error:#}");
        assert!(
            text.contains("refusing unsafe directory state") && text.contains("cross-device"),
            "wrong refusal: {text}"
        );
        assert_eq!(listing(&state)?, mounted_before, "a write landed in the mounted tree");
        assert_eq!(listing(&fixture.decoy)?, decoy_before);
        // A new-node target refuses another mount anywhere: on a whole tree, and as one
        // bind-mounted genesis file.
        let hash = "ab".repeat(32);
        for (label, mounted) in
            [("tree", "console-client".to_owned()), ("file", format!("static/{hash}"))]
        {
            let fresh = Root::create(&fixture.base.join(format!("new-node-{label}")))?;
            fresh.write_new("config.json", b"{}")?;
            fresh.write_new("keyring/KEY", b"key")?;
            fresh.write_new("console-client/client", b"console")?;
            fresh.write_new(&format!("static/{hash}"), b"genesis")?;
            crate::paths::new_node_root(&fresh.path)?;
            let target =
                std::ffi::CString::new(fresh.path.join(&mounted).as_os_str().as_encoded_bytes())?;
            let result = if label == "tree" {
                // SAFETY: as above.
                unsafe {
                    libc::mount(
                        c"tmpfs".as_ptr(),
                        target.as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        std::ptr::null(),
                    )
                }
            } else {
                let elsewhere = fixture.base.join("bind-source");
                fs::write(&elsewhere, b"other bytes")?;
                let source = std::ffi::CString::new(elsewhere.as_os_str().as_encoded_bytes())?;
                // SAFETY: terminated paths; a private namespace's mount table.
                unsafe {
                    libc::mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                }
            };
            ensure!(result == 0, "{label} mount: {}", std::io::Error::last_os_error());
            let text = format!("{:#}", crate::paths::new_node_root(&fresh.path).expect_err(label));
            assert!(
                text.contains("bootstrap target is not a new node database")
                    && (text.contains("another device") || text.contains("cross-device")),
                "{label}: wrong refusal: {text}"
            );
        }
        println!("\nFOREIGN_MOUNT_REFUSAL_INNER_OK");
        Ok(())
    }
    /// The production shape: root reads a tree owned by uid 65534, and a process running as
    /// that account replaces `state` by a symlink to a root-owned database, before the
    /// lookup and after the directory is held.
    #[test]
    #[ignore = "requires real root; run by the native CI step"]
    fn root_capture_resists_a_service_account_swap() -> Result<()> {
        use std::os::unix::{fs::MetadataExt, process::CommandExt};
        // SAFETY: geteuid has no preconditions.
        ensure!(unsafe { libc::geteuid() } == 0, "this control must run as real root");
        let fixture = capture_fixture()?;
        fixture.installed.hand_over_from((65534, 65534), 0)?;
        let state = fixture.installed.path.join("state");
        let decoy = fixture.decoy.display().to_string();
        let swap = |script: &str| -> Result<()> {
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", script, "swap", &decoy])
                .current_dir(&fixture.installed.path)
                // Dropping from root also clears supplementary groups before exec.
                .uid(65534)
                .gid(65534)
                .status()?;
            ensure!(status.success(), "unprivileged swap failed");
            Ok(())
        };
        let before = listing(&state)?;
        let error = export(&fixture, &fixture.installed).err().context("versionless accepted")?;
        assert!(format!("{error:#}").contains("StateDb version"), "wrong refusal: {error:#}");
        assert_eq!(listing(&state)?, before, "root wrote into the service account's StateDb");
        assert!(listing(&state)?.iter().all(|entry| entry.3 == 65534));
        // Before the lookup.
        swap("mv state state.real && ln -s \"$1\" state")?;
        refused(&fixture, &fixture.installed, "local tree is a symlink or special file: state")?;
        swap("rm state && mv state.real state")?;
        // After `state` is held, between the lookup and the copy.
        let held = trees::optional_directory(&fixture.installed, "state")?.context("state")?;
        swap("mv state state.real && ln -s \"$1\" state")?;
        let decoy_before = listing(&fixture.decoy)?;
        let target = Root::create(&fixture.operation.path.join("held-copy"))?;
        let error = trees::copy_tree(&held, &target, "").err().context("swap after hold read")?;
        assert!(format!("{error:#}").contains("root path was exchanged or replaced"));
        assert_eq!(listing(&fixture.decoy)?, decoy_before);
        assert!(fs::symlink_metadata(&fixture.decoy)?.uid() == 0);
        println!("\nROOT_SERVICE_ACCOUNT_SWAP_OK");
        Ok(())
    }
    #[test]
    fn cleanup_rechecks_installed_identity_and_never_follows_links() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let root = Root::open(tmp.path())?;
        let request = stopped_fixture_request(&root)?;
        let operation = Root::create(&root.path.join("operation"))?;
        let stage = Root::create(&operation.path.join(format!("stage-{}", "11".repeat(16))))?;
        stage.write_new("partial", b"owned")?;
        let stop = StopPreparation {
            operation: "ab".repeat(16),
            generation: "cd".repeat(32),
            request_sha256: "ef".repeat(32),
            installed: TreeIdentity::read(&request.context.database)?,
            stage: stage
                .path
                .file_name()
                .context("stage name")?
                .to_str()
                .context("stage text")?
                .to_owned(),
        };
        fs::rename(&request.context.database, root.path.join("saved-original"))?;
        Root::create(&request.context.database)?;
        let error = cleanup_stage(&request, &operation, &stop)
            .expect_err("cleanup ignored changed installed root");
        assert_eq!(
            error.to_string(),
            "installed root changed before staging cleanup",
            "wrong installed-root refusal"
        );
        assert!(stage.path.exists(), "cleanup removed stage after installed-root replacement");
        fs::remove_dir(&request.context.database)?;
        fs::rename(root.path.join("saved-original"), &request.context.database)?;
        let unrelated = Root::create(&operation.path.join("unrelated"))?;
        unrelated.write_new("keep", b"not owned")?;
        std::os::unix::fs::symlink(&unrelated.path, stage.path.join("trap"))?;
        let error =
            cleanup_stage(&request, &operation, &stop).expect_err("cleanup followed a symlink");
        assert_eq!(
            error.to_string(),
            format!(
                "refusing unsafe cleanup child: {}",
                std::io::Error::from_raw_os_error(libc::ELOOP)
            ),
            "wrong symlink refusal"
        );
        assert_eq!(unrelated.bytes("keep", 100)?, b"not owned");
        fs::remove_file(stage.path.join("trap"))?;
        cleanup_stage(&request, &operation, &stop)?;
        assert!(!stage.path.exists(), "owned staging survived cleanup");
        assert_eq!(unrelated.bytes("keep", 100)?, b"not owned");
        cleanup_stage(&request, &operation, &stop)?;
        let (_, command) = request.context.service().abort_guidance()?;
        assert_eq!(
            command, "systemctl --user start -- floria-p2-selected@fixture.service",
            "restart command changed selected unit or scope"
        );
        let mut system_service = request.context.service();
        system_service.user_manager = false;
        assert_eq!(
            system_service.abort_guidance()?.1,
            "systemctl start -- floria-p2-selected@fixture.service",
            "restart command changed system-manager scope"
        );
        Ok(())
    }

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
        own.write_new("error/files/target-report", b"own diagnostics")?;
        // The operator bundle's console client keys, with their own modes and an empty
        // directory: node-local private data kept exactly.
        {
            use std::os::unix::fs::PermissionsExt;
            own.write_new("console-client/client", b"console private key")?;
            own.write_new("console-client/client.pub", b"console public key")?;
            own.ensure_directory("console-client/empty")?;
            fs::set_permissions(
                own.path.join("console-client/client.pub"),
                fs::Permissions::from_mode(0o644),
            )?;
            fs::set_permissions(
                own.path.join("console-client/empty"),
                fs::Permissions::from_mode(0o750),
            )?;
        }
        let console = |root: &Path| -> Result<Vec<(String, bool, u32, u32, u32, Vec<u8>)>> {
            let tree = Root::open(&root.join("console-client"))?;
            trees::private_tree(&tree, 100, 1 << 20)?
                .into_iter()
                .map(|e| {
                    let bytes = if e.directory { vec![] } else { tree.bytes(&e.path, e.size)? };
                    Ok((e.path, e.directory, e.mode, e.uid, e.gid, bytes))
                })
                .collect()
        };
        let console_before = console(&own.path)?;
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
            lane: Lane::Restore,
        };
        let operation = Root::create(&parent.path.join("operation"))?;
        operation.write_new("request.json", &serde_json::to_vec(&request)?)?;
        prepare_stop(&request, &signed, &operation, &"12".repeat(16))?;
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
        assert_eq!(replacement.bytes("error/files/target-report", 100)?, b"own diagnostics");
        assert_eq!(
            console(&replacement.path)?,
            console_before,
            "console client keys were not preserved exactly"
        );
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
        println!("\nNATIVE_STAGE_PRESERVATION_OK");
        Ok(())
    }
}
