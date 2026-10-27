//! Native lifecycle acceptance driven through production entry points.
use crate::{
    capture,
    cas::Objects,
    catalog::Catalog,
    context::NodeContext,
    model::{MANIFEST_LIMIT, SignedManifest, sha256},
    operations::{self, RecoveryOutcome, RestoreRequest},
    safe_io::Root,
    service::Frozen,
    test_hooks::Scope,
    trees,
};
use anyhow::{Context, Result, ensure};
use std::{
    cell::RefCell,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

struct Manager {
    context: NodeContext,
    configured: bool,
    json_rpc: bool,
    no_index_flag: bool,
    flip_on_stop: bool,
    trip_on_describe: bool,
    child: Option<Child>,
    events: Vec<String>,
}
impl Manager {
    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            ensure!(result == 0, "fixture process stop failed");
            let started = std::time::Instant::now();
            loop {
                if child.try_wait()?.is_some() {
                    break;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    child.kill()?;
                    child.wait()?;
                    anyhow::bail!("fixture process did not stop");
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        assert!(self.child.is_none());
        let mut command = Command::new(&self.context.engine);
        command
            .current_dir(&self.context.working_directory)
            .args(["--db"])
            .arg(&self.context.database)
            .arg("--global-config")
            .arg(&self.context.global_config)
            .args(["--threads", "1", "--celldb-cache-size", "33554432", "--logname"])
            .arg(self.context.work_root.join("fixture-node.log"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        self.child = Some(command.spawn()?);
        thread::sleep(Duration::from_millis(250));
        ensure!(
            self.child.as_mut().context("child")?.try_wait()?.is_none(),
            "native fixture exited before mode observation"
        );
        Ok(())
    }
    fn command(&mut self, command: &mut Command) -> Result<String> {
        let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        ensure!(args.last() == Some(&self.context.unit), "fixture was asked about another unit");
        if args.iter().any(|a| a == "stop") {
            self.events.push("stop".to_owned());
            self.stop()?;
            if self.flip_on_stop {
                self.configured = true;
                self.events.push("stop-mode-flip".to_owned());
            }
            return Ok(String::new());
        }
        if args.iter().any(|a| a == "start") {
            self.events.push("start".to_owned());
            self.start()?;
            return Ok(String::new());
        }
        ensure!(args.iter().any(|a| a == "show"), "unsupported fixture manager command");
        let mut output = Vec::new();
        for argument in &args {
            if let Some(properties) = argument.strip_prefix("--property=") {
                for property in properties.split(',') {
                    let value = match property {
                        "ExecStart" => format!(
                            "{{ argv[]={} --db {} --global-config {}{}{}{} ; running }}",
                            self.context.engine.display(),
                            self.context.database.display(),
                            self.context.global_config.display(),
                            if self.configured { " --permanent-celldb" } else { "" },
                            if self.json_rpc { " --json-rpc-address 127.0.0.1:8081" } else { "" },
                            if self.no_index_flag {
                                " --json-rpc-without-wallet-index"
                            } else {
                                ""
                            }
                        ),
                        "User" => String::new(),
                        "WorkingDirectory" => self.context.working_directory.display().to_string(),
                        "MainPID" => {
                            if self.trip_on_describe {
                                self.trip_on_describe = false;
                                crate::budget::stop_for_test(true);
                                self.events.push("final-validation-disk-trip".to_owned());
                            }
                            self.child.as_ref().map_or(0, Child::id).to_string()
                        }
                        "ActiveState" => {
                            if self.child.is_some() { "active" } else { "inactive" }.to_owned()
                        }
                        "LoadState" => "loaded".to_owned(),
                        "FragmentPath" => {
                            self.context.work_root.join("fixture.service").display().to_string()
                        }
                        "DropInPaths" | "EnvironmentFiles" => String::new(),
                        other => anyhow::bail!("unsupported fixture property {other}"),
                    };
                    output.push(if args.iter().any(|a| a == "--value") {
                        value
                    } else {
                        format!("{property}={value}")
                    });
                }
            }
        }
        Ok(output.join("\n"))
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
struct Fixture {
    request: RestoreRequest,
    operation: PathBuf,
    manager: Rc<RefCell<Manager>>,
    signed: SignedManifest,
    source_catalog: PathBuf,
    _references: crate::test_references::References,
    // Drop the native process owner before removing its database tree.
    _temporary: tempfile::TempDir,
}
fn fixture_environment_available() -> bool {
    let missing: Vec<_> = [
        "NODE_SYNC_NATIVE_FIXTURE",
        "NODE_SYNC_NATIVE_SOURCE",
        "NODE_SYNC_NATIVE_ENGINE",
        "NODE_SYNC_NATIVE_WORKER",
    ]
    .into_iter()
    .filter(|name| std::env::var_os(name).is_none())
    .collect();
    if missing.is_empty() {
        return true;
    }
    eprintln!(
        "SKIP native lifecycle fixture: missing {}; run the native lifecycle CI step",
        missing.join(", ")
    );
    false
}
impl Fixture {
    fn new() -> Result<Self> {
        let fixture = PathBuf::from(
            std::env::var_os("NODE_SYNC_NATIVE_FIXTURE")
                .context("NODE_SYNC_NATIVE_FIXTURE required; run the native lifecycle CI step")?,
        )
        .canonicalize()?;
        let source = PathBuf::from(
            std::env::var_os("NODE_SYNC_NATIVE_SOURCE")
                .context("NODE_SYNC_NATIVE_SOURCE required")?,
        )
        .canonicalize()?;
        let engine = PathBuf::from(
            std::env::var_os("NODE_SYNC_NATIVE_ENGINE")
                .context("NODE_SYNC_NATIVE_ENGINE required")?,
        )
        .canonicalize()?;
        let worker = PathBuf::from(
            std::env::var_os("NODE_SYNC_NATIVE_WORKER")
                .context("NODE_SYNC_NATIVE_WORKER required")?,
        )
        .canonicalize()?;
        let temporary =
            tempfile::Builder::new().prefix("floria-sync-lifecycle-").tempdir_in(&fixture)?;
        let parent = Root::open(temporary.path())?;
        let installed_worker = parent.path.join("validation-worker");
        fs::copy(&worker, &installed_worker)?;
        let worker = installed_worker;
        let own = Root::create(&parent.path.join("database"))?;
        let image = fixture.join("image");
        let stopped = Frozen::acquire(&image)?;
        capture::cold_image(&stopped, &Root::open(&image)?, &own)?;
        drop(stopped);
        let source_root = Root::open(&source)?;
        trees::copy_file(&source_root, "config.json", &own, "config.json", MANIFEST_LIMIT)?;
        trees::copy_optional_tree(&source_root, "keyring", &own)?;
        parent.write_new("operator.json", &serde_json::to_vec(&serde_json::json!({
            "nodes":{"fixture":{"server_address":"127.0.0.1:1","server_key":{"name":"fixture-control"},"client_key":{"name":"fixture-client"},"timeouts":1}},
            "chain_rpc":{},"http":{"enable_swagger":false}
        }))?)?;
        parent.write_new("fixture.service", b"private lifecycle fixture")?;
        parent.write_new("publisher.seed", &[42; 32])?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let source_catalog = fixture.join("catalog");
        let signed = Catalog::open(&source_catalog, key.verifying_key().to_bytes())?
            .latest()?
            .context("native generation")?;
        let cache = Objects::create(&parent.path.join("cache"))?;
        let source_objects = Root::open(&source_catalog)?;
        let cache_root = Root::open(cache.root_path())?;
        for object in &signed.manifest.files {
            let name = Objects::object_name(object)?;
            if cache.check(object).is_err() {
                trees::copy_file(
                    &source_objects,
                    &name,
                    &cache_root,
                    &name,
                    object.compressed_size,
                )?;
            }
            cache.check(object)?;
        }
        let references = crate::test_references::References::new(
            &signed.manifest.network,
            &signed.manifest.frontier,
            crate::test_references::Mode::Agree,
        )?;
        let context = NodeContext {
            unit: "floria-sync-lifecycle.service".to_owned(),
            user_manager: true,
            database: own.path.clone(),
            engine_sha256: crate::safe_io::file_hash(
                crate::context::read_file(&engine, 1 << 30)?,
                1 << 30,
            )?
            .1,
            engine,
            validation_worker_sha256: crate::safe_io::file_hash(
                crate::context::read_file(&worker, 1 << 30)?,
                1 << 30,
            )?
            .1,
            validation_worker: worker,
            global_config: source.join("config.global.json"),
            global_id: 3,
            work_root: parent.path.clone(),
            working_directory: own.path,
            operator_config: parent.path.join("operator.json"),
            node_name: "fixture".to_owned(),
            budget_roots: vec![parent.path.clone()],
            disk_policy: crate::budget::DiskPolicy {
                max_owned_bytes: 8 << 30,
                shutdown_free_bytes: Some(1 << 30),
            },
            vault_config_files: vec![],
            references: references.policy.clone(),
        };
        parent.write_new("manifest.json", &signed.bytes()?)?;
        let request = RestoreRequest {
            context: context.clone(),
            manifest: parent.path.join("manifest.json"),
            cache: cache.root_path().to_owned(),
            publisher_key: hex::encode(key.verifying_key().to_bytes()),
            source_url: None,
        };
        let manager = Rc::new(RefCell::new(Manager {
            context,
            configured: false,
            json_rpc: false,
            no_index_flag: false,
            flip_on_stop: false,
            trip_on_describe: false,
            child: None,
            events: Vec::new(),
        }));
        Ok(Self {
            _temporary: temporary,
            request,
            operation: parent.path.join("operation"),
            manager,
            signed,
            source_catalog,
            _references: references,
        })
    }
    fn scope(&self, boundary: impl FnMut(&str) -> Result<()> + 'static) -> Scope {
        let manager = Rc::clone(&self.manager);
        Scope::install(
            Box::new(move |command| manager.borrow_mut().command(command)),
            Box::new(boundary),
        )
    }
    fn inventory(&self) -> Result<Vec<(String, String)>> {
        let own = Root::open(&self.request.context.database)?;
        trees::inventory(&own)?
            .iter()
            .map(|f| Ok((f.path.clone(), sha256(&own.bytes(&f.path, crate::model::RAW_LIMIT)?))))
            .collect()
    }
}
struct ObjectServer {
    url: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl ObjectServer {
    fn new(root: PathBuf) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    if socket.read(&mut b).unwrap_or(0) != 1 {
                        break;
                    }
                    header.push(b[0]);
                    assert!(header.len() < 8192);
                }
                let text = String::from_utf8(header).unwrap();
                let path = text.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                assert!(path.starts_with("/objects/") && !path.contains(".."));
                let bytes = fs::read(root.join(&path[1..])).unwrap();
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .unwrap();
                socket.write_all(&bytes).unwrap();
            }
        });
        Ok(Self { url, stop, thread: Some(thread) })
    }
}
impl Drop for ObjectServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
fn production_restore_stop_cut_recovers_without_exchange() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let after_stop = Rc::new(RefCell::new(None));
    let stopped = Rc::clone(&after_stop);
    let context = fixture.request.context.clone();
    let _scope = fixture.scope(move |point| {
        if point == "after-stop-before-stage" {
            let own = Root::open(&context.database)?;
            let inventory: Vec<_> = trees::inventory(&own)?
                .iter()
                .map(|f| {
                    Ok((f.path.clone(), sha256(&own.bytes(&f.path, crate::model::RAW_LIMIT)?)))
                })
                .collect::<Result<_>>()?;
            *stopped.borrow_mut() = Some(inventory);
            anyhow::bail!("fixture interruption after production stop");
        }
        Ok(())
    });
    fixture.manager.borrow_mut().start()?;
    let result = operations::restore(&fixture.request, &fixture.operation);
    assert!(
        format!("{:#}", result.err().context("restore ignored stop cut")?)
            .contains("fixture interruption after production stop")
    );
    assert!(!fixture.operation.join("restore.json").exists());
    assert!(
        fixture.operation.join("stop-preparation.json").is_file(),
        "production stop lacked durable descriptor"
    );
    let outcome = operations::recover(&fixture.operation)?;
    let RecoveryOutcome::Aborted(report) = outcome else {
        panic!("preparation resumed instead of aborting")
    };
    assert!(report.removed_stage.is_some(), "production abort lost the bound staging descriptor");
    assert_eq!(report.service_state, "inactive");
    assert_eq!(report.restart_command, "systemctl --user start -- floria-sync-lifecycle.service");
    assert_eq!(
        Some(fixture.inventory()?),
        *after_stop.borrow(),
        "abort changed stopped native database"
    );
    let operation = Root::open(&fixture.operation)?;
    let id = operation.bytes("operation-id", 32)?;
    assert!(
        !fixture.request.cache.join(format!("leases/r-{}", sha256(&id))).exists(),
        "abort retained receiver lease"
    );
    assert_eq!(
        fixture.manager.borrow().events,
        vec!["stop"],
        "restore crossed interrupted boundary or restarted"
    );
    assert!(matches!(operations::recover(&fixture.operation)?, RecoveryOutcome::Aborted(_)));
    println!("\nPRODUCTION_RESTORE_STOP_CUT_OK");
    Ok(())
}

#[test]
fn production_entry_points_refuse_lifecycle_mode_changes() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    for case in ["running-configured", "create-stop", "restore-stop", "download"] {
        let mut fixture = Fixture::new()?;
        let state = Rc::clone(&fixture.manager);
        let mode = case.to_owned();
        let _scope = fixture.scope(move |point| {
            state.borrow_mut().events.push(point.to_owned());
            if mode == "download" && point == "during-download" {
                state.borrow_mut().configured = true;
            }
            if point == "before-capture" || point == "before-stage" {
                anyhow::bail!("prohibited native action reached");
            }
            Ok(())
        });
        fixture.manager.borrow_mut().start()?;
        let publisher = crate::publisher::PublisherSecret::load(
            &fixture.request.context.work_root.join("publisher.seed"),
        )?;
        let _server;
        if case == "running-configured" {
            fixture.manager.borrow_mut().configured = true;
        }
        if case == "create-stop" || case == "restore-stop" {
            fixture.manager.borrow_mut().flip_on_stop = true;
        }
        if case == "download" {
            let objects = Objects::open(&fixture.request.cache)?;
            let first = fixture.signed.manifest.files.first().context("native object")?;
            Root::open(objects.root_path())?.unlink(&Objects::object_name(first)?)?;
            _server = ObjectServer::new(fixture.source_catalog.clone())?;
            fixture.request.source_url = Some(_server.url.clone());
        }
        let result = if case == "running-configured" || case == "create-stop" {
            operations::create(
                &fixture.request.context,
                &fixture.operation,
                &fixture.request.cache,
                &publisher,
            )
            .map(|_| ())
        } else {
            operations::restore(&fixture.request, &fixture.operation).map(|_| ())
        };
        let error = result.err();
        assert!(error.is_some(), "{case}: mode mismatch was accepted");
        let message = format!("{error:?}");
        let expected = if case == "running-configured" || case == "download" {
            "running and configured cell-storage modes differ"
        } else {
            "service differs from operation cell-storage mode"
        };
        assert!(message.contains(expected), "{case}: wrong refusal: {message}");
        let manager = fixture.manager.borrow();
        assert!(
            !manager
                .events
                .iter()
                .any(|v| v == "before-capture" || v == "before-stage" || v == "start"),
            "{case}: prohibited action reached: {:?}",
            manager.events
        );
        if case == "running-configured" {
            assert!(
                !manager.events.iter().any(|v| v == "stop"),
                "running/configured mismatch stopped the source"
            );
        }
        if case == "download" {
            assert!(
                manager.events.iter().any(|v| v == "during-download"),
                "download did not execute"
            );
            assert!(
                !manager.events.iter().any(|v| v == "stop"),
                "stopped after download-mode drift"
            );
            assert!(
                !fixture.operation.join("stop-preparation.json").exists(),
                "post-download mode drift wrote a stop descriptor"
            );
        }
        if case.ends_with("stop") {
            assert!(
                manager.events.iter().any(|v| v == "stop-mode-flip"),
                "stop flip did not execute"
            );
        }
        drop(manager);
        fixture.manager.borrow_mut().stop()?;
        println!("LIFECYCLE_MODE_CASE_OK {case}");
    }
    println!("\nPRODUCTION_LIFECYCLE_MODES_OK");
    Ok(())
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[test]
fn production_restore_process_exit_recovers() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if let Some(path) = std::env::var_os("NODE_SYNC_LIFECYCLE_REQUEST") {
        let path = PathBuf::from(path);
        let request: RestoreRequest = serde_json::from_slice(&fs::read(&path)?)?;
        let operation = request.context.work_root.join("operation");
        let manager = Rc::new(RefCell::new(Manager {
            context: request.context.clone(),
            configured: false,
            json_rpc: false,
            no_index_flag: false,
            flip_on_stop: false,
            trip_on_describe: false,
            child: None,
            events: Vec::new(),
        }));
        manager.borrow_mut().start()?;
        let context = request.context.clone();
        let _scope = Scope::install(
            Box::new(move |command| manager.borrow_mut().command(command)),
            Box::new(move |point| {
                if point == "after-stop-before-stage" {
                    let own = Root::open(&context.database)?;
                    let inventory: Vec<_> = trees::inventory(&own)?
                        .iter()
                        .map(|f| {
                            Ok((
                                f.path.clone(),
                                sha256(&own.bytes(&f.path, crate::model::RAW_LIMIT)?),
                            ))
                        })
                        .collect::<Result<_>>()?;
                    Root::open(&context.work_root)?
                        .write_new("post-stop-inventory.json", &serde_json::to_vec(&inventory)?)?;
                    std::process::exit(73);
                }
                Ok(())
            }),
        );
        let result = operations::restore(&request, &operation);
        anyhow::bail!("production process-exit cut was not reached: {result:?}");
    }
    if !fixture_environment_available() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    Root::open(&fixture.request.context.work_root)?
        .write_new("child-request.json", &serde_json::to_vec(&fixture.request)?)?;
    let result = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "native_lifecycle::production_restore_process_exit_recovers",
            "--nocapture",
        ])
        .env(
            "NODE_SYNC_LIFECYCLE_REQUEST",
            fixture.request.context.work_root.join("child-request.json"),
        )
        .status()?;
    assert_eq!(
        result.code(),
        Some(73),
        "process did not exit at production stop-to-stage boundary"
    );
    assert!(
        fixture.operation.join("stop-preparation.json").is_file(),
        "process exit preceded durable stop descriptor"
    );
    let _scope = fixture.scope(|_| Ok(()));
    let result = operations::recover(&fixture.operation)?;
    let RecoveryOutcome::Aborted(report) = result else {
        panic!("process-exit preparation resumed")
    };
    assert!(report.removed_stage.is_some(), "production abort lost the bound staging descriptor");
    assert_eq!(report.service_state, "inactive");
    let expected: Vec<(String, String)> = serde_json::from_slice(&fs::read(
        fixture.request.context.work_root.join("post-stop-inventory.json"),
    )?)?;
    assert_eq!(fixture.inventory()?, expected, "recovery after process exit changed native data");
    let operation = Root::open(&fixture.operation)?;
    let id = operation.bytes("operation-id", 32)?;
    assert!(!fixture.request.cache.join(format!("leases/r-{}", sha256(&id))).exists());
    assert!(matches!(operations::recover(&fixture.operation)?, RecoveryOutcome::Aborted(_)));
    assert!(fixture.manager.borrow().events.is_empty(), "recovery unexpectedly started the node");
    println!("\nPRODUCTION_RESTORE_PROCESS_EXIT_OK");
    Ok(())
}

#[test]
fn production_complete_retries_after_release_cut() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let record = Root::create(&fixture.operation)?;
    record.write_new("request.json", &serde_json::to_vec(&fixture.request)?)?;
    record.write_new("generation.json", &fixture.signed.bytes()?)?;
    let id = "77".repeat(16);
    let lease_id = sha256(id.as_bytes());
    record.write_new("operation-id", id.as_bytes())?;
    let objects = Objects::open(&fixture.request.cache)?;
    let key: [u8; 32] = hex::decode(&fixture.request.publisher_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key length"))?;
    let catalog = Catalog::open(&fixture.request.cache, key)?;
    let generation = {
        let writer = objects.writer()?;
        catalog.begin_owned_download(&fixture.signed, &writer, &lease_id, &record)?
    };
    let other = "cc".repeat(32);
    catalog.lease(&other, &generation)?;
    let old = Root::create(&record.path.join("old-tree"))?;
    // This component fixture starts with the replacement installed and a durable catching-up journal.
    let journal = crate::journal::Journal {
        version: 2,
        operation: id,
        generation,
        old: crate::journal::TreeIdentity::read(&old.path)?,
        new: crate::journal::TreeIdentity::read(&fixture.request.context.database)?,
        installed: fixture.request.context.database.display().to_string(),
        staged: old.path.display().to_string(),
        preservation_sha256: "11".repeat(32),
        corroboration_sha256: Some("22".repeat(32)),
        target_anchor: fixture.signed.manifest.frontier.clone(),
        phase: crate::journal::Phase::CatchingUp,
    };
    journal.write(&record)?;
    let mut interrupted = false;
    let _scope = fixture.scope(move |point| {
        if point == "after-completion-lease-release" && !interrupted {
            interrupted = true;
            anyhow::bail!("fixture crash after completion lease release");
        }
        Ok(())
    });
    let outcome = operations::complete(&fixture.operation);
    let message = format!("{:?}", outcome.err());
    assert!(
        message.contains("fixture crash after completion lease release"),
        "completion did not reach release cut: {message}"
    );
    assert_eq!(crate::journal::Journal::read(&record)?.phase, crate::journal::Phase::Complete);
    assert!(!fixture.request.cache.join(format!("leases/r-{lease_id}")).exists());
    let retry = operations::complete(&fixture.operation);
    assert!(retry.is_ok(), "completion retry after unlink failed: {retry:?}");
    assert!(
        fixture.request.cache.join(format!("leases/r-{other}")).exists(),
        "retry removed another receiver lease"
    );
    println!("\nPRODUCTION_COMPLETE_RETRY_OK");
    Ok(())
}

/// The installed database decides whether a target runs an in-process wallet index, at
/// every boundary; the deprecated no-op flag and JSON-RPC on the command line decide nothing.
#[test]
fn production_restore_refuses_indexed_targets_at_lifecycle_boundaries() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    for case in [
        "disk-directory",
        "disk-symlink",
        "download",
        "stop",
        "json-rpc-without-flag",
        "json-rpc-with-flag",
    ] {
        let accepted = case.starts_with("json-rpc");
        let mut fixture = Fixture::new()?;
        fixture.manager.borrow_mut().start()?;
        let index = fixture.request.context.database.join("wc0-index");
        let appear = index.clone();
        let mode = case.to_owned();
        let _scope = fixture.scope(move |point| {
            if (mode == "download" && point == "during-download")
                || (mode == "stop" && point == "after-stop-before-stage")
            {
                fs::create_dir(&appear)?;
            }
            if point == "before-stage" {
                anyhow::bail!("prohibited staging reached");
            }
            Ok(())
        });
        if accepted {
            let mut manager = fixture.manager.borrow_mut();
            manager.json_rpc = true;
            manager.no_index_flag = case == "json-rpc-with-flag";
        }
        if case == "disk-directory" {
            fs::create_dir(&index)?;
        }
        if case == "disk-symlink" {
            std::os::unix::fs::symlink("absent", &index)?;
        }
        let _server;
        if case == "download" {
            let objects = Objects::open(&fixture.request.cache)?;
            let first = fixture.signed.manifest.files.first().context("native object")?;
            Root::open(objects.root_path())?.unlink(&Objects::object_name(first)?)?;
            _server = ObjectServer::new(fixture.source_catalog.clone())?;
            fixture.request.source_url = Some(_server.url.clone());
        }
        let error = operations::restore(&fixture.request, &fixture.operation)
            .expect_err("restore ran past its staging boundary");
        let message = format!("{error:#}");
        if accepted {
            // Every service check before staging passed: JSON-RPC, with or without the
            // no-op flag, is not a wallet index.
            assert!(
                message.contains("prohibited staging reached")
                    && !message.contains("wallet-indexed"),
                "{case}: target refused: {message}"
            );
            assert!(crate::safe_io::absent(&index)?, "{case}: an index entry was created");
            continue;
        }
        assert!(message.contains("wallet-indexed nodes"), "{case}: wrong refusal: {message}");
        if case.starts_with("disk-") {
            assert!(
                !fixture.operation.exists(),
                "{case}: preparation began before unsupported target refusal"
            );
        }
        let manager = fixture.manager.borrow();
        assert!(
            !manager.events.iter().any(|v| v == "before-stage" || v == "start"),
            "{case}: prohibited action reached: {:?}",
            manager.events
        );
        if case != "stop" {
            assert!(
                !manager.events.iter().any(|v| v == "stop"),
                "{case}: stopped unsupported target"
            );
        }
        // The refusal never removes or replaces the operator's index entry.
        assert!(index.symlink_metadata().is_ok(), "{case}: index entry was removed");
    }
    println!("\nPRODUCTION_RESTORE_INDEX_BOUNDARIES_OK");
    Ok(())
}

#[test]
fn production_restore_disk_refusals_preserve_recovery_phases() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    use crate::journal::{Journal, Phase, Recovery};
    for (point, expected, refusal) in [
        ("reference-corroborated", Phase::Staged, "restore-authorize"),
        ("restore-forward-only", Phase::Staged, "restore-forward-only"),
        ("restore-exchange", Phase::ForwardOnly, "restore-exchange"),
        ("restore-start-installed", Phase::Exchanged, "restore-start-installed"),
        ("restore-start-validating", Phase::StartIssued, "restore-service-start"),
    ] {
        let fixture = Fixture::new()?;
        let selected = point.to_owned();
        let state = Rc::clone(&fixture.manager);
        let hit = Rc::new(RefCell::new(false));
        let seen = Rc::clone(&hit);
        let _scope = fixture.scope(move |boundary| {
            if boundary == selected {
                *seen.borrow_mut() = true;
                if selected == "restore-start-validating" {
                    state.borrow_mut().trip_on_describe = true;
                } else {
                    crate::budget::stop_for_test(true);
                }
            }
            Ok(())
        });
        let error = operations::restore(&fixture.request, &fixture.operation)
            .expect_err("disk refusal did not stop restore exposure");
        let message = format!("{error:#}");
        assert!(*hit.borrow(), "{point}: injection did not execute");
        assert!(
            !fixture.manager.borrow().events.iter().any(|e| e == "start"),
            "{point}: start issued after refusal"
        );
        let record = Root::open(&fixture.operation)?;
        let before = Journal::read(&record)?;
        assert_eq!(before.phase, expected, "{point}: wrong durable phase after refusal");
        if expected == Phase::Staged {
            assert_eq!(before.recovery()?, Recovery::OldRefreshRequired);
            if point == "reference-corroborated" {
                assert!(
                    before.corroboration_sha256.is_none(),
                    "authorization happened after monitor trip"
                );
            } else {
                assert!(before.corroboration_sha256.is_some(), "earlier authorization did not run");
            }
        }
        assert!(message.contains(&format!("disk refusal before {refusal}")), "{point}: {message}");
        if point == "restore-start-validating" {
            assert!(
                fixture
                    .manager
                    .borrow()
                    .events
                    .iter()
                    .any(|event| event == "final-validation-disk-trip"),
                "final service description did not execute the injected trip"
            );
        }
        drop(_scope);
        if before.recovery()? == Recovery::NewContinueOnly {
            Root::open(&fixture.request.context.database)?
                .write_new("consensus/disk-refusal-marker", b"new signing tree")?;
            let _scope = fixture.scope(|boundary| {
                if boundary == "reference-corroborated" {
                    crate::budget::stop_for_test(true);
                }
                Ok(())
            });
            let error = operations::recover(&fixture.operation)
                .err()
                .context("exchanged recovery ignored monitor refusal")?;
            assert!(format!("{error:#}").contains("disk refusal before restore-authorize"));
            let refused = Journal::read(&record)?;
            assert_eq!(refused.phase, before.phase);
            assert_eq!(refused.new, before.new);
            assert_eq!(refused.recovery()?, Recovery::NewContinueOnly);
            assert_eq!(
                Root::open(&fixture.request.context.database)?
                    .bytes("consensus/disk-refusal-marker", 100)?,
                b"new signing tree"
            );
        }
        let events = Rc::new(RefCell::new(Vec::new()));
        let observed = Rc::clone(&events);
        let path = fixture.operation.clone();
        let _scope = fixture.scope(move |boundary| {
            if matches!(boundary, "restore-authorize" | "restore-forward-only" | "restore-exchange")
            {
                let current = Journal::read(&Root::open(&path)?)?;
                observed.borrow_mut().push((
                    boundary.to_owned(),
                    current.phase,
                    current.corroboration_sha256.is_some(),
                ));
            }
            Ok(())
        });
        let outcome = operations::recover(&fixture.operation)?;
        assert!(matches!(outcome, RecoveryOutcome::Installed(_)), "{point}: recovery aborted");
        let after = Journal::read(&record)?;
        assert_eq!(after.phase, Phase::CatchingUp);
        if expected == Phase::Staged {
            assert_eq!(
                &*events.borrow(),
                &[
                    ("restore-authorize".to_owned(), Phase::Staged, false),
                    ("restore-forward-only".to_owned(), Phase::Staged, true),
                    ("restore-exchange".to_owned(), Phase::ForwardOnly, true),
                ],
                "staged recovery must durably authorize, cross forward-only, then exchange"
            );
        } else if expected == Phase::ForwardOnly {
            assert_eq!(
                &*events.borrow(),
                &[
                    ("restore-authorize".to_owned(), Phase::ForwardOnly, false),
                    ("restore-exchange".to_owned(), Phase::ForwardOnly, true),
                ],
                "forward-only recovery re-entered or cleared its boundary"
            );
        } else {
            assert_eq!(after.new, before.new, "exchanged recovery replaced signing state");
            assert_eq!(
                Root::open(&fixture.request.context.database)?
                    .bytes("consensus/disk-refusal-marker", 100)?,
                b"new signing tree"
            );
            assert!(
                !events
                    .borrow()
                    .iter()
                    .any(|(e, _, _)| e == "restore-exchange" || e == "restore-forward-only")
            );
        }
        println!("RESTORE_DISK_BOUNDARY_OK {point}");
    }
    println!("RESTORE_DISK_BOUNDARIES_OK");
    Ok(())
}

#[test]
fn staged_recovery_keeps_staged_on_failed_corroboration_and_monitor() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    use crate::journal::{Journal, Phase};
    for failure in ["reference", "monitor"] {
        let fixture = Fixture::new()?;
        let _scope = fixture.scope(|point| {
            if point == "restore-authorize" {
                anyhow::bail!("fixture cut before authorization");
            }
            Ok(())
        });
        let error =
            operations::restore(&fixture.request, &fixture.operation).expect_err("cut missed");
        assert!(format!("{error:#}").contains("fixture cut before authorization"));
        drop(_scope);
        let record = Root::open(&fixture.operation)?;
        let bad_refs;
        if failure == "reference" {
            bad_refs = crate::test_references::References::new(
                &fixture.signed.manifest.network,
                &fixture.signed.manifest.frontier,
                crate::test_references::Mode::DifferentRoot,
            )?;
            let mut request = fixture.request.clone();
            request.context.references = bad_refs.policy.clone();
            record.replace("request.json", &serde_json::to_vec(&request)?)?;
        }
        let _scope = fixture.scope(move |point| {
            if failure == "monitor" && point == "reference-corroborated" {
                crate::budget::stop_for_test(true);
            }
            Ok(())
        });
        let error = operations::recover(&fixture.operation)
            .err()
            .context("failed corroboration/monitor permitted recovery")?;
        let message = format!("{error:#}");
        assert!(
            message.contains(if failure == "reference" {
                "disagrees with the exact frontier"
            } else {
                "disk refusal before restore-authorize"
            }),
            "{failure}: {message}"
        );
        let journal = Journal::read(&record)?;
        assert_eq!(journal.phase, Phase::Staged, "staged refusal became forward-only");
        assert!(journal.corroboration_sha256.is_none(), "refusal authorized exposure");
        assert!(!fixture.manager.borrow().events.iter().any(|e| e == "start"));
    }
    println!("\nSTAGED_DISK_RECOVERY_OK");
    Ok(())
}

#[test]
fn source_restart_remains_available_after_monitor_refusal() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let _scope = fixture.scope(|_| Ok(()));
    let frozen = Frozen::acquire(&fixture.request.context.database)?;
    crate::budget::stop_for_test(true);
    fixture.request.context.service().start_in_mode(frozen, false)?;
    assert_eq!(fixture.manager.borrow().events, vec!["start"]);
    Ok(())
}

#[test]
fn restore_requires_stable_budget_roots_before_preparation() -> Result<()> {
    let _serial =
        SERIAL.lock().map_err(|_| anyhow::anyhow!("native lifecycle fixture poisoned"))?;
    if !fixture_environment_available() {
        return Ok(());
    }
    let mut fixture = Fixture::new()?;
    fixture.request.context.budget_roots =
        vec![fixture.request.context.database.clone(), fixture.request.cache.clone()];
    let _scope = fixture.scope(|_| Ok(()));
    let error = operations::preflight(&fixture.request)
        .err()
        .context("preflight admitted an allocation root that exchange would detach")?;
    assert!(
        format!("{error:#}")
            .contains("restore allocation roots must remain outside the exchanged database"),
        "wrong unstable-root refusal: {error:#}"
    );
    assert!(!fixture.operation.exists());
    assert!(fixture.manager.borrow().events.is_empty());
    Ok(())
}
