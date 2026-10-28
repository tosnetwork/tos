use crate::{
    model::{FullId, MANIFEST_LIMIT, NativeValidation, Network, approved_forks, sha256},
    safe_io::{Root, file_hash},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequest {
    pub engine: PathBuf,
    pub image: PathBuf,
    pub global_config: PathBuf,
    pub output: PathBuf,
    pub global_id: i32,
    pub permanent_cells: bool,
    pub required_ancestors: Vec<FullId>,
    pub parent_network_namespace: u64,
    pub parent_process: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
    pub validation: NativeValidation,
    pub coverage: Vec<String>,
    pub ancestors: Vec<FullId>,
}
struct Process(Child);
impl Process {
    fn stop(&mut self) -> Result<()> {
        if self.0.try_wait()?.is_some() {
            anyhow::bail!("validation engine exited before the read checks completed");
        }
        // The process is owned by this validation invocation; never signal a discovered host process.
        ensure!(
            unsafe { libc::kill(i32::try_from(self.0.id())?, libc::SIGTERM) } == 0,
            "cannot stop owned validation engine"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.0.try_wait()?.is_some() {
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "validation engine did not settle after stop");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("cannot terminate owned validation engine: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("cannot reap owned validation engine: {error}");
                }
            }
        }
    }
}
fn canonical(path: &std::path::Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "validation path must be canonical"
    );
    Ok(())
}
#[cfg(feature = "native")]
pub async fn validate_image(request: &ValidationRequest) -> Result<ValidationResult> {
    use crate::{
        native_validation::{bounded_diagnostic, check_states, fresh_control},
        records,
    };
    // The verifier is operation-owned, including after an abrupt launcher exit.
    parent_lifetime(request.parent_process)?;
    for path in [&request.engine, &request.image, &request.global_config] {
        canonical(path)?;
    }
    ensure!(
        fs::metadata("/proc/self/ns/net")?.ino() != request.parent_network_namespace,
        "native validation requires a separate network namespace"
    );
    enable_loopback().context("enable isolated validation loopback")?;
    let started = Instant::now();
    let started_utc = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let image = Root::open(&request.image)?;
    let mut recovery_context = Vec::new();
    if request.image.join("tmp").try_exists()? {
        let temporary = Root::open(&request.image.join("tmp"))?;
        for file in crate::trees::inventory(&temporary)? {
            let identity = file_hash(temporary.read(&file.path, file.size)?, file.size)?;
            recovery_context.push((file.path, identity));
        }
    }
    let recovery_context_sha256 = sha256(&serde_json::to_vec(&recovery_context)?);
    // Fresh local validation identity only; these paths must never arrive from the source.
    for path in ["config.json", "keyring", "consensus", "catchains", "import"] {
        ensure!(
            !image.path.join(path).try_exists()?,
            "validation image contains local or import context: {path}"
        );
    }
    let global_path = request.global_config.parent().context("global configuration parent")?;
    let global_name =
        request.global_config.file_name().and_then(|s| s.to_str()).context("global filename")?;
    let global = Root::open(global_path)?.bytes(global_name, MANIFEST_LIMIT)?;
    let held = Network::from_global(&global, request.global_id)?;
    let policy = approved_forks(&global)?;
    ensure!(request.required_ancestors.len() <= 4096, "required ancestry count limit");
    let mut ancestry = policy.clone();
    ancestry.extend(request.required_ancestors.clone());
    let store = node_store::OfflineStore::open_existing(&image.path.join("state"))?;
    let (chain, _) = records::export(&store)?;
    ensure!(chain.forks()? == policy, "captured fork history differs from held policy");
    drop(store);
    let output = Root::create(&request.output)?;
    let init_log = output.create_file("initialize.log")?;
    let mut initializer = Process(
        engine_command(&request.engine, request.permanent_cells)?
            .arg("-D")
            .arg(&request.image)
            .arg("-C")
            .arg(&request.global_config)
            .args(["-I", "127.0.0.1:29001", "-t", "2"])
            .stdin(Stdio::null())
            .stdout(init_log.try_clone()?)
            .stderr(init_log.try_clone()?)
            .spawn()?,
    );
    let init_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = initializer.0.try_wait()? {
            ensure!(status.success(), "validation identity initialization failed");
            break;
        }
        ensure!(
            Instant::now() < init_deadline && init_log.metadata()?.len() <= 32 << 20,
            "validation initialization deadline or log limit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let adnl = fresh_control(&image, "127.0.0.1:29002")?;
    let mut checked = None;
    let mut expected = chain.frontier()?;
    for pass in 0..2 {
        let log = output.create_file(&format!("reopen-{pass}.log"))?;
        let mut process = Process(
            engine_command(&request.engine, request.permanent_cells)?
                .arg("-D")
                .arg(&request.image)
                .arg("-C")
                .arg(&request.global_config)
                .args([
                    "-t",
                    "4",
                    "--celldb-cache-size",
                    "1073741824",
                    "--celldb-cache-min-size",
                    "1073741824",
                    "--initial-sync-delay",
                    "0",
                    "--skip-key-sync",
                    "--unsynced-liteserver",
                ])
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log.try_clone()?)
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(180);
        // The last failed check is kept so that a deadline names the read that never passed
        // instead of only reporting that one did not.
        let mut last = String::from("no read attempt completed");
        let states = loop {
            ensure!(
                process.0.try_wait()?.is_none(),
                "native validation engine exited during reopen; last check: {last}"
            );
            ensure!(log.metadata()?.len() <= 32 << 20, "native validation log byte limit");
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                check_states(&adnl, &held, &expected, &ancestry),
            )
            .await;
            match result {
                Ok(Ok(states)) => break states,
                Ok(Err(error)) => last = bounded_diagnostic(&format!("{error:#}")),
                Err(_) => last = "read attempt exceeded 15 s".to_owned(),
            }
            ensure!(
                Instant::now() < deadline,
                "native recovery or required shard-state read did not complete; last check: {last}"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        process.stop()?;
        let store = node_store::OfflineStore::open_existing(&image.path.join("state"))?;
        let (after, _) = records::export(&store)?;
        let frontier = after.frontier()?;
        records::reconcile_forks(&policy, &after, &[], &states.ancestors)?;
        if pass == 1 {
            ensure!(
                frontier == expected,
                "coherent frontier changed during the second validation pass; recapture required"
            );
        }
        expected = frontier;
        checked = Some((states, after));
    }
    let (states, chain) = checked.context("native validation produced no checked generation")?;
    refuse_pending_recovery(&image.path.join("tmp/persistent-state"))?;
    output.write_new("tip-block.boc", &states.tip)?;
    output.write_new("state-records.cbor", &chain.bytes()?)?;
    let engine_parent = request.engine.parent().context("engine parent")?;
    let engine_name =
        request.engine.file_name().and_then(|s| s.to_str()).context("engine filename")?;
    let (_, engine_sha256) =
        file_hash(Root::open(engine_parent)?.read(engine_name, 1 << 30)?, 1 << 30)?;
    let result = ValidationResult {
        validation: NativeValidation {
            engine_sha256,
            policy_sha256: sha256(&global),
            frontier: expected,
            passes: 2,
            permanent_cells: request.permanent_cells,
            recovery_resolved: true,
            monitored_states_readable: true,
            elapsed_millis: u64::try_from(started.elapsed().as_millis())?,
            recovery_context_sha256,
            started_utc,
            finished_utc: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        },
        coverage: states.coverage,
        ancestors: states.ancestors.into_iter().collect(),
    };
    output.write_new("validation.json", &serde_json::to_vec(&result)?)?;
    Ok(result)
}
fn refuse_pending_recovery(path: &std::path::Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(metadata) => {
            ensure!(metadata.file_type().is_dir(), "recovery path is a link or special file")
        }
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            refuse_pending_recovery(&entry.path())?;
        } else {
            ensure!(kind.is_file(), "recovery path contains a link or special file");
            ensure!(
                !entry.file_name().to_string_lossy().contains(".celldb-rollback."),
                "native recovery material remains after reopen"
            );
        }
    }
    Ok(())
}

fn enable_loopback() -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // The caller verified that this is the operation's separate network namespace.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    ensure!(raw >= 0, "loopback control socket: {}", std::io::Error::last_os_error());
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as _;
    request.ifr_name[1] = b'o' as _;
    ensure!(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) } == 0,
        "read private loopback flags: {}",
        std::io::Error::last_os_error()
    );
    unsafe {
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    ensure!(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) } == 0,
        "enable private loopback: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn engine_command(path: &std::path::Path, permanent_cells: bool) -> Result<Command> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(path);
    if permanent_cells {
        command.arg("--permanent-celldb");
    }
    // A crash dump could contain the fresh validation credentials. Change only the owned child.
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::other(
                    "validation owner exited before child initialization",
                ));
            }
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn parent_lifetime(expected: u32) -> Result<()> {
    ensure!(
        expected > 0 && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0,
        "cannot bind verifier lifetime to its owner"
    );
    ensure!(
        unsafe { libc::getppid() } == libc::pid_t::try_from(expected)?,
        "validation launcher no longer owns this process"
    );
    Ok(())
}
