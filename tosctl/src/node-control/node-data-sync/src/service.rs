use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub struct Service {
    pub unit: String,
    pub database: PathBuf,
    pub engine: PathBuf,
    pub global_config: PathBuf,
    pub working_directory: PathBuf,
    /// The context's work root; it decides where the node's `keys` directory lives.
    pub work_root: PathBuf,
    pub user_manager: bool,
}

/// Exit status of a command that stopped the selected source service and could not, or by
/// design would not, start it again. The operator must review and restart it.
pub const SOURCE_LEFT_STOPPED_EXIT: u8 = 5;
/// The selected source service was stopped by this command and is not running again.
/// The message names the unit, the observed state, why it was not restarted, every error
/// involved and the exact restart command.
#[derive(Debug)]
pub struct SourceLeftStopped(pub String);
impl std::fmt::Display for SourceLeftStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SourceLeftStopped {}
struct CheckedService {
    permanent_cells: bool,
    account: Account,
}

/// The account the selected service runs as, and the account invoking this tool.
/// They differ only for a system unit with a dedicated service account, invoked as root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    pub invoker: u32,
}
/// `User=`, `Group=` and `DynamicUser=` of the selected unit, as the manager reports them.
pub(crate) struct UnitAccount<'a> {
    pub user_manager: bool,
    pub user: &'a str,
    pub group: &'a str,
    pub dynamic: &'a str,
}
pub(crate) struct Invoker<'a> {
    pub uid: u32,
    pub gid: u32,
    pub name: &'a str,
}
/// A resolved local account: numeric uid, primary gid and primary group name.
pub(crate) struct Resolved {
    pub uid: u32,
    pub gid: u32,
    pub group: String,
}
fn account_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
/// One decision for every supported service shape; anything else refuses before a stop.
pub(crate) fn select_account(
    unit: &UnitAccount<'_>,
    invoker: &Invoker<'_>,
    resolve: impl FnOnce(&str) -> Result<Resolved>,
) -> Result<Account> {
    let user = unit.user.trim();
    if unit.user_manager {
        // A user manager runs its units as the manager's own account: the invoker.
        ensure!(
            user.is_empty(),
            "a user-manager unit cannot name a service account; select the system manager"
        );
        return Ok(Account { uid: invoker.uid, gid: invoker.gid, invoker: invoker.uid });
    }
    ensure!(
        !user.is_empty(),
        "a system unit without User= runs as root; set a dedicated service account"
    );
    ensure!(user != "root", "a system unit running as root is not supported");
    ensure!(account_name(user), "unsupported service User= value");
    let resolved = resolve(user)?;
    ensure!(resolved.uid != 0, "a system unit running as root is not supported");
    // Every system unit, whether it runs as the invoker or as a service account.
    ensure!(
        unit.dynamic.trim() == "no",
        "a dynamically allocated service user is not supported; use a fixed service account"
    );
    let group = unit.group.trim();
    ensure!(
        group.is_empty() || group == resolved.group,
        "service Group= must be the service account's primary group"
    );
    if user == invoker.name.trim() && resolved.uid == invoker.uid {
        return Ok(Account { uid: invoker.uid, gid: invoker.gid, invoker: invoker.uid });
    }
    ensure!(
        invoker.uid == 0,
        "service must run as the invoking user, or as a dedicated service account when invoked as root"
    );
    Ok(Account { uid: resolved.uid, gid: resolved.gid, invoker: 0 })
}
impl Account {
    pub fn delegated(&self) -> bool {
        self.uid != self.invoker
    }
    /// With a service account, a group or other write bit would let a third account change
    /// a tree the privileged invoker acts on. Without one, the invoker's layout is unchanged.
    fn exclusive(&self, metadata: &fs::Metadata) -> bool {
        !self.delegated() || metadata.mode() & 0o022 == 0
    }
    /// The installed database belongs to the service account.
    pub fn require_database(&self, database: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(database)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == self.uid && self.exclusive(&metadata),
            "database root must be owned by the service account (uid {}) and writable by no other account",
            self.uid
        );
        if self.delegated() {
            self.require_protected_ancestors(database)?;
        }
        Ok(())
    }
    /// Operation, catalog and cache trees belong to the invoker: the service account must
    /// not be able to change what the invoker validates, signs or installs.
    pub fn require_private(&self, path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && fs::canonicalize(path)? == path,
            "private operation root must be canonical and link-free"
        );
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == self.invoker && self.exclusive(&metadata),
            "{} must be a directory owned by the invoking user (uid {}) and writable by no other account",
            path.display(),
            self.invoker
        );
        if self.delegated() {
            self.require_protected_ancestors(path)?;
        }
        Ok(())
    }
    /// Allocation roots are only measured; with a service account they may belong to either side.
    pub fn require_budget(&self, roots: &[PathBuf]) -> Result<()> {
        if !self.delegated() {
            return Ok(());
        }
        for root in roots {
            let metadata = fs::symlink_metadata(root)?;
            ensure!(
                metadata.is_dir() && (metadata.uid() == self.invoker || metadata.uid() == self.uid),
                "budget root {} belongs to another account",
                root.display()
            );
        }
        Ok(())
    }
    /// Paths the invoker resolves must not be re-pointable by the service account: every
    /// ancestor is the invoker's or root's and writable by no other account, except sticky ones.
    fn require_protected_ancestors(&self, path: &Path) -> Result<()> {
        for ancestor in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.is_dir()
                    && (metadata.uid() == 0 || metadata.uid() == self.invoker)
                    && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0),
                "{} must be owned by root and writable by no other account",
                ancestor.display()
            );
        }
        Ok(())
    }
}

pub struct Frozen {
    _configuration_lock: File,
    pub(crate) root: PathBuf,
}
impl Frozen {
    /// The held configuration lock is still the one at `database/config.json.lock`.
    pub fn check_held(&self, database: &Path) -> Result<()> {
        let held = self._configuration_lock.metadata()?;
        let selected = fs::symlink_metadata(database.join("config.json.lock"))?;
        ensure!(
            self.root == database
                && selected.file_type().is_file()
                && held.ino() == selected.ino()
                && held.dev() == selected.dev(),
            "start lock belongs to another installed tree"
        );
        Ok(())
    }
    /// Offline primitive shared by explicit service operations and disposable native fixtures.
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure!(
            root.is_absolute() && fs::canonicalize(root)? == root,
            "stopped root must be canonical"
        );
        // The engine opens this lock read-write at start: a lock created here must belong
        // to the database owner, not to a privileged invoker.
        let lock = crate::safe_io::Root::open(root)?.open_shared_lock("config.json.lock")?;
        ensure!(lock.metadata()?.is_file(), "invalid native configuration lock");
        let mut record: libc::flock = unsafe { std::mem::zeroed() };
        record.l_type = libc::F_WRLCK as _;
        record.l_whence = libc::SEEK_SET as _;
        ensure!(
            unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_SETLK, &record) } == 0,
            "native configuration lock is busy"
        );
        refuse_writers(root)?;
        Ok(Self { _configuration_lock: lock, root: root.to_owned() })
    }
}
impl Service {
    fn manager(&self) -> Command {
        let mut command = Command::new("systemctl");
        if self.user_manager {
            command.arg("--user");
        }
        command
    }
    pub fn definitions(&self) -> Result<Vec<PathBuf>> {
        let output = command(
            self.manager().args([
                "show",
                "--property=FragmentPath",
                "--property=DropInPaths",
                "--property=EnvironmentFiles",
                "--",
                &self.unit,
            ]),
            Duration::from_secs(10),
        )?;
        let mut paths = Vec::new();
        for line in output.lines() {
            let (_, value) =
                line.split_once('=').context("invalid service definition inventory")?;
            for path in value.split_whitespace() {
                if path.starts_with("(ignore_errors=") {
                    continue;
                }
                ensure!(!path.contains('\\'), "escaped service file path is unsupported");
                paths.push(PathBuf::from(path).canonicalize()?);
                ensure!(paths.len() <= 64, "service definition count limit");
            }
        }
        ensure!(!paths.is_empty(), "selected service has no durable definition");
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
    /// Reporting never substitutes another unit or another service-manager scope.
    pub fn abort_guidance(&self) -> Result<(String, String)> {
        ensure!(
            self.unit.ends_with(".service")
                && self.unit.len() <= 255
                && self.unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b)),
            "invalid explicit service unit"
        );
        let state = command(
            self.manager().args(["show", "--property=ActiveState,LoadState", "--", &self.unit]),
            Duration::from_secs(10),
        )
        .map(|output| reported_state(&output))
        .unwrap_or_else(|_| "unknown".to_owned());
        let scope = if self.user_manager { "--user " } else { "" };
        Ok((state, format!("systemctl {scope}start -- {}", self.unit)))
    }
    pub fn permanent_cells(&self) -> Result<bool> {
        Ok(self.describe(None)?.permanent_cells)
    }
    pub fn require_mode(&self, expected: bool) -> Result<()> {
        self.describe(Some(expected)).map(|_| ())
    }
    /// Restore supports only targets without an in-process wallet index; capture may still
    /// use an indexed source. The installed database decides, through its held descriptor:
    /// a current engine never opens an index whatever its flags, and the only flag that
    /// once disabled it is now a no-op, so the command line decides nothing here.
    pub fn require_restore_target(&self, expected: Option<bool>) -> Result<()> {
        self.describe(expected)?;
        crate::paths::restore_root(&self.database, self.keys_location()?)
    }
    /// Where `keys` lives, decided from the resolved context: the work root is the database
    /// root only when both canonical paths are equal, and then they must be one directory.
    /// A work root that reaches the same directory under another path (a bind mount) refuses.
    pub fn keys_location(&self) -> Result<crate::paths::KeysLocation> {
        let work = fs::canonicalize(&self.work_root)?;
        let database = fs::canonicalize(&self.database)?;
        ensure!(
            work == self.work_root && database == self.database,
            "work and database roots must be canonical and link-free"
        );
        let same_path = work == database;
        let same_tree = crate::safe_io::Root::open(&work)?.identity()?
            == crate::safe_io::Root::open(&database)?.identity()?;
        ensure!(same_path == same_tree, "work root reaches the database root under another path");
        Ok(if same_path {
            crate::paths::KeysLocation::Database
        } else {
            crate::paths::KeysLocation::Elsewhere
        })
    }
    pub fn start_restore(&self, frozen: Frozen, expected: bool) -> Result<()> {
        self.require_restore_target(Some(expected))?;
        self.start_checked(frozen, Some(expected), true)
    }
    pub fn validate(&self) -> Result<()> {
        self.describe(None).map(|_| ())
    }
    /// The checked service description, in the expected cell-storage mode when one is given.
    pub fn require_selected_mode(&self, expected: Option<bool>) -> Result<()> {
        self.describe(expected).map(|_| ())
    }
    /// The selected unit is not running: inactive or failed, with no main process.
    pub fn require_inactive(&self) -> Result<()> {
        let state = command(
            self.manager().args(["show", "--property=ActiveState", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        let pid = command(
            self.manager().args(["show", "--property=MainPID", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        ensure!(
            matches!(state.trim(), "inactive" | "failed") && pid.trim() == "0",
            "selected service is running (state {})",
            state.trim()
        );
        Ok(())
    }
    /// One parser and binding for configured, running and operation-selected storage modes.
    fn describe(&self, expected: Option<bool>) -> Result<CheckedService> {
        ensure!(
            self.unit.ends_with(".service")
                && self.unit.len() <= 255
                && self.unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b)),
            "invalid explicit service unit"
        );
        ensure!(
            self.database.is_absolute() && fs::canonicalize(&self.database)? == self.database,
            "database root must be canonical and link-free"
        );
        ensure!(
            fs::canonicalize(&self.engine)? == self.engine
                && fs::canonicalize(&self.global_config)? == self.global_config
                && fs::canonicalize(&self.working_directory)? == self.working_directory,
            "service paths must be canonical"
        );
        let account = self.account_checked()?;
        account.require_database(&self.database)?;
        let work = command(
            self.manager().args([
                "show",
                "--property=WorkingDirectory",
                "--value",
                "--",
                &self.unit,
            ]),
            Duration::from_secs(10),
        )?;
        ensure!(
            Path::new(work.trim()) == self.working_directory,
            "service working directory differs from selected context"
        );
        let exec = command(
            self.manager().args(["show", "--property=ExecStart", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        let configured = validate_exec(
            &exec,
            &self.engine,
            &self.database,
            &self.global_config,
            &self.working_directory,
        )?;
        let pid = command(
            self.manager().args(["show", "--property=MainPID", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        let pid: u32 = pid.trim().parse().context("service MainPID is not numeric")?;
        if pid != 0 {
            let process = PathBuf::from(format!("/proc/{pid}"));
            ensure!(
                fs::read_link(process.join("exe"))? == self.engine,
                "running executable differs from selected installed engine"
            );
            ensure!(
                fs::read_link(process.join("cwd"))? == self.working_directory,
                "running working directory differs from selected context"
            );
            let bytes = fs::read(process.join("cmdline"))?;
            ensure!(bytes.len() <= 1 << 20, "running argument byte limit");
            let arguments: Vec<_> = bytes
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(std::str::from_utf8)
                .collect::<std::result::Result<_, _>>()?;
            ensure!(
                arguments.iter().all(|argument| !argument.chars().any(char::is_whitespace)),
                "running arguments contain unsupported whitespace"
            );
            let running = validate_exec(
                &format!("{{ argv[]={} ; running }}", arguments.join(" ")),
                &self.engine,
                &self.database,
                &self.global_config,
                &self.working_directory,
            )?;
            check_mode(configured, Some(running), expected)?;
        }
        check_mode(configured, None, expected)?;
        Ok(CheckedService { permanent_cells: configured, account })
    }
    /// The checked account of the selected service; the same decision `describe` enforces.
    pub fn account(&self) -> Result<Account> {
        Ok(self.describe(None)?.account)
    }
    fn property(&self, name: &str) -> Result<String> {
        command(
            self.manager().args([
                "show",
                &format!("--property={name}"),
                "--value",
                "--",
                &self.unit,
            ]),
            Duration::from_secs(10),
        )
    }
    fn account_checked(&self) -> Result<Account> {
        let user = self.property("User")?;
        let (group, dynamic) = if self.user_manager {
            (String::new(), String::new())
        } else {
            (self.property("Group")?, self.property("DynamicUser")?)
        };
        let name = command(Command::new("id").arg("-un"), Duration::from_secs(10))?;
        // SAFETY: geteuid and getegid have no preconditions.
        let invoker = Invoker {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            name: &name,
        };
        let unit = UnitAccount {
            user_manager: self.user_manager,
            user: &user,
            group: &group,
            dynamic: &dynamic,
        };
        select_account(&unit, &invoker, |user| {
            let number = |flag: &str| -> Result<u32> {
                command(Command::new("id").args([flag, "--", user]), Duration::from_secs(10))?
                    .trim()
                    .parse()
                    .context("service account id is not numeric")
            };
            Ok(Resolved {
                uid: number("-u")?,
                gid: number("-g")?,
                group: command(
                    Command::new("id").args(["-gn", "--", user]),
                    Duration::from_secs(10),
                )?
                .trim()
                .to_owned(),
            })
        })
    }
    pub fn stop(&self) -> Result<Frozen> {
        self.validate()?;
        self.stop_command()?;
        self.freeze()
    }
    /// Only the stop request to the selected unit's manager; the caller has validated the
    /// service and freezes it next.
    pub fn stop_command(&self) -> Result<()> {
        command(self.manager().args(["stop", "--", &self.unit]), Duration::from_secs(120))
            .map(|_| ())
    }
    pub fn freeze(&self) -> Result<Frozen> {
        self.validate()?;
        let state = command(
            self.manager().args(["show", "--property=ActiveState", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        ensure!(matches!(state.trim(), "inactive" | "failed"), "selected service is not stopped");
        Frozen::acquire(&self.database)
    }
    pub fn start(&self, frozen: Frozen) -> Result<()> {
        self.start_checked(frozen, None, false)
    }
    pub fn start_in_mode(&self, frozen: Frozen, expected: bool) -> Result<()> {
        self.start_checked(frozen, Some(expected), false)
    }
    fn start_checked(&self, frozen: Frozen, expected: Option<bool>, restore: bool) -> Result<()> {
        if restore {
            #[cfg(all(test, feature = "native-lifecycle-tests"))]
            crate::test_hooks::boundary("restore-start-validating")?;
        }
        self.describe(expected)?;
        frozen.check_held(&self.database)?;
        // Source restart remains available even if capture's allocation monitor refused.
        if restore {
            crate::budget::check_active().context("disk refusal before restore-service-start")?;
        }
        drop(frozen);
        command(self.manager().args(["start", "--", &self.unit]), Duration::from_secs(120))?;
        Ok(())
    }
}
fn check_mode(configured: bool, running: Option<bool>, expected: Option<bool>) -> Result<()> {
    ensure!(
        running.is_none_or(|mode| mode == configured),
        "running and configured cell-storage modes differ"
    );
    ensure!(
        expected.is_none_or(|mode| mode == configured),
        "service differs from operation cell-storage mode"
    );
    Ok(())
}
fn command(command: &mut Command, budget: Duration) -> Result<String> {
    #[cfg(all(test, feature = "native-lifecycle-tests"))]
    if let Some(result) = crate::test_hooks::command(command) {
        return result;
    }
    // Bounded temporary output avoids pipe deadlock when the child fills stderr.
    let output = tempfile::tempfile()?;
    let child = command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .spawn()?;
    let mut owned = OwnedChild(child);
    let child = &mut owned.0;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= budget {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("service command timed out");
        }
        ensure!(output.metadata()?.len() <= 1 << 20, "service command output limit");
        std::thread::sleep(Duration::from_millis(100));
    };
    use std::io::{Read, Seek};
    let mut output = output;
    output.rewind()?;
    let mut bytes = Vec::new();
    output.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1 << 20, "service command output limit");
    let text = String::from_utf8(bytes)?;
    ensure!(status.success(), "service command failed: {status}: {text}");
    Ok(text)
}
pub(crate) fn refuse_writers(root: &Path) -> Result<()> {
    let own = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == own || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let descriptors = match fs::read_dir(entry.path().join("fd")) {
            Ok(value) => value,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        for descriptor in descriptors {
            let descriptor = match descriptor {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let target = match fs::read_link(descriptor.path()) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            if target.starts_with(root) {
                let info =
                    fs::read_to_string(entry.path().join("fdinfo").join(descriptor.file_name()))?;
                let flags = info
                    .lines()
                    .find_map(|s| s.strip_prefix("flags:\t"))
                    .context("cannot inspect database descriptor flags")?;
                let flags = u32::from_str_radix(flags, 8)?;
                ensure!(
                    flags & libc::O_ACCMODE as u32 == libc::O_RDONLY as u32,
                    "another process has a writable database descriptor"
                );
            }
        }
    }
    Ok(())
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                // Cleanup cannot return a status from Drop; report any failed termination.
                if let Err(error) = self.0.kill() {
                    eprintln!("cannot stop owned service command: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("cannot reap owned service command: {error}");
                }
            }
        }
    }
}
fn validate_exec(
    value: &str,
    engine: &Path,
    database: &Path,
    global: &Path,
    work: &Path,
) -> Result<bool> {
    let start = value.find("argv[]=").context("service has no inspectable command")?;
    let suffix = &value[start + "argv[]=".len()..];
    let (argv, tail) = suffix.split_once(" ; ").context("unsupported service command encoding")?;
    ensure!(!tail.contains("argv[]="), "multiple service commands are unsupported");
    ensure!(
        !argv.bytes().any(|b| b"\\\"'$%{};".contains(&b)),
        "nonliteral service command is unsupported"
    );
    let tokens: Vec<_> = argv.split_whitespace().collect();
    ensure!(
        tokens.first().is_some_and(|s| Path::new(s) == engine),
        "selected engine differs from service executable"
    );
    let mut selectors: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    let mut permanent = false;
    let mut index = 1;
    while let Some(option) = tokens.get(index) {
        let (canonical, takes_value) = canonical_option(option)?;
        index += 1;
        if canonical == "permanent-celldb" {
            permanent = true;
        }
        if takes_value {
            let value = *tokens.get(index).context("service option requires a separate value")?;
            index += 1;
            selectors.entry(canonical).or_default().push(value);
        }
    }
    for (flag, expected) in [("db", database), ("global-config", global)] {
        let values = selectors.get(flag).context("service omitted a required path selector")?;
        ensure!(
            values.len() == 1 && resolve_arg(work, values[0])? == expected,
            "service {flag} differs from selected path or is duplicated"
        );
    }
    if let Some(values) = selectors.get("local-config") {
        ensure!(
            values.len() == 1 && resolve_arg(work, values[0])? == database.join("config.json"),
            "local config is duplicated or outside selected database"
        );
    }
    Ok(permanent)
}
// A deliberately restricted spelling/arity subset of the native option table, not a
// second permissive parser. Unsupported native forms must be canonicalized by the operator.
const SAFE_OPTIONS: &[(&str, &str, bool)] = &[
    ("D", "db", true),
    ("C", "global-config", true),
    ("c", "local-config", true),
    ("v", "verbosity", true),
    ("t", "threads", true),
    ("l", "logname", true),
    ("", "initial-sync-delay", true),
    ("", "celldb-cache-size", true),
    ("", "celldb-cache-min-size", true),
    ("", "json-rpc-address", true),
    ("", "exporter-address", true),
    ("", "session-logs", true),
    ("s", "state-ttl", true),
    ("b", "block-ttl", true),
    ("A", "archive-ttl", true),
    ("K", "key-proof-ttl", true),
    ("S", "sync-before", true),
    ("", "permanent-celldb", false),
    ("", "enable-validator-consensus-cleanup", false),
    ("", "disable-validator-consensus-cleanup", false),
    ("", "json-rpc-readonly", false),
    // Accepted for older units; a no-op on current engines and never a restore decision.
    ("", "json-rpc-without-wallet-index", false),
];
fn canonical_option(option: &str) -> Result<(&'static str, bool)> {
    for &(short, long, takes_value) in SAFE_OPTIONS {
        if option.strip_prefix("--") == Some(long)
            || (!short.is_empty() && option.strip_prefix('-') == Some(short))
        {
            return Ok((long, takes_value));
        }
    }
    anyhow::bail!(
        "unsupported service option {option:?}; use reviewed canonical options with separate values (no attached, clustered or equals forms)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_running_and_expected_modes_are_one_invariant() {
        for configured in [false, true] {
            for running in [None, Some(false), Some(true)] {
                for expected in [None, Some(false), Some(true)] {
                    assert_eq!(
                        check_mode(configured, running, expected).is_ok(),
                        running.is_none_or(|v| v == configured)
                            && expected.is_none_or(|v| v == configured)
                    );
                }
            }
        }
        // A flag-shaped value must not be interpreted as a storage-mode switch.
        let base = "{ argv[]=/engine --db /db --global-config /global --logname --permanent-celldb ; running }";
        assert!(
            !validate_exec(
                base,
                Path::new("/engine"),
                Path::new("/db"),
                Path::new("/global"),
                Path::new("/")
            )
            .unwrap()
        );
    }
    #[test]
    fn service_binding_requires_one_literal_matching_database_and_policy() {
        let check = |s| {
            validate_exec(
                s,
                Path::new("/engine"),
                Path::new("/private/db"),
                Path::new("/global.json"),
                Path::new("/private"),
            )
        };
        assert!(check("{ path=/engine ; argv[]=/engine -D /private/db -C /global.json -t 4 ; ignore_errors=no }").is_ok());
        for s in [
            "{ argv[]=/engine -D /other -C /global.json ; x }",
            "{ argv[]=/other -D /private/db -C /global.json ; x }",
            "{ argv[]=/engine -D /private/db -D /other -C /global.json ; x }",
            "{ argv[]=/engine -D /private/db -C /other ; x }",
            "{ argv[]=/engine -D /private/db -C /global.json --import /external ; x }",
            "{ argv[]=/engine -D $DATABASE -C /global.json ; x }",
            "{ argv[]=/engine -D /private/db -C /global.json -T 1 ; x }",
            "{ argv[]=/engine -D /private/db -C /global.json --unsafe-catchain-restore 1 ; x }",
            "{ argv[]=/engine -D /private/db -C /global.json --celldb-in-memory ; x }",
        ] {
            assert!(check(s).is_err(), "accepted {s}");
        }
    }
    #[test]
    fn attached_clustered_and_alias_selectors_cannot_bypass_binding() {
        let check = |extra: &str| {
            validate_exec(
                &format!("{{ argv[]=/engine -D /private/db -C /global.json {extra} ; x }}"),
                Path::new("/engine"),
                Path::new("/private/db"),
                Path::new("/global.json"),
                Path::new("/private"),
            )
        };
        for extra in [
            "-T1",
            "-D/other",
            "-C/other",
            "-c/other",
            "-MT1",
            "-MD/other",
            "-v3",
            "--db=/other",
            "--",
            "positional",
            "--unknown",
        ] {
            let error = check(extra).expect_err(extra).to_string();
            assert!(
                error.contains("unsupported service option"),
                "wrong refusal for {extra}: {error}"
            );
        }
        for extra in [
            "--db /private/db",
            "--global-config /global.json",
            "-c /private/db/config.json --local-config /private/db/config.json",
        ] {
            assert!(check(extra).is_err(), "duplicate effective selector accepted: {extra}");
        }
        assert!(check("--verbosity -1 --threads 4 --json-rpc-readonly").is_ok());
        assert!(
            check("--logname -T1").is_ok(),
            "a native option argument was reinterpreted as an option"
        );
    }
    #[test]
    fn service_subset_arity_matches_native_registrations() {
        let source = include_str!("../../../../../validator-engine/validator-engine.cpp");
        for &(_, long, takes_value) in SAFE_OPTIONS {
            let needle = format!("\"{long}\"");
            let registration =
                source.split("p.add_").find(|part| part.contains(&needle)).expect(long);
            let callback = registration
                .find("[&]")
                .or_else(|| registration.find("[]"))
                .expect("native callback");
            let tail = &registration[callback..];
            let parameters = tail.split_once(']').expect("lambda capture end").1;
            assert_eq!(
                parameters.starts_with("(td::Slice"),
                takes_value,
                "native arity changed: {long}"
            );
        }
    }
}

pub fn operation_lock(database: &Path) -> Result<File> {
    ensure!(
        database.is_absolute() && database.canonicalize()? == database,
        "operation root must be canonical"
    );
    let parent = crate::safe_io::Root::open(database.parent().context("database parent")?)?;
    let name = format!(
        ".node-sync-{}.lock",
        crate::model::sha256(database.as_os_str().as_encoded_bytes())
    );
    parent.lock(&name)
}

fn resolve_arg(work: &Path, value: &str) -> Result<PathBuf> {
    use std::path::Component;
    let path = if Path::new(value).is_absolute() { PathBuf::from(value) } else { work.join(value) };
    let mut output = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir => output.push("/"),
            Component::Normal(part) => output.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(output.pop(), "service path escapes root");
            }
            Component::Prefix(_) => anyhow::bail!("unsupported service path prefix"),
        }
    }
    Ok(output)
}

fn reported_state(output: &str) -> String {
    let mut load = None;
    let mut active = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("LoadState=")
            && load.replace(value).is_some()
        {
            return "unknown".to_owned();
        }
        if let Some(value) = line.strip_prefix("ActiveState=")
            && active.replace(value).is_some()
        {
            return "unknown".to_owned();
        }
    }
    match (load, active) {
        (
            Some("loaded"),
            Some(state @ ("active" | "inactive" | "failed" | "activating" | "deactivating")),
        ) => state.to_owned(),
        _ => "unknown".to_owned(),
    }
}
#[cfg(test)]
mod reported_state_tests {
    #[test]
    fn unloaded_units_are_unknown() {
        assert_eq!(super::reported_state("ActiveState=inactive\nLoadState=not-found\n"), "unknown");
        assert_eq!(super::reported_state("ActiveState=inactive\nLoadState=loaded\n"), "inactive");
        assert_eq!(super::reported_state("ActiveState=inactive\n"), "unknown");
    }
}
#[cfg(test)]
mod account_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const ROOT: Invoker<'static> = Invoker { uid: 0, gid: 0, name: "root\n" };
    fn system<'a>(user: &'a str, group: &'a str, dynamic: &'a str) -> UnitAccount<'a> {
        UnitAccount { user_manager: false, user, group, dynamic }
    }
    fn tos(name: &str) -> Result<Resolved> {
        ensure!(name == "tos", "unexpected account lookup {name}");
        Ok(Resolved { uid: 998, gid: 997, group: "tos".to_owned() })
    }
    fn me() -> (u32, u32) {
        // SAFETY: geteuid and getegid have no preconditions.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    /// The operator bundle's full-node unit, as `systemctl show` reports its command.
    const DEPLOYED: &str = "{ path=/usr/local/bin/validator-engine ; argv[]=/usr/local/bin/validator-engine -C /etc/tos/global-config.json -D /var/lib/tos/fullnode -l /var/log/tos/fullnode/node.log -t 16 --state-ttl 86400 --archive-ttl 604800 --celldb-cache-size 1073741824 --celldb-cache-min-size 1073741824 --json-rpc-address 127.0.0.1:8081 --exporter-address 127.0.0.1:9100 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
    fn deployed(command: &str) -> Result<bool> {
        validate_exec(
            command,
            Path::new("/usr/local/bin/validator-engine"),
            Path::new("/var/lib/tos/fullnode"),
            Path::new("/etc/tos/global-config.json"),
            Path::new("/var/lib/tos/fullnode"),
        )
    }

    #[test]
    fn deployed_full_node_command_is_accepted() -> Result<()> {
        assert!(!deployed(DEPLOYED)?, "deployed unit selects split cell storage");
        let missing = DEPLOYED.replace(" 127.0.0.1:9100 ;", " ;");
        let error = deployed(&missing).expect_err("exporter without a value").to_string();
        assert!(error.contains("requires a separate value"), "wrong refusal: {error}");
        let attached = DEPLOYED
            .replace("--exporter-address 127.0.0.1:9100", "--exporter-address=127.0.0.1:9100");
        let error = deployed(&attached).expect_err("attached exporter value").to_string();
        assert!(error.contains("unsupported service option"), "wrong refusal: {error}");
        // The option's value is never read as an option or a path selector.
        let flag_shaped = DEPLOYED.replace("127.0.0.1:9100", "--permanent-celldb");
        assert!(!deployed(&flag_shaped)?, "an exporter value switched the storage mode");
        Ok(())
    }

    #[test]
    fn deployed_service_account_is_selected_when_invoked_as_root() -> Result<()> {
        let account = select_account(&system("tos\n", "tos\n", "no\n"), &ROOT, tos)?;
        assert_eq!(account, Account { uid: 998, gid: 997, invoker: 0 });
        assert!(account.delegated());
        // Group= may be left to the account's primary group.
        assert_eq!(select_account(&system("tos", "", "no"), &ROOT, tos)?, account);
        Ok(())
    }

    #[test]
    fn unsafe_service_accounts_refuse() {
        let alice = Invoker { uid: 1000, gid: 1000, name: "alice" };
        for (label, unit, invoker, expected) in [
            ("User=root", system("root", "", "no"), &ROOT, "running as root"),
            ("system unit without User=", system("", "", "no"), &ROOT, "without User="),
            ("dynamic user", system("tos", "tos", "yes"), &ROOT, "dynamically allocated"),
            ("foreign group", system("tos", "adm", "no"), &ROOT, "primary group"),
            ("option-shaped name", system("-tos", "", "no"), &ROOT, "unsupported service User="),
            ("another user, not root", system("tos", "tos", "no"), &alice, "invoking user"),
            (
                "user manager naming a service account as root",
                UnitAccount { user_manager: true, user: "tos", group: "", dynamic: "" },
                &ROOT,
                "user-manager unit",
            ),
        ] {
            let error = select_account(&unit, invoker, tos).expect_err(label).to_string();
            assert!(error.contains(expected), "{label}: wrong refusal: {error}");
        }
        let resolves_to_root = |_: &str| Ok(Resolved { uid: 0, gid: 0, group: "root".to_owned() });
        let error = select_account(&system("toor", "", "no"), &ROOT, resolves_to_root)
            .expect_err("uid 0 alias")
            .to_string();
        assert!(error.contains("running as root"), "wrong refusal: {error}");
    }

    #[test]
    fn invoking_user_shapes_are_unchanged() -> Result<()> {
        let alice = Invoker { uid: 1000, gid: 1000, name: "alice\n" };
        let resolve = |_: &str| Ok(Resolved { uid: 1000, gid: 1000, group: "alice".to_owned() });
        let own = Account { uid: 1000, gid: 1000, invoker: 1000 };
        assert_eq!(select_account(&system("alice", "", "no"), &alice, resolve)?, own);
        let user = UnitAccount { user_manager: true, user: "", group: "", dynamic: "" };
        assert_eq!(select_account(&user, &alice, tos)?, own);
        assert!(!own.delegated());
        assert_eq!(select_account(&system("alice", "alice", "no"), &alice, resolve)?, own);
        Ok(())
    }

    #[test]
    fn invoking_user_system_unit_keeps_group_and_dynamic_user_checks() {
        let alice = Invoker { uid: 1000, gid: 1000, name: "alice" };
        let resolve = |_: &str| Ok(Resolved { uid: 1000, gid: 1000, group: "alice".to_owned() });
        for (label, unit, expected) in [
            ("foreign group", system("alice", "adm", "no"), "primary group"),
            ("dynamic user", system("alice", "", "yes"), "dynamically allocated"),
        ] {
            let error = select_account(&unit, &alice, resolve).expect_err(label).to_string();
            assert!(error.contains(expected), "{label}: wrong refusal: {error}");
        }
    }

    #[test]
    fn database_must_belong_to_the_service_account() -> Result<()> {
        let (uid, gid) = me();
        // Directly beneath the shared temporary directory, whose ancestors are root's.
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().canonicalize()?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o700))?;
        // The database owner is the service account and the invoker is someone else.
        let service = Account { uid, gid, invoker: uid.wrapping_add(1) };
        service.require_database(&database)?;
        Account { uid, gid, invoker: uid }.require_database(&database)?;
        let stranger = Account { uid: uid.wrapping_add(1), gid, invoker: 0 };
        let error = stranger.require_database(&database).expect_err("foreign database").to_string();
        assert!(error.contains("owned by the service account"), "wrong refusal: {error}");
        fs::set_permissions(&database, fs::Permissions::from_mode(0o770))?;
        assert!(service.require_database(&database).is_err(), "group-writable database accepted");
        Ok(())
    }

    #[test]
    fn operation_catalog_and_cache_roots_must_belong_to_the_invoker() -> Result<()> {
        let (uid, gid) = me();
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let catalog = temporary.path().canonicalize()?.join("catalog");
        fs::create_dir(&catalog)?;
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o700))?;
        // Invoked as this uid on behalf of another service account: accepted.
        let invoked_here = Account { uid: uid.wrapping_add(1), gid, invoker: uid };
        invoked_here.require_private(&catalog)?;
        Account { uid, gid, invoker: uid }.require_private(&catalog)?;
        // Invoked by another account for the service account that owns the catalog: refused.
        let owned_by_service = Account { uid, gid, invoker: uid.wrapping_add(1) };
        let error =
            owned_by_service.require_private(&catalog).expect_err("service catalog").to_string();
        assert!(error.contains("owned by the invoking user"), "wrong refusal: {error}");
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o750))?;
        invoked_here.require_private(&catalog)?;
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o770))?;
        assert!(invoked_here.require_private(&catalog).is_err(), "group-writable catalog accepted");
        // Without a service account, the invoker's own group layout is not constrained.
        Account { uid, gid, invoker: uid }.require_private(&catalog)?;
        Ok(())
    }

    #[test]
    fn delegated_paths_refuse_ancestors_another_account_can_rename() -> Result<()> {
        let (uid, gid) = me();
        let temporary = tempfile::tempdir()?;
        let open = temporary.path().canonicalize()?.join("open");
        let catalog = open.join("catalog");
        fs::create_dir_all(&catalog)?;
        for path in [temporary.path(), &open, &catalog] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let delegated = Account { uid: uid.wrapping_add(1), gid, invoker: uid };
        delegated.require_private(&catalog)?;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        let error = delegated.require_private(&catalog).expect_err("open ancestor").to_string();
        assert!(error.contains("writable by no other account"), "wrong refusal: {error}");
        // A sticky shared directory cannot be used to rename another account's entry.
        fs::set_permissions(&open, fs::Permissions::from_mode(0o1777))?;
        delegated.require_private(&catalog)?;
        // Without a service account the invoker's own layout is not constrained further.
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        Account { uid, gid, invoker: uid }.require_private(&catalog)?;
        Ok(())
    }

    #[test]
    fn budget_roots_belong_to_the_invoker_or_the_service_account() -> Result<()> {
        let (uid, gid) = me();
        let temporary = tempfile::tempdir()?;
        let roots = vec![temporary.path().canonicalize()?];
        Account { uid: uid.wrapping_add(1), gid, invoker: uid }.require_budget(&roots)?;
        Account { uid, gid, invoker: uid.wrapping_add(1) }.require_budget(&roots)?;
        let error = Account { uid: uid.wrapping_add(1), gid, invoker: uid.wrapping_add(2) }
            .require_budget(&roots)
            .expect_err("foreign budget root")
            .to_string();
        assert!(error.contains("belongs to another account"), "wrong refusal: {error}");
        Ok(())
    }
}
