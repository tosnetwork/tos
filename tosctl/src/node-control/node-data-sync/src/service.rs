use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
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
    pub user_manager: bool,
}
pub struct Frozen {
    _configuration_lock: File,
    pub(crate) root: PathBuf,
}
impl Frozen {
    /// Offline primitive shared by explicit service operations and disposable native fixtures.
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure!(
            root.is_absolute() && fs::canonicalize(root)? == root,
            "stopped root must be canonical"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join("config.json.lock"))?;
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
    pub fn permanent_cells(&self) -> Result<bool> {
        let exec = command(
            self.manager().args(["show", "--property=ExecStart", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        Ok(exec.split_whitespace().any(|word| word == "--permanent-celldb"))
    }
    pub fn validate(&self) -> Result<()> {
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
        let user = command(
            self.manager().args(["show", "--property=User", "--value", "--", &self.unit]),
            Duration::from_secs(10),
        )?;
        let own_user = command(Command::new("id").arg("-un"), Duration::from_secs(10))?;
        ensure!(
            (self.user_manager && user.trim().is_empty())
                || (user.trim() == own_user.trim() && !user.trim().is_empty()),
            "service must run as the invoking user"
        );
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
        validate_exec(
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
            validate_exec(
                &format!("{{ argv[]={} ; running }}", arguments.join(" ")),
                &self.engine,
                &self.database,
                &self.global_config,
                &self.working_directory,
            )?;
        }
        Ok(())
    }
    pub fn stop(&self) -> Result<Frozen> {
        self.validate()?;
        command(self.manager().args(["stop", "--", &self.unit]), Duration::from_secs(120))?;
        self.freeze()
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
        self.validate()?;
        let held = frozen._configuration_lock.metadata()?;
        let selected = fs::symlink_metadata(self.database.join("config.json.lock"))?;
        ensure!(
            selected.file_type().is_file()
                && held.ino() == selected.ino()
                && held.dev() == selected.dev(),
            "start lock belongs to another installed tree"
        );
        drop(frozen);
        command(self.manager().args(["start", "--", &self.unit]), Duration::from_secs(120))?;
        Ok(())
    }
}
fn command(command: &mut Command, budget: Duration) -> Result<String> {
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
fn refuse_writers(root: &Path) -> Result<()> {
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
) -> Result<()> {
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
    let mut index = 1;
    while let Some(option) = tokens.get(index) {
        let (canonical, takes_value) = canonical_option(option)?;
        index += 1;
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
    Ok(())
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
            let callback = registration.find("[&]").expect("native callback");
            let tail = &registration[callback..];
            assert_eq!(
                tail.starts_with("[&](td::Slice"),
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
