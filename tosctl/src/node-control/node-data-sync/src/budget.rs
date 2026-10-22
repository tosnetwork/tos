use crate::safe_io::Root;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// One threshold: admission leaves it after consuming the entire reservation;
/// the monitor stops new work strictly below it. Equality is safe in both paths.
/// There is no separate, unused hard floor. This is a guard, not a disk quota.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskPolicy {
    pub max_owned_bytes: u64,
    /// None selects max(16 GiB, ceil(filesystem capacity / 20)).
    pub shutdown_free_bytes: Option<u64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Space {
    pub capacity: u64,
    pub free: u64,
}
impl DiskPolicy {
    pub fn threshold(&self, space: Space) -> Result<u64> {
        ensure!(
            self.max_owned_bytes > 0,
            "disk_policy.max_owned_bytes is required and must be non-zero"
        );
        ensure!(
            space.capacity > 0 && space.free <= space.capacity,
            "invalid filesystem capacity/free-space probe"
        );
        let percent = (space.capacity / 20)
            .checked_add(u64::from(!space.capacity.is_multiple_of(20)))
            .context("disk percentage overflow")?;
        let threshold = self.shutdown_free_bytes.unwrap_or((16_u64 << 30).max(percent));
        ensure!(
            threshold > 0 && threshold < space.capacity,
            "disk_policy.shutdown_free_bytes must be non-zero and below filesystem capacity"
        );
        ensure!(
            self.max_owned_bytes < space.capacity,
            "disk_policy.max_owned_bytes must be below filesystem capacity"
        );
        Ok(threshold)
    }
}
/// The fixed auxiliary allowance covers metadata, WAL and validation output.
/// Copy multiplicities are deliberately conservative, not assumed compression ratios.
pub fn reservation(raw: u64, compressed: u64, private: u64) -> Result<u64> {
    raw.checked_mul(3)
        .and_then(|n| n.checked_add(compressed))
        .and_then(|n| n.checked_add(private))
        .and_then(|n| n.checked_add(1 << 30))
        .context("task reservation overflow")
}
pub fn admit(policy: &DiskPolicy, existing: &[u64], reserve: u64, space: Space) -> Result<()> {
    let threshold = policy.threshold(space)?;
    let used = existing
        .iter()
        .try_fold(0_u64, |sum, size| sum.checked_add(*size).context("task size overflow"))?;
    let total = used.checked_add(reserve).context("task reservation overflow")?;
    ensure!(total <= policy.max_owned_bytes, "task reservation exceeds aggregate disk budget");
    let remaining =
        space.free.checked_sub(reserve).context("insufficient free disk for reservation")?;
    ensure!(remaining >= threshold, "reservation would cross shared free-space threshold");
    Ok(())
}
pub fn check_sample(policy: &DiskPolicy, owned_bytes: u64, space: Space) -> Result<()> {
    let threshold = policy.threshold(space)?;
    ensure!(owned_bytes <= policy.max_owned_bytes, "task allocation reached disk budget");
    ensure!(space.free >= threshold, "shared free space reached shutdown threshold");
    Ok(())
}
/// Probe errors propagate before admission and on every monitor sample.
pub fn check_probe(
    policy: &DiskPolicy,
    owned: u64,
    probe: impl FnOnce() -> Result<Space>,
) -> Result<()> {
    check_sample(policy, owned, probe()?)
}
static STOP_NEW_WORK: AtomicBool = AtomicBool::new(false);
/// Streaming and native-worker loops consult the same fail-closed stop signal.
pub fn check_active() -> Result<()> {
    ensure!(
        !STOP_NEW_WORK.load(Ordering::Acquire),
        "task disk monitor stopped new work; inspect allocation, free-space limits and operation deadline"
    );
    Ok(())
}
pub const OPERATION_SECONDS: u64 = 7200;
pub struct Monitor {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Monitor {
    pub fn start(
        roots: &[PathBuf],
        operation: &Root,
        reserve: u64,
        policy: &DiskPolicy,
    ) -> Result<Self> {
        ensure!(
            roots.iter().any(|root| operation.path.starts_with(root)),
            "operation is outside task allocation inventory"
        );
        let used = allocated(roots)?;
        admit(
            policy,
            &[used],
            reserve,
            operation.space().with_context(|| {
                format!("probe allocation free space at {}", operation.path.display())
            })?,
        )?;
        STOP_NEW_WORK.store(false, Ordering::Release);
        let roots = roots.to_vec();
        let probe = operation.path.clone();
        let policy = policy.clone();
        let started = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !child_stop.load(Ordering::Acquire) {
                let result = (|| -> Result<()> {
                    ensure!(
                        started.elapsed() < Duration::from_secs(OPERATION_SECONDS),
                        "operation reached two-hour work deadline"
                    );
                    check_probe(&policy, allocated(&roots)?, || {
                        let root = Root::open(&probe).with_context(|| {
                            format!("open allocation space probe {}", probe.display())
                        })?;
                        root.space().with_context(|| {
                            format!("probe allocation free space at {}", probe.display())
                        })
                    })
                })();
                if let Err(error) = result {
                    eprintln!("task allocation monitor: {error:#}");
                    STOP_NEW_WORK.store(true, Ordering::Release);
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Ok(Self { stop, thread: Some(thread) })
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            STOP_NEW_WORK.store(true, Ordering::Release);
            eprintln!("task allocation monitor panicked; no further work is safe");
        }
    }
}

/// Sample physical allocation while allowing listed descendants to disappear.
/// Required roots must retain their identity throughout the sample. This is not
/// an atomic snapshot: allocations created during a walk may enter the next one.
pub fn allocated(roots: &[PathBuf]) -> Result<u64> {
    AllocationWalk::default().sample(roots)
}
const MAX_ALLOCATION_ENTRIES: usize = 2_000_000;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum WalkStep {
    Metadata,
    OpenDirectory,
    ReadEntry,
}
#[cfg(test)]
type WalkHook = Box<dyn FnMut(&Path, WalkStep) -> std::io::Result<()>>;

#[derive(Default)]
struct AllocationWalk {
    seen: std::collections::BTreeSet<(u64, u64)>,
    count: usize,
    #[cfg(test)]
    hook: Option<WalkHook>,
    #[cfg(test)]
    entry_limit: Option<usize>,
}
impl AllocationWalk {
    #[cfg(test)]
    fn event(&mut self, path: &Path, step: WalkStep) -> std::io::Result<()> {
        match self.hook.as_mut() {
            Some(hook) => hook(path, step),
            None => Ok(()),
        }
    }
    fn metadata(&mut self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        #[cfg(test)]
        self.event(path, WalkStep::Metadata)?;
        path.symlink_metadata()
    }
    fn open_directory(&mut self, path: &Path) -> std::io::Result<std::fs::ReadDir> {
        #[cfg(test)]
        self.event(path, WalkStep::OpenDirectory)?;
        std::fs::read_dir(path)
    }
    fn listed_result<T>(
        result: std::io::Result<T>,
        required: bool,
        action: &str,
        path: &Path,
    ) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("{action} {}", path.display())),
        }
    }
    fn visit(&mut self, path: &Path, required: bool) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        // Count attempts before lookup, including entries removed by other writers.
        self.count = self.count.checked_add(1).context("allocation count overflow")?;
        let limit = MAX_ALLOCATION_ENTRIES;
        #[cfg(test)]
        let limit = self.entry_limit.unwrap_or(limit);
        ensure!(self.count <= limit, "task allocation inventory count limit at {}", path.display());
        let metadata = self.metadata(path);
        let Some(metadata) =
            Self::listed_result(metadata, required, "stat allocation entry", path)?
        else {
            return Ok(0);
        };
        if !self.seen.insert((metadata.dev(), metadata.ino())) {
            return Ok(0);
        }
        let mut bytes = metadata.blocks().checked_mul(512).context("allocation overflow")?;
        if metadata.file_type().is_dir() {
            let entries = self.open_directory(path);
            let Some(entries) =
                Self::listed_result(entries, required, "open allocation directory", path)?
            else {
                return Ok(0);
            };
            for entry in entries {
                #[cfg(test)]
                self.event(path, WalkStep::ReadEntry).with_context(|| {
                    format!("read allocation directory entry in {}", path.display())
                })?;
                // An iterator error does not identify a vanished child; do not hide it.
                let entry = entry.with_context(|| {
                    format!("read allocation directory entry in {}", path.display())
                })?;
                bytes = bytes
                    .checked_add(self.visit(&entry.path(), false)?)
                    .context("allocation overflow")?;
            }
        }
        Ok(bytes)
    }
    fn sample(&mut self, roots: &[PathBuf]) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        let mut identities = Vec::new();
        let mut bytes = 0_u64;
        for root in roots {
            let metadata = root
                .symlink_metadata()
                .with_context(|| format!("stat required allocation root {}", root.display()))?;
            identities.push((root, metadata.dev(), metadata.ino()));
            bytes =
                bytes.checked_add(self.visit(root, true)?).context("task allocation overflow")?;
        }
        // Recheck all roots, including roots visited before later roots changed.
        for (root, device, inode) in identities {
            let metadata = root
                .symlink_metadata()
                .with_context(|| format!("recheck required allocation root {}", root.display()))?;
            ensure!(
                (metadata.dev(), metadata.ino()) == (device, inode),
                "required allocation root replaced during sample: {}",
                root.display()
            );
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, os::unix::fs::MetadataExt};

    #[test]
    fn vanished_listed_children_are_zero_and_siblings_are_counted() -> Result<()> {
        for (directory, step) in [
            (false, WalkStep::Metadata),
            (true, WalkStep::Metadata),
            (true, WalkStep::OpenDirectory),
        ] {
            let root = tempfile::tempdir()?;
            let gone = root.path().join("vanishing");
            let kept = root.path().join("kept");
            std::fs::write(&kept, [7; 8192])?;
            if directory {
                std::fs::create_dir(&gone)?;
                std::fs::write(gone.join("WAL"), [1; 4096])?;
            } else {
                std::fs::write(&gone, [1; 4096])?;
            }
            let doomed = gone.clone();
            let mut walker = AllocationWalk {
                hook: Some(Box::new(move |path, event| {
                    if path == doomed && event == step {
                        if directory {
                            std::fs::remove_dir_all(path)?;
                        } else {
                            std::fs::remove_file(path)?;
                        }
                    }
                    Ok(())
                })),
                ..Default::default()
            };
            let bytes = walker
                .sample(&[root.path().to_path_buf()])
                .with_context(|| format!("listed child disappearance must succeed at {step:?}"))?;
            let expected = root
                .path()
                .symlink_metadata()?
                .blocks()
                .checked_add(kept.symlink_metadata()?.blocks())
                .and_then(|n| n.checked_mul(512))
                .context("test allocation overflow")?;
            assert_eq!(
                bytes, expected,
                "vanished subtree must contribute zero; sibling must remain"
            );
            assert_eq!(walker.count, 3, "vanished child must use an entry slot");
        }
        Ok(())
    }

    #[test]
    fn required_roots_cannot_disappear_or_be_replaced() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let missing = parent.path().join("missing");
        let error =
            allocated(std::slice::from_ref(&missing)).expect_err("missing root must refuse");
        assert!(
            format!("{error:#}")
                .contains(&format!("stat required allocation root {}", missing.display()))
        );
        for replace in [false, true] {
            let root = parent.path().join("root");
            std::fs::create_dir(&root)?;
            let old = parent.path().join("old");
            let selected = root.clone();
            let mut walker = AllocationWalk {
                hook: Some(Box::new(move |path, step| {
                    if path == selected && step == WalkStep::OpenDirectory {
                        std::fs::rename(path, &old)?;
                        if replace {
                            std::fs::create_dir(path)?;
                        }
                    }
                    Ok(())
                })),
                ..Default::default()
            };
            let error =
                walker.sample(std::slice::from_ref(&root)).expect_err("root change must refuse");
            let message = format!("{error:#}");
            assert!(message.contains(&root.display().to_string()), "{message}");
            assert!(
                message.contains(if replace {
                    "required allocation root replaced"
                } else {
                    "open allocation directory"
                }),
                "{message}"
            );
            if root.exists() {
                std::fs::remove_dir(&root)?;
            }
            std::fs::remove_dir_all(parent.path().join("old"))?;
        }
        Ok(())
    }

    #[test]
    fn root_disappearing_while_a_child_is_visited_is_fatal() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().join("root");
        std::fs::create_dir(&root)?;
        let child = root.join("child");
        std::fs::write(&child, [1; 4096])?;
        let selected = root.clone();
        let mut walker = AllocationWalk {
            hook: Some(Box::new(move |path, step| {
                if path == child && step == WalkStep::Metadata {
                    std::fs::remove_dir_all(&selected)?;
                }
                Ok(())
            })),
            ..Default::default()
        };
        let error = walker.sample(std::slice::from_ref(&root)).expect_err(
            "missing required root must refuse even when child disappearance is allowed",
        );
        assert!(
            format!("{error:#}")
                .contains(&format!("recheck required allocation root {}", root.display()))
        );
        Ok(())
    }

    #[test]
    fn allocation_errors_name_the_action_and_exact_path() -> Result<()> {
        for step in [WalkStep::Metadata, WalkStep::OpenDirectory, WalkStep::ReadEntry] {
            for kind in
                [io::ErrorKind::PermissionDenied, io::ErrorKind::Other, io::ErrorKind::NotFound]
            {
                let root = tempfile::tempdir()?;
                let child = root.path().join("db");
                std::fs::create_dir(&child)?;
                std::fs::write(child.join("kept"), [0; 4096])?;
                let selected = if kind == io::ErrorKind::NotFound && step != WalkStep::ReadEntry {
                    root.path().to_path_buf()
                } else {
                    child
                };
                let path = selected.clone();
                let mut walker = AllocationWalk {
                    hook: Some(Box::new(move |entry, event| {
                        if entry == selected && event == step {
                            return Err(io::Error::new(kind, "injected filesystem error"));
                        }
                        Ok(())
                    })),
                    ..Default::default()
                };
                let error = walker
                    .sample(&[root.path().to_path_buf()])
                    .expect_err("non-child-disappearance errors must refuse");
                let message = format!("{error:#}");
                let action = match step {
                    WalkStep::Metadata => "stat allocation entry",
                    WalkStep::OpenDirectory => "open allocation directory",
                    WalkStep::ReadEntry => "read allocation directory entry",
                };
                assert!(
                    message.contains(action)
                        && message.contains(&path.display().to_string())
                        && message.contains("injected filesystem error"),
                    "{message}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn vanished_children_still_exhaust_the_walk_limit() -> Result<()> {
        let root = tempfile::tempdir()?;
        for name in ["one", "two"] {
            std::fs::write(root.path().join(name), [1; 4096])?;
        }
        let parent = root.path().to_path_buf();
        let mut walker = AllocationWalk {
            entry_limit: Some(2),
            hook: Some(Box::new(move |path, step| {
                if step == WalkStep::Metadata && path != parent {
                    std::fs::remove_file(path)?;
                }
                Ok(())
            })),
            ..Default::default()
        };
        let error = walker
            .sample(&[root.path().to_path_buf()])
            .expect_err("vanished entries must not bypass the count bound");
        assert!(format!("{error:#}").contains("task allocation inventory count limit"));
        assert_eq!(walker.count, 3);
        Ok(())
    }

    #[test]
    fn allocation_deduplicates_hard_links_and_does_not_follow_symlinks() -> Result<()> {
        let root = tempfile::tempdir()?;
        let external = tempfile::tempdir()?;
        let file = root.path().join("file");
        std::fs::write(&file, [1; 8192])?;
        std::fs::hard_link(&file, root.path().join("linked"))?;
        let link = root.path().join("symlink");
        std::os::unix::fs::symlink(external.path(), &link)?;
        std::fs::write(external.path().join("outside"), [1; 8192])?;
        let expected = [root.path(), &file, &link]
            .iter()
            .try_fold(0_u64, |n, p| {
                n.checked_add(p.symlink_metadata()?.blocks()).context("test blocks overflow")
            })?
            .checked_mul(512)
            .context("test bytes overflow")?;
        assert_eq!(allocated(&[root.path().to_path_buf()])?, expected);
        Ok(())
    }
}
