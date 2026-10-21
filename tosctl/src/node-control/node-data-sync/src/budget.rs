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
        admit(policy, &[used], reserve, operation.space()?)?;
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
                    check_probe(&policy, allocated(&roots)?, || Root::open(&probe)?.space())
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

pub fn allocated(roots: &[PathBuf]) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    fn visit(
        path: &Path,
        seen: &mut std::collections::BTreeSet<(u64, u64)>,
        count: &mut usize,
    ) -> Result<u64> {
        let metadata = path.symlink_metadata()?;
        *count = count.checked_add(1).context("allocation count overflow")?;
        ensure!(*count <= 2_000_000, "task allocation inventory count limit");
        if !seen.insert((metadata.dev(), metadata.ino())) {
            return Ok(0);
        }
        let mut bytes = metadata.blocks().checked_mul(512).context("allocation overflow")?;
        if metadata.file_type().is_dir() {
            for entry in std::fs::read_dir(path)? {
                bytes = bytes
                    .checked_add(visit(&entry?.path(), seen, count)?)
                    .context("allocation overflow")?;
            }
        }
        Ok(bytes)
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    roots.iter().try_fold(0_u64, |sum, root| {
        sum.checked_add(visit(root, &mut seen, &mut count)?).context("task allocation overflow")
    })
}
