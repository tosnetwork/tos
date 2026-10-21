use crate::{
    model::{FREE_FLOOR, TASK_LIMIT},
    safe_io::Root,
};
use anyhow::{Context, Result, ensure};

/// Admission accounts for measured existing trees plus worst-case new allocation.
pub fn admit(existing: &[u64], reserve: u64, free: u64) -> Result<()> {
    let used = existing
        .iter()
        .try_fold(0_u64, |sum, size| sum.checked_add(*size).context("task size overflow"))?;
    let total = used.checked_add(reserve).context("task reservation overflow")?;
    ensure!(total <= TASK_LIMIT, "task reservation exceeds aggregate disk budget");
    let remaining = free.checked_sub(reserve).context("insufficient free disk for reservation")?;
    ensure!(remaining >= FREE_FLOOR, "reservation would cross shared free-space floor");
    Ok(())
}
pub fn check_during_work(root: &Root, owned_bytes: u64) -> Result<()> {
    ensure!(owned_bytes < 316 << 30, "task allocation reached shutdown headroom");
    ensure!(root.free_bytes()? >= 212 << 30, "shared free space reached shutdown headroom");
    Ok(())
}

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
static STOP_NEW_WORK: AtomicBool = AtomicBool::new(false);
/// Streaming and native-worker loops consult the same fail-closed stop signal.
pub fn check_active() -> Result<()> {
    ensure!(
        !STOP_NEW_WORK.load(Ordering::Acquire),
        "task disk monitor stopped new work; inspect allocation and free-space limits"
    );
    Ok(())
}
pub struct Monitor {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Monitor {
    pub fn start(roots: &[PathBuf], operation: &Root, reserve: u64) -> Result<Self> {
        ensure!(
            roots.iter().any(|root| operation.path.starts_with(root)),
            "operation is outside task allocation inventory"
        );
        let used = allocated(roots)?;
        admit(&[used], reserve, operation.free_bytes()?)?;
        check_during_work(operation, used)?;
        STOP_NEW_WORK.store(false, Ordering::Release);
        let roots = roots.to_vec();
        let probe = operation.path.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !child_stop.load(Ordering::Acquire) {
                let result = (|| -> Result<()> {
                    check_during_work(&Root::open(&probe)?, allocated(&roots)?)
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
