use crate::{
    context::NodeContext,
    engine::{ValidationRequest, ValidationResult},
    model::{FullId, MANIFEST_LIMIT},
    safe_io::{Root, file_hash},
};
use anyhow::{Context, Result, ensure};
use std::{
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Run only the locally installed verifier in a separate network namespace.
pub fn validate(
    context: &NodeContext,
    image: &Root,
    operation: &Root,
    ancestors: Vec<FullId>,
    permanent_cells: bool,
) -> Result<ValidationResult> {
    let worker = context.validation_worker.canonicalize()?;
    ensure!(worker == context.validation_worker, "validation worker path is not canonical");
    let (_, actual) = file_hash(crate::context::read_file(&worker, 1 << 30)?, 1 << 30)?;
    ensure!(
        actual == context.validation_worker_sha256,
        "validation worker differs from independently held digest"
    );
    let request = ValidationRequest {
        engine: context.engine.clone(),
        image: image.path.clone(),
        global_config: context.global_config.clone(),
        output: operation.path.join("checked"),
        global_id: context.global_id,
        permanent_cells,
        required_ancestors: ancestors,
        parent_process: std::process::id(),
        parent_network_namespace: std::fs::metadata("/proc/self/ns/net")?.ino(),
    };
    operation.write_new("validation-request.json", &serde_json::to_vec(&request)?)?;
    let log = operation.create_file("worker.log")?;
    let child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(worker)
        .arg(operation.path.join("validation-request.json"))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .spawn()?;
    let mut owned = OwnedWorker(child);
    let child = &mut owned.0;
    let start = Instant::now();
    let result = loop {
        if let Some(status) = child.try_wait()? {
            break if status.success() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("native validation failed; inspect private worker.log"))
            };
        }
        if crate::budget::check_active().is_err()
            || start.elapsed() > Duration::from_secs(600)
            || log.metadata()?.len() > 32 << 20
        {
            child.kill()?;
            child.wait()?;
            break Err(anyhow::anyhow!("native validation worker deadline or output limit"));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    result?;
    let checked = Root::open(&request.output)?;
    let result: ValidationResult =
        serde_json::from_slice(&checked.bytes("validation.json", MANIFEST_LIMIT)?)?;
    ensure!(
        result.validation.engine_sha256 == context.engine_sha256,
        "validation engine changed after preflight"
    );
    Ok(result)
}

pub fn worker_main(path: &Path) -> Result<ValidationRequest> {
    serde_json::from_slice(&crate::context::read_bytes(path, MANIFEST_LIMIT)?)
        .context("native validation request")
}

struct OwnedWorker(std::process::Child);
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("cannot stop owned verifier: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("cannot reap owned verifier: {error}");
                }
            }
        }
    }
}
