use anyhow::{Context, Result, ensure};
use node_data_sync::{
    capture::cold_image, engine::ValidationRequest, safe_io::Root, service::Frozen,
};
use std::{os::unix::fs::MetadataExt, path::Path, process::Command};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        args.len() == 5,
        "usage: capture_and_validate STOPPED_SOURCE PRIVATE_OPERATION ENGINE HELD_GLOBAL_CONFIG"
    );
    let source = Root::open(Path::new(&args[1]))?;
    let operation = Root::create(Path::new(&args[2]))?;
    let image = Root::create(&operation.path.join("image"))?;
    let started = std::time::Instant::now();
    let capture_started =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let frozen = Frozen::acquire(&source.path)?;
    let bytes = cold_image(&frozen, &source, &image)?;
    drop(frozen);
    operation.write_new(
        "capture.json",
        &serde_json::to_vec(&node_data_sync::model::CaptureReceipt {
            method: "cold_copy".to_owned(),
            started_utc: capture_started,
            finished_utc: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            copied_bytes: bytes,
            elapsed_millis: u64::try_from(started.elapsed().as_millis())?,
        })?,
    )?;
    let request = ValidationRequest {
        engine: Path::new(&args[3]).canonicalize()?,
        image: image.path.clone(),
        global_config: Path::new(&args[4]).canonicalize()?,
        output: operation.path.join("checked"),
        global_id: 3,
        permanent_cells: false,
        required_ancestors: vec![],
        parent_process: std::process::id(),
        parent_network_namespace: std::fs::metadata("/proc/self/ns/net")?.ino(),
    };
    operation.write_new("request.json", &serde_json::to_vec(&request)?)?;
    let worker =
        std::env::current_exe()?.parent().context("example parent")?.join("validate_image");
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(worker)
        .arg(operation.path.join("request.json"))
        .status()?;
    ensure!(status.success(), "native generation validation failed");
    let checked = Root::open(&request.output)?;
    let store = operation.path.join("catalog");
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let catalog = node_data_sync::catalog::Catalog::create(&store, key.verifying_key().to_bytes())?;
    let objects = node_data_sync::cas::Objects::open(&store)?;
    let signed = node_data_sync::generation::assemble(
        &image,
        &checked,
        &std::fs::read(&request.global_config)?,
        3,
        &objects,
        &key,
        &catalog,
    )?;
    let digest = catalog.publish(&signed, &objects)?;
    ensure!(catalog.list()?.len() == 1, "generation was not published");
    println!("NATIVE_COLD_GENERATION_VALIDATED copied_bytes={bytes} generation={digest}");
    Ok(())
}
