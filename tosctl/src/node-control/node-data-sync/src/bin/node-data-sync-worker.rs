use anyhow::{Context, Result, ensure};
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(args.len() == 2, "usage: node-data-sync-worker PRIVATE_REQUEST.json");
    let request =
        node_data_sync::worker::worker_main(std::path::Path::new(args.get(1).context("request")?))?;
    node_data_sync::engine::validate_image(&request).await?;
    println!("NATIVE_GENERATION_VALIDATED");
    Ok(())
}
