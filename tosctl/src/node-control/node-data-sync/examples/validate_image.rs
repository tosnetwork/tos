use anyhow::{Context, Result, ensure};
use node_data_sync::{
    engine::{ValidationRequest, validate_image},
    safe_io::Root,
};
#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().collect();
    ensure!(arguments.len() == 2, "usage: validate_image PRIVATE_REQUEST_JSON");
    let path = std::path::absolute(&arguments[1])?;
    let root = Root::open(path.parent().context("request parent")?)?;
    let bytes =
        root.bytes(path.file_name().and_then(|s| s.to_str()).context("request name")?, 1 << 20)?;
    let request: ValidationRequest = serde_json::from_slice(&bytes)?;
    let result = validate_image(&request).await?;
    println!("NATIVE_GENERATION_VALIDATED {}", result.validation.frontier.seqno);
    Ok(())
}
