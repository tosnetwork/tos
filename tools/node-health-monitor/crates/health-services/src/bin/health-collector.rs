#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: health-collector CONFIG_JSON".into());
    }
    let bytes = std::fs::read(&args[1])?;
    if bytes.len() > 16_384 {
        return Err("config too large".into());
    }
    let config = serde_json::from_slice(&bytes)?;
    tokio::select! {result=tos_health_services::collector::run(config)=>result.map_err(Into::into),_=tokio::signal::ctrl_c()=>Ok(())}
}
