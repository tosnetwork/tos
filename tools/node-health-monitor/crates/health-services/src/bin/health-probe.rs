#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: health-probe CONFIG_JSON".into());
    }
    if std::fs::metadata(&args[1])?.len() > 16384 {
        return Err("config too large".into());
    }
    let config = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    tokio::select! {r=tos_health_services::manager_poll::run(config)=>r.map_err(Into::into),_=tokio::signal::ctrl_c()=>Ok(())}
}
