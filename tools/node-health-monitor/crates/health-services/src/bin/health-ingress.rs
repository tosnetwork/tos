#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: health-ingress CONFIG_JSON".into());
    }
    if std::fs::metadata(&args[1])?.len() > 262_144 {
        return Err("config too large".into());
    }
    let config: tos_health_services::ingress::IngressConfig =
        serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tokio::select! {r=tos_health_services::ingress::serve(config,listener)=>r.map_err(Into::into),_=tokio::signal::ctrl_c()=>Ok(())}
}
