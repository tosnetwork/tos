#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(6..=7).contains(&args.len()) {
        return Err("usage: tos-observability INVENTORY_JSON LOOPBACK_LISTEN OPERATOR_TOKEN INGEST_TOKEN SERVICE_TOKEN [CACHE_JSONL]".into());
    }
    let raw = std::fs::read(&args[1])?;
    if raw.len() > 262_144 {
        return Err("inventory too large".into());
    }
    let inventory = serde_json::from_slice(&raw)?;
    let state = tos_health_services::observability::ObservabilityState::new(
        inventory,
        tos_health_services::secret(std::path::Path::new(&args[3]))?,
        tos_health_services::secret(std::path::Path::new(&args[4]))?,
        tos_health_services::secret(std::path::Path::new(&args[5]))?,
    )?;
    if let Some(path) = args.get(6) {
        tos_health_services::observability::import_cache(&state, path.into())?;
    }
    let listener = tokio::net::TcpListener::bind(tos_health_services::loopback(&args[2])?).await?;
    axum::serve(listener, tos_health_services::observability::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
