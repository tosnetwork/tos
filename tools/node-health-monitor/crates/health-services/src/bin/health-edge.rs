#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(5..=6).contains(&args.len()) {
        return Err(
            "usage: health-edge NODE PID LOOPBACK_LISTEN TOKEN_FILE [NATIVE_LOOPBACK_ADDRESS]"
                .into(),
        );
    }
    if !tos_health_services::alias(&args[1]) {
        return Err("invalid node alias".into());
    }
    let pid = args[2].parse::<u32>()?;
    let addr = tos_health_services::loopback(&args[3])?;
    let token = tos_health_services::secret(std::path::Path::new(&args[4]))?;
    let state = tos_health_services::edge::EdgeState::new(args[1].clone(), token);
    let task = tokio::spawn(tos_health_services::edge::sample_loop(state.clone(), pid));
    let native = if let Some(address) = args.get(5) {
        Some(tokio::spawn(
            tos_health_services::native_cache::NativeSampler::new(
                tos_health_services::loopback(address)?,
                state.clone(),
            )?
            .run(),
        ))
    } else {
        None
    };
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, tos_health_services::edge::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    task.abort();
    if let Some(task) = native {
        task.abort();
    }
    Ok(())
}
