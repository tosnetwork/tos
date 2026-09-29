#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(5..=7).contains(&args.len()) {
        return Err(
            "usage: health-edge NODE PID LOOPBACK_LISTEN TOKEN_FILE [NATIVE_LOOPBACK_ADDRESS [NETWORK_ID]]"
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
    let (diagnostic_stop,diagnostic_stopping)=tokio::sync::watch::channel(false);
    let diagnostic=match std::env::var("TOS_HEALTH_DIAGNOSTIC_CONFIG") {
        Ok(path)=>{
            let config=tos_health_services::diagnostic_relay::Config::read(std::path::Path::new(&path))?;
            if config.mapping.node_id!=args[1] || u32::try_from(config.mapping.native_pid).ok()!=Some(pid) {
                return Err("diagnostic mapping differs from approved edge process inventory".into());
            }
            let stats=state.diagnostic_stats.clone();
            Some(tokio::spawn(tos_health_services::diagnostic_relay::run(config,stats,diagnostic_stopping)))
        }
        Err(std::env::VarError::NotPresent)=>None,
        Err(error)=>return Err(error.into()),
    };
    match tos_health_services::edge::CgroupConfig::discover(pid) {
        Ok(cgroup) => state.configure_cgroup(cgroup)?,
        Err(reason) => state.record_cgroup_discovery_error(&reason)?,
    }
    let task = tokio::spawn(tos_health_services::edge::sample_loop(state.clone(), pid));
    let native = if let Some(address) = args.get(5) {
        let sampler = tos_health_services::native_cache::NativeSampler::new(
            tos_health_services::loopback(address)?,
            state.clone(),
        )?;
        let sampler = match args.get(6) {
            Some(network) => sampler.with_network(network.clone())?,
            None => sampler,
        };
        Some(tokio::spawn(sampler.run()))
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
    let _=diagnostic_stop.send(true);
    if let Some(mut task)=diagnostic {
        match tokio::time::timeout(std::time::Duration::from_secs(1),&mut task).await {
            Ok(Ok(Ok(())))=>{},
            Ok(Ok(Err(error)))=>eprintln!("diagnostic relay stopped: {error}"),
            Ok(Err(error))=>eprintln!("diagnostic relay task stopped: {error}"),
            Err(_)=>{task.abort();let _=task.await;},
        }
    }
    Ok(())
}
