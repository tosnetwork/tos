#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tos_health_services::manager::{Manager, ManagerConfig};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: health-state CONFIG_JSON".into());
    }
    let path = std::path::Path::new(&args[1]);
    if std::fs::metadata(path)?.len() > 262_144 {
        return Err("config too large".into());
    }
    let config: ManagerConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    let receiver =
        config.receiver.as_ref().map(tos_health_services::manager::prepare_receiver).transpose()?;
    let manager = Manager::start(&config)?;
    let listener =
        tokio::net::TcpListener::bind(tos_health_services::loopback(&config.listen)?).await?;
    let notify = config.receiver.zip(receiver).map(|(r, (client, token))| {
        tokio::spawn(tos_health_services::manager::notify_loop(manager.clone(), r, client, token))
    });
    let server = axum::serve(listener, tos_health_services::manager::router(manager))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });
    server.await?;
    if let Some(task) = notify {
        task.abort();
    }
    Ok(())
}
