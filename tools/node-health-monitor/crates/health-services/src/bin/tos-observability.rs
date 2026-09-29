use axum::{body::Body, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{os::unix::fs::PermissionsExt, path::Path};
use tower::ServiceExt;

async fn serve_control(
    listener: tokio::net::UnixListener,
    app: Router,
) -> Result<(), std::io::Error> {
    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let app = app.clone();
                async move { app.oneshot(request.map(Body::new)).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(8..=9).contains(&args.len()) {
        return Err("usage: tos-observability INVENTORY_JSON LOOPBACK_LISTEN OPERATOR_TOKEN INGEST_TOKEN SERVICE_TOKEN PRIVATE_QUERY_LEDGER_DB PRIVATE_CONTROL_SOCKET [CACHE_JSONL]".into());
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
    )?
    .with_query_ledger(std::path::Path::new(&args[6]))?;
    if let Some(path) = args.get(8) {
        tos_health_services::observability::import_cache(&state, path.into())?;
    }
    let socket_path = Path::new(&args[7]);
    let parent = socket_path.parent().ok_or("control socket must have a private parent")?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || parent_meta.permissions().mode() & 0o077 != 0 {
        return Err("control socket parent must be a private directory".into());
    }
    let control = tokio::net::UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    let listener = tokio::net::TcpListener::bind(tos_health_services::loopback(&args[2])?).await?;
    let tcp = axum::serve(listener, tos_health_services::observability::router(state.clone()));
    let unix = serve_control(control, tos_health_services::observability::control_router(state));
    tokio::select! {
        result = tcp => result?,
        result = unix => result?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}
