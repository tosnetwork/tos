use axum::{body::Body, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tower::ServiceExt;

async fn serve_control(
    listener: tokio::net::UnixListener,
    app: Router,
    connections: Arc<tokio::sync::Semaphore>,
) -> Result<(), std::io::Error> {
    loop {
        let (stream, _) = listener.accept().await?;
        // Admission precedes the task spawn. The owned permit survives until
        // Hyper has finished this one non-keepalive connection, including
        // response transmission. Idle/header/body readers have a finite cap.
        let Ok(connection_permit) = connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let app = app.clone();
                async move { app.oneshot(request.map(Body::new)).await }
            });
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service),
            )
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
    let unix = serve_control(
        control,
        tos_health_services::observability::control_router(state),
        Arc::new(tokio::sync::Semaphore::new(8)),
    );
    tokio::select! {
        result = tcp => result?,
        result = unix => result?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn socket() -> (std::path::PathBuf, tokio::net::UnixListener) {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path =
            std::env::temp_dir().join(format!("nhm-control-{}-{nanos}.sock", std::process::id()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        (path, listener)
    }
    async fn wait_permits(limit: &tokio::sync::Semaphore, expected: usize, timeout: Duration) {
        tokio::time::timeout(timeout, async {
            while limit.available_permits() != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn eight_idle_control_connections_are_bounded_and_expire() {
        let (path, listener) = socket();
        let limit = Arc::new(tokio::sync::Semaphore::new(8));
        let app = Router::new().route("/ok", get(|| async { "ok" }));
        let task = tokio::spawn(serve_control(listener, app, limit.clone()));
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(tokio::net::UnixStream::connect(&path).await.unwrap());
        }
        wait_permits(&limit, 0, Duration::from_secs(2)).await;
        let mut ninth = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), ninth.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        wait_permits(&limit, 8, Duration::from_secs(6)).await;
        let mut accepted = tokio::net::UnixStream::connect(&path).await.unwrap();
        accepted.write_all(b"GET /ok HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), accepted.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        task.abort();
        drop(held);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn control_permit_covers_the_slow_request_until_connection_finishes() {
        let (path, listener) = socket();
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
        );
        let task = tokio::spawn(serve_control(listener, app, limit.clone()));
        let mut first = tokio::net::UnixStream::connect(&path).await.unwrap();
        first.write_all(b"GET /slow HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        wait_permits(&limit, 0, Duration::from_secs(2)).await;
        let mut second = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), second.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        wait_permits(&limit, 1, Duration::from_secs(2)).await;
        task.abort();
        std::fs::remove_file(path).unwrap();
    }
}
