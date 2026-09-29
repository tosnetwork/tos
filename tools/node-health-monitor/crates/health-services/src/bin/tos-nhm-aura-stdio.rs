//! Bounded AURA stdio-to-private-Unix-MCP transport adapter.
//! No query implementation, network socket, or model provider lives here.

use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Bytes, client::conn::http1, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tos_health_core::query::TOOLS;

const MAX_INPUT: usize = 16_384;
const MAX_OUTPUT: usize = 32_768;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    run_id: String,
    run_token: String,
    service_token: String,
}

fn private_file(path: &Path) -> Result<Credentials, ()> {
    let parent = path.parent().ok_or(())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ())?;
    let file_meta = fs::symlink_metadata(path).map_err(|_| ())?;
    let uid = unsafe { libc::geteuid() };
    if !parent_meta.file_type().is_dir()
        || !file_meta.file_type().is_file()
        || parent_meta.uid() != uid
        || file_meta.uid() != uid
        || parent_meta.mode() & 0o077 != 0
        || file_meta.mode() & 0o177 != 0
    {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if !opened.is_file() || opened.uid() != uid || opened.mode() & 0o177 != 0 {
        return Err(());
    }
    let mut file = file.take(1025);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() > 1024 {
        return Err(());
    }
    let credentials: Credentials = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if credentials.run_id.len() != 36
        || tos_health_services::decode_token(&credentials.run_token).is_none()
        || credentials.service_token.len() < 32
        || credentials.service_token.len() > 128
        || !credentials.service_token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(());
    }
    Ok(credentials)
}

fn allowed(request: &Value) -> Result<bool, ()> {
    let object = request.as_object().ok_or(())?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(());
    }
    let method = object.get("method").and_then(Value::as_str).ok_or(())?;
    match method {
        "initialize"
        | "notifications/initialized"
        | "notifications/cancelled"
        | "ping"
        | "tools/list" => {}
        "tools/call" => {
            let name = object
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .ok_or(())?;
            if !TOOLS.contains(&name) {
                return Err(());
            }
        }
        _ => return Err(()),
    }
    Ok(object.contains_key("id"))
}

async fn relay(socket: &Path, credentials: Credentials) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(socket).map_err(|_| ())?;
    if !metadata.file_type().is_socket() {
        return Err(());
    }
    let stream = tokio::net::UnixStream::connect(socket).await.map_err(|_| ())?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.map_err(|_| ())?;
    let connection = tokio::spawn(async move { connection.await.map_err(|_| ()) });
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut chunk = [0u8; 1024];
        let mut line = Vec::with_capacity(MAX_INPUT);
        let mut session: Option<String> = None;
        let mut protocol: Option<&'static str> = None;
        loop {
            let read = stdin.read(&mut chunk).await.map_err(|_| ())?;
            if read == 0 {
                return if line.is_empty() { Ok(()) } else { Err(()) };
            }
            for &byte in &chunk[..read] {
                if byte != b'\n' {
                    if line.len() >= MAX_INPUT {
                        return Err(());
                    }
                    line.push(byte);
                    continue;
                }
                let rpc_request: Value = serde_json::from_slice(&line).map_err(|_| ())?;
                let response_expected = allowed(&rpc_request)?;
                if rpc_request["method"] == "initialize" {
                    if protocol.is_some() {
                        return Err(());
                    }
                    protocol = Some(match rpc_request["params"]["protocolVersion"].as_str() {
                        Some("2025-03-26") => "2025-03-26",
                        Some("2025-06-18") => "2025-06-18",
                        _ => return Err(()),
                    });
                }
                let version = protocol.ok_or(())?;
                let mut builder = Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "localhost")
                    .header("authorization", format!("Bearer {}", credentials.service_token))
                    .header("x-tos-run-id", &credentials.run_id)
                    .header("x-tos-run-token", &credentials.run_token)
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .header("mcp-protocol-version", version);
                if let Some(value) = session.as_ref() {
                    builder = builder.header("mcp-session-id", value);
                }
                let request =
                    builder.body(Full::new(Bytes::copy_from_slice(&line))).map_err(|_| ())?;
                tokio::time::timeout(Duration::from_secs(5), async {
                    let response = sender.send_request(request).await.map_err(|_| ())?;
                    if !response.status().is_success() {
                        return Err(());
                    }
                    if let Some(value) = response.headers().get("mcp-session-id") {
                        let value = value.to_str().map_err(|_| ())?;
                        if value.is_empty()
                            || value.len() > 128
                            || !value.bytes().all(|byte| byte.is_ascii_graphic())
                        {
                            return Err(());
                        }
                        session = Some(value.to_owned());
                    }
                    if response_expected {
                        if response.status() != StatusCode::OK {
                            return Err(());
                        }
                        let bytes = Limited::new(response.into_body(), MAX_OUTPUT)
                            .collect()
                            .await
                            .map_err(|_| ())?
                            .to_bytes();
                        let result: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
                        if rpc_request["method"] == "initialize"
                            && result["result"]["protocolVersion"] != version
                        {
                            return Err(());
                        }
                        stdout.write_all(&bytes).await.map_err(|_| ())?;
                        stdout.write_all(b"\n").await.map_err(|_| ())?;
                        stdout.flush().await.map_err(|_| ())?;
                    } else {
                        // Notifications have no JSON-RPC response on stdio.
                        let _ = Limited::new(response.into_body(), MAX_OUTPUT)
                            .collect()
                            .await
                            .map_err(|_| ())?;
                    }
                    Ok::<(), ()>(())
                })
                .await
                .map_err(|_| ())??;
                line.clear();
            }
        }
    })
    .await
    .map_err(|_| ())?;
    drop(sender);
    connection.abort();
    result
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = if args.len() == 3 {
        let socket = Path::new(&args[1]);
        let file = Path::new(&args[2]);
        match private_file(file) {
            Ok(credentials) => relay(socket, credentials).await,
            Err(()) => Err(()),
        }
    } else {
        Err(())
    };
    if result.is_err() {
        // Never echo credentials, request frames, or a path containing a run ID.
        eprintln!("NHM AURA stdio transport refused");
        std::process::exit(1);
    }
}
