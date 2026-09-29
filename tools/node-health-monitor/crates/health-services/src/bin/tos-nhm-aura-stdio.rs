//! Bounded AURA stdio-to-private-Unix-MCP transport adapter.
//! No query implementation, network socket, or model provider lives here.

use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Bytes, client::conn::http1, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    io::Read,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        },
    },
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

fn entry_stat(dir: &fs::File, name: &CString) -> Result<libc::stat, ()> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // The pathname is resolved relative to the already-open private directory.
    if unsafe {
        libc::fstatat(dir.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    } != 0
    {
        return Err(());
    }
    Ok(unsafe { stat.assume_init() })
}

fn remove_owned_entry(
    dir: &fs::File,
    name: &CString,
    uid: libc::uid_t,
    expected: Option<&libc::stat>,
) -> Result<(), ()> {
    let current = entry_stat(dir, name)?;
    let kind = current.st_mode & libc::S_IFMT;
    if current.st_uid != uid
        || (kind != libc::S_IFREG && kind != libc::S_IFLNK)
        || expected.is_some_and(|opened| {
            current.st_dev != opened.st_dev || current.st_ino != opened.st_ino
        })
    {
        return Err(());
    }
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(());
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<Credentials, ()> {
    let parent = path.parent().ok_or(())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| ())?;
    let uid = unsafe { libc::geteuid() };
    if !parent_meta.file_type().is_dir()
        || parent_meta.uid() != uid
        || parent_meta.mode() & 0o077 != 0
    {
        return Err(());
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| ())?;
    let opened_parent = dir.metadata().map_err(|_| ())?;
    if opened_parent.dev() != parent_meta.dev()
        || opened_parent.ino() != parent_meta.ino()
        || opened_parent.uid() != uid
        || opened_parent.mode() & 0o077 != 0
    {
        return Err(());
    }
    let name = CString::new(path.file_name().ok_or(())?.as_bytes()).map_err(|_| ())?;
    let entry = entry_stat(&dir, &name)?;
    if entry.st_uid != uid || entry.st_mode & libc::S_IFMT != libc::S_IFREG {
        // Only remove a same-owner symlink inside the verified private
        // directory. Never follow it or delete its target.
        if entry.st_uid == uid && entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let _ = remove_owned_entry(&dir, &name, uid, Some(&entry));
        }
        return Err(());
    }
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let _ = remove_owned_entry(&dir, &name, uid, Some(&entry));
        return Err(());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            let _ = remove_owned_entry(&dir, &name, uid, Some(&entry));
            return Err(());
        }
    };
    if !opened.is_file()
        || opened.uid() != uid
        || opened.dev() != entry.st_dev
        || opened.ino() != entry.st_ino
    {
        return Err(());
    }
    let links = opened.nlink();
    // Unlink before parsing or connecting: bad permissions, malformed JSON,
    // socket failure and normal completion all consume this one-use handoff.
    remove_owned_entry(&dir, &name, uid, Some(&entry))?;
    if opened.mode() & 0o177 != 0 || links != 1 {
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let metadata = fs::symlink_metadata(socket).map_err(|_| ())?;
    if !metadata.file_type().is_socket() {
        return Err(());
    }
    let (mut sender, connection) = tokio::time::timeout(Duration::from_secs(5), async {
        let stream = tokio::net::UnixStream::connect(socket).await.map_err(|_| ())?;
        http1::handshake(TokioIo::new(stream)).await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())??;
    let connection = tokio::spawn(async move { connection.await.map_err(|_| ()) });
    let result = tokio::time::timeout_at(deadline, async {
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
                    // rmcp requires both advertised types; the bounded
                    // response path below admits JSON only and refuses SSE.
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
                        if response
                            .headers()
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
                        {
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
    .await;
    drop(sender);
    connection.abort();
    // Do not return control while this connection task can still own an
    // in-flight request. The broker separately owns grant revoke/replacement.
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await.map_err(|_| ())?;
    result.map_err(|_| ())?
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
