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
/// Evidence-log bound: a run that returns more than this has left the
/// bounded six-tool budget behind, and the relay stops rather than drop lines.
const MAX_EVIDENCE_LOG: usize = 4 * 1024 * 1024;

/// One line per relayed `tools/call`, written for the orchestrator that must
/// bind a model's cited evidence to what the tools actually returned. It
/// carries ids and identity fields only: no token, no payload.
struct EvidenceLog {
    file: fs::File,
    written: usize,
}

impl EvidenceLog {
    fn record(&mut self, request: &Value, response: &Value) -> Result<(), ()> {
        use std::io::Write;
        let tool = request["params"]["name"].as_str().ok_or(())?;
        let result = &response["result"];
        let is_error = result["isError"].as_bool().unwrap_or(false);
        let envelope: Option<Value> =
            result["content"][0]["text"].as_str().and_then(|text| serde_json::from_str(text).ok());
        let envelope = envelope.unwrap_or(Value::Null);
        let evidence: Vec<Value> = if is_error {
            Vec::new()
        } else {
            envelope["evidence"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "evidence_id": item["evidence_id"],
                                "node_id": item["node_id"],
                                "source_id": item["source_id"],
                                "kind": item["kind"],
                                "content_hash": item["content_hash"],
                                "parent_evidence_ids": item["parent_evidence_ids"],
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        // Why a call failed and which argument names the model used (never
        // their values): enough to tell a model's misuse from an endpoint fault.
        let error_code = envelope["error"]["code"]
            .as_str()
            .map(|code| code.chars().take(96).collect::<String>());
        let error_message = envelope["error"]["message"]
            .as_str()
            .map(|message| message.chars().take(200).collect::<String>());
        let argument_keys: Vec<&str> = request["params"]["arguments"]
            .as_object()
            .map(|arguments| arguments.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let mut line = serde_json::to_vec(&serde_json::json!({
            "tool": tool,
            "request_id": envelope["request_id"],
            "status": envelope["status"],
            "error": is_error,
            "error_code": error_code,
            "error_message": error_message,
            "argument_keys": argument_keys,
            "evidence": evidence,
        }))
        .map_err(|_| ())?;
        line.push(b'\n');
        let total = self.written.checked_add(line.len()).ok_or(())?;
        if total > MAX_EVIDENCE_LOG {
            return Err(());
        }
        self.file.write_all(&line).map_err(|_| ())?;
        self.file.flush().map_err(|_| ())?;
        self.written = total;
        Ok(())
    }
}

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

/// Open the private parent directory of `path` without following links and
/// verify it belongs to this user with no group or other bits.
fn private_parent(path: &Path) -> Result<(fs::File, CString, libc::uid_t), ()> {
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
    Ok((dir, name, uid))
}

/// Create the evidence log inside a private directory, exclusively (a file
/// already there is refused, so a stale log is never taken for this run's),
/// mode 0600, no link following.
fn private_log(path: &Path) -> Result<EvidenceLog, ()> {
    let (dir, name, uid) = private_parent(path)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_APPEND
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let opened = file.metadata().map_err(|_| ())?;
    if !opened.is_file() || opened.uid() != uid || opened.mode() & 0o177 != 0 {
        return Err(());
    }
    Ok(EvidenceLog { file, written: 0 })
}

fn private_file(path: &Path) -> Result<Credentials, ()> {
    let (dir, name, uid) = private_parent(path)?;
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

/// Where a client frame goes. Only the MCP methods the private endpoint
/// serves are forwarded; a request for anything else (clients probe
/// `server/discover`, `resources/list`, `prompts/list` and the like) is
/// answered here with a JSON-RPC method-not-found so the session survives,
/// and such a notification is dropped. A frame that is not JSON-RPC 2.0 with
/// a method is still fatal.
enum Route {
    Forward { response_expected: bool },
    LocalError { id: Value, code: i64, message: &'static str },
    Drop,
}

fn route(request: &Value) -> Result<Route, ()> {
    let object = request.as_object().ok_or(())?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(());
    }
    let method = object.get("method").and_then(Value::as_str).ok_or(())?;
    let id = object.get("id").cloned();
    match method {
        "initialize"
        | "notifications/initialized"
        | "notifications/cancelled"
        | "ping"
        | "tools/list" => Ok(Route::Forward { response_expected: id.is_some() }),
        "tools/call" => {
            let name =
                object.get("params").and_then(|params| params.get("name")).and_then(Value::as_str);
            match (name, id) {
                (Some(name), Some(id)) if !TOOLS.contains(&name) => {
                    Ok(Route::LocalError { id, code: -32602, message: "unknown tool" })
                }
                (Some(_), id) => Ok(Route::Forward { response_expected: id.is_some() }),
                (None, Some(id)) => {
                    Ok(Route::LocalError { id, code: -32602, message: "tool name required" })
                }
                (None, None) => Ok(Route::Drop),
            }
        }
        _ => match id {
            Some(id) => Ok(Route::LocalError { id, code: -32601, message: "method not found" }),
            None => Ok(Route::Drop),
        },
    }
}

/// The protocol version carried to the private endpoint. A client asking for
/// a version this endpoint does not serve is offered the newest it does; the
/// client then accepts that version or disconnects, as the protocol says.
fn negotiated_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some("2025-03-26") => "2025-03-26",
        _ => "2025-06-18",
    }
}

const SERVED_VERSIONS: [&str; 2] = ["2025-03-26", "2025-06-18"];

async fn relay(
    socket: &Path,
    credentials: Credentials,
    mut evidence_log: Option<EvidenceLog>,
) -> Result<(), ()> {
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
    let mut connection = tokio::spawn(async move { connection.await.map_err(|_| ()) });
    let mut connection_ended = false;
    let result = tokio::select! {
        biased;
        // Detect a dead Unix transport even while AURA keeps stdin open.
        // No later frame may wait until the whole-run deadline or be retried.
        _ = &mut connection => {
            connection_ended = true;
            Err(())
        }
        result = tokio::time::timeout_at(deadline, async {
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
                let response_expected = match route(&rpc_request)? {
                    Route::Forward { response_expected } => response_expected,
                    Route::LocalError { id, code, message } => {
                        let reply = serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": code, "message": message}
                        });
                        let bytes = serde_json::to_vec(&reply).map_err(|_| ())?;
                        stdout.write_all(&bytes).await.map_err(|_| ())?;
                        stdout.write_all(b"\n").await.map_err(|_| ())?;
                        stdout.flush().await.map_err(|_| ())?;
                        line.clear();
                        continue;
                    }
                    Route::Drop => {
                        line.clear();
                        continue;
                    }
                };
                let mut rpc_request = rpc_request;
                if rpc_request["method"] == "initialize" {
                    if protocol.is_some() {
                        return Err(());
                    }
                    let negotiated =
                        negotiated_version(rpc_request["params"]["protocolVersion"].as_str());
                    // The endpoint refuses a version it does not serve; carry
                    // the negotiated one in the handshake body as well as the
                    // header, and relay the endpoint's answer unchanged so the
                    // client sees the version it will actually get.
                    if rpc_request["params"]["protocolVersion"] != negotiated {
                        rpc_request["params"]["protocolVersion"] =
                            Value::String(negotiated.to_owned());
                        line = serde_json::to_vec(&rpc_request).map_err(|_| ())?;
                    }
                    protocol = Some(negotiated);
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
                    if rpc_request["method"] == "initialize"
                        && std::env::var_os("NHM_AURA_TRACE_PROTOCOL").is_some()
                    {
                        let content_type = match response
                            .headers()
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                        {
                            Some(value) if value.eq_ignore_ascii_case("application/json") => "json",
                            Some(value) if value.eq_ignore_ascii_case("text/event-stream") => "sse",
                            Some(_) => "other",
                            None => "missing",
                        };
                        // Diagnostic categories only: no tokens, paths, IDs, or body bytes.
                        eprintln!(
                            "NHM_AURA_INIT version={version} status={} content_type={content_type}",
                            response.status().as_u16()
                        );
                    }
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
                        if rpc_request["method"] == "initialize" {
                            // The endpoint may answer with another version it
                            // serves; anything outside that set is refused.
                            let served = result["result"]["protocolVersion"]
                                .as_str()
                                .and_then(|value| {
                                    SERVED_VERSIONS.iter().find(|known| **known == value)
                                })
                                .copied()
                                .ok_or(())?;
                            protocol = Some(served);
                        }
                        if rpc_request["method"] == "tools/call" {
                            if let Some(log) = evidence_log.as_mut() {
                                log.record(&rpc_request, &result)?;
                            }
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
        }) => result.unwrap_or(Err(())),
    };
    drop(sender);
    if !connection_ended {
        connection.abort();
        // Do not return control while this connection task can still own an
        // in-flight request. Broker revoke/replacement is a separate gate.
        let _ =
            tokio::time::timeout(Duration::from_secs(5), &mut connection).await.map_err(|_| ())?;
    }
    result
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = if args.len() == 3 || args.len() == 4 {
        let socket = Path::new(&args[1]);
        let file = Path::new(&args[2]);
        // The optional fourth argument names an evidence log; it is created
        // before the one-use credential is consumed so a refused log never
        // costs the handoff.
        let log = match args.get(3) {
            Some(path) => private_log(Path::new(path)).map(Some),
            None => Ok(None),
        };
        match log {
            Ok(log) => match private_file(file) {
                Ok(credentials) => relay(socket, credentials, log).await,
                Err(()) => Err(()),
            },
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
