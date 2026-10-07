/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Sandbox getter results rendered the way the node's `runGetMethodStd` serves them,
//! read back through the same envelope decoding the chain provider applies, and a
//! minimal JSON-RPC node that serves such answers over HTTP to the real client.

use tos_vm::stack::StackItem;

/// A sandbox stack item rendered as the node's `runGetMethodStd` serializer
/// (`serialize_stack_entry_std` in `validator-engine/json-rpc-server-runmethod.cpp`)
/// renders it: a tuple is tested before a list, so a TVM null, which only the list
/// test accepts, becomes an empty `tvm.stackEntryList`, and a cons cell stays a
/// two-element tuple. This mirrors that code and is no evidence of it on its own;
/// `tests/fixtures/get_proposal` and `tests/fixtures/list_proposals` hold the node's
/// real answers.
pub fn as_served(item: &StackItem) -> serde_json::Value {
    use base64::Engine;
    let b64 = |cell: &chain_block::Cell| {
        base64::engine::general_purpose::STANDARD
            .encode(chain_block::write_boc(cell).expect("a boc"))
    };
    if item.is_null() {
        return serde_json::json!({
            "@type": "tvm.stackEntryList",
            "list": {"@type": "tvm.list", "elements": []}
        });
    }
    if let Ok(int) = item.as_integer() {
        return serde_json::json!({
            "@type": "tvm.stackEntryNumber",
            "number": {"@type": "tvm.numberDecimal", "number": int.to_string()}
        });
    }
    if let Ok(items) = item.as_tuple() {
        return serde_json::json!({
            "@type": "tvm.stackEntryTuple",
            "tuple": {"@type": "tvm.tuple", "elements": items.iter().map(as_served).collect::<Vec<_>>()}
        });
    }
    if let Ok(cell) = item.as_cell() {
        return serde_json::json!({
            "@type": "tvm.stackEntryCell",
            "cell": {"@type": "tvm.cell", "bytes": b64(cell)}
        });
    }
    panic!("the getter returned an item this test does not render: {item:?}");
}

/// A whole `runGetMethodStd` response carrying `stack` (top of stack last, as the
/// sandbox returns it), as the node writes it: top of stack first.
// Not every test binary that includes this module calls every helper.
#[allow(dead_code)]
pub fn served_response(stack: &[StackItem]) -> String {
    let served: Vec<serde_json::Value> = stack.iter().rev().map(as_served).collect();
    serde_json::json!({
        "ok": true,
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "@type": "smc.runResult",
            "gas_used": 0,
            "stack": served,
            "exit_code": 0,
            "last_transaction_id": null,
            "block_id": null
        }
    })
    .to_string()
}

/// A `runGetMethodStd` response read back as the chain provider reads it.
// Not every test binary that includes this module calls every helper.
#[allow(dead_code)]
pub fn read_response(response: &str) -> common::tvm_stack_parser::TvmStackParser {
    let value: serde_json::Value = serde_json::from_str(response).expect("a JSON response");
    let result: chain_rpc_client::v2::data_models::RunGetMethodRes =
        serde_json::from_value(value["result"].clone()).expect("a run result");
    contracts::chain_provider::stack_from_rpc(result.stack)
}

/// The block every answer of a [`ServedNode`] is read at.
// Not every test binary that includes this module calls every helper.
#[allow(dead_code)]
pub fn block_json(seqno: u32) -> serde_json::Value {
    use base64::Engine;
    let hash = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    serde_json::json!({
        "@type": "tos.blockIdExt",
        "workchain": -1,
        "shard": "-9223372036854775808",
        "seqno": seqno,
        "root_hash": hash(0x11),
        "file_hash": hash(0x22)
    })
}

/// A `runGetMethodStd` result object carrying `stack` (top of stack last, as the
/// sandbox returns it), read at `block`.
#[allow(dead_code)]
pub fn run_result(stack: &[StackItem], block: serde_json::Value) -> serde_json::Value {
    run_result_with_exit(stack, 0, block)
}

/// A `runGetMethodStd` result object with the getter's exit code.
#[allow(dead_code)]
pub fn run_result_with_exit(
    stack: &[StackItem],
    exit_code: i32,
    block: serde_json::Value,
) -> serde_json::Value {
    let served: Vec<serde_json::Value> = stack.iter().rev().map(as_served).collect();
    serde_json::json!({
        "@type": "smc.runResult",
        "gas_used": 0,
        "stack": served,
        "exit_code": exit_code,
        "last_transaction_id": null,
        "block_id": block
    })
}

/// A `getAddressInformation` result for an active account.
#[allow(dead_code)]
pub fn account_result(code: &[u8], data: &[u8], block: serde_json::Value) -> serde_json::Value {
    use base64::Engine;
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    serde_json::json!({
        "@type": "raw.fullAccountState",
        "balance": "1000000000",
        "code": b64(code),
        "data": b64(data),
        "last_transaction_id": {"@type": "internal.transactionId", "lt": "0", "hash": b64(&[0u8; 32])},
        "block_id": block,
        "sync_utime": 0,
        "state": "active",
        "frozen_hash": ""
    })
}

/// One HTTP answer: the status and the body, where `"@@ID@@"` (quoted) stands for
/// the request's own id.
#[allow(dead_code)]
#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    /// Sent with `transfer-encoding: chunked` instead of a declared length.
    pub chunked: bool,
}

#[allow(dead_code)]
impl Reply {
    /// A successful envelope around `result`.
    pub fn ok(result: serde_json::Value) -> Self {
        let body =
            serde_json::json!({"ok": true, "jsonrpc": "2.0", "id": "@@ID@@", "result": result})
                .to_string();
        Self { status: 200, body, chunked: false }
    }

    /// A body sent exactly as given (with the id placeholder substituted).
    pub fn raw(status: u16, body: impl Into<String>) -> Self {
        Self { status, body: body.into(), chunked: false }
    }

    /// The same reply without a declared length.
    pub fn chunked(self) -> Self {
        Self { chunked: true, ..self }
    }
}

type Handler = dyn Fn(&str, &serde_json::Value) -> Reply + Send + Sync;

/// A JSON-RPC node on a loopback port, answering each request with `handler`.
/// Every method it was asked for is recorded, in order.
#[allow(dead_code)]
pub struct ServedNode {
    pub url: String,
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Every request as received, in order.
    pub requests: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    task: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)]
impl ServedNode {
    pub async fn start(
        handler: impl Fn(&str, &serde_json::Value) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler: std::sync::Arc<Handler> = std::sync::Arc::new(handler);
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = calls.clone();
        let request_log = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                let handler = handler.clone();
                let log = log.clone();
                let request_log = request_log.clone();
                tokio::spawn(async move {
                    let _ = serve_one(socket, handler, log, request_log).await;
                });
            }
        });
        Self { url, calls, requests, task }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    /// The requests for `method`, as received.
    pub fn requests_for(&self, method: &str) -> Vec<serde_json::Value> {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|request| request["method"] == method)
            .cloned()
            .collect()
    }
}

impl Drop for ServedNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_one(
    mut socket: tokio::net::TcpStream,
    handler: std::sync::Arc<Handler>,
    log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    request_log: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    let body = loop {
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:").map(|v| v.trim().to_string()))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if request.len() >= end + 4 + length {
            break request[end + 4..end + 4 + length].to_vec();
        }
    };
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let method = request["method"].as_str().unwrap_or_default().to_string();
    log.lock().expect("log").push(method.clone());
    request_log.lock().expect("request log").push(request.clone());
    // A handler may block (to model a slow node); keep it off the runtime's workers.
    let params = request["params"].clone();
    let called = method.clone();
    let reply = tokio::task::spawn_blocking(move || handler(&called, &params))
        .await
        .map_err(std::io::Error::other)?;
    let id = request["id"].to_string();
    let body = reply.body.replace("\"@@ID@@\"", &id);
    if reply.chunked {
        let head = format!(
            "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            reply.status
        );
        socket.write_all(head.as_bytes()).await?;
        for chunk in body.as_bytes().chunks(64 << 10) {
            socket.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await?;
            socket.write_all(chunk).await?;
            socket.write_all(b"\r\n").await?;
        }
        socket.write_all(b"0\r\n\r\n").await?;
        return socket.shutdown().await;
    }
    let head = format!(
        "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.status,
        body.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(body.as_bytes()).await?;
    socket.shutdown().await
}

/// The masterchain head every [`ServedNode`] answer is pinned to.
#[allow(dead_code)]
pub fn masterchain_info(seqno: u32) -> Reply {
    Reply::ok(serde_json::json!({
        "@type": "blocks.masterchainInfo",
        "last": block_json(seqno),
        "state_root_hash": "",
        "init": block_json(1)
    }))
}

/// A test hook a handler blocks on until the test opens it, in place of a sleep.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct Gate(std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

#[allow(dead_code)]
impl Gate {
    /// Blocks the calling thread (a handler, off the runtime) until opened.
    pub fn wait(&self) {
        let (open, signal) = &*self.0;
        let mut opened = open.lock().expect("gate");
        while !*opened {
            opened = signal.wait(opened).expect("gate");
        }
    }

    pub fn open(&self) {
        let (open, signal) = &*self.0;
        *open.lock().expect("gate") = true;
        signal.notify_all();
    }
}
