#![cfg(feature = "mcp")]

use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use http_body_util::BodyExt;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager,
    tower::{StreamableHttpServerConfig, StreamableHttpService},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tos_health_services::{
    mcp_bridge::McpBridge,
    observability::{control_router, ObservabilityState},
    random_token, Inventory,
};
use tower::ServiceExt;

fn state() -> ObservabilityState {
    ObservabilityState::new(
        Inventory {
            network_id: "a".repeat(64),
            nodes: BTreeSet::from(["v1".into()]),
            scopes: BTreeSet::from(["node".into()]),
        },
        vec![b'o'; 32],
        vec![b'i'; 32],
        vec![b'a'; 32],
    )
    .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap()).unwrap()
}

#[tokio::test]
async fn six_sdk_tools_share_http_query_and_return_one_charged_representation() {
    let directory = std::env::temp_dir().join(format!(
        "nhm-mcp-{}-{}",
        std::process::id(),
        tos_health_services::hex(&random_token().unwrap())
    ));
    std::fs::create_dir(&directory).unwrap();
    let state = state().with_query_ledger(&directory.join("query.sqlite")).unwrap();
    let grant = control_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/control/grants")
                .header("authorization", format!("Bearer {}", "o".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"node_ids":["v1"],"scope_ids":["node"],
          "start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:01:00Z"})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(grant.status().is_success());
    let grant = json_body(grant).await;
    let run = grant["run_id"].as_str().unwrap();
    let token = grant["run_token"].as_str().unwrap();
    let service_auth = format!("Bearer {}", "a".repeat(32));
    assert!(McpBridge::admit(state.clone(), Some(&service_auth), run, &"0".repeat(64)).is_err());
    let bridge = McpBridge::admit(state.clone(), Some(&service_auth), run, token).unwrap();
    assert!(McpBridge::admit(state.clone(), Some(&service_auth), run, token).is_err());

    let mut config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(["localhost"])
        .enforce_origin_validation();
    config.legacy_session_mode = false;
    config.json_response = true;
    config.max_request_body_bytes = 16_384;
    let server = StreamableHttpService::new(
        move || Ok(bridge.clone()),
        LocalSessionManager::default().into(),
        config,
    );
    let invoke = |host: &str, origin: Option<&str>, id: u32, method: &str, params: Value| {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", host)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2025-06-18");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":id,
            "method":method,"params":params})
                .to_string(),
            ))
            .unwrap()
    };
    let initialized = server
        .clone()
        .oneshot(invoke(
            "localhost",
            None,
            1,
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},
               "clientInfo":{"name":"bounded-test","version":"1"}}),
        ))
        .await
        .unwrap();
    assert!(initialized.status().is_success(), "{}", initialized.status());
    let initialized: Value =
        serde_json::from_slice(&initialized.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");

    let listed = server
        .clone()
        .oneshot(invoke("localhost", None, 2, "tools/list", json!({})))
        .await
        .unwrap();
    assert!(listed.status().is_success(), "{}", listed.status());
    let listed: Value =
        serde_json::from_slice(&listed.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, tos_health_core::query::TOOLS);
    assert!(listed["result"]["tools"].as_array().unwrap().iter().all(|tool| !tool["inputSchema"]
        ["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|field| field == "run_token")));

    let called = server
        .clone()
        .oneshot(invoke(
            "localhost",
            None,
            3,
            "tools/call",
            json!({"name":"tos_get_capabilities","arguments":{"run_id":run}}),
        ))
        .await
        .unwrap();
    assert!(called.status().is_success(), "{}", called.status());
    let called: Value =
        serde_json::from_slice(&called.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(called["result"]["isError"], false, "{called}");
    assert!(called["result"].get("structuredContent").is_none());
    let text = called["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(serde_json::from_str::<Value>(text).unwrap()["data"]["query_mode"], "cache_only");

    let inputs = [
        (
            "tos_get_node_snapshot",
            json!({"run_id":run,"node_id":"v1",
          "as_of":"2026-09-01T00:00:30Z","max_age_seconds":30,"components":["process"]}),
        ),
        (
            "tos_get_metric_window",
            json!({"run_id":run,"node_ids":["v1"],
          "metric_ids":["rss_bytes"],"scope_id":"node","start":"2026-09-01T00:00:00Z",
          "end":"2026-09-01T00:00:30Z","step_seconds":15,"mode":"raw",
          "max_points_per_series":10}),
        ),
        (
            "tos_get_event_window",
            json!({"run_id":run,"node_ids":["v1"],
          "scope_id":"node","start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:00:30Z",
          "sources":["collector"],"kinds":["error"],"correlation_id":"","contains":"",
          "limit":10,"cursor":""}),
        ),
        (
            "tos_get_change_history",
            json!({"run_id":run,"node_ids":["v1"],
          "start":"2026-09-01T00:00:00Z","end":"2026-09-01T00:00:30Z","kinds":["restart"],
          "limit":10,"cursor":""}),
        ),
        (
            "tos_get_block_evidence",
            json!({"run_id":run,"node_ids":["v1"],
          "reference_id":"blk_0123456789abcdef","ancestor_depth":0,"max_events":10}),
        ),
    ];
    for (offset, (name, arguments)) in inputs.into_iter().enumerate() {
        let response = server
            .clone()
            .oneshot(invoke(
                "localhost",
                None,
                6 + offset as u32,
                "tools/call",
                json!({"name":name,"arguments":arguments}),
            ))
            .await
            .unwrap();
        assert!(response.status().is_success(), "{name}: {}", response.status());
        let output: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(output["result"].get("structuredContent").is_none(), "{name}: {output}");
        if let Some(text) = output["result"]["content"][0]["text"].as_str() {
            assert!(serde_json::from_str::<Value>(text).unwrap().get("status").is_some());
        } else {
            assert_eq!(output["result"]["isError"], true, "{name}: {output}");
        }
    }
    let wrong = server
        .clone()
        .oneshot(invoke(
            "localhost",
            None,
            11,
            "tools/call",
            json!({"name":"tos_get_capabilities","arguments":{
          "run_id":run,"run_token":"0".repeat(64)}}),
        ))
        .await
        .unwrap();
    let wrong: Value =
        serde_json::from_slice(&wrong.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(wrong.get("error").is_some() || wrong["result"]["isError"] == true, "{wrong}");
    assert!(!wrong.to_string().contains(token));

    let bad_host = server
        .clone()
        .oneshot(invoke("outside.invalid", None, 4, "tools/list", json!({})))
        .await
        .unwrap();
    assert!(!bad_host.status().is_success());
    let bad_origin = server
        .oneshot(invoke("localhost", Some("https://outside.invalid"), 5, "tools/list", json!({})))
        .await
        .unwrap();
    assert!(!bad_origin.status().is_success());
    drop(state);
    let mut reopened =
        tos_health_services::query_ledger::QueryLedger::open(&directory.join("query.sqlite"))
            .unwrap();
    assert!(reopened
        .claim_mcp(run, tos_health_services::query_ledger::boot_millis().unwrap())
        .is_err());
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}
