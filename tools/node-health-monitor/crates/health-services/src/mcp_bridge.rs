//! Feature-gated MCP facade over the one durable HTTP query handler.
//! The facade owns no evidence store, refresh path, or alternate budget ledger.

use crate::observability::{router, ObservabilityState};
use axum::{
    body::{to_bytes, Body, Bytes},
    http::Request,
    response::Response,
};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
    },
    service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};
use serde_json::Value;
use std::{borrow::Cow, future::Future, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tos_health_core::query::TOOLS;
use tower::ServiceExt;

const INPUT_SCHEMAS: [&str; 6] = [
    include_str!("../../../contracts/tools/tos_get_capabilities.input.schema.json"),
    include_str!("../../../contracts/tools/tos_get_node_snapshot.input.schema.json"),
    include_str!("../../../contracts/tools/tos_get_metric_window.input.schema.json"),
    include_str!("../../../contracts/tools/tos_get_event_window.input.schema.json"),
    include_str!("../../../contracts/tools/tos_get_change_history.input.schema.json"),
    include_str!("../../../contracts/tools/tos_get_block_evidence.input.schema.json"),
];
const ROUTES: [&str; 6] = [
    "capabilities",
    "node-snapshot",
    "metric-window",
    "event-window",
    "change-history",
    "block-evidence",
];

/// The five-second tool deadline covers the entire route and body drain.
/// Timing only `oneshot` would allow a delayed response body to outlive it.
async fn bounded_query_response<F, E>(
    request: F,
    deadline: Duration,
) -> Result<(bool, Bytes), McpError>
where
    F: Future<Output = Result<Response, E>>,
{
    tokio::time::timeout(deadline, async {
        let response =
            request.await.map_err(|_| McpError::internal_error("query route unavailable", None))?;
        let error = !response.status().is_success();
        let bytes = to_bytes(response.into_body(), 32_768)
            .await
            .map_err(|_| McpError::internal_error("query response exceeded 32 KiB", None))?;
        Ok((error, bytes))
    })
    .await
    .map_err(|_| McpError::internal_error("query deadline exceeded", None))?
}

#[derive(Clone)]
pub struct McpBridge {
    state: ObservabilityState,
    bound_run: String,
    bound_token: [u8; 32],
    // Shared by SDK service clones for one admitted run. The permit spans the
    // actual HTTP handler and body read, and is released if the call is
    // cancelled. It does not claim to bound a future AURA model subprocess.
    child_slots: Arc<Semaphore>,
}

impl McpBridge {
    /// A durable, single-use transport admission. The caller must keep this
    /// bridge connection-owned; a second connection cannot claim the grant.
    /// Neither secret is a tool parameter, schema property, or result.
    pub fn admit(
        state: ObservabilityState,
        service_authorization: Option<&str>,
        run_id: &str,
        token_text: &str,
    ) -> Result<Self, &'static str> {
        let refused = "MCP admission refused";
        if !crate::authorized(service_authorization, &state.service_token) {
            return Err(refused);
        }
        let token = crate::decode_token(token_text).ok_or(refused)?;
        let now = crate::query_ledger::boot_millis().map_err(|_| refused)?;
        let data = state.data.lock().map_err(|_| refused)?;
        if data.manager_conflicted {
            return Err(refused);
        }
        let grant = data.grants.get(run_id).ok_or(refused)?;
        grant.authenticate("aura", &token, now).map_err(|_| refused)?;
        let ledger = state.query_ledger.as_ref().ok_or(refused)?;
        ledger.lock().map_err(|_| refused)?.claim_mcp(run_id, now).map_err(|_| refused)?;
        drop(data);
        Ok(Self {
            state,
            bound_run: run_id.to_owned(),
            bound_token: token,
            child_slots: Arc::new(Semaphore::new(2)),
        })
    }

    fn tool(index: usize) -> Tool {
        let schema: JsonObject =
            serde_json::from_str(INPUT_SCHEMAS[index]).expect("checked closed tool schema");
        let mut tool = Tool::new(
            TOOLS[index],
            "Read only bounded retained TOS health evidence; no on-demand upstream reads",
            Arc::new(schema),
        );
        tool.annotations = Some(ToolAnnotations::new().read_only(true).open_world(false));
        tool
    }

    pub fn tools() -> Vec<Tool> {
        (0..TOOLS.len()).map(Self::tool).collect()
    }

    /// Execute the exact HTTP route, then return one JSON text representation.
    /// The HTTP QueryService charges these exact JSON bytes to the durable run
    /// ledger; structuredContent is deliberately absent to avoid an uncharged
    /// duplicate. The MCP protocol wrapper itself carries no evidence payload.
    pub async fn invoke(
        &self,
        name: &str,
        arguments: JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let now = crate::query_ledger::boot_millis()
            .map_err(|_| McpError::internal_error("query clock unavailable", None))?;
        let ledger = self
            .state
            .query_ledger
            .as_ref()
            .ok_or_else(|| McpError::internal_error("query ledger unavailable", None))?;
        if ledger
            .lock()
            .map_err(|_| McpError::internal_error("query ledger unavailable", None))?
            .reserve_mcp_call(&self.bound_run, now)
            .is_err()
        {
            // There is no further model-visible budget response to charge.
            return Ok(CallToolResult::error(vec![]));
        }
        let Ok(_child_slot) = self.child_slots.clone().try_acquire_owned() else {
            // A busy call consumes its durable attempt, but performs no query
            // dispatch and creates no evidence or upstream work.
            return Ok(CallToolResult::error(vec![]));
        };
        let Some(index) = TOOLS.iter().position(|tool| *tool == name) else {
            return Err(McpError::new(ErrorCode::METHOD_NOT_FOUND, "unknown TOS tool", None));
        };
        if arguments.contains_key("run_token")
            || arguments.get("run_id").and_then(Value::as_str) != Some(&self.bound_run)
        {
            return Err(McpError::invalid_params("tool run binding mismatch", None));
        }
        let input = serde_json::to_vec(&Value::Object(arguments))
            .map_err(|_| McpError::invalid_params("invalid tool arguments", None))?;
        if input.len() > 16_384 {
            return Err(McpError::invalid_params("tool input exceeds 16 KiB", None));
        }
        let service = std::str::from_utf8(&self.state.service_token)
            .map_err(|_| McpError::internal_error("service credential unavailable", None))?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/query/{}", ROUTES[index]))
            .header("authorization", format!("Bearer {service}"))
            .header("x-tos-run-token", crate::hex(&self.bound_token))
            .header("content-type", "application/json")
            .body(Body::from(input))
            .map_err(|_| McpError::invalid_params("invalid tool request", None))?;
        let (error, bytes) = bounded_query_response(
            router(self.state.clone()).oneshot(request),
            Duration::from_secs(5),
        )
        .await?;
        if bytes.is_empty() {
            // HTTP admission refusals have no query envelope. Do not invent a
            // cause, and do not return uncharged text on that path.
            return Ok(CallToolResult::error(vec![]));
        }
        let body = String::from_utf8(bytes.to_vec())
            .map_err(|_| McpError::internal_error("query response was not UTF-8", None))?;
        let result = if error {
            CallToolResult::error(vec![ContentBlock::text(body)])
        } else {
            CallToolResult::success(vec![ContentBlock::text(body)])
        };
        Ok(result)
    }
}

impl ServerHandler for McpBridge {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2025_06_18)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        // Pinned AURA rmcp 0.12.0 initiates 2025-03-26. This surface is
        // already private and grant-authenticated; do not accept arbitrary
        // versions or expose a second listener for compatibility.
        Cow::Owned(vec![ProtocolVersion::V_2025_03_26, ProtocolVersion::V_2025_06_18])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(Self::tools()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        TOOLS.iter().position(|tool| *tool == name).map(Self::tool)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.invoke(&request.name, request.arguments.unwrap_or_default()).await.map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{query_ledger::boot_millis, random_token, Inventory};
    use serde_json::json;
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        pin::Pin,
        task::{Context, Poll},
    };
    use tos_health_core::query::Grant;

    struct NeverFinishedBody;

    impl hyper::body::Body for NeverFinishedBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn tool_deadline_covers_body_drain_and_never_delivers_partial_output() {
        let pending = Response::new(Body::new(NeverFinishedBody));
        let error = bounded_query_response(
            async { Ok::<_, Infallible>(pending) },
            Duration::from_millis(15),
        )
        .await
        .err()
        .unwrap();
        assert!(format!("{error:?}").contains("query deadline exceeded"));
        let complete = Response::new(Body::from(vec![b'x'; 32_768]));
        assert_eq!(
            bounded_query_response(async { Ok::<_, Infallible>(complete) }, Duration::from_secs(1))
                .await
                .unwrap()
                .1
                .len(),
            32_768
        );
        let too_large = Response::new(Body::from(vec![b'x'; 32_769]));
        assert!(bounded_query_response(
            async { Ok::<_, Infallible>(too_large) },
            Duration::from_secs(1)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn two_child_slots_refuse_third_before_actual_query_dispatch() {
        let directory = std::env::temp_dir().join(format!(
            "nhm-mcp-children-{}-{}",
            std::process::id(),
            crate::hex(&random_token().unwrap())
        ));
        std::fs::create_dir(&directory).unwrap();
        let state = ObservabilityState::new(
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
        .with_query_ledger(&directory.join("query.sqlite"))
        .unwrap();
        let run = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let token = [b't'; 32];
        let now = boot_millis().unwrap();
        let grant = Grant::new(
            run.into(),
            "aura".into(),
            state.inventory.network_id.clone(),
            &token,
            BTreeSet::from(["v1".into()]),
            BTreeSet::from(["node".into()]),
            1_700_000_000_000,
            1_700_000_060_000,
            now,
            0,
        )
        .unwrap();
        state.query_ledger.as_ref().unwrap().lock().unwrap().create(&grant, now).unwrap();
        state.data.lock().unwrap().grants.insert(run.into(), grant);
        let bridge = McpBridge::admit(
            state.clone(),
            Some(&format!("Bearer {}", "a".repeat(32))),
            run,
            &crate::hex(&token),
        )
        .unwrap();
        let first = bridge.child_slots.clone().try_acquire_owned().unwrap();
        let second = bridge.child_slots.clone().try_acquire_owned().unwrap();
        let arguments = || serde_json::from_value(json!({"run_id":run})).unwrap();
        let busy = bridge.invoke(TOOLS[0], arguments()).await.unwrap();
        assert_eq!(serde_json::to_value(busy).unwrap()["isError"], true);
        assert_eq!(state.data.lock().unwrap().grants[run].calls(), 0);
        assert_eq!(
            state.query_ledger.as_ref().unwrap().lock().unwrap().mcp_usage(run).unwrap(),
            Some((1, 0))
        );
        drop(first);
        let accepted = bridge.invoke(TOOLS[0], arguments()).await.unwrap();
        assert_eq!(serde_json::to_value(accepted).unwrap()["isError"], false);
        assert_eq!(state.data.lock().unwrap().grants[run].calls(), 1);
        assert_eq!(
            state.query_ledger.as_ref().unwrap().lock().unwrap().mcp_usage(run).unwrap(),
            Some((2, 0))
        );
        drop(second);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
