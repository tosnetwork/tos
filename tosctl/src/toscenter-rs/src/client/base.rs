use core::fmt;

use crate::error::{RpcError, RpcErrorReason, ToscenterError};
use log::debug;
use reqwest::{header::HeaderMap, redirect::Policy, Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

/// The largest response body any request reads; a larger one is refused whole.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// The longest server-provided text (an error message, an unparsed error body)
/// kept in an error value.
const MAX_ERROR_TEXT_CHARS: usize = 512;

/// The longest `error.data.reason` accepted.
const MAX_REASON_BYTES: usize = 64;

/// The only `error.data.schema_version` this client understands.
const ERROR_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Custom(String),
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Mainnet => f.write_str("https://toscenter.com/api/v2/"),
            Network::Testnet => f.write_str("https://testnet.toscenter.com/api/v2/"),
            Network::Custom(s) => f.write_str(s),
        }
    }
}

#[derive(Debug)]
pub enum ApiKey {
    Header(String),
    Query(String),
}

#[derive(Debug)]
pub struct BaseApiClient {
    client: Client,
    api_key: Option<ApiKey>,
}

impl BaseApiClient {
    pub fn new(api_key: Option<ApiKey>) -> Self {
        let client = Client::builder()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .expect("static reqwest client policy must build");
        Self { client, api_key }
    }

    /// Builds a bounded client whose route is determined only by the supplied
    /// endpoint. This is the required transport for bearer-executable signed
    /// requests: ambient HTTP(S)/ALL_PROXY variables must not be able to
    /// redirect transaction bytes through an unconfigured process.
    pub fn try_new_direct(api_key: Option<ApiKey>) -> Result<Self, ToscenterError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client, api_key })
    }

    /// Sends one request and returns the HTTP status and the bounded body,
    /// uninterpreted. A body above [`MAX_RESPONSE_BYTES`] is
    /// [`ToscenterError::ResponseTooLarge`] on a successful status and
    /// [`ToscenterError::HttpStatus`] on any other.
    async fn send_text(
        &self,
        method: reqwest::Method,
        base_url: &str,
        endpoint: &str,
        params: &[(&str, &str)],
        body: Option<&impl Serialize>,
    ) -> Result<(u16, String), ToscenterError> {
        let mut headers = HeaderMap::new();
        let mut query_params = params.to_vec();

        if let Some(ref key) = self.api_key {
            match key {
                ApiKey::Header(key) => {
                    headers.insert("x-api-key", key.parse()?);
                }
                ApiKey::Query(key) => {
                    query_params.push(("api_key", key));
                }
            };
        }

        let url =
            format!("{}/{}", base_url.trim_end_matches('/'), endpoint.trim_start_matches('/'));
        let url_with_params = reqwest::Url::parse_with_params(&url, query_params)?;
        let request_builder = match method {
            reqwest::Method::GET => self.client.get(url_with_params).headers(headers),
            reqwest::Method::POST => {
                let builder = self.client.post(url_with_params).headers(headers);
                if let Some(body) = body {
                    builder.json(body)
                } else {
                    builder
                }
            }
            _ => {
                return Err(ToscenterError::HttpClientError {
                    code: 405,
                    message: format!("HTTP method {} is not supported", method),
                })
            }
        };

        // Never log headers, query values, or serialized bodies here. They can
        // contain API keys or a bearer-executable signed transaction.
        debug!("Sending {} request to configured endpoint", method);

        let response = request_builder.send().await?;
        let status = response.status();
        debug!("Received HTTP status {} from configured endpoint", status);

        match bounded_response_text(response).await {
            Ok(text) => Ok((status.as_u16(), text)),
            // An oversized body is "too large" only on a successful response; an
            // error status stays an error whatever its body's size.
            Err(ToscenterError::ResponseTooLarge { .. }) if !status.is_success() => {
                Err(ToscenterError::HttpStatus { code: status.as_u16() })
            }
            Err(error) => Err(error),
        }
    }

    /// Sends one request and returns the validated `result` of its answer.
    async fn send_request(
        &self,
        method: reqwest::Method,
        base_url: &str,
        endpoint: &str,
        params: &[(&str, &str)],
        body: Option<&impl Serialize>,
        expected_id: &serde_json::Value,
    ) -> Result<serde_json::Value, ToscenterError> {
        let (status, text) = self.send_text(method, base_url, endpoint, params, body).await?;
        parse_rpc_response(status, &text, expected_id)
    }

    /// A GET of a method route. The answer carries `id: null`.
    pub async fn get<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        base_url: &str,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<T, ToscenterError> {
        let result = self
            .send_request(
                reqwest::Method::GET,
                base_url,
                endpoint,
                params,
                None::<&serde_json::Value>,
                &serde_json::Value::Null,
            )
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// A POST of named params to a method route. The answer carries `id: null`.
    pub async fn post_api<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<T, ToscenterError> {
        let result = self
            .send_request(
                reqwest::Method::POST,
                base_url,
                endpoint,
                &[],
                Some(body),
                &serde_json::Value::Null,
            )
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Posts a JSON-RPC request and returns the HTTP status and the bounded body
    /// unparsed, for a caller that parses it under its own depth and ownership
    /// rules. A body above [`MAX_RESPONSE_BYTES`] is
    /// [`ToscenterError::ResponseTooLarge`]; a non-success status is returned with
    /// its body, not interpreted here.
    pub async fn post_rpc_text(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<(u16, String), ToscenterError> {
        self.send_text(reqwest::Method::POST, base_url, endpoint, &[], Some(body)).await
    }

    /// Posts a JSON-RPC request envelope and returns the validated `result` of
    /// the answer, which must carry `expected_id`.
    pub async fn post_rpc(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
        expected_id: &serde_json::Value,
    ) -> Result<serde_json::Value, ToscenterError> {
        self.send_request(reqwest::Method::POST, base_url, endpoint, &[], Some(body), expected_id)
            .await
    }
}

/// Validates one answer of the JSON-RPC server and returns its `result`.
///
/// A success is HTTP 200 with exactly `jsonrpc: "2.0"`, the request's `id` and
/// `result`. An error is exactly `jsonrpc`, `id` and an `error` object with an
/// integer `code`, a string `message` and `data` holding `schema_version` 1, a
/// string `reason` and a boolean `retryable`; it becomes
/// [`ToscenterError::RateLimitExceeded`] for `RATE_LIMITED` and
/// [`ToscenterError::Rpc`] otherwise. Anything else is
/// [`ToscenterError::ProtocolError`], except that a non-success HTTP status
/// whose body is not a valid error answer keeps its status as an HTTP error.
pub fn parse_rpc_response(
    status: u16,
    text: &str,
    expected_id: &serde_json::Value,
) -> Result<serde_json::Value, ToscenterError> {
    if status == 200 {
        return parse_envelope(status, text, expected_id);
    }
    if !(200..300).contains(&status) {
        // A refusal made before any method ran may not know the request id.
        return match parse_envelope(status, text, expected_id) {
            Err(error @ (ToscenterError::Rpc(_) | ToscenterError::RateLimitExceeded)) => Err(error),
            _ if status == 429 => Err(ToscenterError::RateLimitExceeded),
            _ if (400..500).contains(&status) => Err(ToscenterError::HttpClientError {
                code: u32::from(status),
                message: bounded_text(text),
            }),
            _ => Err(ToscenterError::HttpServerError {
                code: u32::from(status),
                message: bounded_text(text),
            }),
        };
    }
    Err(protocol_error(&format!("unexpected HTTP status {status} for a request with an id")))
}

fn parse_envelope(
    status: u16,
    text: &str,
    expected_id: &serde_json::Value,
) -> Result<serde_json::Value, ToscenterError> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|_| protocol_error("response is not valid JSON"))?;
    let serde_json::Value::Object(mut object) = document else {
        return Err(protocol_error("response is not an object"));
    };
    if object.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
        return Err(protocol_error("jsonrpc must be exactly 2.0"));
    }
    let response_id = object.get("id").ok_or_else(|| protocol_error("response has no id"))?;
    let id_matches = response_id == expected_id || (status != 200 && response_id.is_null());
    if !id_matches {
        return Err(protocol_error("response id does not match the request"));
    }
    if let Some(member) =
        object.keys().find(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "result" | "error"))
    {
        return Err(protocol_error(&format!("response has an unexpected member {member:?}")));
    }
    match (object.remove("result"), object.remove("error")) {
        (Some(result), None) => {
            if status != 200 {
                return Err(protocol_error("a result arrived with a non-200 HTTP status"));
            }
            Ok(result)
        }
        (None, Some(error)) => Err(rpc_error(status, &error)?),
        (Some(_), Some(_)) => Err(protocol_error("response has both result and error")),
        (None, None) => Err(protocol_error("response has neither result nor error")),
    }
}

/// The typed error for a JSON-RPC `error` member, or a protocol error when the
/// member is malformed.
fn rpc_error(status: u16, error: &serde_json::Value) -> Result<ToscenterError, ToscenterError> {
    let error = error.as_object().ok_or_else(|| protocol_error("error must be an object"))?;
    let code = error
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| protocol_error("error code must be an integer"))?;
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| protocol_error("error message must be a string"))?;
    let data = error
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| protocol_error("error data must be an object"))?;
    if data.get("schema_version").and_then(serde_json::Value::as_u64) != Some(ERROR_SCHEMA_VERSION)
    {
        return Err(protocol_error("error schema_version must be 1"));
    }
    let reason = data
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| protocol_error("error reason must be a string"))?;
    if reason.is_empty()
        || reason.len() > MAX_REASON_BYTES
        || !reason
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(protocol_error("error reason is not an upper-case identifier"));
    }
    let retryable = data
        .get("retryable")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| protocol_error("error retryable must be a boolean"))?;
    let reason = RpcErrorReason::from_wire(reason);
    if let Some((expected_code, expected_retryable)) = reason.expected_code_and_retryable() {
        if code != expected_code || retryable != expected_retryable {
            return Err(protocol_error("error code or retryable does not match its reason"));
        }
    }
    if reason == RpcErrorReason::RateLimited {
        return Ok(ToscenterError::RateLimitExceeded);
    }
    Ok(ToscenterError::Rpc(RpcError {
        http_status: status,
        code,
        message: bounded_text(message),
        reason,
        retryable,
    }))
}

fn protocol_error(message: &str) -> ToscenterError {
    ToscenterError::ProtocolError { message: bounded_text(message) }
}

fn bounded_text(message: &str) -> String {
    message.chars().take(MAX_ERROR_TEXT_CHARS).collect()
}

async fn bounded_response_text(mut response: Response) -> Result<String, ToscenterError> {
    if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
        return Err(ToscenterError::ResponseTooLarge { limit: MAX_RESPONSE_BYTES });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ToscenterError::ResponseTooLarge { limit: MAX_RESPONSE_BYTES });
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| ToscenterError::HttpServerError {
        code: 502,
        message: "configured endpoint returned non-UTF-8 JSON".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    async fn read_one_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut buffer = vec![0_u8; 8192];
        let read = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
        let length = match read {
            Ok(Ok(length)) => length,
            _ => 0,
        };
        String::from_utf8_lossy(&buffer[..length]).into_owned()
    }

    fn error_body(id: serde_json::Value, code: i64, reason: &str, retryable: bool) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": format!("message for {reason}"),
                "data": {"schema_version": 1, "reason": reason, "retryable": retryable},
            },
        })
        .to_string()
    }

    /// Serves one canned HTTP answer and returns the request it received.
    async fn serve_once(
        status_line: &'static str,
        body: String,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_one_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (format!("http://{address}"), server)
    }

    #[test]
    fn success_envelope_returns_result() {
        let id = serde_json::json!("request-1");
        let text = r#"{"jsonrpc":"2.0","id":"request-1","result":{"status":1}}"#;
        let result = parse_rpc_response(200, text, &id).unwrap();
        assert_eq!(result, serde_json::json!({"status":1}));

        let rest = r#"{"jsonrpc":"2.0","id":null,"result":"12"}"#;
        assert_eq!(
            parse_rpc_response(200, rest, &serde_json::Value::Null).unwrap(),
            serde_json::json!("12")
        );
    }

    #[test]
    fn typed_error_keeps_code_reason_and_retryable() {
        let id = serde_json::json!(7);
        let text = error_body(id.clone(), -32004, "CONFIG_PARAM_ABSENT", false);
        let error = parse_rpc_response(200, &text, &id).unwrap_err();
        let ToscenterError::Rpc(error) = error else {
            panic!("expected a typed RPC error, got {error:?}");
        };
        assert_eq!(error.http_status, 200);
        assert_eq!(error.code, -32004);
        assert_eq!(error.reason, RpcErrorReason::ConfigParamAbsent);
        assert!(!error.retryable);
        assert_eq!(error.message, "message for CONFIG_PARAM_ABSENT");

        let text = error_body(id.clone(), -32603, "UPSTREAM_UNAVAILABLE", true);
        let ToscenterError::Rpc(error) = parse_rpc_response(200, &text, &id).unwrap_err() else {
            panic!("expected a typed RPC error");
        };
        assert_eq!(error.reason, RpcErrorReason::UpstreamUnavailable);
        assert!(error.retryable);

        // A reason this client does not know survives verbatim.
        let text = error_body(id.clone(), -32050, "SOMETHING_NEW", true);
        let ToscenterError::Rpc(error) = parse_rpc_response(200, &text, &id).unwrap_err() else {
            panic!("expected a typed RPC error");
        };
        assert_eq!(error.reason, RpcErrorReason::Unrecognized("SOMETHING_NEW".to_string()));
        assert_eq!(error.reason.as_str(), "SOMETHING_NEW");

        // Method-level capacity refusals arrive at HTTP 200.
        let text = error_body(id.clone(), -32005, "RATE_LIMITED", true);
        assert!(matches!(
            parse_rpc_response(200, &text, &id),
            Err(ToscenterError::RateLimitExceeded)
        ));
    }

    #[test]
    fn admission_refusals_carry_the_error_object() {
        let id = serde_json::json!("request-1");
        let text = error_body(serde_json::Value::Null, -32000, "UNAUTHORIZED", false);
        let ToscenterError::Rpc(error) = parse_rpc_response(401, &text, &id).unwrap_err() else {
            panic!("expected a typed RPC error");
        };
        assert_eq!(error.http_status, 401);
        assert_eq!(error.reason, RpcErrorReason::Unauthorized);

        let text = error_body(serde_json::Value::Null, -32005, "RATE_LIMITED", true);
        assert!(matches!(
            parse_rpc_response(429, &text, &id),
            Err(ToscenterError::RateLimitExceeded)
        ));
        // A 429 without a readable body is still a rate limit.
        assert!(matches!(
            parse_rpc_response(429, "busy", &id),
            Err(ToscenterError::RateLimitExceeded)
        ));
        // Other statuses without a valid error object keep their HTTP status.
        assert!(matches!(
            parse_rpc_response(503, "upstream down", &id),
            Err(ToscenterError::HttpServerError { code: 503, .. })
        ));
        assert!(matches!(
            parse_rpc_response(404, "", &id),
            Err(ToscenterError::HttpClientError { code: 404, .. })
        ));
        // A non-200 status never yields a result.
        let success = r#"{"jsonrpc":"2.0","id":"request-1","result":{}}"#;
        assert!(parse_rpc_response(500, success, &id).is_err());
        assert!(matches!(
            parse_rpc_response(204, "", &id),
            Err(ToscenterError::ProtocolError { .. })
        ));
    }

    #[test]
    fn malformed_envelopes_are_protocol_errors_and_never_panic() {
        let expected_id = serde_json::json!("request-1");
        let error_object = serde_json::json!({
            "code": -32603,
            "message": "m",
            "data": {"schema_version": 1, "reason": "INTERNAL_ERROR", "retryable": false},
        });
        for malformed in [
            serde_json::json!([]),
            serde_json::json!("text"),
            serde_json::json!({"id":"request-1","result":{}}),
            serde_json::json!({"jsonrpc":"1.0","id":"request-1","result":{}}),
            serde_json::json!({"jsonrpc":2.0,"id":"request-1","result":{}}),
            serde_json::json!({"jsonrpc":"2.0","result":{}}),
            serde_json::json!({"jsonrpc":"2.0","id":"wrong","result":{}}),
            serde_json::json!({"jsonrpc":"2.0","id":null,"result":{}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1"}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","result":{},"error":error_object}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","ok":true,"result":{}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","code":-32603,"error":error_object}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":"bad"}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":"-32603","message":"m","data":{"schema_version":1,"reason":"INTERNAL_ERROR","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603.5,"message":"m","data":{"schema_version":1,"reason":"INTERNAL_ERROR","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"data":{"schema_version":1,"reason":"INTERNAL_ERROR","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m"}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m","data":{"schema_version":2,"reason":"INTERNAL_ERROR","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m","data":{"schema_version":1,"retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m","data":{"schema_version":1,"reason":"internal error","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m","data":{"schema_version":1,"reason":"INTERNAL_ERROR","retryable":"no"}}}),
            // A known reason with a code or retryability it never carries.
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"m","data":{"schema_version":1,"reason":"CONFIG_PARAM_ABSENT","retryable":false}}}),
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","error":{"code":-32004,"message":"m","data":{"schema_version":1,"reason":"CONFIG_PARAM_ABSENT","retryable":true}}}),
        ] {
            let error = parse_rpc_response(200, &malformed.to_string(), &expected_id)
                .expect_err("malformed response must be a typed error");
            assert!(
                matches!(error, ToscenterError::ProtocolError { .. }),
                "{malformed}: {error:?}"
            );
        }
        for text in ["", "{", "not json", "{\"jsonrpc\":\"2.0\"} trailing"] {
            assert!(matches!(
                parse_rpc_response(200, text, &expected_id),
                Err(ToscenterError::ProtocolError { .. })
            ));
        }
    }

    #[test]
    fn server_text_in_errors_is_bounded() {
        let id = serde_json::json!(1);
        let long = "x".repeat(10_000);
        let text = serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "error":{"code":-32603,"message":long,"data":{"schema_version":1,"reason":"INTERNAL_ERROR","retryable":false}}
        })
        .to_string();
        let ToscenterError::Rpc(error) = parse_rpc_response(200, &text, &id).unwrap_err() else {
            panic!("expected a typed RPC error");
        };
        assert_eq!(error.message.chars().count(), MAX_ERROR_TEXT_CHARS);
        let ToscenterError::HttpServerError { message, .. } =
            parse_rpc_response(500, &long, &id).unwrap_err()
        else {
            panic!("expected an HTTP server error");
        };
        assert_eq!(message.chars().count(), MAX_ERROR_TEXT_CHARS);
    }

    #[tokio::test]
    async fn rest_get_parses_null_id_result_and_typed_error() {
        let (url, server) =
            serve_once("200 OK", r#"{"jsonrpc":"2.0","id":null,"result":"1234"}"#.to_string())
                .await;
        let client = BaseApiClient::try_new_direct(None).unwrap();
        let balance: String =
            client.get(&url, "getAddressBalance", &[("address", "a")]).await.unwrap();
        assert_eq!(balance, "1234");
        let request = server.await.unwrap();
        assert!(request.starts_with("GET /getAddressBalance?address=a "), "{request}");

        let (url, server) = serve_once(
            "200 OK",
            error_body(serde_json::Value::Null, -32006, "CONTRACT_KIND_UNSUPPORTED", false),
        )
        .await;
        let error = client
            .get::<serde_json::Value>(&url, "getTokenData", &[("address", "a")])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ToscenterError::Rpc(RpcError { reason: RpcErrorReason::ContractKindUnsupported, .. })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn post_rpc_maps_http_401_and_429_bodies() {
        let client =
            BaseApiClient::try_new_direct(Some(ApiKey::Header("wrong".to_string()))).unwrap();
        let id = serde_json::json!("abc");
        let body = serde_json::json!({"jsonrpc":"2.0","method":"getMasterchainInfo","params":{},"id":"abc"});

        let (url, server) = serve_once(
            "401 Unauthorized",
            error_body(serde_json::Value::Null, -32000, "UNAUTHORIZED", false),
        )
        .await;
        let error = client.post_rpc(&url, "jsonRPC", &body, &id).await.unwrap_err();
        let ToscenterError::Rpc(error) = error else {
            panic!("expected a typed RPC error, got {error:?}");
        };
        assert_eq!((error.http_status, error.code), (401, -32000));
        assert_eq!(error.reason, RpcErrorReason::Unauthorized);
        let request = server.await.unwrap();
        assert!(request.contains("\"jsonrpc\":\"2.0\""), "{request}");

        let (url, server) = serve_once(
            "429 Too Many Requests",
            error_body(serde_json::Value::Null, -32005, "RATE_LIMITED", true),
        )
        .await;
        let error = client.post_rpc(&url, "jsonRPC", &body, &id).await.unwrap_err();
        assert!(matches!(error, ToscenterError::RateLimitExceeded), "{error:?}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_client_refuses_redirect_without_contacting_target() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            timeout(Duration::from_millis(300), target.accept()).await.is_ok()
        });

        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_address = redirect.local_addr().unwrap();
        let redirect_task = tokio::spawn(async move {
            let (mut stream, _) = redirect.accept().await.unwrap();
            read_one_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client =
            BaseApiClient::try_new_direct(Some(ApiKey::Header("secret".to_string()))).unwrap();
        let result = client
            .post_api::<serde_json::Value>(
                &format!("http://{redirect_address}"),
                "submit",
                &serde_json::json!({"boc": "signed"}),
            )
            .await;
        assert!(result.is_err());
        redirect_task.await.unwrap();
        assert!(!target_task.await.unwrap(), "redirect target received bearer request");
    }

    #[tokio::test]
    async fn direct_client_rejects_declared_oversized_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_one_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_RESPONSE_BYTES + 1
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = BaseApiClient::try_new_direct(None).unwrap();
        let error = client
            .get::<serde_json::Value>(&format!("http://{address}"), "read", &[])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("one-megabyte limit"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_client_does_not_retry_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            read_one_request(&mut first).await;
            drop(first);
            timeout(Duration::from_millis(300), listener.accept()).await.is_ok()
        });
        let client = BaseApiClient::try_new_direct(None).unwrap();
        let result = client
            .post_api::<serde_json::Value>(
                &format!("http://{address}"),
                "submit",
                &serde_json::json!({"boc": "signed"}),
            )
            .await;
        assert!(result.is_err());
        assert!(!server.await.unwrap(), "one logical write produced a second request");
    }
}
