use core::fmt;

use crate::{
    error::ToscenterError,
    models::{ApiResponse, ApiResponseResult},
};
use log::debug;
use reqwest::{header::HeaderMap, redirect::Policy, Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 1 << 20;

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

    async fn send_request<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        method: reqwest::Method,
        base_url: &str,
        endpoint: &str,
        params: &[(&str, &str)],
        body: Option<&impl Serialize>,
    ) -> Result<T, ToscenterError> {
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
        debug!("Received HTTP status {} from configured endpoint", response.status());

        let status = response.status();
        let response_text = bounded_response_text(response).await?;
        if !status.is_success() {
            let code = status.as_u16() as u32;
            self.handle_error(code, response_text.clone())?;
            unreachable!("early return via handle_error");
        }

        let response_body: T = serde_json::from_str(&response_text)?;
        Ok(response_body)
    }

    pub async fn get<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        base_url: &str,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<T, ToscenterError> {
        let response_body: ApiResponse<T> = self
            .send_request(
                reqwest::Method::GET,
                base_url,
                endpoint,
                params,
                None::<&serde_json::Value>,
            )
            .await?;
        self.handle_api_response(response_body).await
    }

    pub async fn post_api<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<T, ToscenterError> {
        let response_body: ApiResponse<T> =
            self.send_request(reqwest::Method::POST, base_url, endpoint, &[], Some(body)).await?;
        self.handle_api_response(response_body).await
    }

    pub async fn post_rpc(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
        expected_id: &serde_json::Value,
    ) -> Result<serde_json::Value, ToscenterError> {
        let response_body: serde_json::Value =
            self.send_request(reqwest::Method::POST, base_url, endpoint, &[], Some(body)).await?;
        self.validate_rpc_response(response_body, expected_id)
    }

    async fn handle_api_response<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        response_body: ApiResponse<T>,
    ) -> Result<T, ToscenterError> {
        if response_body.ok {
            if let ApiResponseResult::Success { result } = response_body.data {
                return Ok(result);
            }

            unreachable!("Invalid response from server, expected 'result'");
        }

        if let ApiResponseResult::Error { result, error, code } = response_body.data {
            let error_message = error.or(result).unwrap_or_else(|| "Unknown error".to_string());
            self.handle_error(code, error_message)?;
        }

        unreachable!("Invalid response from server, expected 'result' or 'error'");
    }

    fn handle_error(&self, code: u32, message: String) -> Result<(), ToscenterError> {
        if code == 429 {
            Err(ToscenterError::RateLimitExceeded)
        } else if (400..500).contains(&code) {
            Err(ToscenterError::HttpClientError { code, message })
        } else {
            Err(ToscenterError::HttpServerError { code, message })
        }
    }

    fn validate_rpc_response(
        &self,
        response: serde_json::Value,
        expected_id: &serde_json::Value,
    ) -> Result<serde_json::Value, ToscenterError> {
        let object =
            response.as_object().ok_or_else(|| protocol_error("response is not an object"))?;
        if object.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
            return Err(protocol_error("jsonrpc must be exactly 2.0"));
        }
        let response_id = object.get("id").ok_or_else(|| protocol_error("response has no id"))?;
        if response_id != expected_id {
            return Err(protocol_error("response id does not match the request"));
        }
        let ok = object
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| protocol_error("ok must be a boolean"))?;
        let has_result = object.contains_key("result");
        let has_error = object.contains_key("error") || object.contains_key("code");
        if ok {
            if !has_result || has_error {
                return Err(protocol_error(
                    "successful response must contain result and no error fields",
                ));
            }
            return object
                .get("result")
                .cloned()
                .ok_or_else(|| protocol_error("successful response has no result"));
        }
        if has_result || !object.contains_key("error") || !object.contains_key("code") {
            return Err(protocol_error("error response must contain error and code and no result"));
        }
        let code = object
            .get("code")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| protocol_error("error code must be an unsigned 32-bit integer"))?;
        let message = object
            .get("error")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| protocol_error("error must be a string"))?;
        self.handle_error(code, bounded_protocol_text(message))?;
        Err(protocol_error("unreachable error response state"))
    }
}

fn protocol_error(message: &str) -> ToscenterError {
    ToscenterError::ProtocolError { message: bounded_protocol_text(message) }
}

fn bounded_protocol_text(message: &str) -> String {
    message.chars().take(512).collect()
}

async fn bounded_response_text(mut response: Response) -> Result<String, ToscenterError> {
    if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
        return Err(ToscenterError::HttpServerError {
            code: 502,
            message: "configured endpoint response exceeds the one-megabyte limit".to_string(),
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ToscenterError::HttpServerError {
                code: 502,
                message: "configured endpoint response exceeds the one-megabyte limit".to_string(),
            });
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

    async fn read_one_request(stream: &mut tokio::net::TcpStream) {
        let mut buffer = vec![0_u8; 8192];
        let _ = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
    }

    #[test]
    fn json_rpc_envelope_validation_is_strict_and_never_panics() {
        let client = BaseApiClient::try_new_direct(None).unwrap();
        let expected_id = serde_json::json!("request-1");
        for malformed in [
            serde_json::json!([]),
            serde_json::json!({"ok":true,"jsonrpc":"1.0","id":"request-1","result":{}}),
            serde_json::json!({"ok":true,"jsonrpc":"2.0","id":"wrong","result":{}}),
            serde_json::json!({"ok":true,"jsonrpc":"2.0","id":"request-1"}),
            serde_json::json!({"ok":true,"jsonrpc":"2.0","id":"request-1","result":{},"error":"bad","code":500}),
            serde_json::json!({"ok":false,"jsonrpc":"2.0","id":"request-1","result":{},"error":"bad","code":500}),
            serde_json::json!({"ok":false,"jsonrpc":"2.0","id":"request-1","error":{"message":"bad"},"code":500}),
        ] {
            let error = client
                .validate_rpc_response(malformed, &expected_id)
                .expect_err("malformed response must be a typed error");
            assert!(matches!(error, ToscenterError::ProtocolError { .. }));
        }

        let accepted = client
            .validate_rpc_response(
                serde_json::json!({
                    "ok":true,
                    "jsonrpc":"2.0",
                    "id":"request-1",
                    "result":{"status":1}
                }),
                &expected_id,
            )
            .expect("valid exact envelope");
        assert_eq!(accepted, serde_json::json!({"status":1}));
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
            .send_request::<serde_json::Value>(
                reqwest::Method::POST,
                &format!("http://{redirect_address}"),
                "submit",
                &[],
                Some(&serde_json::json!({"boc": "signed"})),
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
            .send_request::<serde_json::Value>(
                reqwest::Method::GET,
                &format!("http://{address}"),
                "read",
                &[],
                None::<&serde_json::Value>,
            )
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
            .send_request::<serde_json::Value>(
                reqwest::Method::POST,
                &format!("http://{address}"),
                "submit",
                &[],
                Some(&serde_json::json!({"boc": "signed"})),
            )
            .await;
        assert!(result.is_err());
        assert!(!server.await.unwrap(), "one logical write produced a second request");
    }
}
