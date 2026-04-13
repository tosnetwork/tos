use core::fmt;

use crate::{
    error::ToscenterError,
    models::{ApiResponse, ApiResponseResult, JsonRpcResponse, JsonRpcResult},
};
use log::debug;
use reqwest::{header::HeaderMap, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, serde::Deserialize)]
struct RpcProbe {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    code: Option<u32>,
}

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
        Self {
            client: Client::new(),
            api_key,
        }
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

        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        );
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
            _ => unimplemented!(),
        };

        debug!("Request after processing: {:?}", request_builder);

        let response = request_builder.send().await?;
        debug!("Received response: {:?}", response);

        let status = response.status();
        let response_text = response.text().await?;
        debug!("Response text: {}", response_text);

        if !status.is_success() {
            let code = status.as_u16() as u32;
            self.handle_error(code, response_text.clone())?;
            unreachable!("early return via handle_error");
        }

        if let Ok(probe) = serde_json::from_str::<RpcProbe>(&response_text) {
            if probe.ok == Some(false) {
                let code = probe.code.unwrap_or(500);
                let msg = probe
                    .error
                    .unwrap_or_else(|| "Unknown RPC error".to_string());
                self.handle_error(code, msg)?;
                unreachable!("early return via handle_error");
            }
        }

        let response_body: T = serde_json::from_str(&response_text)?;
        debug!("Response body: {:?}", response_body);

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
        let response_body: ApiResponse<T> = self
            .send_request(reqwest::Method::POST, base_url, endpoint, &[], Some(body))
            .await?;
        self.handle_api_response(response_body).await
    }

    pub async fn post_rpc<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<T, ToscenterError> {
        let response_body: JsonRpcResponse<T> = self
            .send_request(reqwest::Method::POST, base_url, endpoint, &[], Some(body))
            .await?;

        if response_body.ok {
            if let JsonRpcResult::Success { result } = response_body.data {
                return Ok(result);
            }

            unreachable!("Invalid response from server, expected 'result'");
        }

        if let JsonRpcResult::Error {
            result,
            error,
            code,
        } = response_body.data
        {
            let error_message = error
                .or(result)
                .unwrap_or_else(|| "Unknown error".to_string());
            self.handle_error(code, error_message)?;
        }

        unreachable!("Invalid response from server, expected 'result' or 'error'");
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

        if let ApiResponseResult::Error {
            result,
            error,
            code,
        } = response_body.data
        {
            let error_message = error
                .or(result)
                .unwrap_or_else(|| "Unknown error".to_string());
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
}
