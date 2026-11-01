// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! RPC supplies transport acknowledgements only; never a finality capability.
use anyhow::{ensure, Result};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};
pub fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let url = reqwest::Url::parse(url)?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "local RPC origin required"
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 2 * 1024 * 1024, "RPC reply bound");
    let result = crate::protocol::parse(&bytes)?;
    ensure!(
        result["jsonrpc"] == "2.0" && result["id"] == 1 && result.get("error").is_none(),
        "RPC acknowledgement unavailable"
    );
    Ok(result.get("result").ok_or_else(|| anyhow::anyhow!("RPC result absent"))?.clone())
}
