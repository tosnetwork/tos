// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Exact request bytes are the invocation identity; duplicate JSON keys refuse.
//! The canonical rules themselves live in the shared `br1-client` crate, so
//! the wallet and this provider cannot disagree on them.
use anyhow::{bail, ensure, Result};
pub use br1_client::wire::{canonical, digest, fields, hash};
use serde_json::Value;
use std::io::Read;

pub const INPUT_LIMIT: usize = 2 * 1024 * 1024;
pub const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
/// One JSON value from exact bytes within this process boundary's input bound.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    br1_client::wire::parse(bytes, INPUT_LIMIT)
}
pub struct Invocation {
    pub request_hash: String,
    pub operation: String,
    pub payload: Value,
}
impl Invocation {
    pub fn read(mut source: impl Read, operation: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        source.by_ref().take((INPUT_LIMIT as u64) + 1).read_to_end(&mut bytes)?;
        let v = parse(&bytes)?;
        fields(&v, &["schema", "nonce", "operation", "payload"])?;
        ensure!(
            v["schema"] == "tos.br1.native.request.v1" && v["operation"] == operation,
            "invocation mismatch"
        );
        let nonce = v["nonce"].as_str().ok_or_else(|| anyhow::anyhow!("nonce"))?;
        ensure!(
            nonce.len() == 32
                && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "nonce encoding"
        );
        if !v["payload"].is_object() {
            bail!("payload object required");
        }
        Ok(Self {
            request_hash: hash(&bytes),
            operation: operation.into(),
            payload: v["payload"].clone(),
        })
    }
    pub fn reply(&self, result: Result<Value>) -> Result<Vec<u8>> {
        let (status, value) = match result {
            Ok(v) => ("ok", v),
            Err(_) => ("refused", Value::Null),
        };
        let wire = canonical(
            &serde_json::json!({"schema":"tos.br1.native.reply.v1","request_sha256":self.request_hash,"status":status,"result":value}),
        )?;
        ensure!(wire.len() <= OUTPUT_LIMIT, "reply byte bound");
        Ok(wire)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_at_any_depth() {
        for text in [r#"{"a":1,"a":2}"#, r#"{"a":[{"x":1,"x":2}]}"#] {
            assert!(parse(text.as_bytes()).is_err());
        }
    }
    #[test]
    fn invocation_and_exact_bytes() -> Result<()> {
        let a=br#"{"schema":"tos.br1.native.request.v1","nonce":"11111111111111111111111111111111","operation":"capabilities","payload":{}}"#;
        let v = Invocation::read(&a[..], "capabilities")?;
        assert_eq!(v.request_hash, hash(a));
        assert!(Invocation::read(&a[..], "broadcast").is_err());
        Ok(())
    }
    #[test]
    fn rejects_trailing_float_and_bound() {
        assert!(parse(b"{}{}").is_err());
        assert!(parse(b"{\"a\":1.5}").is_err());
        let mut oversized = b"{\"x\":\"".to_vec();
        oversized.extend(vec![b'a'; INPUT_LIMIT]);
        oversized.extend_from_slice(b"\"}");
        assert!(matches!(parse(&oversized),Err(error) if error.to_string()=="request byte bound"));
    }
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    #[test]
    fn sorts_nested_objects_independent_of_dependency_features() -> Result<()> {
        let value = parse(br#"{"z":{"b":2,"a":1},"a":0}"#)?;
        assert_eq!(canonical(&value)?, br#"{"a":0,"z":{"a":1,"b":2}}"#);
        Ok(())
    }
}
