// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Exact request bytes are the invocation identity; duplicate JSON keys refuse.
use anyhow::{bail, ensure, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{fmt, io::Read};

pub const INPUT_LIMIT: usize = 2 * 1024 * 1024;
pub const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Unique, E> {
                Err(E::custom("floating point refused"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(x)) = a.next_element()? {
                    out.push(x);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    let Unique(v) = a.next_value()?;
                    out.insert(key, v);
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(!bytes.is_empty() && bytes.len() <= INPUT_LIMIT, "request byte bound");
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let Unique(v) = Unique::deserialize(&mut d)?;
    d.end()?;
    Ok(v)
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut sorted = value.clone();
    sorted.sort_all_objects();
    let bytes = serde_json::to_vec(&sorted)?;
    ensure!(bytes.is_ascii(), "canonical protocol fields must be ASCII");
    Ok(bytes)
}
pub fn fields(v: &Value, want: &[&str]) -> Result<()> {
    let map = v.as_object().ok_or_else(|| anyhow::anyhow!("object required"))?;
    ensure!(
        map.len() == want.len() && want.iter().all(|k| map.contains_key(*k)),
        "unknown or missing fields"
    );
    Ok(())
}
pub fn digest(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or_else(|| anyhow::anyhow!("digest string required"))?;
    ensure!(
        s.len() == 64
            && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0'),
        "nonzero lowercase digest required"
    );
    Ok(s)
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
