// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Canonical JSON for the BR1 protocol: exact bytes are identities, so
//! duplicate members, floats, trailing bytes and non-ASCII are refused and
//! every encoding is sorted and compact.
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

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

/// One JSON value from exact bytes: non-empty, at most `limit` bytes, no
/// duplicate member at any depth, no floating point, nothing after the value.
pub fn parse(bytes: &[u8], limit: usize) -> Result<Value> {
    ensure!(!bytes.is_empty() && bytes.len() <= limit, "request byte bound");
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let Unique(v) = Unique::deserialize(&mut d)?;
    d.end()?;
    Ok(v)
}

/// A JSON object from exact bytes, with the same rules.
pub fn parse_object(bytes: &[u8], limit: usize) -> Result<Value> {
    let value = parse(bytes, limit)?;
    ensure!(value.is_object(), "API object required");
    Ok(value)
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Sorted members, compact separators, ASCII only.
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut sorted = value.clone();
    sorted.sort_all_objects();
    let bytes = serde_json::to_vec(&sorted)?;
    ensure!(bytes.is_ascii(), "canonical protocol fields must be ASCII");
    Ok(bytes)
}

/// Exactly the members named, no others.
pub fn fields(v: &Value, want: &[&str]) -> Result<()> {
    let map = v.as_object().ok_or_else(|| anyhow::anyhow!("object required"))?;
    ensure!(
        map.len() == want.len() && want.iter().all(|k| map.contains_key(*k)),
        "unknown or missing fields"
    );
    Ok(())
}

/// A nonzero lowercase 32-byte hex digest.
pub fn digest(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or_else(|| anyhow::anyhow!("digest string required"))?;
    digest_str(s)?;
    Ok(s)
}

pub fn digest_str(s: &str) -> Result<()> {
    ensure!(
        s.len() == 64
            && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0'),
        "nonzero lowercase digest required"
    );
    Ok(())
}

/// An integer member within `low..=high`.
pub fn integer(v: &Value, low: u64, high: u64) -> Result<u64> {
    let n = v.as_u64().ok_or_else(|| anyhow::anyhow!("integer required"))?;
    ensure!((low..=high).contains(&n), "integer out of range");
    Ok(n)
}

/// Canonical standard base64 of exactly `exact` bytes.
pub fn decode_exact(text: &str, exact: usize) -> Result<Vec<u8>> {
    let maximum = exact
        .checked_add(2)
        .and_then(|x| x.checked_div(3))
        .and_then(|x| x.checked_mul(4))
        .ok_or_else(|| anyhow::anyhow!("base64 bound overflow"))?;
    ensure!(text.len() == maximum, "base64 length");
    let bytes = STANDARD.decode(text)?;
    ensure!(bytes.len() == exact && STANDARD.encode(&bytes) == text, "base64 canonical width");
    Ok(bytes)
}

/// Canonical standard base64 of between one and `maximum` bytes.
pub fn decode_bounded(text: &str, maximum: usize) -> Result<Vec<u8>> {
    let longest = maximum
        .checked_add(2)
        .and_then(|x| x.checked_div(3))
        .and_then(|x| x.checked_mul(4))
        .ok_or_else(|| anyhow::anyhow!("base64 bound overflow"))?;
    ensure!(!text.is_empty() && text.len() <= longest, "base64 length bound");
    let bytes = STANDARD.decode(text)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum && STANDARD.encode(&bytes) == text,
        "base64 canonical encoding"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_at_any_depth() {
        for text in [r#"{"a":1,"a":2}"#, r#"{"a":[{"x":1,"x":2}]}"#] {
            assert!(parse(text.as_bytes(), 1024).is_err());
        }
    }
    #[test]
    fn rejects_trailing_float_and_bound() {
        assert!(parse(b"{}{}", 1024).is_err());
        assert!(parse(b"{\"a\":1.5}", 1024).is_err());
        assert!(parse(b"", 1024).is_err());
        let mut oversized = b"{\"x\":\"".to_vec();
        oversized.extend(vec![b'a'; 1024]);
        oversized.extend_from_slice(b"\"}");
        assert!(
            matches!(parse(&oversized, 1024), Err(error) if error.to_string() == "request byte bound")
        );
        assert!(parse_object(b"[1]", 1024).is_err());
    }
    #[test]
    fn sorts_nested_objects_independent_of_dependency_features() -> Result<()> {
        let value = parse(br#"{"z":{"b":2,"a":1},"a":0}"#, 1024)?;
        assert_eq!(canonical(&value)?, br#"{"a":0,"z":{"a":1,"b":2}}"#);
        assert!(canonical(&Value::String("\u{e9}".into())).is_err());
        Ok(())
    }
    #[test]
    fn digests_and_integers_are_bounded() {
        assert!(digest(&Value::String("00".repeat(32))).is_err());
        assert!(digest(&Value::String("0A".repeat(32))).is_err());
        assert!(digest(&Value::String("0a".repeat(31))).is_err());
        assert!(digest(&Value::String("0a".repeat(32))).is_ok());
        assert!(integer(&Value::from(5), 1, 5).is_ok());
        assert!(integer(&Value::from(6), 1, 5).is_err());
        assert!(integer(&Value::from(-1), 0, 5).is_err());
        assert!(integer(&Value::from("5"), 0, 5).is_err());
    }
    #[test]
    fn base64_is_canonical_and_exact() {
        let text = STANDARD.encode([7u8; 32]);
        assert_eq!(decode_exact(&text, 32).ok(), Some(vec![7u8; 32]));
        assert!(decode_exact(&text, 31).is_err());
        assert!(decode_exact(&text.replace('=', "A"), 32).is_err());
        assert!(decode_bounded(&text, 32).is_ok());
        assert!(decode_bounded(&text, 31).is_err());
        assert!(decode_bounded("", 32).is_err());
        assert!(decode_bounded("AA=", 32).is_err());
        assert!(decode_bounded("AB==", 32).is_err());
    }
}
