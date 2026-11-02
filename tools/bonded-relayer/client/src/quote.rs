// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Quote terms and their authentication. A quote is the relayer's signed
//! offer: a fee amount, a receiving descriptor at a reserved index, a funding
//! cap and a window. Its identity is the hash of its canonical terms.
use crate::wire;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::Value;
use shielded_pool_wallet::relayer_quote;

pub const TERMS_SCHEMA: &str = "tos.br1.quote.terms.v1";
pub const ENVELOPE_SCHEMA: &str = "tos.br1.quote.v1";
pub const RESPONSE_SCHEMA: &str = "tos.br1.quote.response.v1";
pub const SUCCESS: &str = "pool_execution";
pub const QUOTE_TAG: &[u8] = b"TOS-BR1-QUOTE\0";
pub const STATUS_TAG: &[u8] = b"TOS-BR1-STATUS\0";
/// The longest quote window the protocol allows, in seconds.
pub const MAX_LIFETIME: u64 = 300;
/// The most bytes a quote envelope may have.
pub const MAX_QUOTE_BYTES: usize = 32 * 1024;
pub const DESCRIPTOR_BYTES: usize = 2573;
pub const DESCRIPTOR_BASE64: usize = 3432;
pub const ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1312;
pub const ML_DSA_44_SIGNATURE_BYTES: usize = 2420;

/// The twelve members of `tos.br1.quote.terms.v1`, exactly.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub schema: String,
    pub release: String,
    pub nonce: String,
    pub note_index: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    pub slot: u8,
    pub amount: u64,
    pub funding_cap: u64,
    pub descriptor_b64: String,
    pub status_hash: String,
    pub success: String,
}

/// Structural and semantic checks of quote terms against the wallet's
/// release scope, as `relay_wire.check_terms` makes them. Not a signature
/// check and not a check of the descriptor's derivation.
pub fn check_terms(value: &Value, scope: &str) -> Result<Terms> {
    wire::fields(
        value,
        &[
            "schema",
            "release",
            "nonce",
            "note_index",
            "issued_at",
            "valid_until",
            "slot",
            "amount",
            "funding_cap",
            "descriptor_b64",
            "status_hash",
            "success",
        ],
    )
    .map_err(|_| anyhow::anyhow!("quote terms shape"))?;
    ensure!(
        value["schema"] == TERMS_SCHEMA && value["release"] == scope && value["success"] == SUCCESS,
        "quote semantics mismatch"
    );
    wire::digest(&value["nonce"])?;
    wire::digest(&value["status_hash"])?;
    wire::integer(&value["slot"], 0, 2)?;
    wire::integer(&value["note_index"], 0, (1 << 63) - 1)?;
    wire::integer(&value["amount"], 1, (1 << 63) - 1)?;
    wire::integer(&value["funding_cap"], 1, (1 << 63) - 1)?;
    let issued = wire::integer(&value["issued_at"], 1, u64::from(u32::MAX))?;
    let maximum = issued
        .checked_add(MAX_LIFETIME)
        .filter(|m| *m <= u64::from(u32::MAX))
        .ok_or_else(|| anyhow::anyhow!("bounded addition overflow"))?;
    wire::integer(&value["valid_until"], issued.saturating_add(1), maximum)?;
    let descriptor =
        value["descriptor_b64"].as_str().ok_or_else(|| anyhow::anyhow!("descriptor width"))?;
    ensure!(descriptor.len() == DESCRIPTOR_BASE64, "descriptor width");
    let decoded = wire::decode_exact(descriptor, DESCRIPTOR_BYTES)
        .map_err(|_| anyhow::anyhow!("descriptor encoding"))?;
    let index = u64::from_be_bytes(
        decoded[37..45].try_into().map_err(|_| anyhow::anyhow!("descriptor index width"))?,
    );
    ensure!(
        &decoded[..5] == b"SHD1\x01" && value["note_index"] == index,
        "descriptor index or version mismatch"
    );
    let terms: Terms = serde_json::from_value(value.clone())?;
    Ok(terms)
}

/// The quote's identity: the tagged hash of its canonical terms.
pub fn identity(terms: &Value) -> Result<String> {
    let mut bytes = QUOTE_TAG.to_vec();
    bytes.extend(wire::canonical(terms)?);
    Ok(wire::hash(&bytes))
}

/// The capability hash a quote binds: the tagged hash of the token's raw
/// 32 bytes. The token itself is a nonzero lowercase 64-hex string.
pub fn status_hash(token: &str) -> Result<String> {
    wire::digest_str(token)?;
    let mut bytes = STATUS_TAG.to_vec();
    bytes.extend(hex::decode(token)?);
    Ok(wire::hash(&bytes))
}

/// Authenticate quote terms against `expected`, the pinned worker key:
/// canonical base64 of exactly the ML-DSA-44 key and signature widths, a key
/// equal to `expected`, and a valid signature over the exact `terms` bytes.
/// The provider's own verification and the wallet's both use this, so they
/// cannot disagree on which quotes are valid.
pub fn verify_quote_signature(
    expected: &[u8],
    terms: &[u8],
    public_b64: &str,
    signature_b64: &str,
) -> Result<()> {
    let public = wire::decode_exact(public_b64, ML_DSA_44_PUBLIC_KEY_BYTES)?;
    ensure!(public.as_slice() == expected, "quote worker mismatch");
    let public: [u8; ML_DSA_44_PUBLIC_KEY_BYTES] =
        public.try_into().map_err(|_| anyhow::anyhow!("key width"))?;
    let signature = wire::decode_exact(signature_b64, ML_DSA_44_SIGNATURE_BYTES)?;
    let signature: [u8; ML_DSA_44_SIGNATURE_BYTES] =
        signature.try_into().map_err(|_| anyhow::anyhow!("signature width"))?;
    relayer_quote::verify_terms(&public, terms, &signature)?;
    Ok(())
}

/// An envelope `tos.br1.quote.v1` whose terms the pinned worker signed and
/// whose release is `scope`: returns the terms object, exactly as signed.
/// Schema, time, capability, slot and request binding are the caller's.
pub fn verify_envelope(worker_key: &[u8], envelope: &Value, scope: &str) -> Result<Value> {
    wire::fields(envelope, &["schema", "terms", "public_key_b64", "signature_b64"])?;
    ensure!(envelope["schema"] == ENVELOPE_SCHEMA, "quote envelope schema");
    let terms = wire::canonical(&envelope["terms"])?;
    ensure!(envelope["terms"]["release"] == scope, "wallet quote release pin");
    verify_quote_signature(
        worker_key,
        &terms,
        envelope["public_key_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote key"))?,
        envelope["signature_b64"].as_str().ok_or_else(|| anyhow::anyhow!("quote signature"))?,
    )?;
    Ok(envelope["terms"].clone())
}

/// A signed envelope over `terms`, for the relayer's side and for tests.
pub fn sign_envelope(
    private: &fips204::ml_dsa_44::PrivateKey,
    public: &[u8],
    terms: &Value,
) -> Result<Value> {
    let signature = relayer_quote::sign_terms(private, &wire::canonical(terms)?)?;
    Ok(serde_json::json!({
        "schema": ENVELOPE_SCHEMA,
        "terms": terms,
        "public_key_b64": STANDARD.encode(public),
        "signature_b64": STANDARD.encode(signature),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use fips204::{
        ml_dsa_44,
        traits::{KeyGen, SerDes},
    };
    use serde_json::json;

    /// A descriptor-shaped value with the given index, for shape checks only.
    pub(crate) fn descriptor_b64(index: u64) -> String {
        let mut data = vec![0u8; DESCRIPTOR_BYTES];
        data[..5].copy_from_slice(b"SHD1\x01");
        data[5..37].copy_from_slice(&[1u8; 32]);
        data[37..45].copy_from_slice(&index.to_be_bytes());
        STANDARD.encode(data)
    }

    pub(crate) fn terms(scope: &str, token: &str, now: u64) -> Result<Value> {
        Ok(json!({
            "schema": TERMS_SCHEMA,
            "release": scope,
            "nonce": "0a".repeat(32),
            "note_index": 5,
            "issued_at": now,
            "valid_until": now + MAX_LIFETIME,
            "slot": 2,
            "amount": 7,
            "funding_cap": 250_000_000u64,
            "descriptor_b64": descriptor_b64(5),
            "status_hash": status_hash(token)?,
            "success": SUCCESS,
        }))
    }

    #[test]
    fn terms_shape_and_bounds() -> Result<()> {
        let scope = "0b".repeat(32);
        let token = "0c".repeat(32);
        let good = terms(&scope, &token, 1_700_000_000)?;
        let typed = check_terms(&good, &scope)?;
        assert_eq!((typed.slot, typed.amount, typed.note_index), (2, 7, 5));
        let cases: Vec<(&str, Value)> = vec![
            ("schema", json!("tos.br1.quote.terms.v2")),
            ("release", json!("0d".repeat(32))),
            ("success", json!("broadcast")),
            ("nonce", json!("00".repeat(32))),
            ("slot", json!(3)),
            ("amount", json!(0)),
            ("funding_cap", json!(1u64 << 63)),
            ("valid_until", json!(1_700_000_000u64 + MAX_LIFETIME + 1)),
            ("valid_until", json!(1_700_000_000u64)),
            ("issued_at", json!(0)),
            ("note_index", json!(6)),
            ("descriptor_b64", json!(descriptor_b64(5)[1..].to_owned())),
            ("descriptor_b64", json!(STANDARD.encode(vec![0u8; DESCRIPTOR_BYTES]))),
        ];
        for (field, value) in cases {
            let mut altered = good.clone();
            altered[field] = value.clone();
            assert!(check_terms(&altered, &scope).is_err(), "accepted {field}={value}");
        }
        let mut extra = good.clone();
        extra["extra"] = json!(1);
        assert!(check_terms(&extra, &scope).is_err());
        assert!(check_terms(&good, &"0e".repeat(32)).is_err());
        Ok(())
    }

    #[test]
    fn status_hash_is_over_the_raw_token_bytes() -> Result<()> {
        let token = "0c".repeat(32);
        let mut bytes = STATUS_TAG.to_vec();
        bytes.extend([0x0cu8; 32]);
        assert_eq!(status_hash(&token)?, wire::hash(&bytes));
        assert!(status_hash(&"00".repeat(32)).is_err());
        assert!(status_hash(&"0C".repeat(32)).is_err());
        Ok(())
    }

    #[test]
    fn envelopes_bind_terms_worker_and_scope() -> Result<()> {
        let (public, private) = ml_dsa_44::KG::keygen_from_seed(&[37; 32]);
        let public = public.into_bytes();
        let scope = "0b".repeat(32);
        let t = terms(&scope, &"0c".repeat(32), 1_700_000_000)?;
        let envelope = sign_envelope(&private, &public, &t)?;
        assert_eq!(verify_envelope(&public, &envelope, &scope)?, t);
        assert_eq!(identity(&t)?, {
            let mut b = QUOTE_TAG.to_vec();
            b.extend(wire::canonical(&t)?);
            wire::hash(&b)
        });
        let mut wrong = envelope.clone();
        wrong["terms"]["amount"] = json!(8);
        assert!(verify_envelope(&public, &wrong, &scope).is_err());
        let (other, _) = ml_dsa_44::KG::keygen_from_seed(&[38; 32]);
        let mut wrong = envelope.clone();
        wrong["public_key_b64"] = json!(STANDARD.encode(other.into_bytes()));
        assert!(verify_envelope(&public, &wrong, &scope).is_err());
        let mut wrong = envelope.clone();
        wrong["schema"] = json!("tos.br1.quote.v2");
        assert!(verify_envelope(&public, &wrong, &scope).is_err());
        assert!(verify_envelope(&public, &envelope, &"0d".repeat(32)).is_err());
        let mut altered = wire::decode_exact(
            envelope["signature_b64"].as_str().ok_or_else(|| anyhow::anyhow!("sig"))?,
            ML_DSA_44_SIGNATURE_BYTES,
        )?;
        altered[100] ^= 1;
        let mut wrong = envelope.clone();
        wrong["signature_b64"] = json!(STANDARD.encode(altered));
        assert!(verify_envelope(&public, &wrong, &scope).is_err());
        Ok(())
    }
}
