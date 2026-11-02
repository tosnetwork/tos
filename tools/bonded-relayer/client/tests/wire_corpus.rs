// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The Python reference and this crate agree on every vector of the committed
//! differential corpus (`test/bonded-relayer/fixtures/br1-wire-corpus.json`,
//! produced by `test/bonded-relayer/br1_wire_corpus.py`).
use br1_client::{http, quote, release::Release, request::Request, wire};
use serde_json::Value;

fn corpus() -> anyhow::Result<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../test/bonded-relayer/fixtures/br1-wire-corpus.json");
    let text = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&text)?)
}

fn cases(value: &Value) -> anyhow::Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| anyhow::anyhow!("array"))
}

#[test]
fn release_scope_canonical_and_parse_agree() -> anyhow::Result<()> {
    let corpus = corpus()?;
    assert_eq!(corpus["schema"], "tos.br1.wire-corpus.v1");
    let release: Release = serde_json::from_value(corpus["release"]["fields"].clone())?;
    release.validate()?;
    assert_eq!(release.scope()?, corpus["release"]["scope"]);
    for case in cases(&corpus["canonical"])? {
        let encoded = String::from_utf8(wire::canonical(&case["input"])?)?;
        assert_eq!(encoded, case["encoded"], "{}", case["input"]);
    }
    for case in cases(&corpus["parse"])? {
        let text = case["text"].as_str().ok_or_else(|| anyhow::anyhow!("text"))?;
        let refused = wire::parse_object(text.as_bytes(), 1 << 20).is_err();
        assert_eq!(refused, case["refused"], "{text:?}");
    }
    let token = corpus["status_hash"]["token"].as_str().ok_or_else(|| anyhow::anyhow!("token"))?;
    assert_eq!(quote::status_hash(token)?, corpus["status_hash"]["hash"]);
    Ok(())
}

#[test]
fn quote_terms_agree() -> anyhow::Result<()> {
    let corpus = corpus()?;
    let scope = corpus["release"]["scope"].as_str().ok_or_else(|| anyhow::anyhow!("scope"))?;
    let terms = &corpus["terms"]["value"];
    let typed = quote::check_terms(terms, scope)?;
    assert_eq!((typed.slot, typed.amount, typed.note_index), (2, 7, 5));
    assert_eq!(quote::identity(terms)?, corpus["terms"]["identity"]);
    for case in cases(&corpus["terms"]["cases"])? {
        let field = case["field"].as_str().ok_or_else(|| anyhow::anyhow!("field"))?;
        let mut altered = terms.clone();
        altered[field] = case["value"].clone();
        let refused = quote::check_terms(&altered, scope).is_err();
        assert_eq!(refused, case["refused"], "{field}={}", case["value"]);
    }
    Ok(())
}

#[test]
fn requests_agree() -> anyhow::Result<()> {
    let corpus = corpus()?;
    let wire_text = corpus["request"]["wire"].as_str().ok_or_else(|| anyhow::anyhow!("wire"))?;
    let request = Request::parse(wire_text.as_bytes())?;
    assert_eq!(String::from_utf8(request.wire()?)?, wire_text);
    assert_eq!(request.identity()?, corpus["request"]["identity"]);
    assert_eq!(serde_json::to_value(&request)?, corpus["request"]["value"]);
    for case in cases(&corpus["request"]["cases"])? {
        let field = case["field"].as_str().ok_or_else(|| anyhow::anyhow!("field"))?;
        let mut altered = corpus["request"]["value"].clone();
        altered[field] = case["value"].clone();
        let refused = Request::parse(&wire::canonical(&altered)?).is_err();
        assert_eq!(refused, case["refused"], "{field}={}", case["value"]);
    }
    assert_eq!(corpus["limits"]["max_body"], br1_client::request::MAX_BODY_BYTES);
    assert_eq!(corpus["limits"]["max_request_wire"], br1_client::request::MAX_REQUEST_WIRE_BYTES);
    assert_eq!(corpus["limits"]["http_body_limit"], br1_client::request::MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn status_lines_agree() -> anyhow::Result<()> {
    let corpus = corpus()?;
    for case in cases(&corpus["status_lines"])? {
        let line = case["line"].as_str().ok_or_else(|| anyhow::anyhow!("line"))?;
        assert_eq!(http::status_code(line).is_some(), case["answered"], "{line:?}");
    }
    Ok(())
}
