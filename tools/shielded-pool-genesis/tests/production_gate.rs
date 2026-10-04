/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The development key is never what a genesis falls back to.
//!
//! The generator used the development key -- fixed seed, toxic waste in the
//! source -- whenever no key was named, and wrote "unknown" for the profile's
//! provenance. A pool built that way protects nothing. Now the development key
//! is used only when asked for by name, the manifest says which kind of key it
//! carries, and `require_production` refuses development keys, keys with no
//! ceremony, and unknown provenance.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use shielded_pool_genesis::manifest::{render, require_production};
use shielded_pool_genesis::{build, development_parameters, plan, KeyClass, Request};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const TRANSCRIPT: &str = "7c0f5b1d9b1a2e8f1c4d6e7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c";

/// A key that is not the development key: the development key with one bit
/// flipped, the closest a wrong check could come to passing.
fn ceremony_key() -> Vec<u8> {
    let mut key =
        development_parameters(&root()).expect("the development parameters").verifying_key;
    let last = key.len() - 1;
    key[last] ^= 0x01;
    key
}

fn production() -> Request {
    Request {
        development: false,
        verifying_key: Some(ceremony_key()),
        ceremony_transcript: Some(TRANSCRIPT.into()),
        source_commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
        source_blob: Some("89abcdef0123456789abcdef0123456789abcdef".into()),
    }
}

fn refused(request: Request, reason: &str) {
    let error = plan(&root(), request).err().expect("the request was accepted");
    assert!(error.to_string().contains(reason), "refused for another reason: {error}");
}

#[test]
fn naming_no_key_is_refused_rather_than_given_the_development_key() {
    refused(Request::default(), "needs a ceremony verifying key");
}

#[test]
fn the_development_key_is_refused_in_production_even_when_named() {
    let mut request = production();
    request.verifying_key = Some(development_parameters(&root()).unwrap().verifying_key);
    refused(request, "development verifying key");
}

#[test]
fn a_ceremony_key_needs_its_transcript_and_the_profile_provenance() {
    let mut request = production();
    request.ceremony_transcript = None;
    refused(request, "transcript digest");

    let mut request = production();
    request.ceremony_transcript = Some("ABCDEF".into());
    refused(request, "64 lowercase hex");

    for (commit, blob) in
        [(None, Some("b")), (Some("c"), None), (Some("unknown"), Some("b")), (Some(""), Some("b"))]
    {
        let mut request = production();
        request.source_commit = commit.map(String::from);
        request.source_blob = blob.map(String::from);
        refused(request, "source commit and blob");
    }
}

#[test]
fn a_development_genesis_takes_no_key_and_is_marked_so_production_refuses_it() {
    let mut request = Request { development: true, ..Request::default() };
    request.verifying_key = Some(ceremony_key());
    refused(request, "takes no verifying key");

    let (parameters, key, provenance) =
        plan(&root(), Request { development: true, ..Request::default() })
            .expect("a development genesis");
    assert_eq!(key, KeyClass::Development);
    let manifest = render(&build(parameters).unwrap(), &provenance, &key, None).unwrap();
    assert!(manifest.contains("\"class\": \"development\""));
    let error = require_production(&manifest).expect_err("a development manifest passed");
    assert!(error.to_string().contains("development verifying key"), "{error}");
}

#[test]
fn a_ceremony_genesis_is_marked_and_passes_the_production_check() {
    let (parameters, key, provenance) = plan(&root(), production()).expect("a production genesis");
    assert_eq!(key, KeyClass::Ceremony { transcript: TRANSCRIPT.into() });
    let manifest = render(&build(parameters).unwrap(), &provenance, &key, None).unwrap();
    require_production(&manifest).expect("a ceremony manifest with provenance is deployable");

    // Each field the check reads, taken away, is refused.
    for (from, to) in [
        ("\"class\": \"ceremony\"", "\"class\": \"development\""),
        ("\"class\": \"ceremony\"", "\"class\": \"other\""),
        (TRANSCRIPT, "short"),
        ("0123456789abcdef0123456789abcdef01234567", "unknown"),
        ("89abcdef0123456789abcdef0123456789abcdef", "unknown"),
    ] {
        assert!(require_production(&manifest.replace(from, to)).is_err(), "{from} -> {to} passed");
    }
}

#[test]
fn the_frozen_manifest_is_a_development_genesis_and_is_refused_for_production() {
    let text =
        std::fs::read_to_string(root().join("artifacts/shielded-pool/genesis-manifest.json"))
            .expect("the frozen manifest");
    assert!(text.contains("\"class\": \"development\""));
    assert!(require_production(&text).is_err());
}
