/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The parts of the production gate that need no ceremony.
//!
//! The development key is never what a genesis falls back to, a key with a
//! transcript digest typed beside it is not a ceremony key, and a manifest is
//! read as typed JSON rather than searched for strings. What needs a real
//! audited ceremony is in `ceremony_binding.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use shielded_pool_genesis::manifest::{parse, render, require_production, Provenance};
use shielded_pool_genesis::{build, development_parameters, plan, KeyClass, Request};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const TRANSCRIPT: &str = "7c0f5b1d9b1a2e8f1c4d6e7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BLOB: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// A key that is not the development key: the development key with one bit
/// flipped, the closest a wrong check could come to passing.
fn other_key() -> Vec<u8> {
    let mut key =
        development_parameters(&root()).expect("the development parameters").verifying_key;
    let last = key.len() - 1;
    key[last] ^= 0x01;
    key
}

fn refused(request: Request, reason: &str) {
    let error = plan(&root(), request).expect_err("the request was accepted");
    assert!(error.to_string().contains(reason), "refused for another reason: {error}");
}

fn development_manifest() -> (shielded_pool_genesis::Plan, String) {
    let planned =
        plan(&root(), Request { development: true, ..Request::default() }).expect("development");
    let text =
        render(&planned.build().unwrap(), planned.provenance(), planned.key(), None).unwrap();
    (planned, text)
}

fn gate_refuses(text: &str, planned: &shielded_pool_genesis::Plan, reason: &str) {
    let error = require_production(&root(), text, planned, None)
        .expect_err("the production gate accepted it");
    assert!(error.to_string().contains(reason), "refused for another reason: {error}");
}

#[test]
fn naming_no_key_is_refused_rather_than_given_the_development_key() {
    refused(Request::default(), "needs an audited ceremony");
}

/// The shape the first version of this gate accepted: some 1,248-byte key and
/// a well-formed transcript digest beside it. Without an audited ceremony the
/// digest binds nothing, so it is refused however plausible it looks.
#[test]
fn a_key_and_a_typed_in_transcript_are_not_a_ceremony() {
    refused(
        Request {
            verifying_key: Some(other_key()),
            ceremony_transcript: Some(TRANSCRIPT.into()),
            source_commit: Some(COMMIT.into()),
            source_blob: Some(BLOB.into()),
            ..Request::default()
        },
        "needs an audited ceremony",
    );
}

#[test]
fn a_development_genesis_takes_no_key_and_no_transcript() {
    let mut request = Request { development: true, ..Request::default() };
    request.verifying_key = Some(other_key());
    refused(request, "takes no verifying key");

    let mut request = Request { development: true, ..Request::default() };
    request.ceremony_transcript = Some(TRANSCRIPT.into());
    refused(request, "takes no verifying key");
}

#[test]
fn a_development_genesis_is_marked_so_production_refuses_it() {
    let (planned, manifest) = development_manifest();
    assert_eq!(planned.key(), &KeyClass::Development);
    assert_eq!(parse(&manifest).unwrap().key.class, "development");
    gate_refuses(&manifest, &planned, "development verifying key");
}

/// Relabelled: the development manifest claiming a ceremony, with a
/// well-formed ceremony section. The development plan behind it is refused,
/// and so is the development key it names (the second is checked with a
/// ceremony plan in `ceremony_binding.rs`).
#[test]
fn a_relabelled_development_manifest_is_refused() {
    let (planned, manifest) = development_manifest();
    let relabelled = manifest.replace(
        "    \"class\": \"development\"\n",
        &format!(
            "    \"class\": \"ceremony\",\n    \"ceremony\": {{\"protocol\": \
             \"tos-shielded-pool-v1-phase2\", \"status\": \"finished\", \"steps\": 6, \
             \"transcript\": \"{TRANSCRIPT}\", \"beacon_sha256\": \"{TRANSCRIPT}\", \
             \"phase1_transcript\": \"zcash\", \"phase1_slice_sha256\": \"{TRANSCRIPT}\", \
             \"starting_key_sha256\": \"{TRANSCRIPT}\", \"constraints\": 18107, \
             \"instance_variables\": 19, \"key_sha256\": \"{TRANSCRIPT}\", \"vk_sha256\": \
             \"{TRANSCRIPT}\"}}\n"
        ),
    );
    assert_ne!(relabelled, manifest, "the relabelling did not apply");
    assert_eq!(parse(&relabelled).unwrap().key.class, "ceremony");
    gate_refuses(&relabelled, &planned, "development verifying key");
}

/// A second `class` inside the same object. A parser that keeps the last one
/// reads "ceremony"; a reader skimming the file sees "development" first.
#[test]
fn a_duplicate_field_is_refused() {
    let (planned, manifest) = development_manifest();
    let doubled = manifest.replace(
        "    \"class\": \"development\"\n",
        "    \"class\": \"development\",\n    \"class\": \"ceremony\"\n",
    );
    assert_ne!(doubled, manifest);
    let error = parse(&doubled).expect_err("a duplicate key was read");
    assert!(error.to_string().contains("appears twice"), "{error}");
    gate_refuses(&doubled, &planned, "appears twice");

    // The same, at the top level.
    let doubled = manifest.replacen("{\n", "{\n  \"note\": \"x\",\n", 1);
    gate_refuses(&doubled, &planned, "appears twice");
}

/// A `"class": "ceremony"` placed where the old string search would have
/// found it first, inside another object, is an unknown field there.
#[test]
fn a_misplaced_security_field_is_refused() {
    let (planned, manifest) = development_manifest();
    let nested = manifest.replacen(
        "  \"profile\": {\n",
        "  \"profile\": {\n    \"class\": \"ceremony\",\n    \"ceremony_transcript\": \"x\",\n",
        1,
    );
    assert_ne!(nested, manifest);
    let error = parse(&nested).expect_err("a misplaced field was read");
    assert!(error.to_string().contains("unknown field"), "{error}");
    gate_refuses(&nested, &planned, "unknown field");

    for broken in [
        manifest.replace("\"vk_bytes\": 1248", "\"vk_bytes\": \"1248\""),
        format!("{manifest}{{}}"),
        manifest.replace("  \"key\": {\n    \"class\": \"development\"\n  },\n", ""),
    ] {
        assert_ne!(broken, manifest);
        assert!(parse(&broken).is_err(), "a malformed manifest was read:\n{broken}");
    }
}

/// Provenance strings come from the command line. Rendered raw, a quote in one
/// closes the string and opens a field of the caller's choosing.
#[test]
fn provenance_is_escaped_when_rendered() {
    let injected = "abc\", \"class\": \"ceremony";
    let genesis = build(development_parameters(&root()).unwrap()).unwrap();
    let provenance =
        Provenance { source_commit: injected.into(), source_blob: "line\nbreak\\".into() };
    let manifest = render(&genesis, &provenance, &KeyClass::Development, None).unwrap();
    let parsed = parse(&manifest).expect("an escaped manifest still parses");
    assert_eq!(parsed.profile.source_commit, injected);
    assert_eq!(parsed.profile.source_blob, "line\nbreak\\");
    assert_eq!(parsed.key.class, "development");
}

/// The frozen manifest is a development genesis, parses as exactly what the
/// generator renders for one, and is refused for production.
#[test]
fn the_frozen_manifest_is_a_development_genesis_and_is_refused_for_production() {
    let text =
        std::fs::read_to_string(root().join("artifacts/shielded-pool/genesis-manifest.json"))
            .expect("the frozen manifest");
    let (planned, rendered) = development_manifest();
    assert_eq!(text, rendered, "the frozen manifest is not what --development renders");
    assert_eq!(parse(&text).unwrap().key.class, "development");
    gate_refuses(&text, &planned, "development verifying key");
}
