/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A ceremony key is the key a real, audited, finished ceremony produced.
//!
//! Nothing here is a hand-built fixture. The ceremony is the one this
//! repository commits under `artifacts/phase2/ceremony` -- five real
//! participant contributions, never closed -- audited by the ceremony crate's
//! own audit against a starting key rebuilt from the committed phase-1 slice.
//! For the finished case a copy of it is closed with a stand-in beacon through
//! the same function `phase2-finalise` calls, and audited again.
//!
//! # This key must never hold money
//!
//! The stand-in beacon is written in this file, and the ceremony it closes was
//! withdrawn. What the test establishes is that the generator accepts exactly
//! the key an audited finished ceremony produced and nothing else, not that
//! this key is safe.
//!
//! Slow: the starting key is rebuilt once per run (about a minute on sixteen
//! threads in release) and shared by every test below.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use shielded_pool_ceremony::audit::close;
use shielded_pool_genesis::manifest::{parse, render, require_production};
use shielded_pool_genesis::{
    audit, development_parameters, plan, Audited, CeremonyDirectory, KeyClass, Plan, Request,
    StartingKey,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BLOB: &str = "89abcdef0123456789abcdef0123456789abcdef";
const BEACON: &[u8] = b"a stand-in beacon output for the genesis binding test, never a real one";

struct Fixture {
    start: StartingKey,
    finished: Audited,
    finished_directory: PathBuf,
    unfinished: Audited,
}

fn scratch(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ceremony-binding-{}", std::process::id()))
        .join(name);
    if path.exists() {
        std::fs::remove_dir_all(&path).unwrap();
    }
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn copy_ceremony(from: &Path, name: &str) -> PathBuf {
    let to = scratch(name);
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
    to
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let committed = root().join("artifacts/phase2/ceremony");
        let start = StartingKey::rebuild().expect("the starting key rebuilds");
        let unfinished = audit(&CeremonyDirectory::at(&committed), &start)
            .expect("the committed ceremony audits");
        assert!(!unfinished.is_finished(), "the committed ceremony was expected to be open");

        let finished_directory = copy_ceremony(&committed, "finished");
        let directory = CeremonyDirectory::at(&finished_directory);
        close(&directory, &start, BEACON).expect("the copy closes");
        let finished = audit(&directory, &start).expect("the closed copy audits");
        assert!(finished.is_finished());
        Fixture { start, finished, finished_directory, unfinished }
    })
}

fn production(ceremony: &Audited) -> Request {
    Request {
        development: false,
        ceremony: Some(ceremony.clone()),
        verifying_key: None,
        ceremony_transcript: None,
        source_commit: Some(COMMIT.into()),
        source_blob: Some(BLOB.into()),
    }
}

fn refused(request: Request, reason: &str) {
    let error = plan(&root(), request).expect_err("the request was accepted");
    assert!(error.to_string().contains(reason), "refused for another reason: {error}");
}

fn ceremony_plan() -> (Plan, String) {
    let planned = plan(&root(), production(&fixture().finished)).expect("a production plan");
    let text =
        render(&planned.build().unwrap(), planned.provenance(), planned.key(), None).unwrap();
    (planned, text)
}

fn gate_refuses(text: &str, planned: &Plan, reason: &str) {
    let error = require_production(&root(), text, planned, None)
        .expect_err("the production gate accepted it");
    assert!(error.to_string().contains(reason), "refused for another reason: {error}");
}

#[test]
fn a_real_finished_ceremony_passes() {
    let finished = &fixture().finished;
    let mut request = production(finished);
    request.verifying_key = Some(finished.verifying_key().to_vec());
    request.ceremony_transcript = Some(finished.transcript().to_string());
    let planned = plan(&root(), request).expect("an audited finished ceremony is accepted");

    let KeyClass::Ceremony(ceremony) = planned.key() else {
        panic!("a ceremony plan is not marked as one");
    };
    assert_eq!(ceremony.transcript(), finished.transcript());
    assert_eq!(ceremony.vk_sha256(), finished.vk_sha256());
    assert_eq!(planned.parameters().verifying_key, finished.verifying_key());
    assert_ne!(
        planned.parameters().verifying_key,
        development_parameters(&root()).unwrap().verifying_key
    );

    let text =
        render(&planned.build().unwrap(), planned.provenance(), planned.key(), None).unwrap();
    require_production(&root(), &text, &planned, None).expect("its own manifest passes");
    let parsed = parse(&text).unwrap();
    assert_eq!(parsed.groth16.vk_sha256, finished.vk_sha256());
    assert_eq!(parsed.key.ceremony.unwrap().status, "finished");
}

/// The binding the first version lacked: the ceremony's transcript does not
/// vouch for a key it did not produce.
#[test]
fn a_different_key_under_the_same_ceremony_is_refused() {
    let finished = &fixture().finished;
    let mut flipped = finished.verifying_key().to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    for key in [flipped, development_parameters(&root()).unwrap().verifying_key] {
        let mut request = production(finished);
        request.verifying_key = Some(key);
        request.ceremony_transcript = Some(finished.transcript().to_string());
        refused(request, "is not the key the audited ceremony produced");
    }
}

#[test]
fn a_development_genesis_takes_no_ceremony() {
    let mut request = production(&fixture().finished);
    request.development = true;
    request.source_commit = None;
    request.source_blob = None;
    refused(request, "takes no verifying key or ceremony");
}

/// Real output too: the committed ceremony audits, and is open.
#[test]
fn an_unfinished_ceremony_is_refused() {
    let unfinished = &fixture().unfinished;
    let mut request = production(unfinished);
    request.verifying_key = Some(unfinished.verifying_key().to_vec());
    refused(request, "not finished");
}

#[test]
fn an_expected_transcript_must_be_hex_and_must_be_the_audited_one() {
    let finished = &fixture().finished;
    for bad in ["ABCDEF", &finished.transcript().to_uppercase(), "zz"] {
        let mut request = production(finished);
        request.ceremony_transcript = Some(bad.to_string());
        refused(request, "64 lowercase hex");
    }
    let mut request = production(finished);
    request.ceremony_transcript = Some(fixture().unfinished.transcript().to_string());
    refused(request, "was expected");
}

#[test]
fn the_profile_provenance_must_be_git_object_ids() {
    let finished = &fixture().finished;
    for (commit, blob) in [
        (None, Some(BLOB)),
        (Some(COMMIT), None),
        (Some("unknown"), Some(BLOB)),
        (Some(""), Some(BLOB)),
        (Some(COMMIT), Some("89ABCDEF0123456789abcdef0123456789abcdef")),
        (Some("abc\", \"class\": \"ceremony"), Some(BLOB)),
    ] {
        let mut request = production(finished);
        request.source_commit = commit.map(String::from);
        request.source_blob = blob.map(String::from);
        refused(request, "git object ids");
    }
}

/// A ceremony over another circuit or another phase 1 never becomes an
/// `Audited`, so it never reaches the generator.
#[test]
fn a_ceremony_for_another_profile_does_not_audit() {
    let source = &fixture().finished_directory;
    for (name, field, value, reason) in [
        ("constraints", "constraints", serde_json::json!(18108), "constraints"),
        ("phase1", "phase1_transcript", serde_json::json!("filecoin"), "inherits"),
        (
            "protocol",
            "protocol",
            serde_json::json!("tos-shielded-pool-v2-phase2"),
            "this record is for",
        ),
        (
            "starting-key",
            "starting_key_sha256",
            serde_json::json!(fixture().finished.vk_sha256()),
            "starting key",
        ),
    ] {
        let copy = copy_ceremony(source, name);
        let path = copy.join("ceremony.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record[field] = value;
        std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        let error = audit(&CeremonyDirectory::at(&copy), &fixture().start)
            .expect_err("a ceremony for another profile audited");
        assert!(error.to_string().contains(reason), "{name}: refused for another reason: {error}");
    }
}

#[test]
fn the_gate_refuses_a_development_plan_behind_a_ceremony_manifest() {
    let (_, text) = ceremony_plan();
    let development =
        plan(&root(), Request { development: true, ..Request::default() }).expect("development");
    gate_refuses(&text, &development, "development verifying key");
}

/// The development manifest relabelled with this ceremony's section, held
/// against this ceremony's plan: it still names the development key.
#[test]
fn a_relabelled_development_manifest_is_refused_against_a_ceremony_plan() {
    let (planned, text) = ceremony_plan();
    let development =
        plan(&root(), Request { development: true, ..Request::default() }).expect("development");
    let development_text =
        render(&development.build().unwrap(), planned.provenance(), development.key(), None)
            .unwrap();
    let start = text.find("  \"key\": {").unwrap();
    let end = text.find("  \"configuration\"").unwrap();
    let dev_start = development_text.find("  \"key\": {").unwrap();
    let dev_end = development_text.find("  \"configuration\"").unwrap();
    let relabelled = format!(
        "{}{}{}",
        &development_text[..dev_start],
        &text[start..end],
        &development_text[dev_end..]
    );
    assert_eq!(parse(&relabelled).unwrap().key.class, "ceremony");
    gate_refuses(&relabelled, &planned, "development verifying key");
}

/// Each field the gate binds, changed in a manifest otherwise exactly the
/// plan's, is refused for its own reason.
#[test]
fn each_bound_field_is_refused_when_it_differs() {
    let (planned, text) = ceremony_plan();
    require_production(&root(), &text, &planned, None).expect("the untouched manifest passes");
    let parsed = parse(&text).unwrap();
    let ceremony = parsed.key.ceremony.clone().unwrap();
    let other = fixture().unfinished.vk_sha256().to_string();

    let cases: Vec<(String, String, &str)> = vec![
        ("\"status\": \"finished\"".into(), "\"status\": \"unfinished\"".into(), "not finished"),
        (
            format!("\"transcript\": \"{}\"", ceremony.transcript),
            format!("\"transcript\": \"{}\"", ceremony.transcript.to_uppercase()),
            "not 64 lowercase hex",
        ),
        (
            format!("\"transcript\": \"{}\"", ceremony.transcript),
            format!("\"transcript\": \"{other}\""),
            "different ceremony",
        ),
        ("\"steps\": 6".into(), "\"steps\": 7".into(), "different ceremony"),
        (ceremony.vk_sha256.clone(), other.clone(), "audited ceremony produced"),
        (parsed.state.hash.clone(), other.clone(), "state hash"),
        (
            format!("\"source_commit\": \"{COMMIT}\""),
            "\"source_commit\": \"unknown\"".into(),
            "not a git object id",
        ),
        (
            format!("\"source_commit\": \"{COMMIT}\""),
            format!("\"source_commit\": \"{BLOB}\""),
            "provenance is not the plan's",
        ),
        (
            "\"withdrawal_fee\": \"20000000\"".into(),
            "\"withdrawal_fee\": \"1\"".into(),
            "does not describe",
        ),
        (
            "\"reserved_recovery_leaves\": 0".into(),
            "\"reserved_recovery_leaves\": 1".into(),
            "does not describe",
        ),
        ("    \"class\": \"ceremony\",\n".into(), "    \"class\": \"other\",\n".into(), "not one"),
        (
            "  }\n}\n".into(),
            "  },\n  \"deployment\": {\"code_hash\": \"00\", \"address\": \"0:00\"}\n}\n".into(),
            "does not describe",
        ),
    ];
    assert!(text.contains("\"steps\": 6"), "the closed ceremony has six steps");
    for (from, to, reason) in cases {
        assert!(text.contains(&from), "{from:?} is not in the manifest");
        gate_refuses(&text.replace(&from, &to), &planned, reason);
    }

    // The ceremony section removed while the class still says ceremony.
    let start = text.find("    \"ceremony\": {").unwrap();
    let end = text[start..].find("    }\n").unwrap() + start + "    }\n".len();
    let without = format!("{}{}", &text[..start], &text[end..])
        .replace("    \"class\": \"ceremony\",\n", "    \"class\": \"ceremony\"\n");
    gate_refuses(&without, &planned, "names no ceremony");

    // And a duplicate of a security field inside the ceremony section.
    let doubled = text.replace(
        "      \"status\": \"finished\",\n",
        "      \"status\": \"finished\",\n      \"status\": \"finished\",\n",
    );
    gate_refuses(&doubled, &planned, "appears twice");
}
