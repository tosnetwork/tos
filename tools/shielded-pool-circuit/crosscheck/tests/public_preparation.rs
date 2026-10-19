//! The offline entry point refuses mismatched public inputs without writing
//! even a partial candidate directory.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}
fn git(args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(root()).args(args).output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().into()
}
#[test]
fn public_preparation_refuses_wrong_network_bad_cell_digest_and_false_provenance() {
    let root = root();
    let temp = tempfile::tempdir().unwrap();
    let snapshot = root.join("artifacts/shielded-pool/deployments/epoch4-v16-fees.json");
    let original: Value = serde_json::from_slice(&std::fs::read(snapshot).unwrap()).unwrap();
    let commit = git(&["rev-parse", "HEAD"]);
    let blob = git(&["rev-parse", "HEAD:artifacts/shielded-pool/PROFILE.md"]);
    for case in 0..3 {
        let mut changed = original.clone();
        let mut expected_blob = blob.clone();
        let expected = match case {
            0 => {
                changed["global_id"] = 3.into();
                "fee snapshot network/version mismatch"
            }
            1 => {
                changed["parameters"]["21"]["boc_sha256"] = "00".repeat(32).into();
                "configuration 21 digest mismatch"
            }
            2 => {
                expected_blob = "00".repeat(20);
                "profile blob does not match reviewed commit"
            }
            _ => unreachable!(),
        };
        let fee = temp.path().join(format!("fees-{case}.json"));
        std::fs::write(&fee, serde_json::to_vec(&changed).unwrap()).unwrap();
        let output = temp.path().join(format!("candidate-{case}"));
        let result = Command::new(env!("CARGO_BIN_EXE_prepare_public_pool"))
            .arg(&root)
            .arg(root.join("artifacts/phase2-ceremony-2/ceremony"))
            .arg(&output)
            .args([&commit, &expected_blob, "2"])
            .arg(&fee)
            .args([
                "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c",
                "03e67eb4b1cff48c9bc5952992a46d37ae0c32d6ba2f76910f785daca8704579",
            ])
            .output()
            .unwrap();
        assert!(!result.status.success(), "refusal {case} succeeded");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "wrong refusal {case}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists(), "refusal {case} wrote partial deployment output");
    }
}
