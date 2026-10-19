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

const FILES: [&str; 5] =
    ["code.boc", "data.boc", "state-init.boc", "manifest.json", "publication.json"];

fn copy_candidate(output: &std::path::Path) {
    let frozen = root().join("artifacts/shielded-pool/deployments/epoch4-v16");
    for name in FILES {
        std::fs::copy(frozen.join(name), output.join(name)).unwrap();
    }
}

fn self_checksums(output: &std::path::Path) {
    let sums = FILES
        .iter()
        .map(|name| {
            let bytes = std::fs::read(output.join(name)).unwrap();
            let hash: String = shielded_pool_genesis::sha256(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("{hash}  {name}\n")
        })
        .collect::<String>();
    std::fs::write(output.join("SHA256SUMS"), sums).unwrap();
}

fn verify_candidate(output: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_prepare_public_pool"))
        .arg("--verify-frozen")
        .arg(root())
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn reproduction_refuses_each_drifted_file_even_with_matching_generated_checksums() {
    for name in FILES {
        let output = tempfile::tempdir().unwrap();
        copy_candidate(output.path());
        let path = output.path().join(name);
        if name == "publication.json" {
            let mut publication: Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            publication["address"] = format!("0:{}", "00".repeat(32)).into();
            std::fs::write(path, serde_json::to_vec(&publication).unwrap()).unwrap();
        } else {
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 1;
            std::fs::write(path, bytes).unwrap();
        }
        self_checksums(output.path());
        let result = verify_candidate(output.path());
        assert!(!result.status.success(), "drifted {name} accepted its own checksums");
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains(&format!("frozen candidate mismatch: {name}")),
            "wrong refusal for {name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn reproduction_checks_publication_identities_but_allows_measured_gas_to_vary() {
    let output = tempfile::tempdir().unwrap();
    copy_candidate(output.path());
    // A newly written checksum file is not an anchor, even if it is malformed.
    std::fs::write(output.path().join("SHA256SUMS"), "not trusted\n").unwrap();
    let path = output.path().join("publication.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut changed = original.clone();
    changed["sandbox_acceptance"]["gas"] = 1.into();
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let result = verify_candidate(output.path());
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(String::from_utf8_lossy(&result.stdout).contains("FROZEN_CANDIDATE_OK"));
    for field in ["code_hash", "data_hash", "state_init_hash", "vk_sha256", "profile_blob"] {
        let mut changed = original.clone();
        changed[field] = "00".repeat(32).into();
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        self_checksums(output.path());
        let result = verify_candidate(output.path());
        assert!(!result.status.success(), "drifted publication {field} accepted");
        assert!(String::from_utf8_lossy(&result.stderr)
            .contains("frozen candidate mismatch: publication.json"));
    }
}

#[test]
fn documented_reproduction_uses_the_committed_candidate_verifier() {
    let recipe =
        std::fs::read_to_string(root().join("artifacts/shielded-pool/deployments/README.md"))
            .unwrap();
    assert!(recipe.contains("--bin prepare_public_pool -- --verify-frozen . candidate-output"));
    assert!(!recipe.contains("(cd candidate-output && sha256sum -c SHA256SUMS)"));
}
