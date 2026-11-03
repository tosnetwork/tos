//! The ceremony-key local pool carries the pins the shielded client was
//! written against, and nothing it writes disagrees with itself.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use chain_block::{read_single_root_boc, Serializable, StateInit};
use serde_json::Value;
use std::{path::PathBuf, process::Command};

/// `KNOWN_PROFILE_HASHES`: the profile revision the client's codecs were written against.
const PROFILE_PIN: &str = "4de5d5c81406f9ce973dd2b7e4026a72750330b757ba7f4c32bdb9edd07ccbec";
/// `KNOWN_VERIFYING_KEYS`: the audited ceremony key, the only key a spend accepts.
const CEREMONY_VK_PIN: &str = "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn generator(
    root: &PathBuf,
    ceremony: &PathBuf,
    phase1: &PathBuf,
    out: &PathBuf,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_local_ceremony_pool"))
        .args([root, ceremony, phase1, out])
        .output()
        .unwrap()
}

#[test]
fn the_local_ceremony_pool_carries_the_clients_pins_and_agrees_with_itself() {
    let root = root();
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("pool");
    let result = generator(
        &root,
        &root.join("artifacts/phase2-ceremony-2/ceremony"),
        &root.join("artifacts/phase1"),
        &out,
    );
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));

    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("pool.json")).unwrap()).unwrap();
    assert_eq!(manifest["profile_hash"], PROFILE_PIN);
    assert_eq!(manifest["groth16_vk_hash"], CEREMONY_VK_PIN);
    assert_eq!(manifest["development_verifying_key"], false);
    assert_eq!(manifest["global_id"], 3);
    assert_eq!(manifest["scope"], "isolated-local-ceremony-key");

    // The documents describe the one StateInit that was written.
    let code = read_single_root_boc(std::fs::read(out.join("code.boc")).unwrap()).unwrap();
    let data = read_single_root_boc(std::fs::read(out.join("data.boc")).unwrap()).unwrap();
    let init = StateInit::with_code_and_data(code.clone(), data.clone());
    let written = read_single_root_boc(std::fs::read(out.join("state-init.boc")).unwrap()).unwrap();
    assert_eq!(init.serialize().unwrap().repr_hash(), written.repr_hash());
    assert_eq!(manifest["code_hash"], code.hash(0).to_hex_string());
    assert_eq!(manifest["initial_data_hash"], data.hash(0).to_hex_string());
    assert_eq!(manifest["state_init_hash"], written.repr_hash().to_hex_string());
    assert_eq!(manifest["address"], format!("0:{}", written.repr_hash().to_hex_string()));
    assert_eq!(
        manifest["pool_config_hash"],
        data.reference(2).unwrap().repr_hash().to_hex_string()
    );

    let profile: Value =
        serde_json::from_slice(&std::fs::read(out.join("pool-profile.json")).unwrap()).unwrap();
    assert_eq!(profile["schema"], "tosctl-shield-profile-v1");
    assert_eq!(profile["global_id"], 3);
    assert_eq!(profile["pool_address"], manifest["address"]);
    assert_eq!(profile["pool_code_hash"], manifest["code_hash"]);

    // Without the phase-1 slice there is no audit, and without an audit no pool.
    let refused = generator(
        &root,
        &root.join("artifacts/phase2-ceremony-2/ceremony"),
        &temp.path().join("no-phase1"),
        &temp.path().join("refused"),
    );
    assert!(!refused.status.success());
    assert!(!temp.path().join("refused").exists(), "a refused run wrote output");
}
