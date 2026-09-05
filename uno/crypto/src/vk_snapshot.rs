//! Test-only diagnostic snapshot, not a portable VK serialization or wire ID.
use crate::FixedVerifier;
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};

const EXPECTED: &str = include_str!("../fixtures/fixed-vk-debug.blake2b512");

fn digest(representation: &str) -> String {
    blake2b_simd::blake2b(representation.as_bytes()).to_hex().to_string()
}

#[test]
fn constructed_vk_debug_snapshot_is_frozen() {
    let verifier = FixedVerifier::new().expect("fixed verifier");
    let representation = format!("{:?}", verifier.key);
    assert_eq!(digest(&representation), EXPECTED.trim());
    let rebuilt = FixedVerifier::new().expect("rebuilt verifier");
    assert_eq!(format!("{:?}", rebuilt.key), representation);
}

#[test]
fn key_snapshot_is_not_just_the_selector() {
    let historical = VerifyingKey::build(OrchardCircuitVersion::InsecurePreNu6_2);
    let representation = format!("{historical:?}");
    assert_eq!(representation.matches("InsecurePreNu6_2").count(), 1);
    let falsely_labelled = representation.replace("InsecurePreNu6_2", "FixedPostNu6_2");
    let fixed = FixedVerifier::new().expect("fixed verifier");
    assert_ne!(digest(&falsely_labelled), digest(&format!("{:?}", fixed.key)));
}

#[test]
#[ignore = "explicit diagnostic export; never updates the frozen digest"]
fn export_constructed_vk_debug_snapshot() {
    let path = std::env::var_os("UNO_VK_DEBUG_OUT").expect("explicit diagnostic output path");
    let verifier = FixedVerifier::new().expect("fixed verifier");
    let representation = format!("{:?}", verifier.key);
    assert_eq!(digest(&representation), EXPECTED.trim());
    std::fs::write(path, representation.as_bytes()).expect("write diagnostic artifact");
}
