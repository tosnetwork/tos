//! A frozen deployment profile must describe the activation gates its VMs ship.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn constant(file: &str, name: &str) -> u32 {
    let text = std::fs::read_to_string(root().join(file)).expect("runtime source");
    let needle = format!("{name} = ");
    let matches: Vec<_> = text.lines().filter_map(|line| line.split_once(&needle)).collect();
    assert_eq!(matches.len(), 1, "ambiguous runtime constant {name}");
    matches[0].1.trim_end_matches(';').parse().expect("integer runtime constant")
}

#[test]
fn frozen_profile_matches_the_shipped_unified_version() {
    let profile = std::fs::read_to_string(root().join("artifacts/shielded-pool/PROFILE.md"))
        .expect("normative profile");
    assert_eq!(constant("common/global-version.h", "SUPPORTED_VERSION"), 16);
    assert_eq!(constant("crypto/vm/poseidon2ops.h", "poseidon2_min_version"), 16);
    assert_eq!(constant("crypto/vm/poseidon2ops.h", "poseidon2_path7_min_version"), 16);
    assert_eq!(constant("crypto/vm/pqops.h", "pq_mldsa44_min_version"), 16);
    for declaration in [
        "0xF93200  POSEIDON2_PERM8",
        "0xF93201  POSEIDON2_HASH7",
        "0xF93202  POSEIDON2_PATH7",
        "minimum global version: 16",
        "binary advertises `SUPPORTED_VERSION=16`",
        "V15 rejects ML-DSA and PERM8/HASH7/PATH7, while V16 accepts all four",
    ] {
        assert!(profile.contains(declaration), "profile omits shipped rule: {declaration}");
    }
    assert!(!profile.contains("SUPPORTED_VERSION=17"), "profile advertises an unshipped version");
}
