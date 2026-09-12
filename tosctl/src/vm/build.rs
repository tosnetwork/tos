// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
mod metadata {
    include!("../common/build/build.rs");
    pub fn emit() { main(); }
}
fn main() {
    metadata::emit();
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let backend = root.join("../../../third-party/mldsa-native/mldsa");
    println!("cargo:rerun-if-changed={}", backend.display());
    println!("cargo:rerun-if-changed=pq-config.h");
    println!("cargo:rerun-if-changed=../../../crypto/pq/mldsa44-config.h");
    cc::Build::new().file(backend.join("mldsa_native.c"))
        .include(&backend).include(&root)
        .define("MLD_CONFIG_FILE", Some("\"pq-config.h\""))
        .std("c90").warnings(false).compile("tos_rust_mldsa44");
}
