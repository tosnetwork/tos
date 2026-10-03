// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
mod metadata {
    include!("../common/build/build.rs");
    pub fn emit() {
        main();
    }
}
fn main() {
    metadata::emit();
    let root = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"),
    );
    let backend = root.join("../../../third-party/mldsa-native/mldsa");
    println!("cargo:rerun-if-changed={}", backend.display());
    println!("cargo:rerun-if-changed=pq-config.h");
    println!("cargo:rerun-if-changed=pq-shim.c");
    println!("cargo:rerun-if-changed=../../../crypto/pq/mldsa44-config.h");
    cc::Build::new()
        .file(backend.join("mldsa_native.c"))
        .file(root.join("pq-shim.c"))
        .include(&backend)
        .include(&root)
        .define("MLD_CONFIG_FILE", Some("\"pq-config.h\""))
        .std("c90")
        .warnings(false)
        .compile("tos_rust_mldsa44");
    let falcon = root.join("../../../third-party/falcon-reference");
    let adapter = root.join("../../../crypto/pq");
    println!("cargo:rerun-if-changed={}", falcon.display());
    println!("cargo:rerun-if-changed={}", adapter.join("falcon512-native.c").display());
    println!("cargo:rerun-if-changed={}", adapter.join("falcon512-native.h").display());
    let mut build = cc::Build::new();
    for source in ["codec.c", "common.c", "shake.c", "vrfy.c"] {
        build.file(falcon.join(source));
    }
    build
        .file(adapter.join("falcon512-native.c"))
        .include(&falcon)
        .include(&adapter)
        .define("FALCON_FPEMU", "1")
        .define("FALCON_FPNATIVE", "0")
        .define("FALCON_AVX2", "0")
        .define("FALCON_FMA", "0")
        .define("FALCON_PREFIX", "tos_falcon_inner")
        .std("c99")
        .warnings(false)
        .compile("tos_rust_falcon512");
}
