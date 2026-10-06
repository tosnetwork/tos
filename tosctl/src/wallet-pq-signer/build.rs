// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = manifest.join("../../..");
    let pq = root.join("crypto/pq");
    let ml = root.join("third-party/mldsa-native/mldsa");
    let slh = root.join("third-party/slhdsa-c");
    for path in [&pq, &ml, &slh] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let lms = root.join("third-party/lms-reference");
    println!("cargo:rerun-if-changed={}", lms.display());
    let openssl = env::var_os("DEP_OPENSSL_INCLUDE").expect("OpenSSL dependency include path");
    let mut signing = cc::Build::new();
    signing.cpp(true).std("c++17").include(&pq).include(&ml).include(&slh).include(&lms);
    for path in env::split_paths(&openssl) {
        signing.include(path);
    }
    signing
        .define("MLD_CONFIG_FILE", Some("\"wallet-signer-config.h\""))
        .file(pq.join("wallet-pq-signer.cpp"))
        .file(pq.join("wallet-pq-signer-c.cpp"))
        .file(pq.join("slhdsa128s.cpp"))
        .file(pq.join("lms-fee.cpp"))
        .file(pq.join("wallet-lms-fee-c.cpp"))
        .file(pq.join("wallet-lms-sign-c.cpp"))
        .file(pq.join("wallet-lms-tree-c.cpp"))
        .compile("tos_wallet_pq_signer_ffi");
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .include(&pq)
        .include(&ml)
        .define("MLD_CONFIG_FILE", Some("\"mldsa44-config.h\""))
        .file(pq.join("mldsa44.cpp"))
        .compile("tos_wallet_mldsa_verifier");
    for (name, config) in [
        ("tos_wallet_mldsa_sign", "\"wallet-signer-config.h\""),
        ("tos_wallet_mldsa_verify", "\"mldsa44-config.h\""),
    ] {
        cc::Build::new()
            .std("c90")
            .include(&pq)
            .include(&ml)
            .define("MLD_CONFIG_FILE", Some(config))
            .file(ml.join("mldsa_native.c"))
            .warnings(false)
            .compile(name);
    }
    let mut fee = cc::Build::new();
    fee.std("c99").include(&lms).warnings(false);
    for path in env::split_paths(&openssl) {
        fee.include(path);
    }
    for source in [
        "hss_derive.c",
        "hss_zeroize.c",
        "lm_common.c",
        "lm_ots_common.c",
        "lm_ots_sign.c",
        "endian.c",
        "hash.c",
    ] {
        fee.file(lms.join(source));
    }
    fee.compile("tos_wallet_lms_primitives");
    let mut build = cc::Build::new();
    for source in ["slh_dsa.c", "slh_sha2.c", "sha2_256.c", "sha2_512.c"] {
        build.file(slh.join(source));
    }
    build.include(&slh).std("c99").warnings(false).compile("tos_wallet_slh");
}
