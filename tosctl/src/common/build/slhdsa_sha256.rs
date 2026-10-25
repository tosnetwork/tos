// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//
// SHA-256 backend of the SLH-DSA verifier for Cargo builds, included by every build script that
// compiles the imported SLH-DSA code. The rule is the one in crypto/pq/CMakeLists.txt, so the C++
// and Rust builds follow the same switch: TOS_SLHDSA_SHA_NI=1/0 (ON/OFF, TRUE/FALSE, YES/NO) when
// set, otherwise SHA-NI on Linux x86-64. SHA-NI builds crypto/pq/slhdsa-sha256.c in place of the
// imported sha2_256.c; the hashes are identical, only CPU time differs.

/// The selected SHA-256 translation unit and whether it is the SHA-NI backend.
pub struct SlhdsaSha256 {
    pub source: std::path::PathBuf,
    pub sha_ni: bool,
    root: std::path::PathBuf,
}

impl SlhdsaSha256 {
    /// With SHA-NI, compiles the C++ adapter and the vendored transform it calls into two
    /// archives named after `prefix`. Call it after compiling the archive that holds `source`,
    /// so the archives are linked in dependency order. The vendored file alone gets the upstream
    /// definitions and instruction-set flags; neither file uses the C++ runtime library.
    pub fn compile_sha_ni(&self, prefix: &str) {
        if !self.sha_ni {
            return;
        }
        let shani = self.root.join("third-party/bitcoin-sha256");
        cc::Build::new()
            .cpp(true)
            .std("c++17")
            .cpp_link_stdlib(None)
            .include(self.root.join("crypto/pq"))
            .file(self.root.join("crypto/pq/slhdsa-sha256-shani.cpp"))
            .compile(&format!("{prefix}_sha_ni_adapter"));
        cc::Build::new()
            .cpp(true)
            .std("c++17")
            .cpp_link_stdlib(None)
            .include(&shani)
            .define("ENABLE_SSE41", None)
            .define("ENABLE_X86_SHANI", None)
            .flag("-msse4.1")
            .flag("-msse4")
            .flag("-msha")
            .warnings(false)
            .file(shani.join("sha256_x86_shani.cpp"))
            .compile(&format!("{prefix}_sha_ni_transform"));
    }
}

/// `root` is the repository root. Emits the rerun lines for everything the choice depends on.
pub fn slhdsa_sha256(root: &std::path::Path) -> SlhdsaSha256 {
    let replacement = root.join("crypto/pq/slhdsa-sha256.c");
    println!("cargo:rerun-if-env-changed=TOS_SLHDSA_SHA_NI");
    println!("cargo:rerun-if-changed={}", replacement.display());
    println!("cargo:rerun-if-changed={}", root.join("crypto/pq/slhdsa-sha256.h").display());
    println!("cargo:rerun-if-changed={}", root.join("crypto/pq/slhdsa-sha256-shani.cpp").display());
    println!("cargo:rerun-if-changed={}", root.join("third-party/bitcoin-sha256").display());
    println!("cargo:rerun-if-changed={}", root.join("third-party/slhdsa-c/sha2_api.h").display());
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let platform_default = os == "linux" && arch == "x86_64";
    let sha_ni = match std::env::var("TOS_SLHDSA_SHA_NI") {
        Ok(value) => match value.to_ascii_uppercase().as_str() {
            "1" | "ON" | "TRUE" | "YES" => true,
            "0" | "OFF" | "FALSE" | "NO" => false,
            other => {
                panic!("TOS_SLHDSA_SHA_NI must be 1/0, ON/OFF, TRUE/FALSE or YES/NO, not {other:?}")
            }
        },
        Err(_) => platform_default,
    };
    if sha_ni && arch != "x86_64" {
        panic!("TOS_SLHDSA_SHA_NI needs an x86-64 target, not {arch}");
    }
    if sha_ni != platform_default {
        println!("cargo:warning=SLH-DSA SHA-256 backend: TOS_SLHDSA_SHA_NI={}", u8::from(sha_ni));
    }
    let source = if sha_ni { replacement } else { root.join("third-party/slhdsa-c/sha2_256.c") };
    SlhdsaSha256 { source, sha_ni, root: root.to_path_buf() }
}
