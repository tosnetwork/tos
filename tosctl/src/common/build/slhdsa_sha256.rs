// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//
// SHA-256 backend of the SLH-DSA verifier for Cargo builds, included by every build script that
// compiles the imported SLH-DSA code. The rule is the one in crypto/pq/CMakeLists.txt, so the C++
// and Rust builds follow the same switches, each 1/0 (ON/OFF, TRUE/FALSE, YES/NO) when set:
// TOS_SLHDSA_SHA_NI, otherwise SHA-NI on x86-64 Linux and macOS, and TOS_SLHDSA_ARMV8_SHA2, otherwise the
// ARMv8 SHA2 extension on aarch64 Linux and macOS. Either builds crypto/pq/slhdsa-sha256.c in place of the
// imported sha2_256.c; the hashes are identical, only CPU time differs.

/// The selected SHA-256 translation unit and which hardware backend, if any, it carries.
pub struct SlhdsaSha256 {
    pub source: std::path::PathBuf,
    pub sha_ni: bool,
    pub armv8_sha2: bool,
    root: std::path::PathBuf,
}

impl SlhdsaSha256 {
    /// Adds the definition that the C code reporting the backend name is compiled with.
    pub fn define(&self, build: &mut cc::Build) {
        if self.sha_ni {
            build.define("TOS_SLHDSA_SHA_NI", None);
        }
        if self.armv8_sha2 {
            build.define("TOS_SLHDSA_ARMV8_SHA2", None);
        }
    }

    /// With a hardware backend, compiles the C++ adapter and the vendored transform it calls into
    /// two archives named after `prefix`. Call it after compiling the archive that holds `source`,
    /// so the archives are linked in dependency order. The vendored file alone gets the upstream
    /// definitions and instruction-set flags; neither file uses the C++ runtime library.
    pub fn compile_hardware(&self, prefix: &str) {
        let vendored = self.root.join("third-party/bitcoin-sha256");
        let (adapter, name) = if self.sha_ni {
            ("slhdsa-sha256-shani.cpp", "sha_ni")
        } else if self.armv8_sha2 {
            ("slhdsa-sha256-armv8.cpp", "armv8_sha2")
        } else {
            return;
        };
        cc::Build::new()
            .cpp(true)
            .std("c++17")
            .cpp_link_stdlib(None)
            .include(self.root.join("crypto/pq"))
            .file(self.root.join("crypto/pq").join(adapter))
            .compile(&format!("{prefix}_{name}_adapter"));
        let mut transform = cc::Build::new();
        transform.cpp(true).std("c++17").cpp_link_stdlib(None).warnings(false);
        if self.sha_ni {
            transform
                .include(&vendored)
                .define("ENABLE_SSE41", None)
                .define("ENABLE_X86_SHANI", None)
                .flag("-msse4.1")
                .flag("-msse4")
                .flag("-msha")
                .file(vendored.join("sha256_x86_shani.cpp"));
        } else {
            transform
                .define("ENABLE_ARM_SHANI", None)
                .flag("-march=armv8-a+crypto")
                .file(vendored.join("sha256_arm_shani.cpp"));
        }
        transform.compile(&format!("{prefix}_{name}_transform"));
    }
}

/// One switch: the environment variable when set, otherwise the platform default.
fn slhdsa_sha256_switch(name: &str, platform_default: bool) -> bool {
    println!("cargo:rerun-if-env-changed={name}");
    let on = match std::env::var(name) {
        Ok(value) => match value.to_ascii_uppercase().as_str() {
            "1" | "ON" | "TRUE" | "YES" => true,
            "0" | "OFF" | "FALSE" | "NO" => false,
            other => {
                panic!("{name} must be 1/0, ON/OFF, TRUE/FALSE or YES/NO, not {other:?}")
            }
        },
        Err(_) => platform_default,
    };
    if on != platform_default {
        println!("cargo:warning=SLH-DSA SHA-256 backend: {name}={}", u8::from(on));
    }
    on
}

/// `root` is the repository root. Emits the rerun lines for everything the choice depends on.
pub fn slhdsa_sha256(root: &std::path::Path) -> SlhdsaSha256 {
    let replacement = root.join("crypto/pq/slhdsa-sha256.c");
    println!("cargo:rerun-if-changed={}", replacement.display());
    println!("cargo:rerun-if-changed={}", root.join("crypto/pq/slhdsa-sha256.h").display());
    println!("cargo:rerun-if-changed={}", root.join("crypto/pq/slhdsa-sha256-shani.cpp").display());
    println!("cargo:rerun-if-changed={}", root.join("crypto/pq/slhdsa-sha256-armv8.cpp").display());
    println!("cargo:rerun-if-changed={}", root.join("third-party/bitcoin-sha256").display());
    println!("cargo:rerun-if-changed={}", root.join("third-party/slhdsa-c/sha2_api.h").display());
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let armv8_target = (os == "linux" || os == "macos") && arch == "aarch64" && endian == "little";
    let sha_ni_target = (os == "linux" || os == "macos") && arch == "x86_64";
    let sha_ni = slhdsa_sha256_switch("TOS_SLHDSA_SHA_NI", sha_ni_target);
    let armv8_sha2 = slhdsa_sha256_switch("TOS_SLHDSA_ARMV8_SHA2", armv8_target);
    if sha_ni && arch != "x86_64" {
        panic!("TOS_SLHDSA_SHA_NI needs an x86-64 target, not {arch}");
    }
    if armv8_sha2 && !armv8_target {
        panic!(
            "TOS_SLHDSA_ARMV8_SHA2 needs a little-endian aarch64 Linux or macOS target, not {os} {arch}"
        );
    }
    let source = if sha_ni || armv8_sha2 {
        replacement
    } else {
        root.join("third-party/slhdsa-c/sha2_256.c")
    };
    SlhdsaSha256 { source, sha_ni, armv8_sha2, root: root.to_path_buf() }
}
