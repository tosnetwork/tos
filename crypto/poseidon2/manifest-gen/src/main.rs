//! Regenerates every frozen Poseidon2 artifact from the pinned upstream
//! reference. Nothing here re-derives a constant: each value is read out of the
//! pinned crate, checked for shape, and only re-serialized. The permutation
//! outputs are produced by *executing* that reference, because its own published
//! vectors lock t=2/3/4 only.
//!
//! Usage: cargo run --release -- <repo root>

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use zkhash::ark_ff::{BigInteger, PrimeField, Zero};
use zkhash::fields::bls12::FpBLS12 as Fr;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bls12::{
    MAT_DIAG8_M_1, MAT_INTERNAL8, POSEIDON2_BLS_8_PARAMS, RC8,
};

const T: usize = 8;
/// The frozen commitment-tree depth; the empty-subtree ladder has one entry per
/// level plus the empty leaf itself.
const TREE_DEPTH: usize = 12;
const SBOX_ALPHA: u8 = 5;
const ROUNDS_F: u8 = 8;
const ROUNDS_P: u8 = 57;
/// The manifest tag, NUL included, exactly as the byte stream carries it.
const MANIFEST_TAG: &[u8] = b"TOS-POSEIDON2-BLS381-T8-v1\0";
const DOMAIN_PREFIX: &[u8] = b"TOS-SHIELDED-DOMAIN-v1:";
/// Tag of the domain-table manifest. Its byte layout is defined here, not by
/// the profile, because nothing on chain commits to it.
const DOMAIN_MANIFEST_TAG: &[u8] = b"TOS-SHIELDED-DOMAINS-v1\0";

const UPSTREAM_REPO: &str = "https://github.com/HorizenLabs/poseidon2";
const UPSTREAM_COMMIT: &str = "055bde3f4782731ba5f5ce5888a440a94327eaf3";

/// The frozen shielded-pool domain labels. Order is the manifest order and is
/// itself part of what the generated tables commit to.
const LABELS: [&str; 14] = [
    "DUMMY-OWNER-NF",
    "OWNER-NF-HASH",
    "OWNER-COMMITMENT",
    "NOTE-BODY",
    "NOTE-COMMITMENT",
    "NULLIFIER",
    "PHANTOM-NULLIFIER",
    "RECOVERY-TEMPLATE",
    "COMMIT-NODE",
    "IMT-LEAF",
    "IMT-NODE",
    "INTENT-CORE",
    "INTENT-OUTPUTS",
    "INTENT-FINAL",
];

fn fr_be32(x: &Fr) -> [u8; 32] {
    let bytes = x.into_bigint().to_bytes_be();
    assert!(bytes.len() <= 32, "field element does not fit in 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn modulus_be32() -> [u8; 32] {
    let bytes = Fr::MODULUS.to_bytes_be();
    assert_eq!(bytes.len(), 32, "unexpected modulus width");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn cpp_bytes(b: &[u8; 32]) -> String {
    let mut s = String::from("{");
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "0x{byte:02x}").unwrap();
    }
    s.push('}');
    s
}

fn rust_bytes(b: &[u8; 32]) -> String {
    let mut s = String::from("[");
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "0x{byte:02x}").unwrap();
    }
    s.push(']');
    s
}

struct Kat {
    name: String,
    input: [Fr; T],
    output: Vec<Fr>,
}

fn main() {
    let root: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: poseidon2-manifest-gen <repo root>");
    assert!(root.join("crypto/vm").is_dir(), "{} is not a repo root", root.display());

    // ---- shape, before anything is serialized -------------------------------
    // A manifest built from the wrong shape would still hash to something.
    assert_eq!(MAT_DIAG8_M_1.len(), T, "MAT_DIAG8_M_1 length");
    assert_eq!(MAT_INTERNAL8.len(), T, "MAT_INTERNAL8 rows");
    for row in MAT_INTERNAL8.iter() {
        assert_eq!(row.len(), T, "MAT_INTERNAL8 columns");
    }
    let rounds = usize::from(ROUNDS_F) + usize::from(ROUNDS_P);
    assert_eq!(RC8.len(), rounds, "RC8 rows must be rounds_f + rounds_p");
    for row in RC8.iter() {
        assert_eq!(row.len(), T, "RC8 columns");
    }

    // ---- the exact manifest byte stream ------------------------------------
    let mut manifest: Vec<u8> = Vec::new();
    manifest.extend_from_slice(MANIFEST_TAG);
    manifest.extend_from_slice(&modulus_be32());
    manifest.push(T as u8);
    manifest.push(SBOX_ALPHA);
    manifest.push(ROUNDS_F);
    manifest.push(ROUNDS_P);
    for x in MAT_DIAG8_M_1.iter() {
        manifest.extend_from_slice(&fr_be32(x));
    }
    for row in MAT_INTERNAL8.iter() {
        for x in row.iter() {
            manifest.extend_from_slice(&fr_be32(x));
        }
    }
    for row in RC8.iter() {
        for x in row.iter() {
            manifest.extend_from_slice(&fr_be32(x));
        }
    }
    let expected_len = MANIFEST_TAG.len() + 32 + 4 + 32 * (T + T * T + rounds * T);
    assert_eq!(manifest.len(), expected_len, "manifest length");
    let manifest_hash: [u8; 32] = Sha256::digest(&manifest).into();

    // ---- domain constants ---------------------------------------------------
    let mut domains: Vec<(&str, Fr)> = Vec::new();
    for label in LABELS {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(label.as_bytes());
        let d = Fr::from_be_bytes_mod_order(&hasher.finalize());
        assert!(!d.is_zero(), "domain constant for {label} reduced to zero");
        domains.push((label, d));
    }

    // ---- known-answer vectors, by running the pinned reference --------------
    let perm = Poseidon2::new(&POSEIDON2_BLS_8_PARAMS);
    let mut inputs: Vec<(String, [Fr; T])> = Vec::new();
    let mut counting = [Fr::from(0u64); T];
    for (i, slot) in counting.iter_mut().enumerate() {
        *slot = Fr::from(i as u64);
    }
    inputs.push(("counting".into(), counting));
    inputs.push(("zero".into(), [Fr::from(0u64); T]));
    inputs.push(("all_fr_minus_one".into(), [-Fr::from(1u64); T]));
    for pos in [0usize, T - 1] {
        let mut v = [Fr::from(0u64); T];
        v[pos] = Fr::from(1u64);
        inputs.push((format!("one_hot_{pos}"), v));
    }
    // Deterministic pseudorandom states: lane j of vector k is SHA-256 of an
    // explicit label reduced into the field, so they are reproducible without
    // carrying a RNG or a seed file.
    for k in 0..16u32 {
        let mut v = [Fr::from(0u64); T];
        for (j, slot) in v.iter_mut().enumerate() {
            let h = Sha256::digest(format!("TOS-POSEIDON2-KAT-v1/{k}/{j}").as_bytes());
            *slot = Fr::from_be_bytes_mod_order(&h);
        }
        inputs.push((format!("pseudorandom_{k}"), v));
    }
    let perm_kats: Vec<Kat> = inputs
        .into_iter()
        .map(|(name, input)| Kat { output: perm.permutation(&input), name, input })
        .collect();

    // HASH7 puts the domain constant in lane 0 and takes lane 0 of the result.
    // Frozen per label so a wrong domain or a wrong output lane is caught.
    let mut hash_kats: Vec<(String, [Fr; T], Fr)> = Vec::new();
    for (label, domain) in &domains {
        for variant in 0..2u32 {
            let mut state = [Fr::from(0u64); T];
            state[0] = *domain;
            for (j, slot) in state.iter_mut().enumerate().skip(1) {
                *slot = if variant == 0 {
                    Fr::from(j as u64)
                } else {
                    let h =
                        Sha256::digest(format!("TOS-POSEIDON2-H7-KAT-v1/{label}/{j}").as_bytes());
                    Fr::from_be_bytes_mod_order(&h)
                };
            }
            let out = perm.permutation(&state);
            hash_kats.push((format!("{label}/v{variant}"), state, out[0]));
        }
    }

    // A second, smaller manifest over the domain table. The domain constants
    // themselves are fully determined by the profile; this digest is a build
    // check against drift between the three places they are written, and is
    // deliberately not part of any consensus state.
    let mut domain_manifest: Vec<u8> = Vec::new();
    domain_manifest.extend_from_slice(DOMAIN_MANIFEST_TAG);
    domain_manifest.push(u8::try_from(domains.len()).expect("label count fits in a byte"));
    for (label, value) in &domains {
        let bytes = label.as_bytes();
        domain_manifest.push(u8::try_from(bytes.len()).expect("label length fits in a byte"));
        domain_manifest.extend_from_slice(bytes);
        domain_manifest.extend_from_slice(&fr_be32(value));
    }
    let domain_hash: [u8; 32] = Sha256::digest(&domain_manifest).into();

    // The empty-subtree ladder, derived by running the same reference. A
    // contract that recomputed it would pay twelve permutations per append for
    // a value that never changes.
    let commit_node_domain = domains
        .iter()
        .find(|(label, _)| *label == "COMMIT-NODE")
        .expect("COMMIT-NODE domain")
        .1;
    let mut empty_roots = vec![Fr::from(0u64)];
    for level in 0..TREE_DEPTH {
        let mut state = [empty_roots[level]; T];
        state[0] = commit_node_domain;
        empty_roots.push(perm.permutation(&state)[0]);
    }

    write_func_domains(&root, &domains, &domain_hash, &empty_roots);
    write_cpp_params(&root, &manifest_hash);
    write_cpp_kats(&root, &perm_kats, &hash_kats, &domains, &domain_hash);
    write_rust_params(&root, &manifest_hash);
    write_rust_kats(&root, &perm_kats, &hash_kats, &domains, &domain_hash, &empty_roots);
    write_typescript(&root, &manifest_hash, &perm_kats, &hash_kats, &domains, &domain_hash,
                     &empty_roots);
    write_provenance(&root, &manifest, &manifest_hash);
    format_generated(&root);

    eprintln!("manifest bytes   {}", manifest.len());
    eprintln!("manifest sha256  {}", hex::encode(manifest_hash));
    eprintln!("perm8 vectors    {}", perm_kats.len());
    eprintln!("hash7 vectors    {}", hash_kats.len());
}

/// Generated files go through the repository's own formatters, so that
/// regenerating never produces a diff the lint gate would reject. A missing
/// formatter is a hard stop: writing unformatted output and saying nothing
/// would leave the next person to discover it in CI.
fn format_generated(root: &Path) {
    let cpp = [root.join("crypto/vm/poseidon2-params.h"), root.join("crypto/vm/poseidon2-kat.h")];
    let rust = [
        root.join("tosctl/src/block/src/poseidon2_params.rs"),
        root.join("tosctl/src/block/src/poseidon2_kat.rs"),
    ];
    // An older clang-format runs but cannot read this repository's style file,
    // so a candidate counts only if it actually formats with that style.
    let formatted = ["clang-format-21", "clang-format-20", "clang-format"].into_iter().find(|name| {
        cpp.iter().all(|path| {
            Command::new(name)
                .arg("--style=file")
                .arg("-i")
                .arg(path)
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        })
    });
    assert!(formatted.is_some(), "no clang-format understood the repository style; format {cpp:?} by hand");
    for path in &rust {
        let status = Command::new("rustfmt")
            .arg("--edition")
            .arg("2021")
            .arg(path)
            .status()
            .unwrap_or_else(|e| panic!("no rustfmt found ({e}); format {path:?} before committing"));
        assert!(status.success(), "rustfmt failed on {}", path.display());
    }
}

const BANNER: &str = "// Generated by crypto/poseidon2/manifest-gen from the pinned upstream\n\
                      // reference. Do not edit by hand; see crypto/poseidon2/PROVENANCE.md.\n";

/// The domain constants as FunC, because the profile forbids a hand-written
/// numeric domain table. The values are pushed as decimal literals, which is
/// what the assembler accepts for a 256-bit immediate.
fn write_func_domains(root: &Path, domains: &[(&str, Fr)], domain_hash: &[u8; 32],
                      empty_roots: &[Fr]) {
    let dir = root.join("crypto/smartcont/shielded");
    std::fs::create_dir_all(&dir).expect("shielded dir");
    let mut s = String::new();
    s.push_str(";; Generated by crypto/poseidon2/manifest-gen. Do not edit by hand;\n");
    s.push_str(";; see crypto/poseidon2/PROVENANCE.md.\n;;\n");
    s.push_str(";; domain_fr(label) = uint256_be(SHA256(\"TOS-SHIELDED-DOMAIN-v1:\" || label)) mod r\n");
    writeln!(s, ";; domain table sha256 = {}\n", hex::encode(domain_hash)).unwrap();
    for (label, value) in domains {
        let name = label.to_lowercase().replace('-', "_");
        writeln!(s, ";; {label}").unwrap();
        writeln!(s, "int domain_{name}() asm \"{} PUSHINT\";", decimal(value)).unwrap();
    }
    std::fs::write(dir.join("domains.fc"), s).expect("write FunC domains");

    let mut e = String::new();
    e.push_str(";; Generated by crypto/poseidon2/manifest-gen. Do not edit by hand;\n");
    e.push_str(";; see crypto/poseidon2/PROVENANCE.md.\n;;\n");
    e.push_str(";; EMPTY_ROOT[0] = 0\n");
    e.push_str(";; EMPTY_ROOT[level+1] = H7(\"COMMIT-NODE\", EMPTY_ROOT[level] x7)\n");
    e.push_str(";; Derived, not chosen: a contract recomputing it would pay twelve\n");
    e.push_str(";; permutations per append for a value that never changes.\n\n");
    for (level, value) in empty_roots.iter().enumerate() {
        writeln!(e, "int empty_root_{level}() asm \"{} PUSHINT\";", decimal(value)).unwrap();
    }
    std::fs::write(dir.join("empty-roots.fc"), e).expect("write FunC empty roots");
}

/// Decimal rendering of a canonical field element, by hand so that the emitted
/// literal has no dependency on a formatter's idea of an integer.
fn decimal(value: &Fr) -> String {
    let mut digits = vec![0u8];
    for byte in fr_be32(value) {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

fn write_cpp_params(root: &Path, manifest_hash: &[u8; 32]) {
    let mut s = String::new();
    s.push_str("/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */\n");
    s.push_str(BANNER);
    s.push_str("#pragma once\n\nnamespace vm {\nnamespace poseidon2 {\n\n");
    s.push_str("inline constexpr int state_width = 8;\n");
    s.push_str("inline constexpr int sbox_alpha = 5;\n");
    s.push_str("inline constexpr int rounds_f = 8;\n");
    s.push_str("inline constexpr int rounds_p = 57;\n");
    s.push_str("inline constexpr int rounds_total = rounds_f + rounds_p;\n");
    s.push_str("inline constexpr int rounds_f_beginning = rounds_f / 2;\n\n");
    s.push_str("// The tag as the manifest stream carries it: the trailing NUL of this\n");
    s.push_str("// literal is part of the hashed bytes.\n");
    s.push_str("inline constexpr char manifest_tag[] = \"TOS-POSEIDON2-BLS381-T8-v1\";\n\n");
    writeln!(s, "inline constexpr unsigned char modulus_be[32] = {};\n", cpp_bytes(&modulus_be32())).unwrap();
    writeln!(s, "inline constexpr unsigned char manifest_sha256[32] = {};\n", cpp_bytes(manifest_hash)).unwrap();

    s.push_str("inline constexpr unsigned char mat_diag8_be[state_width][32] = {\n");
    for x in MAT_DIAG8_M_1.iter() {
        writeln!(s, "    {},", cpp_bytes(&fr_be32(x))).unwrap();
    }
    s.push_str("};\n\n");

    s.push_str("inline constexpr unsigned char mat_internal8_be[state_width][state_width][32] = {\n");
    for row in MAT_INTERNAL8.iter() {
        s.push_str("    {\n");
        for x in row.iter() {
            writeln!(s, "        {},", cpp_bytes(&fr_be32(x))).unwrap();
        }
        s.push_str("    },\n");
    }
    s.push_str("};\n\n");

    s.push_str("inline constexpr unsigned char rc8_be[rounds_total][state_width][32] = {\n");
    for row in RC8.iter() {
        s.push_str("    {\n");
        for x in row.iter() {
            writeln!(s, "        {},", cpp_bytes(&fr_be32(x))).unwrap();
        }
        s.push_str("    },\n");
    }
    s.push_str("};\n\n");
    s.push_str("}  // namespace poseidon2\n}  // namespace vm\n");
    std::fs::write(root.join("crypto/vm/poseidon2-params.h"), s).expect("write C++ params");
}

fn write_cpp_kats(root: &Path, perm: &[Kat], hash: &[(String, [Fr; T], Fr)], domains: &[(&str, Fr)],
                  domain_hash: &[u8; 32]) {
    let mut s = String::new();
    s.push_str("/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */\n");
    s.push_str(BANNER);
    s.push_str("#pragma once\n\nnamespace vm {\nnamespace poseidon2 {\nnamespace kat {\n\n");
    s.push_str("struct PermVector {\n  const char* name;\n  unsigned char input[8][32];\n  unsigned char output[8][32];\n};\n\n");
    s.push_str("struct HashVector {\n  const char* name;\n  unsigned char state[8][32];\n  unsigned char output[32];\n};\n\n");
    s.push_str("struct Domain {\n  const char* label;\n  unsigned char value[32];\n};\n\n");

    writeln!(s, "inline constexpr unsigned char domain_manifest_sha256[32] = {};\n",
             cpp_bytes(domain_hash))
    .unwrap();
    writeln!(s, "inline constexpr Domain domains[{}] = {{", domains.len()).unwrap();
    for (label, value) in domains {
        writeln!(s, "    {{\"{}\", {}}},", label, cpp_bytes(&fr_be32(value))).unwrap();
    }
    s.push_str("};\n\n");

    writeln!(s, "inline constexpr PermVector perm8[{}] = {{", perm.len()).unwrap();
    for k in perm {
        writeln!(s, "    {{\"{}\",", k.name).unwrap();
        s.push_str("     {");
        for (i, x) in k.input.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&cpp_bytes(&fr_be32(x)));
        }
        s.push_str("},\n     {");
        for (i, x) in k.output.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&cpp_bytes(&fr_be32(x)));
        }
        s.push_str("}},\n");
    }
    s.push_str("};\n\n");

    writeln!(s, "inline constexpr HashVector hash7[{}] = {{", hash.len()).unwrap();
    for (name, state, out) in hash {
        writeln!(s, "    {{\"{name}\",").unwrap();
        s.push_str("     {");
        for (i, x) in state.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&cpp_bytes(&fr_be32(x)));
        }
        writeln!(s, "}},\n     {}}},", cpp_bytes(&fr_be32(out))).unwrap();
    }
    s.push_str("};\n\n");
    s.push_str("}  // namespace kat\n}  // namespace poseidon2\n}  // namespace vm\n");
    std::fs::write(root.join("crypto/vm/poseidon2-kat.h"), s).expect("write C++ kats");
}

fn write_rust_params(root: &Path, manifest_hash: &[u8; 32]) {
    let mut s = String::new();
    s.push_str("// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later\n");
    s.push_str(BANNER);
    s.push_str("//! Frozen Poseidon2 t=8 parameters over the BLS12-381 scalar field.\n\n");
    s.push_str("pub const STATE_WIDTH: usize = 8;\n");
    s.push_str("pub const SBOX_ALPHA: u32 = 5;\n");
    s.push_str("pub const ROUNDS_F: usize = 8;\n");
    s.push_str("pub const ROUNDS_P: usize = 57;\n");
    s.push_str("pub const ROUNDS_TOTAL: usize = ROUNDS_F + ROUNDS_P;\n");
    s.push_str("pub const ROUNDS_F_BEGINNING: usize = ROUNDS_F / 2;\n\n");
    s.push_str("/// The tag as the manifest stream carries it, trailing NUL included.\n");
    s.push_str("pub const MANIFEST_TAG: &[u8] = b\"TOS-POSEIDON2-BLS381-T8-v1\\0\";\n\n");
    writeln!(s, "pub const MODULUS_BE: [u8; 32] = {};\n", rust_bytes(&modulus_be32())).unwrap();
    writeln!(s, "pub const MANIFEST_SHA256: [u8; 32] = {};\n", rust_bytes(manifest_hash)).unwrap();

    s.push_str("pub const MAT_DIAG8_BE: [[u8; 32]; STATE_WIDTH] = [\n");
    for x in MAT_DIAG8_M_1.iter() {
        writeln!(s, "    {},", rust_bytes(&fr_be32(x))).unwrap();
    }
    s.push_str("];\n\n");

    s.push_str("pub const MAT_INTERNAL8_BE: [[[u8; 32]; STATE_WIDTH]; STATE_WIDTH] = [\n");
    for row in MAT_INTERNAL8.iter() {
        s.push_str("    [\n");
        for x in row.iter() {
            writeln!(s, "        {},", rust_bytes(&fr_be32(x))).unwrap();
        }
        s.push_str("    ],\n");
    }
    s.push_str("];\n\n");

    s.push_str("pub const RC8_BE: [[[u8; 32]; STATE_WIDTH]; ROUNDS_TOTAL] = [\n");
    for row in RC8.iter() {
        s.push_str("    [\n");
        for x in row.iter() {
            writeln!(s, "        {},", rust_bytes(&fr_be32(x))).unwrap();
        }
        s.push_str("    ],\n");
    }
    s.push_str("];\n");
    std::fs::write(root.join("tosctl/src/block/src/poseidon2_params.rs"), s)
        .expect("write Rust params");
}

fn write_rust_kats(root: &Path, perm: &[Kat], hash: &[(String, [Fr; T], Fr)], domains: &[(&str, Fr)],
                   domain_hash: &[u8; 32], empty_roots: &[Fr]) {
    let mut s = String::new();
    s.push_str("// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later\n");
    s.push_str(BANNER);
    s.push_str("//! Known-answer vectors for Poseidon2 t=8, produced by executing the pinned\n");
    s.push_str("//! upstream reference. Public so that the VM crate tests the same table the\n");
    s.push_str("//! permutation here is tested against.\n\n");
    writeln!(s, "pub const DOMAIN_MANIFEST_SHA256: [u8; 32] = {};\n", rust_bytes(domain_hash))
        .unwrap();
    writeln!(s, "/// EMPTY_ROOT[level] for the 7-ary depth-12 commitment tree.")
        .unwrap();
    writeln!(s, "pub const EMPTY_ROOTS: [[u8; 32]; {}] = [", empty_roots.len()).unwrap();
    for value in empty_roots {
        writeln!(s, "    {},", rust_bytes(&fr_be32(value))).unwrap();
    }
    s.push_str("];\n\n");
    writeln!(s, "pub const DOMAINS: [(&str, [u8; 32]); {}] = [", domains.len()).unwrap();
    for (label, value) in domains {
        writeln!(s, "    (\"{}\", {}),", label, rust_bytes(&fr_be32(value))).unwrap();
    }
    s.push_str("];\n\n");

    writeln!(s, "pub const PERM8: [(&str, [[u8; 32]; 8], [[u8; 32]; 8]); {}] = [", perm.len()).unwrap();
    for k in perm {
        writeln!(s, "    (\"{}\",", k.name).unwrap();
        s.push_str("     [");
        for (i, x) in k.input.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&rust_bytes(&fr_be32(x)));
        }
        s.push_str("],\n     [");
        for (i, x) in k.output.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&rust_bytes(&fr_be32(x)));
        }
        s.push_str("]),\n");
    }
    s.push_str("];\n\n");

    writeln!(s, "pub const HASH7: [(&str, [[u8; 32]; 8], [u8; 32]); {}] = [", hash.len()).unwrap();
    for (name, state, out) in hash {
        writeln!(s, "    (\"{name}\",").unwrap();
        s.push_str("     [");
        for (i, x) in state.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&rust_bytes(&fr_be32(x)));
        }
        writeln!(s, "],\n     {}),", rust_bytes(&fr_be32(out))).unwrap();
    }
    s.push_str("];\n");
    std::fs::write(root.join("tosctl/src/block/src/poseidon2_kat.rs"), s)
        .expect("write Rust kats");
}


/// The same parameters and vectors as TypeScript, for the SDK wallet.
///
/// A fifth hand-written copy of 65 round-constant rows is a fifth chance to
/// mistype one, and the one that is mistyped is always the one nobody checks.
/// So the SDK gets them from here like everyone else, as decimal strings
/// because that is what `BigInt` reads without a parser.
fn write_typescript(root: &Path, manifest_hash: &[u8; 32], perm: &[Kat],
                    hash: &[(String, [Fr; T], Fr)], domains: &[(&str, Fr)],
                    domain_hash: &[u8; 32], empty_roots: &[Fr]) {
    let dir = root.join("sdk/js/packages/crypto/src/shielded/generated");
    std::fs::create_dir_all(&dir).expect("shielded generated dir");

    let dec = |x: &Fr| -> String { fr_dec(x) };
    let mut s = String::new();
    s.push_str("// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later\n");
    s.push_str("// Generated by crypto/poseidon2/manifest-gen from the pinned upstream\n");
    s.push_str("// reference. Do not edit by hand; see crypto/poseidon2/PROVENANCE.md.\n\n");
    s.push_str("/** Frozen Poseidon2 t=8 parameters over the BLS12-381 scalar field. */\n\n");
    s.push_str("export const STATE_WIDTH = 8;\n");
    s.push_str("export const SBOX_ALPHA = 5n;\n");
    s.push_str("export const ROUNDS_F = 8;\n");
    s.push_str("export const ROUNDS_P = 57;\n");
    s.push_str("export const ROUNDS_TOTAL = ROUNDS_F + ROUNDS_P;\n");
    s.push_str("export const ROUNDS_F_BEGINNING = ROUNDS_F / 2;\n\n");
    // The modulus is not itself a field element, so it is written from its
    // bytes rather than through `fr_dec`.
    writeln!(s, "export const MODULUS = BigInt('0x{}');\n", hex::encode(modulus_be32())).unwrap();
    writeln!(s, "export const MANIFEST_SHA256 = '{}';\n", hex::encode(manifest_hash)).unwrap();
    writeln!(s, "export const DOMAIN_MANIFEST_SHA256 = '{}';\n", hex::encode(domain_hash))
        .unwrap();

    s.push_str("export const MAT_DIAG8: readonly bigint[] = [\n");
    for x in MAT_DIAG8_M_1.iter() {
        writeln!(s, "  {}n,", dec(x)).unwrap();
    }
    s.push_str("];\n\n");

    s.push_str("export const MAT_INTERNAL8: readonly (readonly bigint[])[] = [\n");
    for row in MAT_INTERNAL8.iter() {
        s.push_str("  [\n");
        for x in row.iter() {
            writeln!(s, "    {}n,", dec(x)).unwrap();
        }
        s.push_str("  ],\n");
    }
    s.push_str("];\n\n");

    s.push_str("export const RC8: readonly (readonly bigint[])[] = [\n");
    for row in RC8.iter() {
        s.push_str("  [\n");
        for x in row.iter() {
            writeln!(s, "    {}n,", dec(x)).unwrap();
        }
        s.push_str("  ],\n");
    }
    s.push_str("];\n\n");

    s.push_str("/** Section 4's domain constants, by label. */\n");
    s.push_str("export const DOMAINS: Readonly<Record<string, bigint>> = {\n");
    for (label, value) in domains {
        writeln!(s, "  '{label}': {}n,", dec(value)).unwrap();
    }
    s.push_str("};\n\n");

    s.push_str("/** Section 5's empty-subtree ladder under COMMIT-NODE. */\n");
    s.push_str("export const EMPTY_ROOTS: readonly bigint[] = [\n");
    for value in empty_roots {
        writeln!(s, "  {}n,", dec(value)).unwrap();
    }
    s.push_str("];\n\n");

    s.push_str("/** Known-answer vectors, produced by executing the pinned upstream. */\n");
    s.push_str("export const PERM_VECTORS: readonly { input: bigint[]; output: bigint[] }[] = [\n");
    for kat in perm {
        s.push_str("  {\n    input: [");
        for x in kat.input.iter() {
            write!(s, "{}n, ", dec(x)).unwrap();
        }
        s.push_str("],\n    output: [");
        for x in kat.output.iter() {
            write!(s, "{}n, ", dec(x)).unwrap();
        }
        s.push_str("],\n  },\n");
    }
    s.push_str("];\n\n");

    s.push_str("export const HASH_VECTORS: readonly { label: string; input: bigint[]; output: bigint }[] = [\n");
    for (label, input, output) in hash {
        write!(s, "  {{ label: '{label}', input: [").unwrap();
        for x in input.iter() {
            write!(s, "{}n, ", dec(x)).unwrap();
        }
        writeln!(s, "], output: {}n }},", dec(output)).unwrap();
    }
    s.push_str("];\n");

    std::fs::write(dir.join("poseidon2-params.ts"), s).expect("write TypeScript params");
}

/// A field element as a decimal string, which is what `BigInt` reads.
fn fr_dec(x: &Fr) -> String {
    let bytes = fr_be32(x);
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn write_provenance(root: &Path, manifest: &[u8], manifest_hash: &[u8; 32]) {
    let dir = root.join("crypto/poseidon2");
    std::fs::create_dir_all(&dir).expect("provenance dir");
    std::fs::write(dir.join("manifest.bin"), manifest).expect("write manifest");
    let mut s = String::new();
    s.push_str("# Poseidon2 t=8 parameter provenance\n\n");
    s.push_str("Every generated file below is produced by `manifest-gen`, which executes the\n");
    s.push_str("pinned upstream reference rather than re-deriving anything.\n\n");
    writeln!(s, "    upstream        {UPSTREAM_REPO}").unwrap();
    writeln!(s, "    commit          {UPSTREAM_COMMIT}\n").unwrap();
    s.push_str("Upstream source files the constants and the permutation come from:\n\n");
    for path in [
        "plain_implementations/src/poseidon2/poseidon2_instance_bls12.rs",
        "plain_implementations/src/poseidon2/poseidon2.rs",
        "plain_implementations/src/poseidon2/poseidon2_params.rs",
        "plain_implementations/src/fields/bls12.rs",
    ] {
        writeln!(s, "    {path}").unwrap();
    }
    s.push_str("\nTheir SHA-256 digests are recorded in `upstream-sources.sha256`. That file is\n");
    s.push_str("a record, not a check the generator performs: verify it against the pin with\n\n");
    s.push_str("    git -C <clone of the upstream> show ");
    s.push_str(UPSTREAM_COMMIT);
    s.push_str(":<path> | sha256sum\n\n");
    s.push_str("## Manifest\n\n");
    s.push_str("The manifest is the byte stream defined by the work order, not a formatted\n");
    s.push_str("document: the tag with its NUL, the modulus, the four parameters, then every\n");
    s.push_str("constant as 32-byte big-endian, in order.\n\n");
    writeln!(s, "    bytes           {}", manifest.len()).unwrap();
    writeln!(s, "    sha256          {}\n", hex::encode(manifest_hash)).unwrap();
    s.push_str("Both VMs rebuild this stream from their own vendored tables and compare the\n");
    s.push_str("digest, so a constant that differs between them cannot pass unnoticed.\n\n");
    s.push_str("## Generated files\n\n");
    for path in [
        "crypto/vm/poseidon2-params.h",
        "crypto/vm/poseidon2-kat.h",
        "tosctl/src/block/src/poseidon2_params.rs",
        "tosctl/src/block/src/poseidon2_kat.rs",
        "crypto/poseidon2/manifest.bin",
    ] {
        writeln!(s, "    {path}").unwrap();
    }
    s.push_str("\n## Regenerating\n\n");
    s.push_str("    cd crypto/poseidon2/manifest-gen\n");
    s.push_str("    cargo run --release -- ../../..\n\n");
    s.push_str("The generator fails on any wrong table shape, a non-canonical constant or a\n");
    s.push_str("domain constant that reduces to zero. A regenerated tree that differs from the\n");
    s.push_str("committed one means the pin moved, and that is a consensus-visible change.\n");
    std::fs::write(dir.join("PROVENANCE.md"), s).expect("write provenance");
}
