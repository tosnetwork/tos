// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// The Rust VM's SLH-DSA-SHA2-128s backend against the shared fixture the C++ test reads, in
// whichever SHA-256 backend this build selected. Every signature must verify; flipping a byte of
// the randomizer, of the last hypertree layer or of the message must not.
// TOS_REQUIRE_SHA_NI=1 also requires the SHA-NI path to be the one executing.

use super::tos_rust_slhdsa128s_verify;
use std::ffi::CStr;
use std::os::raw::c_char;

extern "C" {
    fn tos_rust_slhdsa_sha256_backend() -> *const c_char;
}

fn backend() -> String {
    // SAFETY: the shim returns a pointer to a static NUL-terminated string.
    unsafe { CStr::from_ptr(tos_rust_slhdsa_sha256_backend()) }
        .to_str()
        .expect("ASCII backend name")
        .to_string()
}

fn verify(message: &[u8], context: &[u8], signature: &[u8], key: &[u8]) -> i32 {
    assert_eq!(key.len(), super::SLH_PUBLIC_KEY_BYTES);
    // SAFETY: borrowed buffers outlive this synchronous, verify-only call; the key length is
    // checked above and the shim checks the signature length itself.
    unsafe {
        tos_rust_slhdsa128s_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            context.as_ptr(),
            context.len(),
            key.as_ptr(),
        )
    }
}

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn slhdsa_fixture_vectors() {
    let backend = backend();
    println!("SLH-DSA SHA-256 backend: {backend}");
    if std::env::var("TOS_REQUIRE_SHA_NI").as_deref() == Ok("1") {
        assert_eq!(backend, "sha-ni");
    }
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-slhdsa/slh-verify-vectors.txt");
    let text = std::fs::read_to_string(path).expect("shared SLH-DSA fixture");
    let mut vectors = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<Vec<u8>> = line.split_whitespace().map(from_hex).collect();
        assert_eq!(fields.len(), 4, "public_key context message signature");
        let (key, context, message, signature) = (&fields[0], &fields[1], &fields[2], &fields[3]);
        assert_eq!(signature.len(), super::SLH_SIGNATURE_BYTES);

        assert_eq!(verify(message, context, signature, key), 1);
        for at in [0, signature.len() - 1] {
            let mut bad = signature.clone();
            bad[at] ^= 1;
            assert_eq!(verify(message, context, &bad, key), 0);
        }
        let mut other = message.clone();
        other[0] ^= 1;
        assert_eq!(verify(&other, context, signature, key), 0);
        vectors += 1;
    }
    assert_eq!(vectors, 4);
}
