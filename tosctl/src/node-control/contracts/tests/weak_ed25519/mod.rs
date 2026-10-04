//! Ed25519 public keys an attestor or settlement authority must not be given.
//!
//! The eight canonical encodings of the 8-torsion subgroup -- anyone can forge
//! a signature that verifies under them -- and encodings whose y is at least
//! 2^255 - 19, with and without x's sign bit, which name a point under a
//! second, non-canonical spelling. Bytes are in the order a contract loads
//! them with `load_uint(256)`.

#![allow(dead_code)]

fn key(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

pub fn weak_keys() -> Vec<[u8; 32]> {
    [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        // y = 2^255 - 19 exactly, and y = 2^255 - 1, each with the sign bit set too.
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    .iter()
    .map(|hex| key(hex))
    .collect()
}

/// A signature under `public_key` over `message` that needs no secret, if this
/// message admits one: R is one of the eight torsion encodings and S is zero,
/// which verifies whenever R happens to equal -[k]A for k = H(R || A || message).
/// Only a torsion `public_key` makes that likely; vary the message until it
/// does. Accepted by the same cofactorless check the sandbox VM runs, so a
/// returned signature is one CHKSIGNU accepts.
pub fn forge(public_key: &[u8; 32], message: &[u8]) -> Option<[u8; 64]> {
    use ed25519_dalek::Verifier;
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key).ok()?;
    weak_keys().into_iter().take(8).find_map(|commitment| {
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&commitment);
        key.verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .is_ok()
            .then_some(signature)
    })
}
