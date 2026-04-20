//! Hybrid ECDH + ML-KEM-768 KEM combiner (§2.7).
//!
//! Byte-identical to `uno/crypto/hybrid-kem.{h,cpp}`. Shared between the
//! sender (future `tosctl uno send`) and receiver (current `scan` path).
//!
//! ```text
//!   k_aead = BLAKE3(
//!       "uno-hybrid-kem-v1"                ||   //  17 B (no NUL)
//!       compress(s_dh)              (32 B) ||
//!       s_pq                        (32 B) ||
//!       compress(epk)               (32 B) ||
//!       BLAKE3(mlkem_ct)            (32 B)
//!   )[0..32]
//!
//!   nonce = BLAKE3("uno-nonce-v1" || compress(epk))[0..12]
//! ```
//!
//! The double-hash on `mlkem_ct` (rather than absorbing the full 1088 bytes)
//! keeps the transcript fixed-size at 17 + 32·4 = 145 bytes.

use crate::sizes::{AEAD_KEY, AEAD_NONCE, RISTRETTO_POINT};
use crate::tags;

/// Derive `k_aead` from the four transcript inputs.
///
/// `s_dh` / `s_pq` / `epk` / `mlkem_ct` must have the sizes declared in §2.7;
/// we assert lengths rather than silently truncating.
pub fn derive_key(
    s_dh_compressed_32: &[u8],
    s_pq_32: &[u8],
    epk_compressed_32: &[u8],
    mlkem_ct: &[u8],
) -> [u8; AEAD_KEY] {
    assert_eq!(s_dh_compressed_32.len(), RISTRETTO_POINT);
    assert_eq!(s_pq_32.len(),              32);
    assert_eq!(epk_compressed_32.len(),    RISTRETTO_POINT);
    assert_eq!(mlkem_ct.len(),             crate::sizes::MLKEM768_CT);

    let ct_hash = {
        let mut h = blake3::Hasher::new();
        h.update(mlkem_ct);
        *h.finalize().as_bytes()
    };

    let mut h = blake3::Hasher::new();
    h.update(tags::UNO_HYBRID_KEM_V1);
    h.update(s_dh_compressed_32);
    h.update(s_pq_32);
    h.update(epk_compressed_32);
    h.update(&ct_hash);
    let out = h.finalize();
    let mut k = [0u8; AEAD_KEY];
    k.copy_from_slice(&out.as_bytes()[..AEAD_KEY]);
    k
}

/// Nonce derivation: `BLAKE3("uno-nonce-v1" || compress(epk))[0..12]`.
pub fn derive_nonce(epk_compressed_32: &[u8]) -> [u8; AEAD_NONCE] {
    assert_eq!(epk_compressed_32.len(), RISTRETTO_POINT);
    let mut h = blake3::Hasher::new();
    h.update(tags::UNO_NONCE_V1);
    h.update(epk_compressed_32);
    let d = h.finalize();
    let mut n = [0u8; AEAD_NONCE];
    n.copy_from_slice(&d.as_bytes()[..AEAD_NONCE]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let s_dh = [0x11u8; 32];
        let s_pq = [0x22u8; 32];
        let epk  = [0x33u8; 32];
        let mlkem_ct = vec![0x44u8; crate::sizes::MLKEM768_CT];
        let k1 = derive_key(&s_dh, &s_pq, &epk, &mlkem_ct);
        let k2 = derive_key(&s_dh, &s_pq, &epk, &mlkem_ct);
        assert_eq!(k1, k2);
    }

    #[test]
    fn nonce_is_deterministic_in_epk() {
        let n1 = derive_nonce(&[0u8; 32]);
        let n2 = derive_nonce(&[0u8; 32]);
        let n3 = derive_nonce(&[1u8; 32]);
        assert_eq!(n1, n2);
        assert_ne!(n1, n3);
    }

    #[test]
    fn ct_binding_is_effective() {
        // Flipping any byte of the mlkem_ct must change k_aead.
        let s_dh = [0u8; 32]; let s_pq = [0u8; 32]; let epk = [0u8; 32];
        let mut ct = vec![0u8; crate::sizes::MLKEM768_CT];
        let k1 = derive_key(&s_dh, &s_pq, &epk, &ct);
        ct[0] ^= 1;
        let k2 = derive_key(&s_dh, &s_pq, &epk, &ct);
        assert_ne!(k1, k2);
    }
}
