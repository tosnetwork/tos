//! Fresh per-spend Schnorr-on-Ristretto255 signature (§2.5).
//!
//! Per §2.5 the wallet samples a fresh `rsk ∈ scalars(Ristretto255)` for each
//! spend and publishes `rk = rsk · G`. The spend_auth_sig signs the
//! canonical `tx_hash` (§4.1) under `rsk`. There is no long-term `ak` / `ask`
//! — the AIR has no responsibility for linking `rk` to the seed (§4.2
//! footnote), so the Schnorr primitive is self-contained.
//!
//! # Scheme (matches §4.3 step 3 verifier + A3 C++ mirror)
//!
//! Standard Schnorr, with the challenge hashed via BLAKE2b-512 → Ristretto
//! scalar for byte-identical cross-impl behavior:
//!
//! ```text
//!   sign(rsk, msg):
//!       k      = BLAKE2b-512("uno-schnorr-nonce-v1", rsk, msg)  // 64 B
//!       kscalar= Scalar::from_bytes_mod_order_wide(k)
//!       R      = kscalar · G                                    // 32 B
//!       c      = Scalar::from_bytes_mod_order_wide(
//!                    BLAKE2b-512("uno-schnorr-chal-v1", R, rk, msg))
//!       s      = kscalar + c · rsk
//!       sig    = R.compress() || s.to_bytes()                   // 64 B
//!
//!   verify(rk, msg, sig):
//!       (R_bytes, s_bytes) = split sig 32/32
//!       s = Scalar(s_bytes)
//!       R = CompressedRistretto(R_bytes)
//!       c = Scalar::from_bytes_mod_order_wide(
//!               BLAKE2b-512("uno-schnorr-chal-v1", R_bytes, rk, msg))
//!       check:  s · G  ==  R + c · rk
//! ```
//!
//! Deterministic nonce derivation (`k`) is a defensive choice against RNG
//! weaknesses on mobile clients; equivalent to RFC 6979 for Schnorr. The
//! `rsk` itself is sampled from OS randomness (see `keypair` below); only
//! the per-signature nonce is deterministic.
//!
//! This module mirrors the C++ `uno/crypto/schnorr.cpp` spend-auth routines
//! (when they land in the final codec commit); test-level bit-compatibility
//! is deferred to the cross-impl golden fixture — §12 / decision #5.

use anyhow::{anyhow, Result};
use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use zeroize::Zeroize;

const DS_NONCE: &[u8] = b"uno-schnorr-nonce-v1";
const DS_CHALLENGE: &[u8] = b"uno-schnorr-chal-v1";

/// A fresh per-spend keypair.
///
/// `rsk` zeroizes on drop (it's a one-time secret but still worth wiping
/// from memory for coldness). `Debug` prints only the public `rk` to avoid
/// accidentally logging the secret.
#[derive(Clone)]
pub struct SpendKeyPair {
    pub rsk: Scalar,
    pub rk:  [u8; 32],
}

impl std::fmt::Debug for SpendKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally opaque on `rsk` — never dump the secret scalar.
        f.debug_struct("SpendKeyPair")
            .field("rk", &hex::encode(self.rk))
            .field("rsk", &"<redacted>")
            .finish()
    }
}

impl Drop for SpendKeyPair {
    fn drop(&mut self) {
        // Scalar Drop clears automatically in curve25519-dalek 4.x via the
        // zeroize feature. Defensively, also zeroize the compressed pubkey
        // buffer (public; wiping is belt-and-suspenders).
        self.rk.zeroize();
    }
}

/// Build a fresh spend keypair. `rsk` is sampled from OS randomness.
pub fn keypair<R: RngCore>(rng: &mut R) -> SpendKeyPair {
    let rsk = sample_scalar(rng);
    let rk_point = rsk * RISTRETTO_BASEPOINT_POINT;
    let rk = rk_point.compress().to_bytes();
    SpendKeyPair { rsk, rk }
}

/// Build a keypair from a pre-sampled 64-byte uniform buffer (test-only, but
/// exposed because `send` tests need determinism).
pub fn keypair_from_uniform_64(uniform: [u8; 64]) -> SpendKeyPair {
    let rsk = Scalar::from_bytes_mod_order_wide(&uniform);
    let rk_point = rsk * RISTRETTO_BASEPOINT_POINT;
    let rk = rk_point.compress().to_bytes();
    SpendKeyPair { rsk, rk }
}

fn sample_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    // 64 bytes → wide-reduction → uniform Ristretto scalar.
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let s = Scalar::from_bytes_mod_order_wide(&buf);
    buf.zeroize();
    s
}

/// Schnorr-on-Ristretto255 sign.
pub fn sign(kp: &SpendKeyPair, msg: &[u8; 32]) -> [u8; 64] {
    // Deterministic nonce.
    let k_bytes = blake2b_512(&[DS_NONCE, &kp.rsk.to_bytes(), msg]);
    let k = Scalar::from_bytes_mod_order_wide(&k_bytes);
    let r_point: RistrettoPoint = k * RISTRETTO_BASEPOINT_POINT;
    let r_bytes = r_point.compress().to_bytes();

    // Challenge.
    let c_bytes = blake2b_512(&[DS_CHALLENGE, &r_bytes, &kp.rk, msg]);
    let c = Scalar::from_bytes_mod_order_wide(&c_bytes);

    // s = k + c · rsk
    let s = k + c * kp.rsk;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

/// Schnorr-on-Ristretto255 verify. Returns `Ok(())` on valid sig,
/// `Err(...)` otherwise.
pub fn verify(rk_bytes: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    let rk = CompressedRistretto(*rk_bytes)
        .decompress()
        .ok_or_else(|| anyhow!("schnorr verify: rk is not a valid Ristretto point"))?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);

    let big_r = CompressedRistretto(r_bytes)
        .decompress()
        .ok_or_else(|| anyhow!("schnorr verify: R is not a valid Ristretto point"))?;
    // Canonical scalar decode — reject non-canonical s encodings.
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or_else(|| anyhow!("schnorr verify: s is not a canonical scalar"))?;

    let c_bytes = blake2b_512(&[DS_CHALLENGE, &r_bytes, rk_bytes, msg]);
    let c = Scalar::from_bytes_mod_order_wide(&c_bytes);

    // Verify: s·G ?= R + c·rk
    let lhs = s * RISTRETTO_BASEPOINT_POINT;
    let rhs = big_r + c * rk;
    if lhs == rhs {
        Ok(())
    } else {
        Err(anyhow!("schnorr verify: signature does not verify"))
    }
}

fn blake2b_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2b::<U64>::new();
    for piece in inputs {
        h.update(piece);
    }
    let out = h.finalize();
    let mut fixed = [0u8; 64];
    fixed.copy_from_slice(&out);
    fixed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = OsRng;
        let kp = keypair(&mut rng);
        let msg = [0x42u8; 32];
        let sig = sign(&kp, &msg);
        verify(&kp.rk, &msg, &sig).expect("valid sig should verify");
    }

    #[test]
    fn sig_is_deterministic_for_same_rsk_and_msg() {
        let kp = keypair_from_uniform_64([0x11; 64]);
        let msg = [0x22u8; 32];
        let a = sign(&kp, &msg);
        let b = sign(&kp, &msg);
        assert_eq!(a, b, "deterministic nonce → deterministic sig");
    }

    #[test]
    fn flipping_msg_breaks_verify() {
        let mut rng = OsRng;
        let kp = keypair(&mut rng);
        let msg = [0x01u8; 32];
        let sig = sign(&kp, &msg);
        let mut bad = msg;
        bad[0] ^= 1;
        assert!(verify(&kp.rk, &bad, &sig).is_err());
    }

    #[test]
    fn flipping_sig_breaks_verify() {
        let mut rng = OsRng;
        let kp = keypair(&mut rng);
        let msg = [0x01u8; 32];
        let mut sig = sign(&kp, &msg);
        sig[0] ^= 1;
        assert!(verify(&kp.rk, &msg, &sig).is_err());
    }

    #[test]
    fn flipping_rk_breaks_verify() {
        let mut rng = OsRng;
        let kp = keypair(&mut rng);
        let msg = [0x01u8; 32];
        let sig = sign(&kp, &msg);
        let mut wrong_rk = kp.rk;
        wrong_rk[0] ^= 1;
        // wrong_rk might not even decompress; both outcomes are errors.
        assert!(verify(&wrong_rk, &msg, &sig).is_err());
    }
}
