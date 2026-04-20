//! Uno v1 key hierarchy derivation per §2.6.
//!
//! Produces from a 32-byte main TOS seed (or a 24-word BIP-39 mnemonic):
//!
//! ```text
//!   uno_seed   = BLAKE2b-256("uno-seed-v1" || main_tos_seed)
//!   nk         = Poseidon2("uno-nk-v1",  uno_seed)
//!   ivk        = Poseidon2("uno-ivk-v1", uno_seed, nk)
//!   ovk        = BLAKE2b-256("uno-ovk-v1"   || uno_seed)
//!   mlkem_seed = BLAKE2b-256("uno-mlkem-v1" || uno_seed)
//!   (pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen(mlkem_seed)
//!   fvk = (ivk, nk, ovk, sk_mlkem)
//! ```
//!
//! Design note: the doc-§2.6 derivation rule I-B landed on does **not**
//! include a long-term Schnorr spend-auth key `ask`/`ak` — fresh per-spend
//! `rk` is used instead (§2.5). A3's C++ header still declares `ak`/`ask`
//! fields; the wallet emits them as zero-filled placeholders to stay
//! source-compatible with any tooling that reads the FullViewingKey JSON.
//! When the C++ side catches up to the no-`ak` rule, the placeholders can
//! be dropped from the JSON schema.

use anyhow::{anyhow, Context, Result};
use blake2::digest::consts::{U32, U64};
use blake2::{Blake2b, Digest};
use bip39::Mnemonic;
use curve25519_dalek::scalar::Scalar;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::poseidon2;
use crate::sizes::{DIGEST, MLKEM768_PK, MLKEM768_SK, UNO_SEED};
use crate::tags;

/// 32-byte digest / viewing-key component. Stored raw; zeroize on drop to
/// reduce the in-memory footprint of scan-cache copies.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest32(#[serde(with = "hex::serde")] pub [u8; 32]);

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest32({})", hex::encode(self.0))
    }
}

/// Full viewing key — the complete audit bundle.
///
/// Matches the JSON emitted by `tosctl uno keygen`. `pk_mlkem` is carried
/// alongside `sk_mlkem` because ML-KEM recovers the pk from the sk; this
/// matches the A3 C++ `FullViewingKey` convention.
#[derive(Clone, Serialize, Deserialize)]
pub struct FullViewingKey {
    /// `uno_seed = BLAKE2b-256("uno-seed-v1" || main_tos_seed)` (32 B).
    #[serde(with = "hex::serde")]
    pub uno_seed: [u8; UNO_SEED],

    /// `nk = Poseidon2("uno-nk-v1", uno_seed)` — 256-bit nullifier key.
    pub nk: Digest32,

    /// `ivk = Poseidon2("uno-ivk-v1", uno_seed, nk)` — 256-bit incoming VK.
    pub ivk: Digest32,

    /// `ovk = BLAKE2b-256("uno-ovk-v1" || uno_seed)` — 32 B outgoing VK.
    pub ovk: Digest32,

    /// `mlkem_seed = BLAKE2b-256("uno-mlkem-v1" || uno_seed)` — 32 B ML-KEM
    /// KeyGen seed fed into `ML-KEM-768.KeyGen`.
    pub mlkem_seed: Digest32,

    /// ML-KEM-768 public key (1184 B).
    #[serde(with = "hex::serde")]
    pub pk_mlkem: Vec<u8>,

    /// ML-KEM-768 secret key (2400 B). Hex-encoded in JSON.
    #[serde(with = "hex::serde")]
    pub sk_mlkem: Vec<u8>,
}

impl Drop for FullViewingKey {
    fn drop(&mut self) {
        self.uno_seed.zeroize();
        self.nk.0.zeroize();
        self.ivk.0.zeroize();
        self.ovk.0.zeroize();
        self.mlkem_seed.0.zeroize();
        self.sk_mlkem.zeroize();
        // pk_mlkem is public; no need to zero.
    }
}

impl FullViewingKey {
    /// `ivk` as a Ristretto255 scalar — mod-L reduction of the 32 wire bytes.
    /// Used off-circuit to derive `pk_d = ivk · g_d` and, receiver-side, for
    /// `s_dh = ivk · epk`.
    pub fn ivk_scalar(&self) -> Scalar {
        // Scalar::from_bytes_mod_order accepts any 32-byte input and reduces
        // it mod ℓ (the Ed25519/Ristretto group order). This matches
        // `uno/crypto/stealth-address.cpp::ivk_to_scalar`.
        Scalar::from_bytes_mod_order(self.ivk.0)
    }
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 helper
// ---------------------------------------------------------------------------

fn blake2b_256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    for piece in inputs {
        h.update(piece);
    }
    let out = h.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    fixed
}

/// BLAKE2b-512, returned as 64 bytes.
pub fn blake2b_512(inputs: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2b::<U64>::new();
    for piece in inputs {
        h.update(piece);
    }
    let out = h.finalize();
    let mut fixed = [0u8; 64];
    fixed.copy_from_slice(&out);
    fixed
}

// ---------------------------------------------------------------------------
// Main TOS seed sources
// ---------------------------------------------------------------------------

/// Parse a 24-word BIP-39 mnemonic and return the main TOS seed. TOS main
/// wallets use the 64-byte PBKDF2 output as "seed"; we truncate to the first
/// 32 bytes for `uno_seed` derivation per §2.6 convention.
pub fn tos_seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| anyhow!("invalid BIP-39 mnemonic: {e}"))?;
    let seed_64 = mnemonic.to_seed_normalized(passphrase);
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&seed_64[..32]);
    Ok(seed_32)
}

/// Load a 32-byte main TOS seed from a file. Accepts either:
///   - 32 raw bytes, or
///   - 64 hex characters (one line), trimmed of whitespace.
pub fn tos_seed_from_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading seed file {}", path.display()))?;
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        return Ok(out);
    }
    let s = String::from_utf8(raw)
        .map_err(|_| anyhow!("seed file is neither 32 raw bytes nor ASCII hex"))?;
    let trimmed = s.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow!("seed file hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("seed hex must decode to 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Full §2.6 derivation from a 32-byte main TOS seed.
pub fn derive_fvk(main_tos_seed: &[u8; 32]) -> Result<FullViewingKey> {
    // (1) uno_seed
    let uno_seed = blake2b_256(&[tags::UNO_SEED_V1, main_tos_seed]);

    // (2) in-circuit-reproducible secrets via Poseidon2
    //
    //   nk  = Poseidon2("uno-nk-v1",  uno_seed)
    //   ivk = Poseidon2("uno-ivk-v1", uno_seed, nk)
    //
    // `uno_seed` is a 32-byte opaque blob. Per the §2.6 footnote, we treat
    // it as 4 canonical Goldilocks limbs for absorption; if the raw bytes
    // produce a non-canonical limb, we fold by subtracting p once (matches
    // the C++ Goldilocks::from_wrapped_u64 convention A3 uses for seed input).
    let nk = poseidon2::hash_tagged_bytes(tags::UNO_NK_V1, &uno_seed);
    // ivk absorbs (uno_seed, nk) — 8 limbs total + 1 tag fe = 9 → width-16 permutation.
    let ivk_input = {
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&uno_seed);
        concat[32..].copy_from_slice(&nk);
        poseidon2::bytes_to_fes_wrapped(&concat)
    };
    let ivk = poseidon2::hash_tagged(tags::UNO_IVK_V1, &ivk_input);

    // (3) byte-oriented secrets
    let ovk        = blake2b_256(&[tags::UNO_OVK_V1, &uno_seed]);
    let mlkem_seed = blake2b_256(&[tags::UNO_MLKEM_V1, &uno_seed]);

    // (4) ML-KEM-768 deterministic key generation
    //
    // FIPS 203 uses two 32-byte random inputs (d, z). We expand our 32-byte
    // `mlkem_seed` to 64 bytes via BLAKE2b-512 so that (d, z) are
    // domain-separated but deterministic in `uno_seed`. The C++ side uses the
    // identical BLAKE2b-512 expansion (see `uno/crypto/stealth-address.h`
    // header comment).
    let dz = blake2b_512(&[b"uno-mlkem-keygen-v1", &mlkem_seed]);
    let mut d_buf = [0u8; 32];
    let mut z_buf = [0u8; 32];
    d_buf.copy_from_slice(&dz[..32]);
    z_buf.copy_from_slice(&dz[32..]);
    let d_arr: B32 = Array::from(d_buf);
    let z_arr: B32 = Array::from(z_buf);
    let (dk, ek) = MlKem768::generate_deterministic(&d_arr, &z_arr);
    let pk_mlkem = ek.as_bytes().as_slice().to_vec();
    let sk_mlkem = dk.as_bytes().as_slice().to_vec();

    debug_assert_eq!(pk_mlkem.len(), MLKEM768_PK);
    debug_assert_eq!(sk_mlkem.len(), MLKEM768_SK);

    Ok(FullViewingKey {
        uno_seed,
        nk:         Digest32(nk),
        ivk:        Digest32(ivk),
        ovk:        Digest32(ovk),
        mlkem_seed: Digest32(mlkem_seed),
        pk_mlkem,
        sk_mlkem,
    })
}

/// `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` (§2.6, decision #1).
///
/// Inputs packed as Goldilocks elements: `ivk` = 4 limbs (32 B); `d` = 11 B
/// padded with one zero byte to 16 B = 2 limbs. Total absorb = 6 fes + 1 tag =
/// 7 → width-8 permutation.
pub fn ivk_commitment(ivk: &[u8; DIGEST], diversifier_11: &[u8]) -> Result<[u8; DIGEST]> {
    if diversifier_11.len() != 11 {
        return Err(anyhow!("diversifier must be 11 bytes, got {}", diversifier_11.len()));
    }
    // ivk → 4 Goldilocks limbs (wrapped load, canonical fold for bytes).
    let mut fes = poseidon2::bytes_to_fes_wrapped(ivk);
    // d (11 B) padded to 16 B → 2 limbs.
    let mut padded = [0u8; 16];
    padded[..11].copy_from_slice(diversifier_11);
    fes.extend(poseidon2::bytes_to_fes_wrapped(&padded));
    Ok(poseidon2::hash_tagged(tags::UNO_IVK_CM_V1, &fes))
}

// ---------------------------------------------------------------------------
// ML-KEM encap/decap wrappers used by note encryption (§2.7)
// ---------------------------------------------------------------------------

/// Decapsulate an ML-KEM-768 ciphertext with the wallet's `sk_mlkem`,
/// returning the 32-byte shared secret.
pub fn mlkem_decap(sk_mlkem: &[u8], ct: &[u8]) -> Result<[u8; 32]> {
    type DK = <MlKem768 as KemCore>::DecapsulationKey;
    if sk_mlkem.len() != MLKEM768_SK {
        return Err(anyhow!("sk_mlkem must be {MLKEM768_SK} bytes, got {}", sk_mlkem.len()));
    }
    if ct.len() != crate::sizes::MLKEM768_CT {
        return Err(anyhow!("mlkem_ct must be {} bytes, got {}", crate::sizes::MLKEM768_CT, ct.len()));
    }
    let dk_arr = Array::<u8, <DK as EncodedSizeUser>::EncodedSize>::try_from(sk_mlkem)
        .map_err(|_| anyhow!("ml-kem decap key length mismatch"))?;
    let dk = DK::from_bytes(&dk_arr);
    let ct_typed = Ciphertext::<MlKem768>::try_from(ct)
        .map_err(|_| anyhow!("ml-kem ct length mismatch"))?;
    let ss = dk.decapsulate(&ct_typed)
        .map_err(|_| anyhow!("ml-kem decap failed"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

/// Encapsulate to a peer's ML-KEM-768 pk, returning `(ciphertext, shared_secret)`.
pub fn mlkem_encap(pk_mlkem: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    type EK = <MlKem768 as KemCore>::EncapsulationKey;
    if pk_mlkem.len() != MLKEM768_PK {
        return Err(anyhow!("pk_mlkem must be {MLKEM768_PK} bytes, got {}", pk_mlkem.len()));
    }
    let ek_arr = Array::<u8, <EK as EncodedSizeUser>::EncodedSize>::try_from(pk_mlkem)
        .map_err(|_| anyhow!("ml-kem encap key length mismatch"))?;
    let ek = EK::from_bytes(&ek_arr);
    let mut rng = rand::thread_rng();
    let (ct, ss) = ek.encapsulate(&mut rng)
        .map_err(|_| anyhow!("ml-kem encap failed"))?;
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), ss_bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for i in 0..32 { s[i] = i as u8; }
        s
    }

    #[test]
    fn derive_is_deterministic() {
        let seed = fixed_seed();
        let a = derive_fvk(&seed).unwrap();
        let b = derive_fvk(&seed).unwrap();
        assert_eq!(a.nk.0,         b.nk.0);
        assert_eq!(a.ivk.0,        b.ivk.0);
        assert_eq!(a.ovk.0,        b.ovk.0);
        assert_eq!(a.mlkem_seed.0, b.mlkem_seed.0);
        assert_eq!(a.pk_mlkem,     b.pk_mlkem);
        assert_eq!(a.sk_mlkem,     b.sk_mlkem);
    }

    #[test]
    fn uno_seed_is_domain_separated() {
        let seed = fixed_seed();
        let fvk = derive_fvk(&seed).unwrap();
        // Raw bytes of uno_seed MUST NOT equal the input TOS seed (i.e. the
        // domain-separated BLAKE2b MUST have been applied).
        assert_ne!(fvk.uno_seed, seed, "uno_seed must differ from main_tos_seed");
    }

    #[test]
    fn ivk_commitment_binds_to_diversifier() {
        let seed = fixed_seed();
        let fvk = derive_fvk(&seed).unwrap();
        let d1 = [0xaau8; 11];
        let d2 = [0xbbu8; 11];
        let ic1 = ivk_commitment(&fvk.ivk.0, &d1).unwrap();
        let ic2 = ivk_commitment(&fvk.ivk.0, &d2).unwrap();
        assert_ne!(ic1, ic2, "different diversifiers must yield different commitments");

        // Same inputs → same commitment.
        let ic1b = ivk_commitment(&fvk.ivk.0, &d1).unwrap();
        assert_eq!(ic1, ic1b);
    }

    #[test]
    fn mlkem_encap_decap_roundtrip() {
        let seed = fixed_seed();
        let fvk = derive_fvk(&seed).unwrap();
        let (ct, ss_sender) = mlkem_encap(&fvk.pk_mlkem).unwrap();
        let ss_receiver = mlkem_decap(&fvk.sk_mlkem, &ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn mnemonic_to_seed_is_deterministic() {
        let m = "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon art";
        let s1 = tos_seed_from_mnemonic(m, "").unwrap();
        let s2 = tos_seed_from_mnemonic(m, "").unwrap();
        assert_eq!(s1, s2);
        // Different passphrase → different seed.
        let s3 = tos_seed_from_mnemonic(m, "TREZOR").unwrap();
        assert_ne!(s1, s3);
    }
}
