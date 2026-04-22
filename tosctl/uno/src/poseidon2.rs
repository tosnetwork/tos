//! Poseidon2-over-Goldilocks off-circuit wrapper.
//!
//! Design doc §2.2, §2.6. The wallet must compute `nk`, `ivk`,
//! `ivk_commitment`, and `filter_tag` byte-identically to the C++ side
//! (`uno/crypto/poseidon2.cpp` + `uno/crypto/goldilocks.cpp`) and to the
//! in-circuit Plonky3 AIR, otherwise the ownership claim (§4.2 claim 3) does
//! not reproduce.
//!
//! We wrap the Plonky3 `p3-poseidon2` permutation directly. The pin
//! (commit `6374a36f`) matches the rev in `uno/plonky3-ffi/Cargo.toml`.
//!
//! # Representation contract
//!
//! - A 256-bit digest is **4 canonical Goldilocks field elements** stored as
//!   4 × 8-byte little-endian u64 limbs. Non-canonical limbs are rejected
//!   on read.
//! - A domain tag is packed into **8 field elements** (exactly — the C++
//!   wrapper's `pack_domain_tag`): bytes are loaded 8 at a time as LE u64
//!   into Fp; the final partial chunk is zero-padded; trailing slots are
//!   zero. Tags must be ASCII (≤ 56 bytes total); uno tags are all ≤ 16 B.
//!
//! # Sponge flow
//!
//! Matches `uno/crypto/poseidon2.cpp::hash_with_tag_and_fp`:
//!
//! - `n <= 8`: t=16 permutation with state = `[tag(8) || inputs(n) || pad(8-n)]`.
//! - `n  > 8`: iterated t=16 sponge — rate 8 bytes, capacity 8. Tag occupies
//!   the capacity half; inputs absorb into the rate half, adding into
//!   current state (not replacing). Final partial block uses `10*` padding.
//!
//! Truncated output is the first 4 state elements.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_16, Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;

use crate::sizes::DIGEST;

// Goldilocks prime.
const P_GL: u64 = <Goldilocks as PrimeField64>::ORDER_U64;

// ---------------------------------------------------------------------------
// Permutation singleton (width 16; all tagged hashes route through t=16).
// ---------------------------------------------------------------------------

fn perm16() -> &'static Poseidon2Goldilocks<16> {
    use std::sync::OnceLock;
    static P: OnceLock<Poseidon2Goldilocks<16>> = OnceLock::new();
    P.get_or_init(default_goldilocks_poseidon2_16)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Fallible parse: wire limb (u64 LE) → Goldilocks, rejecting non-canonical.
pub fn limb_to_fe(limb: u64) -> Option<Goldilocks> {
    if limb >= P_GL {
        None
    } else {
        Some(Goldilocks::from_u64(limb))
    }
}

/// Decode 32 wire-bytes as 4 canonical Goldilocks limbs.
pub fn digest_to_fes(bytes: &[u8]) -> Option<[Goldilocks; 4]> {
    if bytes.len() != DIGEST {
        return None;
    }
    let mut out = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let mut limb_le = [0u8; 8];
        limb_le.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        out[i] = limb_to_fe(u64::from_le_bytes(limb_le))?;
    }
    Some(out)
}

/// Encode 4 field elements to 32 wire bytes (canonical u64 LE limbs).
pub fn fes_to_digest(fes: &[Goldilocks; 4]) -> [u8; DIGEST] {
    let mut out = [0u8; DIGEST];
    for i in 0..4 {
        let v = fes[i].as_canonical_u64();
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// Load u64 LE, folding into canonical range with one conditional subtract.
/// Matches C++ `fp_from_u64` used on seed-derivation byte inputs.
fn load_wrapped(limb: u64) -> Goldilocks {
    let v = if limb >= P_GL { limb - P_GL } else { limb };
    Goldilocks::from_u64(v)
}

/// Public: byte slice → Vec<Fp> using the wrapped-load convention.
pub fn bytes_to_fes_wrapped(bytes: &[u8]) -> Vec<Goldilocks> {
    assert!(bytes.len() % 8 == 0);
    bytes
        .chunks_exact(8)
        .map(|c| load_wrapped(u64::from_le_bytes(c.try_into().unwrap())))
        .collect()
}

/// Pack an ASCII tag into exactly 8 Goldilocks elements — matches C++
/// `pack_domain_tag` byte-for-byte. Extra slots are zero.
fn pack_tag_block(tag: &[u8]) -> [Goldilocks; 8] {
    let mut out = [Goldilocks::ZERO; 8];
    let n = tag.len().min(64);
    let full = (n / 8).min(8);
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..i * 8 + 8]);
        let v = u64::from_le_bytes(limb);
        assert!(v < P_GL, "tag chunk not canonical (non-ASCII?)");
        out[i] = Goldilocks::from_u64(v);
    }
    let rem = n - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        let v = u64::from_le_bytes(buf);
        assert!(v < P_GL);
        out[full] = Goldilocks::from_u64(v);
    }
    out
}

// ---------------------------------------------------------------------------
// Tag-separated hash
// ---------------------------------------------------------------------------

/// `Poseidon2(tag, fes...)` — byte-identical to
/// `uno/crypto/poseidon2.cpp::hash_with_tag_and_fp`.
///
/// Output is the first 4 field elements of the final state, serialized as
/// 4 × 8-byte LE u64 limbs (32 bytes).
pub fn hash_tagged(tag: &[u8], fes: &[Goldilocks]) -> [u8; DIGEST] {
    let tag_block = pack_tag_block(tag);

    if fes.len() <= 8 {
        // Single wide block: [tag(8) || inputs(n) || pad(8-n)]
        let mut state = [Goldilocks::ZERO; 16];
        state[..8].copy_from_slice(&tag_block);
        for (i, f) in fes.iter().enumerate() {
            state[8 + i] = *f;
        }
        perm16().permute_mut(&mut state);
        return fes_to_digest(&[state[0], state[1], state[2], state[3]]);
    }

    // Iterated t=16 sponge: rate 8 (low), capacity 8 (high, pre-seeded with tag).
    let mut state = [Goldilocks::ZERO; 16];
    state[8..].copy_from_slice(&tag_block);

    let mut i = 0usize;
    while i + 8 <= fes.len() {
        for j in 0..8 {
            state[j] = state[j] + fes[i + j];
        }
        perm16().permute_mut(&mut state);
        i += 8;
    }
    let rem = fes.len() - i;
    if rem > 0 {
        for j in 0..rem {
            state[j] = state[j] + fes[i + j];
        }
        // 10* padding: next slot absorbs 1
        state[rem] = state[rem] + Goldilocks::ONE;
        perm16().permute_mut(&mut state);
    } else {
        // Even multiple of 8: lone padding block.
        state[0] = state[0] + Goldilocks::ONE;
        perm16().permute_mut(&mut state);
    }

    fes_to_digest(&[state[0], state[1], state[2], state[3]])
}

/// `Poseidon2(tag, bytes)` — byte-oriented inputs, wrapped-loaded.
pub fn hash_tagged_bytes(tag: &[u8], bytes: &[u8]) -> [u8; DIGEST] {
    let fes = bytes_to_fes_wrapped(bytes);
    hash_tagged(tag, &fes)
}

/// `filter_tag = Truncate16(Poseidon2("uno-filter-v1", k_aead))` (§2.8).
pub fn filter_tag(k_aead_32: &[u8]) -> u16 {
    assert_eq!(k_aead_32.len(), 32);
    let digest = hash_tagged_bytes(crate::tags::UNO_FILTER_V1, k_aead_32);
    u16::from_le_bytes([digest[0], digest[1]])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_tagged_is_deterministic() {
        let fes = [
            Goldilocks::from_u64(1),
            Goldilocks::from_u64(2),
            Goldilocks::from_u64(3),
        ];
        let a = hash_tagged(b"uno-nk-v1", &fes);
        let b = hash_tagged(b"uno-nk-v1", &fes);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_tagged_bytes_and_fes_agree_for_canonical_input() {
        // All three limbs < P_GL, so wrapped-load == identity.
        let bytes: [u8; 24] = [
            1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
        ];
        let fes = [
            Goldilocks::from_u64(1),
            Goldilocks::from_u64(2),
            Goldilocks::from_u64(3),
        ];
        let a = hash_tagged_bytes(b"uno-test-tag", &bytes);
        let b = hash_tagged(b"uno-test-tag", &fes);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_roundtrip_rejects_noncanonical() {
        let bad = [0xffu8; 32];
        assert!(digest_to_fes(&bad).is_none(), "0xff × 32 > p_Goldilocks");
    }

    #[test]
    fn filter_tag_stable_and_nontrivial() {
        let k = [0x42u8; 32];
        let t = filter_tag(&k);
        assert_eq!(t, filter_tag(&k));
        let mut any_nonzero = false;
        for i in 0..16u8 {
            let kk = [i; 32];
            if filter_tag(&kk) != 0 {
                any_nonzero = true;
                break;
            }
        }
        assert!(any_nonzero);
    }

    #[test]
    fn long_input_iterates_sponge() {
        // 10 inputs > 8 triggers the iterated branch.
        let fes: Vec<Goldilocks> = (1..=10).map(|i| Goldilocks::from_u64(i)).collect();
        let a = hash_tagged(b"uno-ivk-v1", &fes);
        let b = hash_tagged(b"uno-ivk-v1", &fes);
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_tag_distinct_output() {
        let fes = [Goldilocks::from_u64(42)];
        let a = hash_tagged(b"uno-nk-v1", &fes);
        let b = hash_tagged(b"uno-nf-v1", &fes);
        assert_ne!(a, b);
    }
}
