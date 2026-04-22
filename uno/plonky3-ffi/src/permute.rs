//! Poseidon2-Goldilocks permutation entry points (C ABI).
//!
//! The C++ side (`uno/crypto/poseidon2.cpp`) consumes these symbols to
//! implement every Poseidon2 sponge / compression in the Uno crypto stack
//! (Merkle compression, note-commitment absorb, nullifier derivation,
//! domain-tagged tagged-hash). Exposing them here keeps Plonky3 as the
//! single source of truth for the Goldilocks Poseidon2 parameters: the
//! same `default_goldilocks_poseidon2_{8,16}` instances that back the
//! prover/verifier are re-used via the `p3_symmetric::Permutation` trait.
//!
//! # C ABI
//!
//! ```c
//! void uno_poseidon2_goldilocks_permute_t8 (uint64_t state[8]);
//! void uno_poseidon2_goldilocks_permute_t16(uint64_t state[16]);
//! ```
//!
//! The state is read and written **in place**. Each slot is a canonical
//! Goldilocks limb, i.e. `0 <= v < p_G = 2^64 - 2^32 + 1`. The symbols
//! return void; any input-validation failure (null pointer, non-canonical
//! limb) short-circuits and leaves the caller's buffer untouched, which is
//! the "defensive canonicalise" contract the C++ wrapper already assumes
//! (see `uno/crypto/poseidon2.cpp :: poseidon2_permute_t{8,16}`).
//!
//! # Determinism
//!
//! These functions touch no RNG, no wall-clock, no heap. They are pure
//! data transformations over the pinned `default_goldilocks_poseidon2_*`
//! constants (§16 decision #42 of doc/uno-workchain.md), so they are
//! stable across every validator, every build, every invocation.

use p3_field::PrimeField64;
use p3_goldilocks::{default_goldilocks_poseidon2_16, default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation;

/// The Goldilocks modulus `p_G = 2^64 - 2^32 + 1`. Inputs must satisfy
/// `v < p_G` to be treated as canonical field elements; non-canonical
/// limbs are rejected at the FFI boundary to close off an encoding
/// malleability vector that would otherwise let callers feed
/// `v` and `v + p_G` into the same permutation and observe identical
/// outputs.
const GOLDILOCKS_ORDER: u64 = Goldilocks::ORDER_U64;

/// Width-8 Poseidon2-Goldilocks permutation, in place.
///
/// On success the 8 `u64`s at `state` are replaced with the permutation
/// output (also canonical `< p_G`). If `state` is null or any limb is
/// `>= p_G`, the call returns without writing.
///
/// # Safety
/// `state` must either be null or point to a writable, properly-aligned
/// buffer of at least 8 `u64`s for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn uno_poseidon2_goldilocks_permute_t8(state: *mut u64) {
    if state.is_null() {
        return;
    }
    // SAFETY: caller upholds that `state` points to 8 writable u64s.
    let raw: &mut [u64; 8] = unsafe { &mut *(state as *mut [u64; 8]) };

    // Reject non-canonical limbs; see module doc on the malleability
    // argument. A legitimate caller (C++ wrapper, or any cross-impl
    // consumer following the §4.3 wire contract) always canonicalises
    // before the call, so this branch is tight.
    for &v in raw.iter() {
        if v >= GOLDILOCKS_ORDER {
            return;
        }
    }

    let mut fe: [Goldilocks; 8] = [Goldilocks::new(0); 8];
    for (i, &v) in raw.iter().enumerate() {
        // SAFETY: we just verified `v < ORDER`, so this is a canonical
        // Goldilocks element by construction.
        fe[i] = Goldilocks::new(v);
    }

    let perm = default_goldilocks_poseidon2_8();
    let out = perm.permute(fe);

    for (i, elem) in out.iter().enumerate() {
        raw[i] = elem.as_canonical_u64();
    }
}

/// Width-16 Poseidon2-Goldilocks permutation, in place.
///
/// Contract mirrors [`uno_poseidon2_goldilocks_permute_t8`] at width 16.
/// Used by the wide sponge for claim-2 / claim-6 note-commitment absorb
/// (15-fe input fits in the width-16 state with one capacity slot).
///
/// # Safety
/// `state` must either be null or point to a writable, properly-aligned
/// buffer of at least 16 `u64`s for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn uno_poseidon2_goldilocks_permute_t16(state: *mut u64) {
    if state.is_null() {
        return;
    }
    // SAFETY: caller upholds that `state` points to 16 writable u64s.
    let raw: &mut [u64; 16] = unsafe { &mut *(state as *mut [u64; 16]) };

    for &v in raw.iter() {
        if v >= GOLDILOCKS_ORDER {
            return;
        }
    }

    let mut fe: [Goldilocks; 16] = [Goldilocks::new(0); 16];
    for (i, &v) in raw.iter().enumerate() {
        fe[i] = Goldilocks::new(v);
    }

    let perm = default_goldilocks_poseidon2_16();
    let out = perm.permute(fe);

    for (i, elem) in out.iter().enumerate() {
        raw[i] = elem.as_canonical_u64();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The permutation must be deterministic: same input, same output,
    /// byte-for-byte.
    #[test]
    fn permute_t8_deterministic() {
        let mut a = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let mut b = [1u64, 2, 3, 4, 5, 6, 7, 8];
        unsafe { uno_poseidon2_goldilocks_permute_t8(a.as_mut_ptr()) };
        unsafe { uno_poseidon2_goldilocks_permute_t8(b.as_mut_ptr()) };
        assert_eq!(a, b, "permute_t8 must be deterministic");
    }

    /// Permuting the zero state must produce a non-zero state (Poseidon2 has
    /// non-zero round constants, so even the zero vector leaves the identity
    /// fixed-point).
    #[test]
    fn permute_t8_zero_state_is_nontrivial() {
        let mut s = [0u64; 8];
        unsafe { uno_poseidon2_goldilocks_permute_t8(s.as_mut_ptr()) };
        assert!(
            s.iter().any(|&v| v != 0),
            "zero state must not be a fixed point of Poseidon2"
        );
        for &v in s.iter() {
            assert!(v < GOLDILOCKS_ORDER, "output must be canonical");
        }
    }

    /// The FFI entry point must match the trait permutation byte-for-byte;
    /// this is the parity gate that guarantees the C++ wrapper sees the
    /// same outputs as the internal Plonky3 prover/verifier.
    #[test]
    fn permute_t8_matches_trait_permute() {
        let input: [u64; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
        let mut via_ffi = input;
        unsafe { uno_poseidon2_goldilocks_permute_t8(via_ffi.as_mut_ptr()) };

        let perm = default_goldilocks_poseidon2_8();
        let fe: [Goldilocks; 8] = core::array::from_fn(|i| Goldilocks::new(input[i]));
        let expected = perm.permute(fe);
        for i in 0..8 {
            assert_eq!(
                via_ffi[i],
                expected[i].as_canonical_u64(),
                "FFI output must equal trait permutation at index {i}"
            );
        }
    }

    /// Width-16 parity gate (same contract as t8).
    #[test]
    fn permute_t16_matches_trait_permute() {
        let input: [u64; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut via_ffi = input;
        unsafe { uno_poseidon2_goldilocks_permute_t16(via_ffi.as_mut_ptr()) };

        let perm = default_goldilocks_poseidon2_16();
        let fe: [Goldilocks; 16] = core::array::from_fn(|i| Goldilocks::new(input[i]));
        let expected = perm.permute(fe);
        for i in 0..16 {
            assert_eq!(
                via_ffi[i],
                expected[i].as_canonical_u64(),
                "FFI output must equal trait permutation at index {i}"
            );
        }
    }

    /// Null pointer must be a no-op (documented contract).
    #[test]
    fn permute_t8_null_is_noop() {
        unsafe { uno_poseidon2_goldilocks_permute_t8(core::ptr::null_mut()) };
        unsafe { uno_poseidon2_goldilocks_permute_t16(core::ptr::null_mut()) };
    }

    /// Non-canonical limb (>= p_G) must leave the state unchanged.
    #[test]
    fn permute_t8_non_canonical_is_noop() {
        let mut s: [u64; 8] = [GOLDILOCKS_ORDER, 0, 0, 0, 0, 0, 0, 0];
        let before = s;
        unsafe { uno_poseidon2_goldilocks_permute_t8(s.as_mut_ptr()) };
        assert_eq!(s, before, "non-canonical input must not mutate state");
    }

    #[test]
    fn permute_t16_non_canonical_is_noop() {
        let mut s: [u64; 16] = [0; 16];
        s[15] = u64::MAX; // > p_G
        let before = s;
        unsafe { uno_poseidon2_goldilocks_permute_t16(s.as_mut_ptr()) };
        assert_eq!(s, before, "non-canonical input must not mutate state");
    }

    /// Idempotent invariant: permute the same state twice via the trait and
    /// via the FFI entry point; they must agree. This catches any drift
    /// between the committed `default_goldilocks_poseidon2_*` constants and
    /// the constants used on the FFI path.
    #[test]
    fn permute_roundtrip_against_trait_all_zero_widths() {
        // t=8
        let perm8 = default_goldilocks_poseidon2_8();
        let mut via_ffi8 = [0u64; 8];
        unsafe { uno_poseidon2_goldilocks_permute_t8(via_ffi8.as_mut_ptr()) };
        let expected8 = perm8.permute([Goldilocks::new(0); 8]);
        for i in 0..8 {
            assert_eq!(via_ffi8[i], expected8[i].as_canonical_u64());
        }

        // t=16
        let perm16 = default_goldilocks_poseidon2_16();
        let mut via_ffi16 = [0u64; 16];
        unsafe { uno_poseidon2_goldilocks_permute_t16(via_ffi16.as_mut_ptr()) };
        let expected16 = perm16.permute([Goldilocks::new(0); 16]);
        for i in 0..16 {
            assert_eq!(via_ffi16[i], expected16[i].as_canonical_u64());
        }
    }
}
