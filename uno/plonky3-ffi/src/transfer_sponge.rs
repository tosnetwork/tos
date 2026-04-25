//! Poseidon2 sponge helpers and AIR constraint evaluation for the Transfer AIR.
//!
//! Contains:
//! - `Poseidon2Air8` / `Poseidon2Air16` singleton accessors (`p2_air_8`,
//!   `p2_air_16`) and the `eval_poseidon2` / `eval_poseidon2_16` delegation
//!   fns used by `MvpTransferAir::eval`.
//! - Off-circuit Poseidon2 sponge reference implementations (`poseidon2_cm_full_sponge`,
//!   `poseidon2_nf_full_wide`, Merkle-path helpers, etc.).
//!
//! Extracted from `transfer_air.rs`; re-exported from there via
//! `pub use crate::transfer_sponge::*`.

use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    default_goldilocks_poseidon2_16,
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks,
};
use p3_poseidon2_air::RoundConstants;
use p3_symmetric::Permutation;

use crate::transfer_columns::{
    MERKLE_DEPTH, P2Cols, P2Cols16,
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS_16,
    POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH, POSEIDON2_WIDTH_16,
    TAG_CM, TAG_IVK_CM,
};
use crate::transfer_preimage::{
    pack_32b_as_4fe, pack_diversifier_as_2fe, reduce_to_goldilocks,
};

// ---------------------------------------------------------------------------
// Poseidon2 constraint evaluation (M-P2 Phase 2 — delegated to upstream)
// ---------------------------------------------------------------------------
//
// **Phase 2 swap (2026-04-22)**: we used to carry ~180 LOC of handwritten
// round-eval helpers (`eval_full_round`, `eval_partial_round`, `eval_sbox`,
// plus round-constant adapter fns) that "mirrored upstream byte-for-byte"
// because `p3_poseidon2_air::eval` was `pub(crate)` at Plonky3 v0.5.1.
// The vendored `third-party/plonky3-uno` was patched to `pub`-export
// `eval` (1-char delta in `poseidon2-air/src/air.rs`); we now delegate
// to the upstream implementation directly. Round constants come from
// `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_{8,16}_*` (decision #42)
// identically to before; the `Poseidon2Air` singletons cache the
// constructed `RoundConstants` once per process.

type Poseidon2Air8 = p3_poseidon2_air::Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>;

type Poseidon2Air16 = p3_poseidon2_air::Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>;

pub(crate) fn p2_air_8() -> &'static Poseidon2Air8 {
    use std::sync::OnceLock;
    static AIR: OnceLock<Poseidon2Air8> = OnceLock::new();
    AIR.get_or_init(|| {
        Poseidon2Air8::new(RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
        ))
    })
}

pub(crate) fn p2_air_16() -> &'static Poseidon2Air16 {
    use std::sync::OnceLock;
    static AIR: OnceLock<Poseidon2Air16> = OnceLock::new();
    AIR.get_or_init(|| {
        Poseidon2Air16::new(RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL,
        ))
    })
}

pub(crate) fn eval_poseidon2<AB>(builder: &mut AB, local: &P2Cols<AB::Var>)
where
    AB: AirBuilder<F = Goldilocks>,
{
    p3_poseidon2_air::eval::<
        AB,
        GenericPoseidon2LinearLayersGoldilocks,
        POSEIDON2_WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >(p2_air_8(), builder, local);
}

pub(crate) fn eval_poseidon2_16<AB>(builder: &mut AB, local: &P2Cols16<AB::Var>)
where
    AB: AirBuilder<F = Goldilocks>,
{
    p3_poseidon2_air::eval::<
        AB,
        GenericPoseidon2LinearLayersGoldilocks,
        POSEIDON2_WIDTH_16,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS_16,
    >(p2_air_16(), builder, local);
}

// ---------------------------------------------------------------------------
// Sponge tag-block helpers
// ---------------------------------------------------------------------------

/// Phase 4b-step3-step2b-AIR-v2: tag block for "uno-nf-v1" used by
/// the 9-fe iterated-sponge nullifier derivation. Shape matches
/// `uno_cm_v1_tag_block` exactly (9-byte tag: first fe = 8 bytes
/// of "uno-nf-v", second fe = "1" + 7 zero-pad, rest zero).
#[inline]
pub fn uno_nf_v1_tag_block() -> [Goldilocks; 8] {
    crate::transfer_preimage::pack_tag_block(b"uno-nf-v1")
}

/// Domain tag "uno-cm-v1" packed as 8 Goldilocks field elements in
/// the convention tosctl / C++ use for the capacity slots of the
/// width-16 sponge: 8-byte LE chunks of the UTF-8 tag string,
/// zero-padded. Only the first fe holds a non-zero u64 for this
/// 9-byte tag.
#[inline]
pub fn uno_cm_v1_tag_block() -> [Goldilocks; 8] {
    // Mirror of `tosctl/uno/src/poseidon2.rs::pack_tag_block` for
    // the specific tag "uno-cm-v1" (9 ASCII bytes). The tag fits
    // inside one 8-byte chunk + 1 trailing byte in the second
    // chunk; all remaining chunks are zero.
    let tag: &[u8] = b"uno-cm-v1";
    let mut out = [Goldilocks::ZERO; 8];
    let full = tag.len() / 8;
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(limb));
    }
    let rem = tag.len() - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        out[full] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}

// ---------------------------------------------------------------------------
// Off-circuit Poseidon2 sponge reference implementations
// ---------------------------------------------------------------------------

/// Off-circuit Rust mirror of tosctl `compute_note_commitment` /
/// C++ `compute_note_commitment`. Computes the 4-fe cm digest via
/// the 15-fe iterated Poseidon2-w=16 sponge with "uno-cm-v1" tag.
///
/// NOT yet wired into the AIR — step 1.1+ adds trace-gen + row-
/// gated constraints that verify this derivation in-circuit, at
/// which point `witness.cm_bytes` can be bound by the STARK to
/// match the output of this function (currently the AIR only
/// constrains the old single-permutation 6-input u64-proxy
/// `poseidon2_cm_fe`, which does NOT match tosctl's cm bytes).
///
/// Returns `[Goldilocks; 4]` — pack them with
/// `as_canonical_u64().to_le_bytes()` to get 32-byte cm.
/// Cross-crate byte-parity wrapper around `poseidon2_cm_full_sponge`:
/// constructs its own default `Poseidon2Goldilocks<16>` (so callers
/// don't need to import the vendored `p3-goldilocks`) and packs the
/// 4-fe digest into 32 LE bytes per Goldilocks limb.
///
/// Designed for `tosctl/uno` integration tests that cannot directly
/// reference the vendored-path `Goldilocks` type (Cargo resolves
/// `p3-field` / `p3-goldilocks` to two distinct crates for the
/// vendored vs. git-pathed consumers).
///
/// Output format matches `tosctl::poseidon2::hash_tagged(b"uno-cm-v1",
/// fes_15)` byte-for-byte for equivalent inputs — see
/// `tosctl/uno/tests/phase4b_step3_sponge_parity.rs`.
#[allow(dead_code)]
pub fn poseidon2_cm_full_sponge_bytes(
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let perm16 = default_goldilocks_poseidon2_16();
    let digest = poseidon2_cm_full_sponge(&perm16, d, pk_d, ivk_commitment, value, rcm);
    let mut out = [0u8; 32];
    for (i, fe) in digest.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
}

#[allow(dead_code)]
pub fn poseidon2_cm_full_sponge(
    perm16: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [Goldilocks; 4] {
    // Assemble the 15 input field elements per §3.2.
    let d_fes = pack_diversifier_as_2fe(d);
    let pk_d_fes = pack_32b_as_4fe(pk_d);
    let ivk_cm_fes = pack_32b_as_4fe(ivk_commitment);
    let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(value));
    let rcm_fes = pack_32b_as_4fe(rcm);

    let mut fes = [Goldilocks::ZERO; 15];
    fes[0] = d_fes[0];
    fes[1] = d_fes[1];
    fes[2..6].copy_from_slice(&pk_d_fes);
    fes[6..10].copy_from_slice(&ivk_cm_fes);
    fes[10] = value_fe;
    fes[11..15].copy_from_slice(&rcm_fes);

    // Initial sponge state: tag block pinned at capacity slots.
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    let tag = uno_cm_v1_tag_block();
    state[8..16].copy_from_slice(&tag);

    // Permutation 1: absorb fes[0..8] into rate slots 0..7.
    for j in 0..8 {
        state[j] = state[j] + fes[j];
    }
    perm16.permute_mut(&mut state);

    // Permutation 2: absorb remaining 7 fes (rem = 15 - 8 = 7) into
    // rate slots 0..6; state[7] += ONE for 10* padding.
    for j in 0..7 {
        state[j] = state[j] + fes[8 + j];
    }
    state[7] = state[7] + Goldilocks::from_u64(1);
    perm16.permute_mut(&mut state);

    [state[0], state[1], state[2], state[3]]
}

// Small Poseidon2 wrappers.

pub(crate) fn poseidon2_merkle_step(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    left: u64,
    right: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(reduce_to_goldilocks(left));
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(right));
    perm.permute_mut(&mut state);
    state[0]
}

/// Compute the Merkle root for a 32-level path: at each level `k`, combine
/// `current` with `path[k]` under the bit `(pos >> k) & 1` ordering.
#[allow(dead_code)]
pub(crate) fn poseidon2_merkle_path_root(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf: u64,
    pos: u64,
    path: &[u64; MERKLE_DEPTH],
) -> Goldilocks {
    let mut current = reduce_to_goldilocks(leaf);
    for k in 0..MERKLE_DEPTH {
        let bit = (pos >> k) & 1;
        let sib = reduce_to_goldilocks(path[k]);
        let (left, right) = if bit == 0 {
            (current, sib)
        } else {
            (sib, current)
        };
        current = poseidon2_merkle_step(perm, left, right).as_canonical_u64();
    }
    Goldilocks::from_u64(current)
}

/// Phase 4b-step3-step3a: 4-fe Merkle root via Poseidon2-w=8
/// `(left[4] ‖ right[4]) → out[4]` compression. Mirror of the AIR's
/// post-step-3a last-row binding; callers pass raw 32-byte leaf +
/// sibling bytes (each decomposed by `pack_32b_as_4fe`), this
/// function applies the 32-level walk off-circuit and returns the
/// 4-fe anchor digest.
pub(crate) fn poseidon2_merkle_path_root_4fe(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf_bytes: &[u8; 32],
    pos: u64,
    path_bytes: &[[u8; 32]; MERKLE_DEPTH],
) -> [Goldilocks; 4] {
    let mut cur: [Goldilocks; 4] = pack_32b_as_4fe(leaf_bytes);
    for k in 0..MERKLE_DEPTH {
        let bit = (pos >> k) & 1;
        let sib: [Goldilocks; 4] = pack_32b_as_4fe(&path_bytes[k]);
        let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
        let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
        for m in 0..4 {
            state[m] = left[m];
        }
        for m in 0..4 {
            state[4 + m] = right[m];
        }
        perm.permute_mut(&mut state);
        cur = [state[0], state[1], state[2], state[3]];
    }
    cur
}

/// Bytes wrapper around `poseidon2_merkle_path_root_4fe`: packs the
/// 4-fe digest into 32 LE bytes (8 B per Goldilocks limb). Useful for
/// test fixtures that need to round-trip anchor-bytes through the
/// 4-fe walk.
pub(crate) fn poseidon2_merkle_path_root_4fe_bytes(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    leaf_bytes: &[u8; 32],
    pos: u64,
    path_bytes: &[[u8; 32]; MERKLE_DEPTH],
) -> [u8; 32] {
    let fes = poseidon2_merkle_path_root_4fe(perm, leaf_bytes, pos, path_bytes);
    let mut out = [0u8; 32];
    for (i, fe) in fes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
}

pub(crate) fn poseidon2_ivk_commitment(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH]>,
    ivk: u64,
    d: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(TAG_IVK_CM);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(ivk));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(d));
    perm.permute_mut(&mut state);
    state[0]
}

/// Phase 4b-step3-step5e: **output-side legacy only** — retire with
/// the `O_CM_CLAIM` trace col. `poseidon2_cm_fe` is still called in
/// trace-gen at line ~3889 to populate `O_CM_CLAIM` (Phase 4b-step2a
/// decoupled this from PI; Phase 4b-step3-step1.3-pi rewired PI to
/// `O_CM_SPONGE_OUT`, so `O_CM_CLAIM` is now dead weight on the trace
/// side but still bound by the legacy claim-6 single-perm constraint
/// block at `transfer_air.rs:1141` — retiring the col + constraint is
/// a separate cleanup commit). Once both the col and the output-side
/// claim-6 AIR block are removed, `poseidon2_cm_fe` can be deleted.
///
/// The u64-returning wrapper `poseidon2_cm()` that formerly lived here
/// was deleted by step 5e because it had no callers; the single-line
/// `.as_canonical_u64()` was shadowing
/// the real helper.
pub(crate) fn poseidon2_cm_fe(
    perm16: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    d: u64,
    pk_d: u64,
    ivk_cm: u64,
    value: u64,
    rcm: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    state[0] = Goldilocks::from_u64(TAG_CM);
    state[1] = Goldilocks::from_u64(reduce_to_goldilocks(d));
    state[2] = Goldilocks::from_u64(reduce_to_goldilocks(pk_d));
    state[3] = Goldilocks::from_u64(reduce_to_goldilocks(ivk_cm));
    state[4] = Goldilocks::from_u64(reduce_to_goldilocks(value));
    state[5] = Goldilocks::from_u64(reduce_to_goldilocks(rcm));
    perm16.permute_mut(&mut state);
    state[0]
}

/// Phase 4b-step3-step2b-AIR-v2: nullifier computation via the 9-fe
/// iterated Poseidon2-w=16 sponge with "uno-nf-v1" tag block —
/// byte-identical to `uno/crypto/poseidon2.cpp::derive_nullifier` and
/// the codec-parity test helper `hash_tagged(b"uno-nf-v1", 9 fes)`.
///
/// Layout:
///   tag_block = pack_tag_block("uno-nf-v1")   — 8 fes, constant
///   fes[0..8] = (nk_fes[0..4], cm_fes[0..4])  — 8 fes (rate-8 absorb)
///   fes[8]    = pos                           — final fe
///
///   Bank 1:
///     state[0..8]   = fes[0..8]
///     state[8..16]  = tag_block              (capacity)
///     permute → bank1_out
///
///   Bank 2:
///     state[0]      = bank1_out[0] + pos     (fes[8] absorb)
///     state[1]      = bank1_out[1] + 1       (10* padding)
///     state[2..8]   = bank1_out[2..8]        (rate carry, no absorb)
///     state[8..16]  = bank1_out[8..16]       (capacity carry)
///     permute → bank2_out
///
///   Return bank2_out[0..4] — the 4-fe nf digest → PI[pi_nf(i) + 0..4].
///
/// Supersedes the Phase 4b-step3-step2b-AIR-v1 single-perm attempt
/// (commits b92a6bdbb + 0e23eef30) which pinned `state[0] = TAG_NF`
/// (a u64 constant) and bypassed the proper tag-block capacity
/// mechanism — not spec-compliant against C++
/// `build_plonky3_public_inputs` / `derive_nullifier`.
pub fn poseidon2_nf_full_wide(
    perm: &impl Permutation<[Goldilocks; POSEIDON2_WIDTH_16]>,
    nk_bytes: &[u8; 32],
    cm_bytes: &[u8; 32],
    pos: u64,
) -> [Goldilocks; 4] {
    let nk_fes = pack_32b_as_4fe(nk_bytes);
    let cm_fes = pack_32b_as_4fe(cm_bytes);
    let tag_block = uno_nf_v1_tag_block();
    // Bank 1: rate absorb of 8 fes, tag pinned at capacity.
    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
    state[0..4].copy_from_slice(&nk_fes);
    state[4..8].copy_from_slice(&cm_fes);
    state[8..16].copy_from_slice(&tag_block);
    perm.permute_mut(&mut state);
    // Bank 2: partial absorb of the 1 remaining fe + 10* padding.
    state[0] = state[0] + Goldilocks::from_u64(reduce_to_goldilocks(pos));
    state[1] = state[1] + Goldilocks::ONE;
    perm.permute_mut(&mut state);
    [state[0], state[1], state[2], state[3]]
}

/// Phase 4b-step3-step2b-AIR-v2: cross-crate byte-parity wrapper around
/// `poseidon2_nf_full_wide`. Constructs its own default
/// `Poseidon2Goldilocks<16>` (so callers don't need the vendored
/// `p3-goldilocks`) and packs the 4-fe digest into 32 LE bytes per
/// Goldilocks limb. Designed for `tosctl/uno` integration tests that
/// cannot directly reference the vendored-path `Goldilocks` type.
pub fn poseidon2_nf_full_wide_bytes(
    nk_bytes: &[u8; 32],
    cm_bytes: &[u8; 32],
    pos: u64,
) -> [u8; 32] {
    let perm16 = default_goldilocks_poseidon2_16();
    let fes = poseidon2_nf_full_wide(&perm16, nk_bytes, cm_bytes, pos);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8]
            .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
    }
    out
}
