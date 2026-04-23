//! Phase 4b-step3-step1.0 cross-crate byte-parity regression test.
//!
//! Validates that the off-circuit Poseidon2-w=16 15-fe iterated-sponge
//! `poseidon2_cm_full_sponge_bytes` helper landed in
//! `uno_plonky3_ffi::transfer_air` produces byte-identical output to
//! tosctl's production `poseidon2::hash_tagged(b"uno-cm-v1", ...)`,
//! which is in turn byte-identical to the C++ validator's
//! `compute_note_commitment` per the 3-agent audit summary in
//! `doc/uno-p2-phase4b-step3-plan.md §4.1`.
//!
//! When step 1.2 adds the in-circuit Poseidon2 AIR constraints that
//! ratify `poseidon2_cm_full_sponge`, the whole chain will be:
//!
//!   tosctl `compute_note_commitment` (real 15-fe sponge)
//!   == Rust AIR `poseidon2_cm_full_sponge_bytes`  ←── THIS TEST
//!   == Rust AIR in-circuit sponge constraints (step 1.2, future)
//!   == C++ `compute_note_commitment` (same sponge)
//!   == witness.cm_bytes as packed by encode_256 on both sides
//!
//! A failure here signals that the Rust AIR helper drifted from the
//! tosctl / C++ specification — catch it BEFORE step 1.2 pours
//! ~260 LOC of in-circuit constraints on top.
//!
//! Cross-crate note: `uno_plonky3_ffi` uses a vendored-path
//! `p3-field` / `p3-goldilocks`, while `tosctl/uno` uses a git-pathed
//! copy of the same commit (`6374a36f`). Cargo sees these as two
//! distinct crates, so the test cannot share the `Goldilocks` type
//! directly — we use the `*_bytes` wrappers as a bytes-only bridge.

use tosctl_uno::poseidon2::{bytes_to_fes_wrapped, hash_tagged};
use uno_plonky3_ffi::transfer_air::{
    poseidon2_cm_full_sponge_bytes, uno_cm_v1_tag_block_bytes,
};

// ---------------------------------------------------------------------------
// Helper: use tosctl's own p3-field/goldilocks for its side of the
// comparison. We assemble the 15-fe input with an explicit byte layout
// (120 bytes = 15 × 8) and feed the whole buffer into
// `bytes_to_fes_wrapped` — byte-identical to the packing convention
// used by `uno_plonky3_ffi`'s `pack_32b_as_4fe` +
// `pack_diversifier_as_2fe`.
// ---------------------------------------------------------------------------

fn build_15fe_buffer(
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(120);
    // fes[0..1] = d (16 B: 11 real + 5 zero-pad = bytes[0..16] of the
    // widened [u8; 32] form).
    buf.extend_from_slice(&d[0..16]);
    // fes[2..5] = pk_d (32 B = 4 fes).
    buf.extend_from_slice(pk_d);
    // fes[6..9] = ivk_commitment (32 B = 4 fes).
    buf.extend_from_slice(ivk_commitment);
    // fes[10] = value (8 B LE).
    buf.extend_from_slice(&value.to_le_bytes());
    // fes[11..14] = rcm (32 B = 4 fes).
    buf.extend_from_slice(rcm);
    assert_eq!(buf.len(), 120, "15 fes × 8 B = 120 B");
    buf
}

fn tosctl_hash_tagged_bytes(
    d: &[u8; 32],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let buf = build_15fe_buffer(d, pk_d, ivk_commitment, value, rcm);
    let fes = bytes_to_fes_wrapped(&buf);
    assert_eq!(fes.len(), 15);
    hash_tagged(b"uno-cm-v1", &fes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Deterministic test vector spanning all 5 input fields.
#[test]
fn rust_air_sponge_matches_tosctl_hash_tagged_byte_for_byte() {
    let d = {
        let mut buf = [0u8; 32];
        buf[..11].copy_from_slice(b"unodivv1-01");
        buf
    };
    let pk_d = [0x22u8; 32];
    let ivk_commitment = [0x33u8; 32];
    let value: u64 = 0x1234_5678_0000_9ABCu64;
    let rcm = [0x44u8; 32];

    // Path 1: Rust AIR off-circuit helper (bytes wrapper).
    let air_bytes = poseidon2_cm_full_sponge_bytes(
        &d, &pk_d, &ivk_commitment, value, &rcm,
    );

    // Path 2: tosctl hash_tagged on the same 15-fe input (via bytes).
    let tosctl_bytes = tosctl_hash_tagged_bytes(&d, &pk_d, &ivk_commitment, value, &rcm);

    assert_eq!(
        air_bytes,
        tosctl_bytes,
        "Rust AIR poseidon2_cm_full_sponge_bytes must match tosctl \
         hash_tagged byte-for-byte for the same 15-fe input with \
         'uno-cm-v1' tag.\n\
         air    = {:02x?}\n\
         tosctl = {:02x?}",
        air_bytes,
        tosctl_bytes,
    );
}

/// All-zero inputs — catches regressions where the tag-block is not
/// correctly loaded into the sponge capacity slots.
#[test]
fn rust_air_sponge_matches_tosctl_all_zero_inputs() {
    let d = [0u8; 32];
    let pk_d = [0u8; 32];
    let ivk_commitment = [0u8; 32];
    let value: u64 = 0;
    let rcm = [0u8; 32];

    let air_bytes = poseidon2_cm_full_sponge_bytes(
        &d, &pk_d, &ivk_commitment, value, &rcm,
    );

    let tosctl_bytes = tosctl_hash_tagged_bytes(&d, &pk_d, &ivk_commitment, value, &rcm);

    assert_eq!(
        air_bytes, tosctl_bytes,
        "sponge parity must hold on all-zero inputs (tag-block \
         capacity pinning is the only source of non-zero state)",
    );
    assert!(
        air_bytes.iter().any(|b| *b != 0),
        "all-zero digest indicates tag-block is not being loaded into \
         the sponge capacity (bug in uno_cm_v1_tag_block or its \
         state[8..16] placement)",
    );
}

/// Tag-block byte-layout parity: the 8-fe tag block, serialized as
/// 64 LE bytes, must equal `bytes_to_fes_wrapped(tag_padded_64_bytes)`.
#[test]
fn uno_cm_v1_tag_block_matches_tosctl_pack() {
    let got_bytes = uno_cm_v1_tag_block_bytes();

    // tosctl-side: pad the tag to 64 bytes and read via bytes_to_fes_wrapped.
    let mut tag_64 = [0u8; 64];
    let tag = b"uno-cm-v1";
    tag_64[..tag.len()].copy_from_slice(tag);

    // `bytes_to_fes_wrapped` returns Vec<Goldilocks>; we re-pack to
    // LE bytes to compare without needing the Goldilocks type here.
    let fes = bytes_to_fes_wrapped(&tag_64);
    assert_eq!(fes.len(), 8);

    // Each fe as canonical u64 LE bytes — tosctl uses `PrimeField64`;
    // we access it through the same tosctl p3-field version in scope.
    use p3_field::PrimeField64;
    let mut want_bytes = [0u8; 64];
    for (i, fe) in fes.iter().enumerate() {
        want_bytes[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }

    assert_eq!(
        got_bytes, want_bytes,
        "uno_cm_v1_tag_block must match the tosctl pack_tag_block \
         byte layout"
    );
}
