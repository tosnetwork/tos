//! Byte-packing / public-input decode helpers for the Transfer AIR.
//!
//! Contains pure arithmetic utilities (`reduce_to_goldilocks`,
//! `pack_32b_as_4fe`, `pack_diversifier_as_2fe`, etc.) and the PI
//! decoder (`decode_public_inputs`). These have no dependencies on the
//! Poseidon2 constraint machinery or witness types — they are pure
//! functions on bytes and u64.
//!
//! Extracted from `transfer_air.rs`; re-exported from there via
//! `pub use crate::transfer_preimage::*`.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Goldilocks prime.
pub(crate) const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Reduce a `u64` into a canonical Goldilocks residue.
#[inline]
pub(crate) fn reduce_to_goldilocks(x: u64) -> u64 {
    if x >= GOLDILOCKS_P {
        x.wrapping_sub(GOLDILOCKS_P)
    } else {
        x
    }
}

/// Phase 4b-step3-step0 shim: extract the u64 proxy from the first 8
/// bytes of a widened 32-byte witness field (little-endian). The AIR
/// in its current pre-step3 shape still processes Poseidon2 / Merkle
/// inputs as u64 proxies; lifting to full 4-fe inputs is Phase 4b-
/// step3-step1..3 per `doc/uno-p2-phase4b-step3-plan.md`. Callers
/// write `first_u64_proxy(&w.ivk)` etc. at every former
/// `w.ivk` (u64) reference site.
#[inline]
pub(crate) fn first_u64_proxy(bytes: &[u8; 32]) -> u64 {
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Phase 4b-step3-step1.0 helpers — 15-fe iterated-sponge
// Poseidon2-w=16 `cm` derivation, off-circuit reference
// ---------------------------------------------------------------------------
//
// These functions are the byte-for-byte Rust mirror of tosctl's
// `tosctl/uno/src/poseidon2.rs::hash_tagged` called with tag
// "uno-cm-v1" and 15 Goldilocks field elements in the order
// specified by `uno/core/poseidon2.cpp::compute_note_commitment`.
// They are NOT yet wired into the AIR; Phase 4b-step3-step1.1+
// will build trace-gen + constraints on top of them. Landing them
// here as a standalone commit lets us unit-test the off-circuit
// reference against tosctl / C++ before committing to the ~420 LOC
// of AIR structural change needed to express the sponge in a STARK
// constraint system.
//
// Layout per §3.2 of `doc/uno-workchain.md` and the iterated-sponge
// description recorded in `doc/uno-p2-phase4b-step3-plan.md` §4.1:
//
//   tag_block        = pack("uno-cm-v1" into 8 fes via 8-byte LE chunks)
//   fes[0..1]        = d   (11 B diversifier, zero-padded to 16 B,
//                           split as 2 × u64 LE mod p)
//   fes[2..5]        = pk_d            (32 B → 4 × u64 LE mod p)
//   fes[6..9]        = ivk_commitment  (32 B → 4 × u64 LE mod p)
//   fes[10]          = value           (u64 mod p)
//   fes[11..14]      = rcm             (32 B → 4 × u64 LE mod p)
//                      (15 fes total)
//
//   state[8..16]     = tag_block (capacity slots, pinned)
//
//   Permutation 1:   state[0..7] += fes[0..7]; permute.
//   Permutation 2:   state[0..6] += fes[8..14]; state[7] += ONE
//                    (10* padding, since rem=7 after block 1);
//                    permute.
//
//   Output:          state[0..4]  (4 fe = 32 B after LE-u64 packing)

/// Phase 4b-step3-step2b-AIR-v2: generic tag-block packer — mirror
/// of `tosctl/uno/src/poseidon2.rs::pack_tag_block` and
/// `uno/crypto/poseidon2.cpp::pack_domain_tag`. Packs the UTF-8
/// bytes of a ≤ 64-byte domain tag into 8 Goldilocks field elements
/// via 8-byte LE chunks + zero-pad in the trailing slot. Used to
/// materialize the capacity slots of the width-16 iterated sponge
/// for any tagged Uno derivation ("uno-cm-v1", "uno-nf-v1",
/// "uno-ivk-cm-v1", etc).
#[inline]
pub fn pack_tag_block(tag: &[u8]) -> [Goldilocks; 8] {
    let mut out = [Goldilocks::ZERO; 8];
    let n = tag.len().min(64);
    let full = (n / 8).min(8);
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..(i + 1) * 8]);
        out[i] = Goldilocks::from_u64(u64::from_le_bytes(limb));
    }
    let rem = n - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        out[full] = Goldilocks::from_u64(u64::from_le_bytes(buf));
    }
    out
}

/// 32 bytes → 4 Goldilocks field elements via 8-byte LE chunks,
/// each reduced mod p_Goldilocks (`reduce_to_goldilocks` if needed;
/// inputs from tosctl are already canonical). Byte-identical to
/// `tosctl/uno/src/poseidon2.rs::bytes_to_fes_wrapped` for a 32 B
/// input + C++ `pack_bytes32_as_4`.
#[inline]
pub fn pack_32b_as_4fe(bytes: &[u8; 32]) -> [Goldilocks; 4] {
    let mut out = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        out[i] = Goldilocks::from_u64(reduce_to_goldilocks(limb));
    }
    out
}

/// 11-byte diversifier (passed as [u8; 32] with bytes[0..11] real +
/// bytes[11..32] zero-pad per the Phase 4b-step3-step0 witness wire
/// format) → 2 Goldilocks field elements. Consumes bytes[0..16] as
/// 2 × u64 LE mod p; bytes[16..32] are not looked at (they are
/// expected to be zero and play no role in the sponge).
#[inline]
pub fn pack_diversifier_as_2fe(d: &[u8; 32]) -> [Goldilocks; 2] {
    [
        Goldilocks::from_u64(reduce_to_goldilocks(
            u64::from_le_bytes(d[0..8].try_into().unwrap()),
        )),
        Goldilocks::from_u64(reduce_to_goldilocks(
            u64::from_le_bytes(d[8..16].try_into().unwrap()),
        )),
    ]
}

/// Cross-crate byte-equivalent of `uno_cm_v1_tag_block()`: packs the
/// 8-fe tag block into 64 LE bytes (8 B per fe). Enables byte-level
/// parity checks from crates that cannot directly see the vendored
/// `Goldilocks` type.
#[allow(dead_code)]
pub fn uno_cm_v1_tag_block_bytes() -> [u8; 64] {
    let tag_fes = crate::transfer_sponge::uno_cm_v1_tag_block();
    let mut out = [0u8; 64];
    for (i, fe) in tag_fes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&fe.as_canonical_u64().to_le_bytes());
    }
    out
}

/// 32-byte → 4 canonical-Goldilocks u64 limbs. Byte-identical mirror of
/// `uno/core/transaction.cpp::encode_256` (§4.3 step 4, decision #5):
///
/// * split into 4 consecutive u64 LE chunks,
/// * each chunk reduced via a single conditional subtract (safe for
///   `x ∈ [0, 2·p_Goldilocks)`, which covers any u64).
///
/// Used by `MvpWitness::public_inputs` (tier-1) to pack raw `anchor` / `rk`
/// / `cm` / `epk` bytes into the PI vector so Rust-prover PIs byte-match
/// C++ `build_plonky3_public_inputs(tx)` slot-for-slot.
#[inline]
pub fn encode_256_as_4_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for limb in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[limb * 8..(limb + 1) * 8]);
        out[limb] = reduce_to_goldilocks(u64::from_le_bytes(chunk));
    }
    out
}

/// Default test chain_id ("UNOT" LE).
pub const CHAIN_ID_TEST: u32 = 0x544F4E55;

/// Default test expiry_block for witness-derived public inputs.
pub const EXPIRY_BLOCK_TEST: u64 = 100_000;

/// Decode a public-input byte buffer into Goldilocks field elements. The
/// decoder is length-agnostic; callers pair it with
/// [`crate::transfer_columns::derive_shape_from_public_inputs_len`] to
/// detect the shape first.
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Goldilocks>, Plonky3Status> {
    if bytes.len() % 8 != 0 {
        return Err(Plonky3Status::PublicInputLengthMismatch);
    }
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let v = u64::from_le_bytes(chunk.try_into().unwrap());
        if v >= GOLDILOCKS_P {
            return Err(Plonky3Status::PublicInputDecodeFailed);
        }
        out.push(Goldilocks::from_u64(v));
    }
    Ok(out)
}
