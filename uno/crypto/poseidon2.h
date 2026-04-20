/*
    Uno Workchain — Poseidon2 over Goldilocks (off-circuit wrapper).

    Poseidon2 (Grassi, Khovratovich, Schofnegger 2023, ePrint 2023/323) is
    the only in-circuit hash admitted by the Transfer AIR (§2.2). The
    *off-circuit* variant implemented here must produce byte-identical
    outputs to the in-circuit Plonky3 AIR gates, or the prover and verifier
    disagree silently.

    Parameter choices (all over Goldilocks p = 2^64 − 2^32 + 1):
      - Width t = 8   used for 4-to-1 compression
          (note-commitment tree internal nodes, `cm`, `nf`, `nk`, `ivk`).
      - Width t = 16  used for wide sponge absorb
          (Fiat-Shamir transcript, filter_tag derivation).

    The exact round-constant and MDS-matrix values are the Plonky3 reference:
        plonky3/poseidon2/src/mds.rs
        plonky3/poseidon2/src/round_numbers.rs
    These are shipped into C++ by the FFI crate at `uno/plonky3-ffi/` (owner:
    Agent 4). This wrapper calls extern-"C" symbols exported by that crate.

    Symbol contract (extern "C"):

        // Permute `state` in place with the Poseidon2 permutation of the
        // requested width. `state` points to `width` Goldilocks elements,
        // each a canonical u64 in [0, kGoldilocksPrime).
        void uno_poseidon2_goldilocks_permute_t8(uint64_t state[8]);
        void uno_poseidon2_goldilocks_permute_t16(uint64_t state[16]);

        // Keyed 2-to-1 compression: out = Trunc4(Permute(left || right || 0))
        // with `left` and `right` each 4 field elements, output 4 field
        // elements = 256 bits. This is the exact symbol the commitment-tree
        // (Agent 2) imports.
        void poseidon2_goldilocks_compress_2to1(
            const uint64_t left[4],
            const uint64_t right[4],
            uint64_t out[4]);

    The wrappers in this header present a C++-clean surface (td::Slice,
    Digest, Fp) on top of those symbols.

    Test vectors: one 2-to-1 compression is pinned at library init under
    `_verify_test_vectors()`. The vector is captured from the Plonky3
    upstream test suite the first time this module is linked; see
    `uno/plonky3-ffi/tests/poseidon2_vectors.json`. Until the FFI crate
    publishes a vector, `_verify_test_vectors()` is a TODO guarded by the
    UNO_POSEIDON2_HAVE_REF_VECTOR compile flag.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/goldilocks.h"

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// Raw permutation (Plonky3 contract)
// ---------------------------------------------------------------------------

/// Apply the width-8 Poseidon2-over-Goldilocks permutation in place.
/// Each Fp is in canonical [0, p) on entry and exit.
void poseidon2_permute_t8(std::array<Fp, 8>& state) noexcept;

/// Width-16 Poseidon2-over-Goldilocks permutation.
void poseidon2_permute_t16(std::array<Fp, 16>& state) noexcept;

// ---------------------------------------------------------------------------
// 2-to-1 compression (commitment-tree primitive)
// ---------------------------------------------------------------------------

/// 2-to-1 compression as used by the note-commitment tree (§2.3):
///
///     out = Trunc_4( Permute_t8( left || right || 0_0 ) )
///
/// Both `left` and `right` are 4 field elements (a Digest). Result is 4 field
/// elements = 256 bits. This is the exact symbol imported by Agent 2's
/// commitment-tree module under the extern-"C" name
/// `poseidon2_goldilocks_compress_2to1`; see below.
Digest poseidon2_compress_2to1(const Digest& left, const Digest& right) noexcept;

/// 4-to-1 compression over Goldilocks (used for `cm`, `nf`, key derivation).
/// Inputs are 16 field elements; output is a Digest (4 field elements).
/// Internally runs the width-16 permutation and truncates to 4 elements.
Digest poseidon2_compress_4to1(const std::array<Fp, 16>& inputs) noexcept;

// ---------------------------------------------------------------------------
// Domain-separated hash (field-native Poseidon2 sponge)
// ---------------------------------------------------------------------------

/// Domain-separated Poseidon2 hash over a tag + variadic field-element inputs.
/// Equivalent to:
///   state = [pack_domain_tag(tag), inputs..., zero-pad]; permute; truncate to 4.
///
/// Width is chosen automatically: t=8 if total absorbed elements fit one
/// absorb block, t=16 otherwise.
///
/// This function is the off-circuit counterpart to the Transfer AIR's
/// `Poseidon2(tag, ...)` gate calls (§2.4, §2.6, §2.8).
Digest poseidon2_hash_tagged(td::Slice tag, const Fp* inputs, size_t n_inputs);

/// Convenience overload: hash a byte-oriented value by packing little-endian
/// u64 words into Fp. The byte length must be a multiple of 8 and each
/// loaded word must already be < kGoldilocksPrime (canonical). Use this for
/// absorbing `uno_seed`, `cm`, `nk`, `ivk`, etc. — all of which are stored
/// as 4 canonical Goldilocks limbs.
Digest poseidon2_hash_tagged_bytes(td::Slice tag, td::Slice inputs_le_bytes);

// ---------------------------------------------------------------------------
// Filter-tag derivation (§2.8)
// ---------------------------------------------------------------------------

/// Compute `filter_tag = Truncate_16bit(Poseidon2("uno-filter-v1", k_aead))`.
/// `k_aead` is the 32-byte AEAD key output by the hybrid-KEM combiner.
/// Returns the 16-bit tag as a little-endian uint16.
uint16_t poseidon2_filter_tag(td::Slice k_aead_32);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Runs once at process init (or by tests) to confirm the linked Plonky3
/// FFI backend produces the pinned reference outputs. Aborts on mismatch.
/// No-op until UNO_POSEIDON2_HAVE_REF_VECTOR is defined (Agent 4 drops it
/// in once their FFI crate exports the vector JSON).
void _poseidon2_verify_test_vectors();

}  // namespace uno_workchain::crypto

// ---------------------------------------------------------------------------
// Exported extern-"C" symbol consumed by Agent 2 (commitment-tree).
// Declared in this header so both sides see the same prototype.
// ---------------------------------------------------------------------------
extern "C" {

/// 2-to-1 Poseidon2-over-Goldilocks compression. Used by the commitment-tree
/// internal-node hash. Inputs: 4 canonical Goldilocks limbs per side. Output:
/// 4 canonical Goldilocks limbs, written to `out`.
void poseidon2_goldilocks_compress_2to1(const uint64_t left[4],
                                        const uint64_t right[4],
                                        uint64_t out[4]);

}  // extern "C"
