/*
    Uno Workchain — Goldilocks field arithmetic.

    Goldilocks is the prime field Fp with
        p = 2^64 - 2^32 + 1  =  0xFFFFFFFF_00000001
    This is the native operating field of Plonky3 for the Uno v1 Transfer AIR
    (scheme_id = 0x01). Every in-circuit value, hash digest, nullifier, and
    commitment is a sequence of Goldilocks field elements. See §2.1 and §2.2
    of doc/uno-workchain.md.

    This header exposes a *thin C++ wrapper* around an in-tree implementation.
    Goldilocks arithmetic is small (a few dozen lines) so we do not take an
    FFI dependency on Plonky3 just for field ops; the FFI crate (Agent 4,
    uno/plonky3-ffi) is reserved for Poseidon2 and for the STARK verifier.

    Style: no raw pointers on the public surface. Byte I/O uses `td::Slice`
    for read, `td::MutableSlice` for write, and `td::SecureString` for
    caller-owned secret buffers.

    Correctness tests: a static `_verify_test_vectors()` runs at library load
    (via a namespace-scope dummy) and asserts known-answer values for add,
    mul, and the p-wrap edge case.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "td/utils/Slice.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Status.h"

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Goldilocks prime p = 2^64 - 2^32 + 1.
inline constexpr uint64_t kGoldilocksPrime = 0xFFFFFFFF00000001ULL;

/// Canonical byte size of one field element on the wire (little-endian,
/// canonical in [0, p) representative).
inline constexpr size_t kFieldElementBytes = 8;

/// A Poseidon2 "digest" in Uno v1 is 4 field elements = 256 bits = 32 bytes.
/// Used for commitments, nullifiers, Merkle nodes, derived keys.
inline constexpr size_t kDigestFieldElements = 4;
inline constexpr size_t kDigestBytes = kDigestFieldElements * kFieldElementBytes;

// ---------------------------------------------------------------------------
// Fp: a canonical Goldilocks field element in [0, p)
// ---------------------------------------------------------------------------

/// Single Goldilocks field element, always stored in canonical range
/// [0, kGoldilocksPrime). All arithmetic operators reduce before returning.
///
/// This is value-type, trivially copyable. Constant-time-equality is not
/// claimed — the callers that need side-channel resistance (scalar material)
/// operate on byte buffers backed by td::SecureString, not on Fp.
struct Fp {
    uint64_t v;

    constexpr Fp() noexcept : v(0) {}
    constexpr explicit Fp(uint64_t x) noexcept : v(reduce(x)) {}

    static constexpr uint64_t reduce(uint64_t x) noexcept {
        return x >= kGoldilocksPrime ? x - kGoldilocksPrime : x;
    }

    static Fp zero() noexcept { return Fp{}; }
    static Fp one() noexcept { return Fp{1}; }

    bool is_zero() const noexcept { return v == 0; }

    Fp add(Fp o) const noexcept;
    Fp sub(Fp o) const noexcept;
    Fp mul(Fp o) const noexcept;
    Fp neg() const noexcept;

    /// Modular inverse; returns zero() iff this is zero (caller must guard).
    Fp inv() const noexcept;

    /// Little-endian canonical encoding: 8 bytes of v_canonical.
    void to_le_bytes(td::MutableSlice out) const;

    /// Little-endian decoding. Rejects non-canonical inputs (v >= p).
    static td::Result<Fp> from_le_bytes(td::Slice in);
};

inline bool operator==(Fp a, Fp b) noexcept { return a.v == b.v; }
inline bool operator!=(Fp a, Fp b) noexcept { return a.v != b.v; }

// ---------------------------------------------------------------------------
// Digest: 4 field elements, canonical wire form for Poseidon2-derived hashes
// ---------------------------------------------------------------------------

/// 256-bit Poseidon2-over-Goldilocks digest. Four canonical Fp, little-endian
/// on the wire. Used for: note commitments, nullifiers, Merkle node values,
/// derived keys (nk, ivk), transcript absorb output.
struct Digest {
    std::array<Fp, kDigestFieldElements> e;

    static Digest zero() noexcept { return Digest{}; }

    /// Pack to 32 bytes, little-endian per element, elements in index order.
    /// Writes exactly kDigestBytes bytes; `out.size()` must be ≥ kDigestBytes.
    void to_bytes(td::MutableSlice out) const;

    /// Inverse of to_bytes. Rejects any non-canonical field element.
    static td::Result<Digest> from_bytes(td::Slice in);
};

inline bool operator==(const Digest& a, const Digest& b) noexcept {
    return a.e == b.e;
}
inline bool operator!=(const Digest& a, const Digest& b) noexcept {
    return !(a == b);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Reduce an arbitrary 64-bit value into Fp. Used when packing a uint64
/// (e.g., `value`, `expiry_block`, `fee`) as a Goldilocks public input.
/// Values that need to round-trip faithfully must fit in [0, p); `value_u64`
/// of a note does fit, since `p > 2^64 - 2^32` and values are < 2^64.
Fp fp_from_u64(uint64_t x) noexcept;

/// Hashing domain-separator absorb: pack a fixed-size ASCII tag (e.g.,
/// "uno-nk-v1") into field elements, zero-padding so exactly one t=8
/// Poseidon2 absorb block is consumed. See §2.0 of the design doc.
///
/// Output is written as a sequence of Fp into `out`; returns the count
/// written. `out.size()` in elements must be ≥ 8.
size_t pack_domain_tag(td::Slice tag, std::array<Fp, 8>& out);

/// Internal correctness check run at static init. Calls std::abort() on
/// failure — this is a developer guardrail, not a runtime validator.
void _verify_test_vectors();

}  // namespace uno_workchain::crypto
