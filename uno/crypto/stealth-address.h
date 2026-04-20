/*
    Uno Workchain — stealth-address / diversified-address derivation (§2.6).

    Builds the full Uno v1 key hierarchy from a 32-byte `uno_seed`:

        ask        = BLAKE2b-256("uno-ask-v1"    || uno_seed)  reduced mod L
        esk_seed   = BLAKE2b-256("uno-esk-v1"    || uno_seed)
        mlkem_seed = BLAKE2b-256("uno-mlkem-v1"  || uno_seed)   // 32 B → we
                                                                // expand to 64 B
                                                                // (d || z) via
                                                                // BLAKE2b-512
                                                                // for FIPS 203
                                                                // derand keygen.
        ovk        = BLAKE2b-256("uno-ovk-v1"    || uno_seed)
        nk         = Poseidon2("uno-nk-v1", uno_seed)            (256 bits)
        ivk        = Poseidon2("uno-ivk-v1", nk, ak_bytes)       (256 bits)
        ak         = ask · G
        (pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen(mlkem_seed)

        fvk = (ak, nk, ovk, sk_mlkem)

    Diversified addresses:

        g_d  = HashToRistretto("uno-diversifier-v1" || d)    (11-byte d)
        pk_d = Poseidon2(ivk, d) · g_d ∈ Ristretto255
        Address = (d, compress(pk_d), pk_mlkem)             // 11 + 32 + 1184 ≈ 1227 B

    The "hash-to-curve" construction is RFC 9380 applied to Curve25519 +
    the Ristretto decode map; libsodium exposes this as
    `crypto_core_ristretto255_from_hash(64 bytes → point)`. We pre-hash the
    domain-tag + diversifier to 64 bytes via BLAKE2b-512 so the full input
    is uniform — §2.6 footnote on hash-to-curve binding.

    Why `nk`/`ivk` use Poseidon2 while everyone else is BLAKE2b: those two
    keys must be re-derivable *inside* the AIR (claims 3, 4 §4.2). Poseidon2
    is orders of magnitude cheaper to constrain in-circuit than BLAKE2b.
    The off-circuit wrapper here MUST produce the byte-identical output to
    the AIR gate; the Fp-based Poseidon2 driver in uno/crypto/poseidon2.h
    handles that.
*/
#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/goldilocks.h"
#include "uno/crypto/mlkem768.h"
#include "uno/crypto/ristretto255.h"

namespace uno_workchain::crypto {

inline constexpr size_t kUnoSeedBytes        = 32;
inline constexpr size_t kDiversifierBytes    = 11;
inline constexpr size_t kOvkBytes            = 32;
/// Size (bytes) of the `ivk_commitment` field published in the Address.
/// Decision #1 / §2.6: `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)`,
/// 4 Goldilocks field elements = 256 bits = 32 bytes.
inline constexpr size_t kIvkCommitmentBytes  = 32;
/// Address layout (§2.6 updated): d (11 B) || compress(pk_d) (32 B)
///                              || ivk_commitment (32 B) || pk_mlkem (1184 B)
/// Total: 1259 B. The 32 bytes of `ivk_commitment` are appended between
/// `pk_d` and `pk_mlkem` — this is the wire-order contract; any reordering
/// breaks genesis JSON, wallet sync, and the cross-impl fixture.
inline constexpr size_t kAddressBytes        = kDiversifierBytes       // d
                                              + kRistrettoPointBytes   // compress(pk_d)
                                              + kIvkCommitmentBytes    // ivk_commitment
                                              + kMlKem768PublicKeyBytes;  // pk_mlkem

/// Full viewing key: enables audit / scan / recipient-identity disclosure.
struct FullViewingKey {
    RistrettoPoint ak;                   // spend-auth pubkey
    Digest          nk;                   // nullifier key (256-bit Poseidon2 output)
    td::SecureString ovk;                 // outgoing viewing key, 32 B
    MlKem768SecretKey sk_mlkem;           // PQ KEM secret
    MlKem768PublicKey pk_mlkem;           // carry the pk alongside for address build
    RistrettoScalar ask;                  // spend-auth scalar (needed for signing)
    Digest          ivk;                   // incoming viewing key (in-circuit-derivable)
};

/// Derive the Uno v1 key hierarchy from a seed. Pure function; no I/O.
td::Result<FullViewingKey> derive_keys_from_seed(td::Slice uno_seed_32);

/// Recover the diversifier → pk_d curve point from ivk (Poseidon2 scalar
/// form) and the 11-byte diversifier. Returns `pk_d` compressed.
td::Result<RistrettoPoint> derive_pk_d(const Digest& ivk,
                                       td::Slice diversifier_11);

/// Hash-to-curve for diversified base points:
///     g_d = HashToRistretto("uno-diversifier-v1" || d)
/// Implemented as
///     uniform_64 = BLAKE2b-512("uno-diversifier-v1" || d)
///     g_d        = ristretto_from_hash_64(uniform_64)
RistrettoPoint derive_diversified_base_point(td::Slice diversifier_11);

/// Convert a 32-byte Poseidon2 `ivk` digest into a Ristretto scalar by
/// reducing the 32 bytes mod L. Used when `ivk` is supplied to scalar-mult
/// operations (diversified ECDH).  §2.6 mandates that `pk_d` lives in
/// Ristretto255, and the Poseidon2 output is interpreted bytewise as a
/// scalar for this purpose — the AIR's claim 3 proves the equivalent
/// in-circuit hash-binding identity (§4.2 claim 3 owned by Agent 4).
RistrettoScalar ivk_to_scalar(const Digest& ivk);

/// Also convert `Poseidon2(ivk, d)` to a scalar (the actual multiplier
/// used in `pk_d = Poseidon2(ivk, d) · g_d`). This is what spend-side
/// derivation needs to compute `pk_d` off-circuit.
RistrettoScalar derive_diversified_scalar(const Digest& ivk,
                                          td::Slice diversifier_11);

// ---------------------------------------------------------------------------
// Address envelope
// ---------------------------------------------------------------------------

struct Address {
    std::array<uint8_t, kDiversifierBytes>     d;
    RistrettoPoint                             compressed_pk_d;
    /// `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` — 32 bytes of
    /// canonical Goldilocks wire encoding (4 limbs × 8 LE bytes). Bound into
    /// every `cm` addressed to this diversifier (decision #1, §3.2); the
    /// Transfer AIR's ownership claim (§4.2 claim 3) recomputes it from the
    /// private witness `(ivk, d)` and asserts equality.
    std::array<uint8_t, kIvkCommitmentBytes>   ivk_commitment{};
    MlKem768PublicKey                          pk_mlkem;

    /// Serialize to kAddressBytes (1259) bytes:
    ///   d (11) || compress(pk_d) (32) || ivk_commitment (32) || pk_mlkem (1184)
    std::vector<uint8_t> to_bytes() const;

    /// Deserialize. Validates pk_d is on the Ristretto255 group; does not
    /// validate pk_mlkem (which is 1184 bytes of polynomial coefficients and
    /// is only validated by ML-KEM-768.Encap). `ivk_commitment` is carried
    /// as opaque 32 bytes; it is not re-derivable from the public address
    /// alone, so we cannot cross-check it here.
    static td::Result<Address> from_bytes(td::Slice in);
};

/// Compute `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` off-circuit.
///
/// Produces the canonical 32-byte wire form (4 × 8-byte LE Goldilocks limbs).
/// Byte-identical to what the Transfer AIR computes in-circuit (§4.2 claim 3).
/// Exposed as a free function so genesis tooling and fixture builders that
/// don't hold a full `FullViewingKey` can still mint the field.
std::array<uint8_t, kIvkCommitmentBytes>
derive_ivk_commitment_bytes(const Digest& ivk, td::Slice diversifier_11);

/// Build an address from the wallet's viewing key and a chosen diversifier.
/// Populates `ivk_commitment` via `derive_ivk_commitment_bytes(fvk.ivk, d)`.
td::Result<Address> build_address(const FullViewingKey& fvk,
                                  td::Slice diversifier_11);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Derivation round-trip under a fixed seed. Checks:
///  - Deterministic: re-running returns byte-identical material.
///  - Consistency:  pk_d derived from (ivk, d) equals the scalar_mul of
///                  derive_diversified_scalar · derive_diversified_base_point.
td::Status stealth_address_verify_test_vectors();

}  // namespace uno_workchain::crypto
