/*
    Uno Workchain — ML-KEM-768 wrapper (FIPS 203).

    ML-KEM-768 (Kyber-768 standardized form, NIST FIPS 203) is the
    post-quantum KEM used in the hybrid note-encryption combiner (§2.7).
    v1 scheme_id = 0x01 requires:
      - Deterministic KeyGen from a 32-byte seed (FIPS 203 §7.1,
        AuxiliaryFunctions K-PKE.KeyGen calls an expanded deterministic
        seed; we adopt the canonical 32-byte `d` input and the derived
        `z` so that the full keypair is reconstructible from one seed —
        required by the stealth-address key hierarchy §2.6 so that users
        who import an `uno_seed` recover the same `pk_mlkem, sk_mlkem`).
      - Encapsulate(pk) → (ct, ss); ct = 1088 B, ss = 32 B.
      - Decapsulate(sk, ct) → ss (32 B). Implicit rejection: on ct failure,
        return an HKDF-derived pseudorandom ss rather than an error (FIPS 203
        §7.3).  This is what liboqs exposes; consumer code MUST check AEAD
        tags to reject.

    Backend: liboqs (Open Quantum Safe). liboqs is the most broadly audited
    open-source FIPS-203 implementation with constant-time guarantees on
    Decapsulate. Agent 5 wires it as a build dep.

    Alternative: FIPS 203-compliant reference in pq-crystals/kyber.git. If
    Agent 5 finds liboqs integration blocked (e.g., ABI breakage, cross-
    compile issues), fall back to vendoring the PQ-Crystals reference
    implementation under `third-party/kyber/`. In either case the public
    API here is unchanged.

    Public API style: no raw pointers, all secret material behind
    `td::SecureString`.
*/
#pragma once

#include <array>
#include <cstdint>
#include <memory>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// FIPS 203 ML-KEM-768 fixed sizes
// ---------------------------------------------------------------------------

inline constexpr size_t kMlKem768PublicKeyBytes    = 1184;
inline constexpr size_t kMlKem768SecretKeyBytes    = 2400;
inline constexpr size_t kMlKem768CiphertextBytes   = 1088;
inline constexpr size_t kMlKem768SharedSecretBytes = 32;
/// FIPS 203 deterministic seed size (`d` in the spec). We extend this to
/// 64 bytes when combining with the `z` input, but callers pass exactly
/// 64 bytes as a single `uno-mlkem-v1` derivation — see
/// stealth-address::derive_mlkem_seed().
inline constexpr size_t kMlKem768SeedBytes        = 64;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// ML-KEM-768 public key (1184 bytes). Appears on the wire inside
/// `Address.pk_mlkem` (§2.6).
struct MlKem768PublicKey {
    std::array<uint8_t, kMlKem768PublicKeyBytes> bytes{};

    td::Slice as_slice() const {
        return td::Slice{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }
    static td::Result<MlKem768PublicKey> from_slice(td::Slice in);
};

/// ML-KEM-768 secret key (2400 bytes). Held in SecureString; never serialised
/// to disk without the wallet's at-rest encryption layer.
class MlKem768SecretKey {
  public:
    MlKem768SecretKey() noexcept : bytes_(kMlKem768SecretKeyBytes, '\0') {}
    const td::SecureString& as_secure_string() const { return bytes_; }
    td::Slice as_slice() const { return bytes_.as_slice(); }
    td::MutableSlice as_mutable_slice() { return bytes_.as_mutable_slice(); }
    static td::Result<MlKem768SecretKey> from_slice(td::Slice in);

  private:
    td::SecureString bytes_;
};

/// Ciphertext (1088 bytes), carried on the wire as an OutputDescription's
/// `mlkem_ct` reference cell.
struct MlKem768Ciphertext {
    std::array<uint8_t, kMlKem768CiphertextBytes> bytes{};
    td::Slice as_slice() const {
        return td::Slice{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }
    static td::Result<MlKem768Ciphertext> from_slice(td::Slice in);
};

/// Shared-secret output (32 bytes). Kept in SecureString so the memory is
/// zeroed on drop; this value feeds directly into the hybrid-KEM combiner.
using MlKem768SharedSecret = td::SecureString;

struct MlKem768KeyPair {
    MlKem768PublicKey pk;
    MlKem768SecretKey sk;
};

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Deterministic KeyGen from a 64-byte seed (FIPS 203 §7.1 with the
/// canonical (d, z) concatenation). The stealth-address hierarchy (§2.6)
/// supplies this via
///     mlkem_seed_64 = BLAKE2b-512("uno-mlkem-v1" || uno_seed)
/// and the 64 bytes are passed in verbatim.
///
/// Returns Error if the underlying ML-KEM library is not linked or the
/// seed length is wrong.
td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed(td::Slice seed_64);

/// Convenience overload that accepts a 32-byte seed and deterministically
/// expands it to the 64-byte (d || z) form used by FIPS 203 derand keygen:
///     expanded = BLAKE2b-512("uno-mlkem-expand-v1" || seed_32)
/// Intended for tests / CLI; production callers pass the full 64-byte
/// output of the stealth-address seed derivation.
td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed32(td::Slice seed_32);

/// Encapsulate a fresh shared secret under `pk`. Uses the library's
/// internal randomness (which on Linux reads /dev/urandom) — sufficient for
/// a one-shot per-output KEM ct. Returns `(ct, ss)`.
struct MlKem768EncapResult {
    MlKem768Ciphertext ct;
    MlKem768SharedSecret ss;
};
td::Result<MlKem768EncapResult> mlkem768_encap(const MlKem768PublicKey& pk);

/// Deterministic Encapsulate using a caller-supplied 32-byte randomness.
/// Required for reproducible test vectors and for wallet-side regeneration
/// of prior outputs (e.g. for audit via `ovk`).
td::Result<MlKem768EncapResult> mlkem768_encap_deterministic(
    const MlKem768PublicKey& pk, td::Slice randomness_32);

/// Decapsulate. Implicit rejection: on a malformed `ct`, returns a
/// pseudorandom `ss` indistinguishable from a valid one — callers MUST
/// check the downstream AEAD tag to reject.
td::Result<MlKem768SharedSecret> mlkem768_decap(const MlKem768SecretKey& sk,
                                                const MlKem768Ciphertext& ct);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Runs a keygen/encap/decap round-trip under a fixed seed and asserts
/// that Decap(Encap) == Encap's ss. Does *not* pin the raw ss bytes because
/// the mlkem_seed → (pk,sk) mapping depends on liboqs's internal derivation
/// (which matches FIPS 203 but has a build-specific endianness choice in
/// some older liboqs versions); we pin the derived shared-secret equality.
td::Status mlkem768_verify_test_vectors();

}  // namespace uno_workchain::crypto
