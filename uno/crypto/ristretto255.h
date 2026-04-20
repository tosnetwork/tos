/*
    Uno Workchain — Ristretto255 curve ops.

    Ristretto255 (RFC 9496) is the Uno curve for:
      • spend-auth pubkey `ak = ask · G` and randomized `rk = ak + α · G`
      • diversified transmission key `pk_d = Poseidon2(ivk,d) · g_d`
      • hybrid-KEM ECDH: `s_dh = esk · pk_d` / `s_dh' = ivk · epk`
      • hash-to-curve for diversified base points `g_d` (RFC 9380)

    Backend: libsodium (`crypto_core_ristretto255_*`, `crypto_scalarmult_ristretto255*`).
    libsodium is already a build dep of TOS (CMake/FindSodium.cmake). No
    in-tree constant-time field arithmetic is re-derived; we defer to the
    libsodium surface end-to-end.

    API contract (no raw pointers on the public surface):
      • Scalars and points are always wrapped in fixed-size byte containers.
      • Secret byte buffers (scalars) use `td::SecureString` so the underlying
        memory is zeroed on drop.
      • Decoding functions are strict: non-canonical encodings are rejected
        with `td::Status::Error`, matching RFC 9496 §4.3.4 validation rules.

    Test vectors: `ristretto255_verify_test_vectors()` checks
      (a) basepoint scalar mult by 1 yields the canonical basepoint bytes
          from RFC 9496 §6.1, and
      (b) hash-to-curve on the "Ristretto is traditionally…" RFC test message
          returns the pinned compressed point.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace uno_workchain::crypto {

// ---------------------------------------------------------------------------
// Fixed sizes (match libsodium / RFC 9496)
// ---------------------------------------------------------------------------

inline constexpr size_t kRistrettoPointBytes  = 32;  // compressed element
inline constexpr size_t kRistrettoScalarBytes = 32;  // 252-bit scalar, LE
inline constexpr size_t kRistrettoHashBytes   = 64;  // input to one_way hash-to-curve

// ---------------------------------------------------------------------------
// Typed wrappers (value types, fixed size, canonical bytes on the wire)
// ---------------------------------------------------------------------------

/// Compressed Ristretto255 element, 32 bytes. "Point" ≡ group element.
/// Immutable after construction. Use `decompress_and_validate()` before
/// feeding into scalar-mult in consensus paths; libsodium primitives will
/// also reject invalid encodings but early rejection yields clearer errors.
struct RistrettoPoint {
    std::array<uint8_t, kRistrettoPointBytes> bytes{};

    static RistrettoPoint from_array(std::array<uint8_t, kRistrettoPointBytes> b) {
        return RistrettoPoint{b};
    }
    td::Slice as_slice() const {
        return td::Slice{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }
    td::MutableSlice as_mutable_slice() {
        return td::MutableSlice{reinterpret_cast<char*>(bytes.data()), bytes.size()};
    }

    /// RFC 9496 §4.3.4 decoding validation (non-canonical / negative /
    /// non-square rejects). Returns OK iff the bytes encode a valid
    /// Ristretto element; *does not* return the decompressed point —
    /// consumer APIs accept the compressed form directly.
    td::Status validate() const;
};

/// 32-byte Ristretto255 scalar in [0, L) where
///   L = 2^252 + 27742317777372353535851937790883648493.
/// Constant-time-equality is not claimed by this type; libsodium's scalar
/// APIs do the work.  Stored in `td::SecureString` so scalar material is
/// zeroed on destruction.
class RistrettoScalar {
  public:
    RistrettoScalar() noexcept : bytes_(kRistrettoScalarBytes, '\0') {}

    /// Consumes a 32-byte buffer. No validation that bytes < L — callers
    /// that need reduction use `reduce_64_bytes(…)`. Mismatched lengths
    /// abort (programming error).
    static td::Result<RistrettoScalar> from_bytes(td::Slice in);

    /// Uniform 64-byte → scalar reduction (RFC 9496 §4.3.1). Used when
    /// deriving a scalar from a domain-separated hash (e.g., `ask` derived
    /// from `BLAKE2b("uno-ask-v1" || uno_seed)` reduced mod L).
    static RistrettoScalar reduce_64_bytes(td::Slice in_64);

    td::Slice as_slice() const { return bytes_.as_slice(); }
    const td::SecureString& as_secure_string() const { return bytes_; }

  private:
    explicit RistrettoScalar(td::SecureString s) noexcept : bytes_(std::move(s)) {}
    td::SecureString bytes_;
};

// ---------------------------------------------------------------------------
// Group operations
// ---------------------------------------------------------------------------

/// The standard Ristretto255 basepoint G, compressed.
/// (RFC 9496 §6 pins the representation.)
RistrettoPoint ristretto_basepoint() noexcept;

/// `out = scalar · G` where G is the basepoint. Returns Error iff the
/// scalar byte buffer is the wrong size (libsodium accepts any 32-byte
/// value ≤ L internally).
td::Result<RistrettoPoint> ristretto_basepoint_mul(const RistrettoScalar& scalar);

/// `out = scalar · point`. Returns Error if `point` fails
/// `validate()` (non-canonical encoding / identity).
td::Result<RistrettoPoint> ristretto_scalar_mul(const RistrettoScalar& scalar,
                                                const RistrettoPoint& point);

/// `out = a + b` (group add on compressed points).
td::Result<RistrettoPoint> ristretto_add(const RistrettoPoint& a,
                                         const RistrettoPoint& b);

/// `out = a - b`.
td::Result<RistrettoPoint> ristretto_sub(const RistrettoPoint& a,
                                         const RistrettoPoint& b);

// ---------------------------------------------------------------------------
// Hash-to-curve
// ---------------------------------------------------------------------------

/// One-way map from 64 bytes of uniform input → Ristretto255 element
/// (RFC 9380 with the Elligator map applied to Curve25519 + the Ristretto
/// decode step; exposed by libsodium as
/// `crypto_core_ristretto255_from_hash`). This is the primitive underlying
/// the hash-to-curve used for diversified base points `g_d` (§2.6):
///
///   g_d = HashToRistretto("uno-diversifier-v1" || d)
///
/// Callers should pre-hash to 64 bytes with BLAKE2b; see
/// `stealth-address.h :: derive_diversified_base_point()`.
RistrettoPoint ristretto_from_hash_64(td::Slice in_64);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Asserts RFC 9496 §6.1 test vectors. Returns Error with description on
/// mismatch so callers can surface the failure; aborts only in the
/// static-init path.
td::Status ristretto255_verify_test_vectors();

}  // namespace uno_workchain::crypto
