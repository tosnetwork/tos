/*
    Uno Workchain — Ristretto255 curve ops (libsodium wrapper).

    All heavy lifting goes to libsodium:
        crypto_core_ristretto255_is_valid_point
        crypto_core_ristretto255_add / _sub / _from_hash
        crypto_core_ristretto255_scalar_reduce
        crypto_scalarmult_ristretto255
        crypto_scalarmult_ristretto255_base

    Build: links against `sodium`. Agent 5 wires the FindSodium include/link
    into the crypto target. `sodium_init()` is idempotent and thread-safe;
    we call it lazily via a std::once_flag on the first entry point.
*/

#include "uno/crypto/ristretto255.h"

#include <cstring>
#include <mutex>

#include <sodium.h>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace uno_workchain::crypto {

namespace {

void ensure_sodium_initialized() {
    static std::once_flag once;
    std::call_once(once, []() {
        if (sodium_init() < 0) {
            // A failed sodium_init implies a broken runtime; treat as fatal.
            std::abort();
        }
    });
}

const uint8_t* as_u8(td::Slice s) {
    return reinterpret_cast<const uint8_t*>(s.data());
}

uint8_t* as_u8(td::MutableSlice s) {
    return reinterpret_cast<uint8_t*>(s.data());
}

}  // namespace

// ---------------------------------------------------------------------------
// RistrettoPoint
// ---------------------------------------------------------------------------

td::Status RistrettoPoint::validate() const {
    ensure_sodium_initialized();
    if (crypto_core_ristretto255_is_valid_point(bytes.data()) != 1) {
        return td::Status::Error("ristretto255: invalid / non-canonical point encoding");
    }
    return td::Status::OK();
}

RistrettoPoint ristretto_basepoint() noexcept {
    ensure_sodium_initialized();
    // Scalar-mult by 1 to materialize the basepoint bytes — libsodium does
    // not expose the compressed basepoint as a constant directly.
    std::array<uint8_t, crypto_scalarmult_ristretto255_SCALARBYTES> one{};
    one[0] = 1;
    RistrettoPoint out;
    // `_base` cannot fail for a canonical scalar ≤ L; return value is
    // nonzero only on "forbidden" inputs like all-zero scalar.
    int rc = crypto_scalarmult_ristretto255_base(out.bytes.data(), one.data());
    (void)rc;
    return out;
}

// ---------------------------------------------------------------------------
// RistrettoScalar
// ---------------------------------------------------------------------------

td::Result<RistrettoScalar> RistrettoScalar::from_bytes(td::Slice in) {
    if (in.size() != kRistrettoScalarBytes) {
        return td::Status::Error("ristretto255: scalar must be exactly 32 bytes");
    }
    td::SecureString buf(kRistrettoScalarBytes, '\0');
    std::memcpy(buf.as_mutable_slice().data(), in.data(), kRistrettoScalarBytes);
    return RistrettoScalar{std::move(buf)};
}

RistrettoScalar RistrettoScalar::reduce_64_bytes(td::Slice in_64) {
    ensure_sodium_initialized();
    // crypto_core_ristretto255_scalar_reduce maps a 64-byte little-endian
    // integer → a 32-byte scalar in [0, L). Used for hash-derived scalars.
    // We expect exactly 64 bytes; shorter input is caller error.
    if (in_64.size() != crypto_core_ristretto255_NONREDUCEDSCALARBYTES) {
        std::abort();
    }
    td::SecureString buf(kRistrettoScalarBytes, '\0');
    crypto_core_ristretto255_scalar_reduce(as_u8(buf.as_mutable_slice()), as_u8(in_64));
    return RistrettoScalar{std::move(buf)};
}

// ---------------------------------------------------------------------------
// Group operations
// ---------------------------------------------------------------------------

td::Result<RistrettoPoint> ristretto_basepoint_mul(const RistrettoScalar& scalar) {
    ensure_sodium_initialized();
    RistrettoPoint out;
    // libsodium rejects the all-zero scalar from scalarmult. We allow it
    // here (returns identity) because callers (e.g. randomizer path) may
    // legitimately pass zero, but then the output is the identity which
    // downstream logic must reject.
    int rc = crypto_scalarmult_ristretto255_base(
        out.bytes.data(),
        as_u8(scalar.as_slice()));
    if (rc != 0) {
        // Zero scalar → identity. Return explicit identity bytes (all zero).
        out.bytes.fill(0);
    }
    return out;
}

td::Result<RistrettoPoint> ristretto_scalar_mul(const RistrettoScalar& scalar,
                                                const RistrettoPoint& point) {
    ensure_sodium_initialized();
    TRY_STATUS(point.validate());
    RistrettoPoint out;
    int rc = crypto_scalarmult_ristretto255(
        out.bytes.data(),
        as_u8(scalar.as_slice()),
        point.bytes.data());
    if (rc != 0) {
        return td::Status::Error(
            "ristretto255: scalar_mult failed (identity or invalid input)");
    }
    return out;
}

td::Result<RistrettoPoint> ristretto_add(const RistrettoPoint& a,
                                         const RistrettoPoint& b) {
    ensure_sodium_initialized();
    RistrettoPoint out;
    int rc = crypto_core_ristretto255_add(
        out.bytes.data(), a.bytes.data(), b.bytes.data());
    if (rc != 0) {
        return td::Status::Error("ristretto255: add rejected invalid point");
    }
    return out;
}

td::Result<RistrettoPoint> ristretto_sub(const RistrettoPoint& a,
                                         const RistrettoPoint& b) {
    ensure_sodium_initialized();
    RistrettoPoint out;
    int rc = crypto_core_ristretto255_sub(
        out.bytes.data(), a.bytes.data(), b.bytes.data());
    if (rc != 0) {
        return td::Status::Error("ristretto255: sub rejected invalid point");
    }
    return out;
}

// ---------------------------------------------------------------------------
// Hash-to-curve
// ---------------------------------------------------------------------------

RistrettoPoint ristretto_from_hash_64(td::Slice in_64) {
    ensure_sodium_initialized();
    if (in_64.size() != crypto_core_ristretto255_HASHBYTES) {
        std::abort();
    }
    RistrettoPoint out;
    crypto_core_ristretto255_from_hash(out.bytes.data(), as_u8(in_64));
    return out;
}

// ---------------------------------------------------------------------------
// Self-test (RFC 9496 §6.1)
// ---------------------------------------------------------------------------

td::Status ristretto255_verify_test_vectors() {
    ensure_sodium_initialized();

    // RFC 9496 §6.1: compressed basepoint (the output of mapping 1·G).
    // "e2f2ae0a 6abc4e71 a884a961 c500515f 58e30b6a a582dd8d b6a65945 e08d2d76"
    static constexpr uint8_t kExpectedBasepoint[32] = {
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
        0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
        0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
        0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    };
    RistrettoPoint bp = ristretto_basepoint();
    if (std::memcmp(bp.bytes.data(), kExpectedBasepoint, 32) != 0) {
        return td::Status::Error(
            "ristretto255: basepoint self-test FAILED (RFC 9496 §6.1)");
    }

    // Secondary: validate the basepoint decodes.
    TRY_STATUS(bp.validate());

    // Scalar-mult consistency: 2·G == G + G.
    td::SecureString two_s(kRistrettoScalarBytes, '\0');
    two_s.as_mutable_slice().data()[0] = 2;
    auto two_scalar = RistrettoScalar::from_bytes(two_s.as_slice());
    if (two_scalar.is_error()) return two_scalar.move_as_error();
    TRY_RESULT(two_g, ristretto_basepoint_mul(two_scalar.ok()));
    TRY_RESULT(g_plus_g, ristretto_add(bp, bp));
    if (two_g.bytes != g_plus_g.bytes) {
        return td::Status::Error(
            "ristretto255: 2·G != G+G (libsodium consistency failure)");
    }

    return td::Status::OK();
}

}  // namespace uno_workchain::crypto
