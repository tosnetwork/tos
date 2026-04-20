/*
    Uno Workchain — Schnorr-on-Ristretto255 (implementation).

    Implementation notes:
      - Nonce derivation follows Ed25519's `SHA-512(prefix || msg)` pattern,
        substituting BLAKE2b-512. `prefix` is the 32-byte private-key hash
        keyed with a domain tag so that the same seed can be reused across
        spend-auth and (future) different signing roles without collision.
      - Scalar reduction uses libsodium's `scalar_reduce(64→32)`.
      - Scalar addition for `rsk = ask + α` uses
        `crypto_core_ristretto255_scalar_add`.
      - All scalar/point material transits via `td::SecureString`-backed
        wrappers; no raw `uint8_t*` leaks into the public surface.
*/

#include "uno/crypto/schnorr-ristretto.h"

#include <cstring>

#include <sodium.h>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace uno_workchain::crypto {

namespace {

constexpr const char* kDomainTag = "uno-schnorr-v1";
constexpr size_t kDomainTagLen = 14;

// BLAKE2b-512 one-shot via libsodium's `crypto_generichash` (which is
// BLAKE2b). Produces 64 bytes suitable for Ristretto scalar_reduce.
void blake2b_512(td::Slice in, uint8_t out[64]) {
    crypto_generichash(out, 64,
                       reinterpret_cast<const uint8_t*>(in.data()), in.size(),
                       nullptr, 0);
}

// Hash-to-scalar: BLAKE2b-512 over `tag || inputs…` then reduce mod L.
RistrettoScalar hash_to_scalar(std::initializer_list<td::Slice> inputs) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 64);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(kDomainTag),
                              kDomainTagLen);
    for (auto s : inputs) {
        crypto_generichash_update(&st,
                                  reinterpret_cast<const uint8_t*>(s.data()),
                                  s.size());
    }
    uint8_t digest[64];
    crypto_generichash_final(&st, digest, 64);
    td::Slice digest_slice{reinterpret_cast<const char*>(digest), 64};
    auto sc = RistrettoScalar::reduce_64_bytes(digest_slice);
    sodium_memzero(digest, sizeof(digest));
    return sc;
}

const uint8_t* as_u8(td::Slice s) { return reinterpret_cast<const uint8_t*>(s.data()); }

}  // namespace

// ---------------------------------------------------------------------------
// KeyPair
// ---------------------------------------------------------------------------

td::Result<SchnorrKeyPair> SchnorrKeyPair::from_seed32(td::Slice seed) {
    if (seed.size() != 32) {
        return td::Status::Error("schnorr: seed must be 32 bytes");
    }
    // Derive a uniform scalar by hashing seed to 64 bytes and reducing.
    uint8_t buf[64];
    blake2b_512(seed, buf);
    td::Slice buf_slice{reinterpret_cast<const char*>(buf), 64};
    RistrettoScalar sk = RistrettoScalar::reduce_64_bytes(buf_slice);
    sodium_memzero(buf, sizeof(buf));

    TRY_RESULT(pk, ristretto_basepoint_mul(sk));
    return SchnorrKeyPair{std::move(sk), pk};
}

td::Result<SchnorrKeyPair> SchnorrKeyPair::from_scalar(RistrettoScalar sk) {
    TRY_RESULT(pk, ristretto_basepoint_mul(sk));
    return SchnorrKeyPair{std::move(sk), pk};
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

td::Result<SchnorrSignature> schnorr_sign(const RistrettoScalar& sk,
                                          const RistrettoPoint& pk,
                                          td::Slice msg) {
    // 1. Deterministic nonce: r = H_scalar("nonce" || sk || msg)
    td::Slice nonce_tag{"nonce", 5};
    RistrettoScalar r = hash_to_scalar({nonce_tag, sk.as_slice(), msg});

    // 2. R = r · G
    TRY_RESULT(R, ristretto_basepoint_mul(r));

    // 3. c = H_scalar("chal" || R || pk || msg)
    td::Slice chal_tag{"chal", 4};
    RistrettoScalar c = hash_to_scalar({chal_tag, R.as_slice(), pk.as_slice(), msg});

    // 4. s = r + c·sk  (all mod L)
    uint8_t s_out[32];
    uint8_t cs[32];
    crypto_core_ristretto255_scalar_mul(cs, as_u8(c.as_slice()), as_u8(sk.as_slice()));
    crypto_core_ristretto255_scalar_add(s_out, as_u8(r.as_slice()), cs);
    sodium_memzero(cs, sizeof(cs));

    SchnorrSignature sig{};
    std::memcpy(sig.data(), R.bytes.data(), 32);
    std::memcpy(sig.data() + 32, s_out, 32);
    sodium_memzero(s_out, sizeof(s_out));
    return sig;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

td::Status schnorr_verify(const RistrettoPoint& pk,
                          td::Slice msg,
                          const SchnorrSignature& sig) {
    // Extract R, s
    RistrettoPoint R;
    std::memcpy(R.bytes.data(), sig.data(), 32);
    TRY_STATUS(R.validate());

    td::Slice s_slice{reinterpret_cast<const char*>(sig.data() + 32), 32};
    TRY_RESULT(s_sc, RistrettoScalar::from_bytes(s_slice));

    // Reject s ≥ L (libsodium's scalar_mult below does not enforce this
    // for all callers; canonicality is part of the signature encoding).
    // We check by reducing; if reduction changes bytes, s was non-canonical.
    // Use the `scalar_reduce` on a 64-byte buffer with s in the low 32 and
    // zero in the high 32 as a canonicalization check.
    {
        uint8_t padded[64] = {0};
        std::memcpy(padded, sig.data() + 32, 32);
        uint8_t reduced[32];
        crypto_core_ristretto255_scalar_reduce(reduced, padded);
        if (std::memcmp(reduced, sig.data() + 32, 32) != 0) {
            sodium_memzero(padded, sizeof(padded));
            return td::Status::Error("schnorr: non-canonical scalar s (s ≥ L)");
        }
    }

    // c = H_scalar("chal" || R || pk || msg)
    td::Slice chal_tag{"chal", 4};
    RistrettoScalar c = hash_to_scalar({chal_tag, R.as_slice(), pk.as_slice(), msg});

    // Check s·G == R + c·pk
    TRY_RESULT(lhs, ristretto_basepoint_mul(s_sc));
    TRY_RESULT(c_pk, ristretto_scalar_mul(c, pk));
    TRY_RESULT(rhs, ristretto_add(R, c_pk));

    if (lhs.bytes != rhs.bytes) {
        return td::Status::Error("schnorr: verification failed");
    }
    return td::Status::OK();
}

// ---------------------------------------------------------------------------
// Randomized spend-auth
// ---------------------------------------------------------------------------

td::Result<RandomizedKeyPair> randomize_spend_auth(const RistrettoScalar& ask,
                                                   const RistrettoPoint& ak,
                                                   const RistrettoScalar& alpha) {
    // rsk = ask + α
    uint8_t rsk_bytes[32];
    crypto_core_ristretto255_scalar_add(rsk_bytes,
                                        as_u8(ask.as_slice()),
                                        as_u8(alpha.as_slice()));
    td::Slice rsk_slice{reinterpret_cast<const char*>(rsk_bytes), 32};
    TRY_RESULT(rsk, RistrettoScalar::from_bytes(rsk_slice));
    sodium_memzero(rsk_bytes, sizeof(rsk_bytes));

    // rk = ak + α·G
    TRY_RESULT(alpha_g, ristretto_basepoint_mul(alpha));
    TRY_RESULT(rk, ristretto_add(ak, alpha_g));

    return RandomizedKeyPair{std::move(rsk), rk};
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

td::Status schnorr_verify_test_vectors() {
    // Round-trip correctness: generate a keypair from a fixed 32-byte seed,
    // sign a fixed message, verify. We deliberately do NOT pin specific
    // signature bytes here because deterministic nonce derivation across
    // libsodium versions is stable but our hash-to-scalar construction is
    // local to this module; any signature-format change will break the
    // downstream `spend_auth_sig` wire format and must be a conscious
    // cross-agent decision.
    static const uint8_t kSeed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    td::Slice seed{reinterpret_cast<const char*>(kSeed), 32};
    TRY_RESULT(kp, SchnorrKeyPair::from_seed32(seed));

    td::Slice msg{"uno-schnorr-test-message", 24};
    TRY_RESULT(sig, schnorr_sign(kp.sk, kp.pk, msg));
    TRY_STATUS(schnorr_verify(kp.pk, msg, sig));

    // Tamper: flip a byte in message → verify must fail.
    std::array<uint8_t, 24> tampered{};
    std::memcpy(tampered.data(), msg.data(), 24);
    tampered[0] ^= 0x01;
    td::Slice tampered_slice{reinterpret_cast<const char*>(tampered.data()), 24};
    auto v = schnorr_verify(kp.pk, tampered_slice, sig);
    if (v.is_ok()) {
        return td::Status::Error(
            "schnorr: tampered message accepted (verify unsound)");
    }
    return td::Status::OK();
}

}  // namespace uno_workchain::crypto
