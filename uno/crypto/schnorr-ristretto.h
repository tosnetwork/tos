/*
    Uno Workchain — Schnorr signatures on Ristretto255 (spend-auth).

    Used to carry `spend_auth_sig` (§2.5, §4.1). The signing key is the
    randomized scalar `rsk = ask + α`; the verification key is the randomized
    `rk = ak + α·G` published in the `SpendDescription`. Signing is performed
    off-circuit; the ZK proof certifies that the prover knows the seed
    material behind `ak`, and the AIR emits the `rk = ak + α·G` binding
    (claim 6, §4.2) so that validation of this Schnorr signature couples
    off-circuit to the in-circuit identity.

    Scheme (matches the canonical Schnorr-over-edwards/Ristretto construction
    used by sr25519 and ed25519, simplified: no curve cofactor clearing is
    needed on Ristretto255 because the Ristretto encoding defines a prime
    order subgroup directly):

      sign(sk, msg):
        r      = uniform scalar  (RFC 6979-style deterministic from sk || msg)
        R      = r · G                          // point
        c      = H_scalar("uno-schnorr-v1" || R || pk || msg)
        s      = r + c · sk                     // scalar mod L
        return (R_bytes, s_bytes)               // 32 + 32 = 64 bytes

      verify(pk, msg, (R_bytes, s_bytes)):
        c      = H_scalar("uno-schnorr-v1" || R || pk || msg)
        return s · G == R + c · pk

    H_scalar is BLAKE2b-512 → `crypto_core_ristretto255_scalar_reduce` to
    produce a uniform scalar ∈ [0, L).

    Security note: deterministic nonce derivation closes the "bad RNG →
    secret leak" class of attacks that has hit ECDSA in the wild. We use
    the same construction as Ed25519 (hash of the secret key plus the
    message).

    Test vectors: one known-answer vector (keygen from a fixed seed, sign
    a fixed message, verify) is checked in `_verify_test_vectors()`. Against
    pinned bytes captured from a round-trip invocation; any future
    byte-format change would fail this vector.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/ristretto255.h"

namespace uno_workchain::crypto {

inline constexpr size_t kSchnorrSignatureBytes = 64;  // R (32) || s (32)

using SchnorrSignature = std::array<uint8_t, kSchnorrSignatureBytes>;

// ---------------------------------------------------------------------------
// Key pair
// ---------------------------------------------------------------------------

struct SchnorrKeyPair {
    RistrettoScalar sk;  // 32-byte scalar; td::SecureString backing
    RistrettoPoint pk;   // sk · G

    /// Deterministic key derivation from a 32-byte seed. Used for wallet
    /// test keys; production `ask` comes from the stealth-address key
    /// hierarchy and is built via `RistrettoScalar::reduce_64_bytes()`.
    static td::Result<SchnorrKeyPair> from_seed32(td::Slice seed);

    /// Build from an already-materialized scalar. The caller guarantees
    /// the scalar is in [0, L).
    static td::Result<SchnorrKeyPair> from_scalar(RistrettoScalar sk);
};

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/// Sign `msg` with `sk`. `pk` is required (not recomputed) so that an
/// attacker-controlled mismatched-pk execution is impossible; callers
/// always have `pk` in hand.
td::Result<SchnorrSignature> schnorr_sign(const RistrettoScalar& sk,
                                          const RistrettoPoint& pk,
                                          td::Slice msg);

/// Verify `sig` for `msg` under `pk`. Returns Ok on success; an Error
/// status on mismatch (non-canonical point, scalar out of range, or
/// equation mismatch).
td::Status schnorr_verify(const RistrettoPoint& pk,
                          td::Slice msg,
                          const SchnorrSignature& sig);

// ---------------------------------------------------------------------------
// Randomized (spend-auth) helpers (§2.5)
// ---------------------------------------------------------------------------

/// Compute the randomized per-spend keypair:
///     rsk = ask + α        (mod L)
///     rk  = ak + α · G
///
/// `ak` is expected to be the Ristretto encoding of `ask · G`; no check is
/// performed here — caller provides the matching pair.
struct RandomizedKeyPair {
    RistrettoScalar rsk;
    RistrettoPoint rk;
};

td::Result<RandomizedKeyPair> randomize_spend_auth(const RistrettoScalar& ask,
                                                   const RistrettoPoint& ak,
                                                   const RistrettoScalar& alpha);

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

td::Status schnorr_verify_test_vectors();

}  // namespace uno_workchain::crypto
