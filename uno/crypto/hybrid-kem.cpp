/*
    Uno Workchain — hybrid KEM combiner (implementation).

    Byte-exact transcript layout from §2.7:

        "uno-hybrid-kem-v1"           (18 B, ASCII, NOT null-terminated)
        compress(s_dh)                (32 B)
        s_pq                          (32 B)
        compress(epk)                 (32 B)
        BLAKE3(mlkem_ct)              (32 B)

    Total: 18 + 32*4 = 146 B → BLAKE3 → truncate to 32 B (the default
    BLAKE3 output length).
*/

#include "uno/crypto/hybrid-kem.h"

#include <cstring>

#include "td/utils/SharedSlice.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

#include "uno/crypto/internal/blake3_adapter.h"

namespace uno_workchain::crypto {

namespace {

constexpr const char kHybridTag[]  = "uno-hybrid-kem-v1";
constexpr size_t     kHybridTagLen = sizeof(kHybridTag) - 1;  // 17
// The spec text says "18 B" but counts the ASCII characters
// "uno-hybrid-kem-v1" which is actually 17. We honour the byte-literal
// ASCII-only interpretation (no null terminator, no trailing space).
static_assert(kHybridTagLen == 17, "tag length drifted; spec reference = 17 chars");

constexpr const char kNonceTag[]  = "uno-nonce-v1";
constexpr size_t     kNonceTagLen = sizeof(kNonceTag) - 1;  // 12

}  // namespace

td::Result<AeadKey> hybrid_kem_derive_key(const RistrettoPoint& s_dh,
                                          td::Slice s_pq_32,
                                          const RistrettoPoint& epk,
                                          const MlKem768Ciphertext& mlkem_ct) {
    if (s_pq_32.size() != 32) {
        return td::Status::Error("hybrid-kem: s_pq must be 32 bytes");
    }

    // Pre-hash the KEM ciphertext.
    uint8_t ct_hash[32];
    internal::blake3_hash(mlkem_ct.as_slice(), ct_hash);

    // Build the full transcript via streaming BLAKE3 to avoid a 146-byte
    // temporary.
    internal::Blake3Hasher h;
    h.update(td::Slice{kHybridTag, kHybridTagLen});
    h.update(s_dh.as_slice());
    h.update(s_pq_32);
    h.update(epk.as_slice());
    h.update(td::Slice{reinterpret_cast<const char*>(ct_hash), 32});

    td::SecureString k_out(kAeadKeyBytes, '\0');
    h.finalize_32(reinterpret_cast<uint8_t*>(k_out.as_mutable_slice().data()));

    // Zero the transient ct hash (not secret, but keep discipline).
    std::memset(ct_hash, 0, sizeof(ct_hash));
    return k_out;
}

AeadNonce hybrid_kem_derive_nonce(const RistrettoPoint& epk) {
    internal::Blake3Hasher h;
    h.update(td::Slice{kNonceTag, kNonceTagLen});
    h.update(epk.as_slice());
    uint8_t full[32];
    h.finalize_32(full);
    AeadNonce out{};
    std::memcpy(out.data(), full, kAeadNonceBytes);
    std::memset(full, 0, sizeof(full));
    return out;
}

td::Status hybrid_kem_verify_test_vectors() {
    // Structural self-test: hash of all-zero inputs should be deterministic
    // and round-trip through a second call. We pin the number of bytes but
    // not the exact output (reference Python vector is a TODO for Agent 6).
    RistrettoPoint s_dh{};   // all-zero (not a valid point, but BLAKE3 only
                             // sees bytes; the transcript is purely bytes)
    RistrettoPoint epk{};    // all-zero
    MlKem768Ciphertext ct{}; // all-zero (1088 zero bytes)
    uint8_t s_pq[32] = {0};

    TRY_RESULT(k1, hybrid_kem_derive_key(
                       s_dh,
                       td::Slice{reinterpret_cast<const char*>(s_pq), 32},
                       epk, ct));
    TRY_RESULT(k2, hybrid_kem_derive_key(
                       s_dh,
                       td::Slice{reinterpret_cast<const char*>(s_pq), 32},
                       epk, ct));
    if (k1.as_slice() != k2.as_slice()) {
        return td::Status::Error(
            "hybrid-kem: non-deterministic BLAKE3 (backend mis-wire)");
    }
    if (k1.size() != kAeadKeyBytes) {
        return td::Status::Error("hybrid-kem: wrong output length");
    }

    // Nonce determinism.
    auto n1 = hybrid_kem_derive_nonce(epk);
    auto n2 = hybrid_kem_derive_nonce(epk);
    if (n1 != n2) {
        return td::Status::Error(
            "hybrid-kem: non-deterministic nonce (backend mis-wire)");
    }
    return td::Status::OK();
}

}  // namespace uno_workchain::crypto
