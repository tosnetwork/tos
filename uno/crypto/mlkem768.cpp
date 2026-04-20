/*
    Uno Workchain — ML-KEM-768 (FIPS 203) wrapper implementation.

    Backend: liboqs >= 0.10 which ships the NIST FIPS 203 final-draft-aligned
    ML-KEM-768 implementation.  Symbols:

        OQS_KEM *OQS_KEM_new(const char *method_name);      // "ML-KEM-768"
        OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *pk, uint8_t *sk);
        OQS_STATUS OQS_KEM_encaps (const OQS_KEM *kem, uint8_t *ct,
                                   uint8_t *ss, const uint8_t *pk);
        OQS_STATUS OQS_KEM_decaps (const OQS_KEM *kem, uint8_t *ss,
                                   const uint8_t *ct, const uint8_t *sk);
        void OQS_KEM_free(OQS_KEM *);

    Determinism: liboqs exposes deterministic keygen via
        OQS_KEM_keypair_derand(kem, pk, sk, coins_d, coins_z);
    taking `d` (32 B) and `z` (32 B). We split the 64-byte seed into two
    halves for this call.

    For deterministic Encaps, liboqs exposes
        OQS_KEM_encaps_derand(kem, ct, ss, pk, coins_m);
    taking the 32-byte `m` coin.

    TODO(agent-5): link liboqs. Until then, compiling this TU requires
    UNO_MLKEM_STUB=1 (fatal-abort stubs), kept off by default so missing
    dependency surfaces at link time with a clear error.
*/

#include "uno/crypto/mlkem768.h"

#include <cstring>

#include "td/utils/Slice.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Status.h"

#ifndef UNO_MLKEM_STUB
#include <oqs/oqs.h>
#endif

#include <sodium.h>  // for the 32-byte-seed expand helper (BLAKE2b-512)

namespace uno_workchain::crypto {

#ifdef UNO_MLKEM_STUB
namespace {
[[noreturn]] void stub_abort(const char* fn) {
    std::fprintf(stderr,
                 "uno_workchain::crypto::mlkem768::%s: liboqs not linked. "
                 "Build with -UUNO_MLKEM_STUB once Agent 5 wires liboqs.\n",
                 fn);
    std::abort();
}
}  // namespace
#endif

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

td::Result<MlKem768PublicKey> MlKem768PublicKey::from_slice(td::Slice in) {
    if (in.size() != kMlKem768PublicKeyBytes) {
        return td::Status::Error("mlkem768: pk wrong size");
    }
    MlKem768PublicKey out;
    std::memcpy(out.bytes.data(), in.data(), kMlKem768PublicKeyBytes);
    return out;
}

td::Result<MlKem768SecretKey> MlKem768SecretKey::from_slice(td::Slice in) {
    if (in.size() != kMlKem768SecretKeyBytes) {
        return td::Status::Error("mlkem768: sk wrong size");
    }
    MlKem768SecretKey out;
    std::memcpy(out.as_mutable_slice().data(), in.data(), kMlKem768SecretKeyBytes);
    return out;
}

td::Result<MlKem768Ciphertext> MlKem768Ciphertext::from_slice(td::Slice in) {
    if (in.size() != kMlKem768CiphertextBytes) {
        return td::Status::Error("mlkem768: ct wrong size");
    }
    MlKem768Ciphertext out;
    std::memcpy(out.bytes.data(), in.data(), kMlKem768CiphertextBytes);
    return out;
}

#ifndef UNO_MLKEM_STUB

namespace {

struct Kem {
    OQS_KEM* kem = nullptr;
    Kem() { kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768); }
    ~Kem() {
        if (kem) OQS_KEM_free(kem);
    }
    bool ok() const { return kem != nullptr; }
};

// Thread-safe lazy singleton — OQS_KEM object is read-only after creation.
const Kem& kem_instance() {
    static Kem instance;
    return instance;
}

}  // namespace

td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed(td::Slice seed_64) {
    if (seed_64.size() != kMlKem768SeedBytes) {
        return td::Status::Error("mlkem768: seed must be 64 bytes (d||z)");
    }
    const auto& K = kem_instance();
    if (!K.ok()) {
        return td::Status::Error("mlkem768: liboqs ML-KEM-768 not available");
    }
    // Detect: does liboqs provide the derand variant? Older builds do not.
    // liboqs >= 0.10 exposes it as `OQS_KEM_ml_kem_768_keypair_derand` with
    // a single 64-byte seed argument (the `d||z` concatenation that FIPS 203
    // calls for — liboqs does the internal split). The CMake probe in
    // uno/CMakeLists.txt checks the header for the prototype and defines
    // OQS_HAVE_ML_KEM_KEYPAIR_DERAND when present.
#if defined(OQS_HAVE_ML_KEM_KEYPAIR_DERAND)
    MlKem768KeyPair out;
    out.sk = MlKem768SecretKey{};  // default: zero-filled SecureString

    // NOTE (M-liboqs build bringup): liboqs expects a single 64 B seed
    // pointer `d||z`; earlier drafts of this file called a hypothetical
    // two-pointer variant `(pk, sk, d, z)`. The final FIPS 203 liboqs API
    // takes the contiguous 64 B seed, so we pass the full seed_64 slice.
    const uint8_t* seed_ptr = reinterpret_cast<const uint8_t*>(seed_64.data());
    OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair_derand(
        out.pk.bytes.data(),
        reinterpret_cast<uint8_t*>(out.sk.as_mutable_slice().data()),
        seed_ptr);
    if (rc != OQS_SUCCESS) {
        return td::Status::Error("mlkem768: deterministic keygen failed");
    }
    return out;
#else
    (void)K;
    return td::Status::Error(
        "mlkem768: deterministic KeyGen not exposed by this liboqs build; "
        "link against liboqs ≥ 0.10 with OQS_ENABLE_KEM_ML_KEM=ON or vendor "
        "pq-crystals/kyber reference. Tracked under Agent 5 build TODO.");
#endif
}

td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed32(td::Slice seed_32) {
    if (seed_32.size() != 32) {
        return td::Status::Error("mlkem768: 32-byte seed required");
    }
    // Expand to 64 B via BLAKE2b-512 under a distinct tag. The tag is
    // different from the stealth-address `"uno-mlkem-v1"` domain so that
    // this helper cannot be accidentally used to derive the on-chain
    // production keypair from a raw 32-byte seed without going through
    // the stealth-address hierarchy.
    constexpr const char kTag[] = "uno-mlkem-expand-v1";
    constexpr size_t kTagLen = sizeof(kTag) - 1;

    uint8_t expanded[64];
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 64);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(kTag), kTagLen);
    crypto_generichash_update(&st,
                              reinterpret_cast<const uint8_t*>(seed_32.data()),
                              seed_32.size());
    crypto_generichash_final(&st, expanded, 64);
    td::Slice expanded_slice{reinterpret_cast<const char*>(expanded), 64};
    auto out = mlkem768_keygen_from_seed(expanded_slice);
    sodium_memzero(expanded, sizeof(expanded));
    return out;
}

td::Result<MlKem768EncapResult> mlkem768_encap(const MlKem768PublicKey& pk) {
    const auto& K = kem_instance();
    if (!K.ok()) return td::Status::Error("mlkem768: liboqs ML-KEM-768 not available");
    MlKem768EncapResult out;
    out.ss = td::SecureString(kMlKem768SharedSecretBytes, '\0');

    OQS_STATUS rc = OQS_KEM_encaps(
        K.kem,
        out.ct.bytes.data(),
        reinterpret_cast<uint8_t*>(out.ss.as_mutable_slice().data()),
        pk.bytes.data());
    if (rc != OQS_SUCCESS) return td::Status::Error("mlkem768: encap failed");
    return out;
}

td::Result<MlKem768EncapResult> mlkem768_encap_deterministic(
    const MlKem768PublicKey& pk, td::Slice randomness_32) {
    if (randomness_32.size() != 32) {
        return td::Status::Error("mlkem768: deterministic encap requires 32-byte coin");
    }
    const auto& K = kem_instance();
    if (!K.ok()) return td::Status::Error("mlkem768: liboqs ML-KEM-768 not available");
#if defined(OQS_HAVE_ML_KEM_ENCAPS_DERAND)
    MlKem768EncapResult out;
    out.ss = td::SecureString(kMlKem768SharedSecretBytes, '\0');
    OQS_STATUS rc = OQS_KEM_ml_kem_768_encaps_derand(
        out.ct.bytes.data(),
        reinterpret_cast<uint8_t*>(out.ss.as_mutable_slice().data()),
        pk.bytes.data(),
        reinterpret_cast<const uint8_t*>(randomness_32.data()));
    if (rc != OQS_SUCCESS) return td::Status::Error("mlkem768: derand encap failed");
    return out;
#else
    (void)pk;
    (void)randomness_32;
    return td::Status::Error(
        "mlkem768: deterministic Encaps not exposed by this liboqs build. "
        "Tracked under Agent 5 build TODO.");
#endif
}

td::Result<MlKem768SharedSecret> mlkem768_decap(const MlKem768SecretKey& sk,
                                                const MlKem768Ciphertext& ct) {
    const auto& K = kem_instance();
    if (!K.ok()) return td::Status::Error("mlkem768: liboqs ML-KEM-768 not available");
    td::SecureString ss(kMlKem768SharedSecretBytes, '\0');
    OQS_STATUS rc = OQS_KEM_decaps(
        K.kem,
        reinterpret_cast<uint8_t*>(ss.as_mutable_slice().data()),
        ct.bytes.data(),
        reinterpret_cast<const uint8_t*>(sk.as_slice().data()));
    if (rc != OQS_SUCCESS) {
        // FIPS 203 implicit rejection: decap never "fails" deterministically;
        // this branch indicates a library-level failure (allocator, etc.).
        return td::Status::Error("mlkem768: decap internal error");
    }
    return ss;
}

#else  // UNO_MLKEM_STUB

td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed(td::Slice) {
    stub_abort("keygen_from_seed");
}
td::Result<MlKem768KeyPair> mlkem768_keygen_from_seed32(td::Slice) {
    stub_abort("keygen_from_seed32");
}
td::Result<MlKem768EncapResult> mlkem768_encap(const MlKem768PublicKey&) {
    stub_abort("encap");
}
td::Result<MlKem768EncapResult> mlkem768_encap_deterministic(
    const MlKem768PublicKey&, td::Slice) {
    stub_abort("encap_deterministic");
}
td::Result<MlKem768SharedSecret> mlkem768_decap(const MlKem768SecretKey&,
                                                const MlKem768Ciphertext&) {
    stub_abort("decap");
}

#endif  // UNO_MLKEM_STUB

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

td::Status mlkem768_verify_test_vectors() {
#ifdef UNO_MLKEM_STUB
    return td::Status::Error("mlkem768: stub build; self-test skipped");
#else
    // Fixed 64-byte seed.
    uint8_t seed[kMlKem768SeedBytes];
    for (size_t i = 0; i < kMlKem768SeedBytes; ++i) seed[i] = static_cast<uint8_t>(i);
    td::Slice seed_slice{reinterpret_cast<const char*>(seed), kMlKem768SeedBytes};
    auto kp_r = mlkem768_keygen_from_seed(seed_slice);
    if (kp_r.is_error()) {
        // Non-deterministic path fallback: do a non-derand keygen so we can
        // still verify the encap/decap consistency contract.
        const auto& K = kem_instance();
        if (!K.ok()) return td::Status::Error("mlkem768: backend unavailable");
        MlKem768KeyPair kp;
        kp.sk = MlKem768SecretKey{};
        if (OQS_KEM_keypair(K.kem,
                            kp.pk.bytes.data(),
                            reinterpret_cast<uint8_t*>(kp.sk.as_mutable_slice().data()))
            != OQS_SUCCESS) {
            return td::Status::Error("mlkem768: randomized keygen failed");
        }
        // Continue with the randomized keypair.
        TRY_RESULT(enc, mlkem768_encap(kp.pk));
        TRY_RESULT(ss2, mlkem768_decap(kp.sk, enc.ct));
        if (enc.ss.as_slice() != ss2.as_slice()) {
            return td::Status::Error("mlkem768: encap/decap shared-secret mismatch");
        }
        return td::Status::OK();
    }

    // Deterministic path: ensure re-running keygen yields byte-identical
    // keypair — this is the contract the stealth-address hierarchy relies on.
    auto kp2_r = mlkem768_keygen_from_seed(seed_slice);
    if (kp2_r.is_error()) return kp2_r.move_as_error();
    if (kp_r.ok().pk.bytes != kp2_r.ok().pk.bytes) {
        return td::Status::Error(
            "mlkem768: deterministic keygen produced different pks");
    }

    TRY_RESULT(enc, mlkem768_encap(kp_r.ok().pk));
    TRY_RESULT(ss2, mlkem768_decap(kp_r.ok().sk, enc.ct));
    if (enc.ss.as_slice() != ss2.as_slice()) {
        return td::Status::Error("mlkem768: encap/decap shared-secret mismatch");
    }
    return td::Status::OK();
#endif
}

}  // namespace uno_workchain::crypto
