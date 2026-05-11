/*
    JVM Workchain — production crypto host adapter.

    Maps the AvataCryptoHost callbacks onto:
      - libsodium  : SHA-256, Ed25519 verify
      - secp256k1  : ECDSA recover + verify (Bitcoin Core fork in
                     third-party/secp256k1)
      - blst       : BLS12-381 verify (Supranational blst in
                     third-party/blst)

    The host is intentionally narrow: no signing primitives, no key
    derivation, no batched verify.  Adding capabilities is a new ABI
    revision (see jvm/avata/include/avata/crypto.h).
*/
#include "jvm/core/crypto-host.h"

#include <atomic>
#include <cstring>
#include <mutex>

#include "sodium/crypto_hash_sha256.h"
#include "sodium/crypto_sign.h"

extern "C" {
#include "secp256k1.h"
#include "secp256k1_recovery.h"

#include "blst.h"
}

namespace jvm_workchain {

namespace {

// One process-wide verification context; created on first use.  The
// secp256k1 verification context carries no secret state, only
// precomputed tables, so sharing it across threads (read-only) is the
// documented usage.
struct Secp256k1ContextHolder {
    std::once_flag init;
    secp256k1_context* ctx{nullptr};

    secp256k1_context* get() {
        std::call_once(init, [this] {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        });
        return ctx;
    }
};

Secp256k1ContextHolder& secp_holder() {
    static Secp256k1ContextHolder holder;
    return holder;
}

// IETF BLS signature draft v5 / Ethereum 2.0 ciphersuite for min-pk:
// signatures live in G2, public keys in G1.
constexpr const char kBlsSignatureDst[]
    = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
constexpr std::size_t kBlsSignatureDstLen = sizeof(kBlsSignatureDst) - 1;

int sha256_callback(void* /*user*/,
                    const unsigned char* data,
                    std::size_t length,
                    unsigned char* out) {
    if (out == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    if (length != 0 && data == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    static const unsigned char kEmpty[1] = {0};
    int rc = crypto_hash_sha256(out, length == 0 ? kEmpty : data, length);
    return rc == 0 ? AVATA_CRYPTO_OK : AVATA_CRYPTO_ERROR;
}

int secp256k1_recover_callback(void* /*user*/,
                               const unsigned char* digest,
                               const unsigned char* signature_65,
                               unsigned char* out_pubkey_65) {
    if (digest == nullptr || signature_65 == nullptr
        || out_pubkey_65 == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    secp256k1_context* ctx = secp_holder().get();
    if (ctx == nullptr) {
        return AVATA_CRYPTO_ERROR;
    }
    // signature_65 layout: r(32) || s(32) || v(1).  v normalized to {0,1}.
    int recid = static_cast<int>(signature_65[64]);
    if (recid == 27 || recid == 28) {
        recid -= 27;
    }
    if (recid < 0 || recid > 3) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    secp256k1_ecdsa_recoverable_signature rsig{};
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &rsig, signature_65, recid)) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    secp256k1_pubkey pubkey{};
    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, digest)) {
        return AVATA_CRYPTO_VERIFICATION_FAILED;
    }
    std::size_t out_len = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, out_pubkey_65, &out_len, &pubkey,
                                       SECP256K1_EC_UNCOMPRESSED)
        || out_len != 65) {
        return AVATA_CRYPTO_ERROR;
    }
    return AVATA_CRYPTO_OK;
}

int secp256k1_verify_callback(void* /*user*/,
                              const unsigned char* pubkey,
                              std::size_t pubkey_length,
                              const unsigned char* digest,
                              const unsigned char* signature_64) {
    if (pubkey == nullptr || digest == nullptr || signature_64 == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    if (pubkey_length != 33 && pubkey_length != 65) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    secp256k1_context* ctx = secp_holder().get();
    if (ctx == nullptr) {
        return AVATA_CRYPTO_ERROR;
    }
    secp256k1_pubkey parsed_pubkey{};
    if (!secp256k1_ec_pubkey_parse(ctx, &parsed_pubkey, pubkey,
                                   pubkey_length)) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    secp256k1_ecdsa_signature sig{};
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature_64)) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    // Normalize to low-S form to make verification deterministic against
    // malleated signatures.  Libsecp256k1 verify itself accepts both forms
    // by default; enforcing low-S here matches Bitcoin Core / EIP-2.
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    int rc = secp256k1_ecdsa_verify(ctx, &sig, digest, &parsed_pubkey);
    return rc == 1 ? AVATA_CRYPTO_OK : AVATA_CRYPTO_VERIFICATION_FAILED;
}

int ed25519_verify_callback(void* /*user*/,
                            const unsigned char* pubkey_32,
                            const unsigned char* message,
                            std::size_t message_length,
                            const unsigned char* signature_64) {
    if (pubkey_32 == nullptr || signature_64 == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    if (message_length != 0 && message == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    static const unsigned char kEmpty[1] = {0};
    int rc = crypto_sign_verify_detached(
        signature_64,
        message_length == 0 ? kEmpty : message,
        message_length,
        pubkey_32);
    return rc == 0 ? AVATA_CRYPTO_OK : AVATA_CRYPTO_VERIFICATION_FAILED;
}

int bls12381_verify_callback(void* /*user*/,
                             const unsigned char* pubkey_g1_48,
                             const unsigned char* message,
                             std::size_t message_length,
                             const unsigned char* signature_g2_96) {
    if (pubkey_g1_48 == nullptr || signature_g2_96 == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    if (message_length != 0 && message == nullptr) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    blst_p1_affine pk{};
    if (blst_p1_uncompress(&pk, pubkey_g1_48) != BLST_SUCCESS) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    blst_p2_affine sig{};
    if (blst_p2_uncompress(&sig, signature_g2_96) != BLST_SUCCESS) {
        return AVATA_CRYPTO_INVALID_INPUT;
    }
    static const unsigned char kEmpty[1] = {0};
    BLST_ERROR err = blst_core_verify_pk_in_g1(
        &pk,
        &sig,
        /*hash_or_encode=*/true,
        message_length == 0 ? kEmpty : message,
        message_length,
        reinterpret_cast<const unsigned char*>(kBlsSignatureDst),
        kBlsSignatureDstLen,
        /*aug=*/nullptr,
        /*aug_len=*/0);
    return err == BLST_SUCCESS ? AVATA_CRYPTO_OK
                               : AVATA_CRYPTO_VERIFICATION_FAILED;
}

}  // namespace

AvataCryptoHost make_production_crypto_host() {
    AvataCryptoHost host{};
    host.user = nullptr;
    host.sha256 = sha256_callback;
    host.secp256k1_recover = secp256k1_recover_callback;
    host.secp256k1_verify = secp256k1_verify_callback;
    host.ed25519_verify = ed25519_verify_callback;
    host.bls12381_verify = bls12381_verify_callback;
    return host;
}

}  // namespace jvm_workchain
