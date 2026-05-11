/* TOS Network - Avata JVM crypto host interface.

   Hash + signature verification primitives needed by java.lang.Crypto.
   Pure-function semantics (input -> deterministic output), but exposed
   through a host-callback ABI to keep the standalone Avata build free of
   secp256k1 / libsodium / blst third-party dependencies.  The consensus
   validator installs a real host in jvm/core/; standalone Avata builds
   leave it null and the JNI side throws a deterministic
   ContractViolationError. */

#ifndef AVATA_CRYPTO_H
#define AVATA_CRYPTO_H

#include <stddef.h>

#if defined(PLATFORM_WINDOWS) || defined(_WIN32)
#define AVATA_CRYPTO_EXPORT __declspec(dllexport)
#else
#define AVATA_CRYPTO_EXPORT \
  __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes returned by all crypto host callbacks. Hosts MUST NOT
   surface internal library-specific error codes; squashing to a small
   enumeration keeps consensus-visible behavior portable across the three
   underlying crypto libraries. */
#define AVATA_CRYPTO_OK 0
#define AVATA_CRYPTO_INVALID_INPUT 1
#define AVATA_CRYPTO_VERIFICATION_FAILED 2
#define AVATA_CRYPTO_ERROR 3

/* Wire-level sizes — all consensus-stable. */
#define AVATA_CRYPTO_SHA256_OUT_SIZE 32
#define AVATA_CRYPTO_DIGEST_SIZE 32
#define AVATA_CRYPTO_SECP256K1_SIGNATURE_SIZE 64
#define AVATA_CRYPTO_SECP256K1_RECOVERABLE_SIG_SIZE 65
#define AVATA_CRYPTO_SECP256K1_COMPRESSED_PUBKEY_SIZE 33
#define AVATA_CRYPTO_SECP256K1_UNCOMPRESSED_PUBKEY_SIZE 65
#define AVATA_CRYPTO_ED25519_PUBKEY_SIZE 32
#define AVATA_CRYPTO_ED25519_SIGNATURE_SIZE 64
#define AVATA_CRYPTO_BLS12_381_PUBKEY_SIZE 48
#define AVATA_CRYPTO_BLS12_381_SIGNATURE_SIZE 96

/* SHA-256.  Writes AVATA_CRYPTO_SHA256_OUT_SIZE bytes to `out`. */
typedef int (*AvataCryptoSha256)(
    void* user,
    const unsigned char* data,
    size_t length,
    unsigned char* out);

/* secp256k1 ECDSA recover.
   signature is 65 bytes: r(32) || s(32) || v(1).  v in {0, 1, 27, 28}.
   Writes the uncompressed public key (65 bytes including 0x04 prefix) to
   `out_pubkey`.  Hosts MUST reject signatures whose s component is in the
   upper half of n (EIP-2 low-S form), so verification + recovery match. */
typedef int (*AvataCryptoSecp256k1Recover)(
    void* user,
    const unsigned char* digest,
    const unsigned char* signature_65,
    unsigned char* out_pubkey_65);

/* secp256k1 ECDSA verify.
   pubkey is either 33-byte compressed or 65-byte uncompressed; the host
   inspects `pubkey_length` to disambiguate.  Signature is 64 bytes
   (r || s) in low-S form. */
typedef int (*AvataCryptoSecp256k1Verify)(
    void* user,
    const unsigned char* pubkey,
    size_t pubkey_length,
    const unsigned char* digest,
    const unsigned char* signature_64);

/* Ed25519 verify (RFC 8032).  pubkey is 32 bytes; signature is 64 bytes;
   message is arbitrary length. */
typedef int (*AvataCryptoEd25519Verify)(
    void* user,
    const unsigned char* pubkey_32,
    const unsigned char* message,
    size_t message_length,
    const unsigned char* signature_64);

/* BLS12-381 verify in the "min-pk" arrangement: pubkey in G1 (48 bytes
   compressed) and signature in G2 (96 bytes compressed). The host MUST
   apply the canonical DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
   (Ethereum 2.0 / IETF draft-irtf-cfrg-bls-signature, v5). */
typedef int (*AvataCryptoBls12381Verify)(
    void* user,
    const unsigned char* pubkey_g1_48,
    const unsigned char* message,
    size_t message_length,
    const unsigned char* signature_g2_96);

typedef struct AvataCryptoHost {
  void* user;
  AvataCryptoSha256 sha256;
  AvataCryptoSecp256k1Recover secp256k1_recover;
  AvataCryptoSecp256k1Verify secp256k1_verify;
  AvataCryptoEd25519Verify ed25519_verify;
  AvataCryptoBls12381Verify bls12381_verify;
} AvataCryptoHost;

/* Install/clear the crypto host. Storage/Event semantics: callbacks are
   pinned for the duration of the next contract invocation; cleared at
   transaction end so a stale pointer cannot leak between calls.

   sha256 MUST always be installed when the host is set, because contract
   code is allowed to call Crypto.sha256() without auth.  Signature
   verifiers may be nullable (a host that does not implement BLS leaves
   bls12381_verify==null; JNI sees that and trips a deterministic trap). */
AVATA_CRYPTO_EXPORT void avata_set_crypto_host(const AvataCryptoHost* host);
AVATA_CRYPTO_EXPORT void avata_clear_crypto_host(void);
AVATA_CRYPTO_EXPORT int avata_has_crypto_host(void);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_CRYPTO_H
