#ifndef UNO_CRYPTO_PROTOTYPE_H
#define UNO_CRYPTO_PROTOTYPE_H

/* Generated from Rust ABI declarations. Do not edit; see ABI.md. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define UNO_CRYPTO_ABI_VERSION 1

#define UNO_BALANCE_ABI_VERSION 2

#define UNO_RELATION_SEND 1

#define UNO_RELATION_COLLECT 2

enum UnoCryptoStatus
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  UNO_CRYPTO_OK = 0,
  UNO_CRYPTO_ARGUMENTS = 1,
  UNO_CRYPTO_DECODE = 2,
  UNO_CRYPTO_VERIFY = 3,
  UNO_CRYPTO_KEY = 4,
  UNO_CRYPTO_PANIC = 5,
};
#ifndef __cplusplus
typedef uint32_t UnoCryptoStatus;
#endif // __cplusplus

/**
 * Public registration context, not native struct bytes in the transcript.
 * The host independently matches these fields to the address and configuration.
 */
typedef struct {
  uint32_t abi_version;
  int32_t global_id;
  uint8_t genesis_hash[32];
  int32_t workchain_id;
  uint8_t account[32];
  uint8_t incarnation[32];
  uint8_t asset[32];
  uint8_t custody[32];
  uint8_t policy[32];
  uint16_t schema_version;
  uint16_t relation_profile;
  uint16_t proof_profile;
  uint32_t key_epoch;
  uint8_t public_key[32];
  uint8_t proof[64];
} UnoCryptoKeyPossessionRequestV1;

/**
 * Fixed-width encoded public inputs. Numeric policy and domain provenance
 * must be resolved by the host; ABI version is not a network activation gate.
 */
typedef struct {
  uint32_t abi_version;
  uint8_t domain[80];
  uint8_t deposit_id[32];
  uint8_t recipient[32];
  uint64_t amount;
} UnoCryptoSystemEncryptionRequest;

typedef struct {
  uint8_t commitment[32];
  uint8_t handle[32];
} UnoCryptoSystemCiphertext;

typedef struct {
  uint64_t max_balance;
  uint64_t max_value;
  size_t max_collect;
  size_t max_context_bytes;
  size_t max_proof_bytes;
} UnoCryptoLimits;

typedef struct {
  uint32_t abi_version;
  uint32_t relation;
  UnoCryptoLimits limits;
  uint8_t domain[80];
  uint64_t fee;
  const uint8_t *context;
  size_t context_bytes;
  const uint8_t (*points)[32];
  size_t point_count;
  const uint8_t (*receipt_ids)[32];
  size_t receipt_count;
  const uint8_t (*commitments)[32];
  size_t commitment_count;
  const uint8_t (*responses)[32];
  size_t response_count;
  const uint8_t *proof;
  size_t proof_bytes;
} UnoCryptoVerifyRequestV2;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Verify registration possession, not a new balance relation.
 *
 * # Safety
 * Request must be initialized, aligned, readable and unchanged until return.
 * No pointer is retained. Span checks cannot establish allocation validity.
 */
uint32_t uno_crypto_verify_key_possession_v1(const UnoCryptoKeyPossessionRequestV1 *request);

/**
 * Construct a public system ciphertext. Output is untouched unless successful.
 *
 * # Safety
 * Request must be initialized and readable; output must be aligned, writable
 * and disjoint from request for the entire call. No pointer is retained.
 * Numeric span checks do not prove allocation validity. Pending-only use and
 * deposit authentication are host obligations, not implied by success.
 */
uint32_t uno_crypto_system_encrypt_v1(const UnoCryptoSystemEncryptionRequest *request,
                                      UnoCryptoSystemCiphertext *output);

/**
 * Reconstruct and compare both canonical ciphertext components without writes.
 *
 * # Safety
 * Non-null arguments must be initialized, aligned and readable for the call.
 * This call does not authorize issuance, bind an account or consume a message.
 */
uint32_t uno_crypto_system_verify_v1(const UnoCryptoSystemEncryptionRequest *request,
                                     const UnoCryptoSystemCiphertext *supplied);

/**
 * Verify borrowed fields without retaining pointers or transferring ownership.
 * No result authorizes a state change or authenticates the context's provenance.
 *
 * # Safety
 * Non-null nonempty pointers must refer to initialized, aligned, readable
 * allocations of the supplied lengths, unchanged until return. Numeric checks
 * cannot validate arbitrary allocations. Unwinding panics are contained;
 * process abort, allocator OOM abort and invalid caller memory are not recoverable.
 */
uint32_t uno_crypto_verify_v2(const UnoCryptoVerifyRequestV2 *request);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* UNO_CRYPTO_PROTOTYPE_H */
