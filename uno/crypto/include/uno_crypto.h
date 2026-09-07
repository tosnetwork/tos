#ifndef UNO_CRYPTO_PROTOTYPE_H
#define UNO_CRYPTO_PROTOTYPE_H

/* Generated from Rust ABI declarations. Do not edit; see ABI.md. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define UNO_CRYPTO_ABI_VERSION 1

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
} UnoCryptoVerifyRequest;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

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
uint32_t uno_crypto_verify_v1(const UnoCryptoVerifyRequest *request);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* UNO_CRYPTO_PROTOTYPE_H */
