#ifndef UNO_CRYPTO_PROTOTYPE_H
#define UNO_CRYPTO_PROTOTYPE_H

/* Generated from Rust ABI declarations. Do not edit; see ABI.md. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define UNO_CRYPTO_ABI_VERSION 0

#define UNO_CRYPTO_FIXED_PROFILE 1

#define UNO_TRANSFER 0

#define UNO_UNSHIELD 1

#define UNO_SHIELD_CLAIM 2

#define UNO_WITHDRAWAL_REFUND 3

#define UNO_GENESIS 4

#define UNO_PRIVATE_FEE_DISTRIBUTION 5

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
  uint8_t cv_net[32];
  uint8_t nullifier[32];
  uint8_t rk[32];
  uint8_t cmx[32];
  uint8_t epk[32];
  uint8_t enc_ciphertext[580];
  uint8_t out_ciphertext[80];
  uint8_t spend_signature[64];
} UnoCryptoAction;

typedef struct {
  uint32_t abi_version;
  uint32_t profile;
  uint32_t context;
  uint8_t flags;
  int64_t value_balance;
  uint64_t principal_hi;
  uint64_t principal_lo;
  uint64_t fee_hi;
  uint64_t fee_lo;
  uint8_t anchor[32];
  uint8_t sighash[32];
  uint8_t binding_signature[64];
  const UnoCryptoAction *actions;
  size_t action_count;
  const uint8_t *proof;
  size_t proof_bytes;
  size_t max_actions;
  size_t max_proof_bytes;
} UnoCryptoVerifyRequest;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Verify borrowed public fields without retaining pointers or transferring ownership.
 *
 * # Safety
 * Non-null pointers must refer to initialized, aligned allocations readable for
 * the supplied lengths and must not be mutated or freed until this call returns.
 * Numeric/null checks cannot validate arbitrary pointers. No unwinding panic
 * crosses the ABI; process aborts, OOM and invalid caller memory are not recoverable.
 */
uint32_t uno_crypto_verify_v0(const UnoCryptoVerifyRequest *request);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* UNO_CRYPTO_PROTOTYPE_H */
