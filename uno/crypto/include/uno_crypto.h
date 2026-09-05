#ifndef UNO_CRYPTO_PROTOTYPE_H
#define UNO_CRYPTO_PROTOTYPE_H
#include <stddef.h>
#include <stdint.h>

/* Prototype ABI tags only. They do not define chain wire or activation values. */
#define UNO_CRYPTO_ABI_VERSION 0
#define UNO_CRYPTO_FIXED_PROFILE 1
enum UnoCryptoContext { UNO_TRANSFER = 0, UNO_UNSHIELD = 1, UNO_SHIELD_CLAIM = 2,
  UNO_WITHDRAWAL_REFUND = 3, UNO_GENESIS = 4, UNO_PRIVATE_FEE_DISTRIBUTION = 5 };
enum UnoCryptoStatus { UNO_CRYPTO_OK = 0, UNO_CRYPTO_ARGUMENTS = 1, UNO_CRYPTO_DECODE = 2,
  UNO_CRYPTO_VERIFY = 3, UNO_CRYPTO_KEY = 4, UNO_CRYPTO_PANIC = 5 };

typedef struct UnoCryptoAction {
  uint8_t cv_net[32], nullifier[32], rk[32], cmx[32], epk[32];
  uint8_t enc_ciphertext[580], out_ciphertext[80], spend_signature[64];
} UnoCryptoAction;

typedef struct UnoCryptoVerifyRequest {
  uint32_t abi_version, profile, context;
  uint8_t flags;
  int64_t value_balance;
  uint64_t principal_hi, principal_lo, fee_hi, fee_lo;
  uint8_t anchor[32], sighash[32], binding_signature[64];
  const UnoCryptoAction *actions;
  size_t action_count;
  const uint8_t *proof;
  size_t proof_bytes, max_actions, max_proof_bytes;
} UnoCryptoVerifyRequest;

#ifdef __cplusplus
extern "C" {
#endif
/* Read-only borrowed input; all allocations must remain valid and immutable for
 * the call. Success checks cryptography/context, not issuance or receipt authority.
 * Caller must supply authenticated limits, context and the committed TOS digest.
 * No pointers are retained and no allocator ownership crosses the ABI. */
uint32_t uno_crypto_verify_v0(const UnoCryptoVerifyRequest *request);
#ifdef __cplusplus
}
#endif
#endif
