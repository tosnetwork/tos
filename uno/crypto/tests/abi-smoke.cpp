#include "uno_crypto.h"
#include <cstddef>
#include <cstdint>

static_assert(sizeof(UnoCryptoAction) == 884);
#if INTPTR_MAX == INT64_MAX
static_assert(sizeof(UnoCryptoVerifyRequest) == 232);
static_assert(offsetof(UnoCryptoVerifyRequest, value_balance) == 16);
static_assert(offsetof(UnoCryptoVerifyRequest, actions) == 184);
#endif

int main() {
  if (uno_crypto_verify_v0(nullptr) != UNO_CRYPTO_ARGUMENTS) return 1;
  UnoCryptoAction action{};
  uint8_t proof[4992]{};
  UnoCryptoVerifyRequest request{};
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.context = UNO_TRANSFER;
  request.flags = 3;
  request.actions = &action;
  request.action_count = 1;
  request.proof = proof;
  request.proof_bytes = sizeof(proof);
  request.max_actions = 1;
  request.max_proof_bytes = sizeof(proof);
  // Correct ABI shape reaches decoding; these zero point fields are not valid.
  if (uno_crypto_verify_v0(&request) != UNO_CRYPTO_DECODE) return 2;
  request.abi_version = 1;
  if (uno_crypto_verify_v0(&request) != UNO_CRYPTO_ARGUMENTS) return 3;
  return 0;
}
