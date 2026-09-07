#include "uno_crypto.h"
#include <cstdio>
#include <memory>

// Deliberately violate the caller allocation contract. This is an instrument
// canary, not an assertion that arbitrary invalid pointers are recoverable.
int main() {
  auto point = std::make_unique<uint8_t[]>(32);
  uint8_t commitments[8][32]{}, responses[6][32]{}, proof[864]{}, context[1]{1};
  UnoCryptoVerifyRequest request{
    UNO_CRYPTO_ABI_VERSION, UNO_RELATION_SEND, {1, 1, 8, 1, sizeof(proof)},
    context, 1, reinterpret_cast<const uint8_t(*)[32]>(point.get()), 10,
    nullptr, 0, commitments, 8, responses, 6, proof, sizeof(proof)
  };
  const auto status = uno_crypto_verify_v1(&request);
  std::fprintf(stderr, "CANARY_NOT_DETECTED: invalid allocation reached status %u\n", status);
  return 2;
}
