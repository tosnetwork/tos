#pragma once
#include "block/workchain-proof-work.h"

namespace block {
// Test-only friend. Production receives its capability from proof admission.
struct WorkchainProofTestAccess {
  static WorkchainProofVerifier create(std::uint64_t units) { return WorkchainProofVerifier(units); }
};
}  // namespace block
