#pragma once
#include "block/workchain-confidential-state.h"
#include "block/workchain-execution-errors.h"
#include "uno/crypto/include/uno_crypto.h"
#include <array>

namespace block {
// Populate from host-resolved registration fields, not an opaque caller-supplied
// challenge. Address/configuration matching is registration admission's job;
// success here proves possession only, never the origin/independence of a secret.
td::Status verify_workchain_registration_possession(
    const WorkchainConfidentialAccount& registration,
    const std::array<unsigned char, 64>& proof);

// Reconstruct the zero-balance statement from the current authenticated account.
// Domain comes from authenticated protocol configuration. Pending and in-flight
// obligations are separate host predicates; this proof says nothing about them.
td::Status verify_workchain_closure_possession(
    const WorkchainConfidentialAccount& account,
    const std::array<unsigned char, 80>& domain,
    const std::array<unsigned char, 96>& proof);
}
