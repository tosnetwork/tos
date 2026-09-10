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
}
