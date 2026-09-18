#pragma once
#include "native-finality.h"

namespace tos::auth {
// Local crash-recovery record. It is not a wire object and carries no authority
// by itself: restart still has to recover the exact original block bytes and
// resulting state before ManagerFinalizedHeadSource can publish the head.
Result<Bytes> encode_manager_finality_journal(
    const ChainContext&, const NativeFinalityVerification&);
Result<NativeFinalityVerification> decode_manager_finality_journal(
    std::span<const std::uint8_t>, const ChainContext&);
}  // namespace tos::auth
