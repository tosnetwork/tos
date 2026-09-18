#pragma once
#include "crypto/block/signature-set.h"
#include "crypto/block/validator-set.h"
#include "native-finality.h"

namespace tos::auth {
// Build the receipt from the same native signature-set verifier the manager
// already trusts. The next set is tried first, exactly as the manager does for
// a finality broadcast, then the current set. A receipt exists only when the
// final signature set verifies against one complete native ValidatorSet.
Result<NativeFinalityVerification> verify_manager_finality_receipt(
    const tos::BlockIdExt&, const td::Ref<block::BlockSignatureSet>&,
    const td::Ref<block::ValidatorSet>& next,
    const td::Ref<block::ValidatorSet>& current);
}  // namespace tos::auth
