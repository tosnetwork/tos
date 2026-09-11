#pragma once

#include "block/workchain-execution-dispatch.h"

namespace tos::validator {
// The actual AccountBinding decisions used by ValidateQuery's two visitors.
// Keeping these callable lets the default regression exercise both refusals
// without bypassing the earlier registry gate to manufacture actor reachability.
td::Result<bool> validator_account_binding_custom(const block::ResolvedWorkchainAccountBinding& binding);
td::Status validator_account_binding_ready(const block::ResolvedWorkchainAccountBinding& binding);
}  // namespace tos::validator
