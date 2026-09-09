#pragma once

#include "block/workchain-execution-dispatch.h"
#include "td/utils/overloaded.h"

namespace tos::validator {

// Classifies only the legacy AccountCompute configuration. This does not select
// an execution path, bind an adapter, or authorize account-batch execution.
inline td::Result<bool> collator_uses_custom_account_compute(
    const block::ResolvedScopedWorkchainExecution& execution) {
  // Exhaustiveness remains a compile-time obligation for every execution family.
  return std::visit(td::overloaded(
      [](const block::ResolvedWorkchainExecution& account) -> td::Result<bool> {
        return block::resolved_workchain_execution_is_custom(account);
      },
      [](const block::ResolvedWorkchainBlockExecution&) -> td::Result<bool> { return false; },
      [](const block::ResolvedWorkchainAccountBinding&) -> td::Result<bool> {
        // Batch execution must not inherit the per-account custom-compute mode.
        // Its retained adapter and later execution refusal are independent.
        return false;
      }), execution);
}

}  // namespace tos::validator
