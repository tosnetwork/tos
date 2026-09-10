#pragma once
#include "block/workchain-execution-dispatch.h"
#include "td/utils/overloaded.h"

// PREPARED, NOT CONNECTED. Test-only executable specification for the two
// local validator decisions. No production target includes this file. No
// candidate content, admission verdict or batch execution is supplied here.
// Moving either production refusal requires a separate gate decision.
namespace prepared_validator {
using Resolution = td::Result<std::optional<block::ResolvedScopedWorkchainExecution>>;

inline td::Result<bool> custom(Resolution resolution) {
  // Authenticated predecessor configuration resolution is local provenance.
  if (resolution.is_error()) return resolution.move_as_error();
  if (!resolution.ok()) return false;
  return std::visit(td::overloaded(
      [](const block::ResolvedWorkchainExecution& account) -> td::Result<bool> {
        return block::resolved_workchain_execution_is_custom(account);
      },
      [](const block::ResolvedWorkchainBlockExecution&) -> td::Result<bool> { return false; },
      [](const block::ResolvedWorkchainAccountBinding&) -> td::Result<bool> {
        // This flag configures legacy per-account run_compute; batch execution
        // must not acquire that legacy context merely because it is non-TVM.
        return false;
      }), *resolution.ok());
}

inline td::Status ready(Resolution resolution) {
  // Resolution success is a local binding fact, not proof of replay capability.
  // The actual registry readiness gate and both actual visitors remain closed.
  if (resolution.is_error()) return resolution.move_as_error();
  if (!resolution.ok()) return td::Status::OK();
  return std::visit(td::overloaded(
      [](const block::ResolvedWorkchainExecution&) { return td::Status::OK(); },
      [](const block::ResolvedWorkchainBlockExecution&) { return td::Status::OK(); },
      [](const block::ResolvedWorkchainAccountBinding&) {
        return td::Status::OK();
      }), *resolution.ok());
}
}  // namespace prepared_validator
