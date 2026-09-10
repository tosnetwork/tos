#pragma once

#include <functional>
#include <limits>
#include <set>
#include "vm/cells/Cell.h"

namespace block {
enum class WorkchainReadPhaseReason { Complete, CallbackFailure, InvalidContext, OutsideFootprint, ReadException };
struct WorkchainReadPhaseResult {
  WorkchainReadPhaseReason reason;
  td::Status callback_status;
  std::uint64_t attempts;
};

// Synchronous lifetime boundary only. The owner retains the original usage
// tree; this function never wraps a cell, replaces a proof callback, or caches a
// load. No observer escapes into an actor continuation. The borrowed footprint
// must be the completed admission meter's set, not an engine-supplied claim.
inline WorkchainReadPhaseResult run_workchain_read_phase(
    const vm::CellUsageTree::NodePtr& node, const std::set<vm::CellHash>& admitted,
    const std::function<td::Status()>& body) {
  if (node.empty() || !body) {
    return {WorkchainReadPhaseReason::InvalidContext, td::Status::OK(), 0};
  }
  struct Outside {};
  bool forbidden = false;
  std::uint64_t attempts = 0;
  auto status = td::Status::OK();
  bool exception = false;
  {
    vm::CellUsageTree::ScopedReadObserver observer(node, [&](const vm::Cell& cell) {
      // Defensive counter overflow, not the phase's resource limit: admission
      // bounds execution work long before this value is reachable.
      if (attempts == std::numeric_limits<std::uint64_t>::max()) {
        forbidden = true;
        throw Outside{};
      }
      ++attempts;  // Count forbidden attempts too, before preventing their load.
      if (!cell.get_tree_node().empty() || !admitted.count(cell.get_hash())) {
        forbidden = true;
        throw Outside{};
      }
    });
    try {
      status = body();
    } catch (const Outside&) {
      // The sticky flag also survives a callback which catches this exception.
    } catch (...) {
      // This is a local observation result, NOT a candidate validity verdict.
      // Semantic callback failures must return their typed Status unchanged.
      exception = true;
    }
  }  // Observer is removed before returning or exposing any result.
  if (forbidden) return {WorkchainReadPhaseReason::OutsideFootprint, std::move(status), attempts};
  if (exception) return {WorkchainReadPhaseReason::ReadException, std::move(status), attempts};
  if (status.is_error()) return {WorkchainReadPhaseReason::CallbackFailure, std::move(status), attempts};
  return {WorkchainReadPhaseReason::Complete, std::move(status), attempts};
}
}  // namespace block
