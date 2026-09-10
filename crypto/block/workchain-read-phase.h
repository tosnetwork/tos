#pragma once

#include <functional>
#include <exception>
#include <cstdint>
#include <new>
#include <limits>
#include <set>
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellUsageTree.h"
#include "vm/excno.hpp"

namespace block {
enum class WorkchainReadPhaseReason { Complete, CallbackFailure, InvalidContext, OutsideFootprint, ReadException };
// Failure nature only, not a candidate/local verdict. The caller must combine
// this with the acquisition and ownership of the operation that threw. In
// particular, VmError does not establish whose bytes a parser was reading.
enum class WorkchainReadExceptionKind {
  None, VirtualizedContent, VmError, VmNoGas, VmFatal, CellCreate, CellWrite, Allocation, Other
};
struct WorkchainReadPhaseResult {
  // Dispatch on reason first. Only ReadException authorizes classification by
  // exception_kind; an OutsideFootprint result may retain a secondary exception
  // produced by a callback intercepting the footprint refusal.
  WorkchainReadPhaseReason reason;
  td::Status callback_status;
  std::uint64_t attempts;
  WorkchainReadExceptionKind exception_kind = WorkchainReadExceptionKind::None;
  // Consume within the owner's synchronous scope: an arbitrary exception can
  // retain borrowed objects. This is not an actor-continuation transport.
  std::exception_ptr exception;
};

// Synchronous lifetime boundary only. The owner retains the original usage
// tree; this function never wraps a cell, replaces a proof callback, or caches a
// load. No observer escapes into an actor continuation. The borrowed footprint
// must be the completed admission meter's set, not an engine-supplied claim.
// The caller must exclusively drive this single-threaded tree during body().
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
  // Reserve the diagnostic before body/observer activity. Capturing bad_alloc
  // must not allocate another Status while handling the original failure.
  auto thrown_status = td::Status::Error("read phase callback threw; inspect exception_kind and exception");
  bool exception = false;
  auto kind = WorkchainReadExceptionKind::None;
  std::exception_ptr captured;
  auto capture = [&](WorkchainReadExceptionKind observed) {
    exception = true;
    kind = observed;
    captured = std::current_exception();
    // Preserve the original exception (including VM details) separately. This
    // message is not an error-classification interface or a numeric code map.
    status = std::move(thrown_status);
  };
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
    } catch (const vm::VmVirtError&) {
      capture(WorkchainReadExceptionKind::VirtualizedContent);
    } catch (const vm::VmError&) {
      capture(WorkchainReadExceptionKind::VmError);
    } catch (const vm::VmNoGas&) {
      capture(WorkchainReadExceptionKind::VmNoGas);
    } catch (const vm::VmFatal&) {
      capture(WorkchainReadExceptionKind::VmFatal);
    } catch (const vm::CellBuilder::CellCreateError&) {
      capture(WorkchainReadExceptionKind::CellCreate);
    } catch (const vm::CellBuilder::CellWriteError&) {
      capture(WorkchainReadExceptionKind::CellWrite);
    } catch (const std::bad_alloc&) {
      capture(WorkchainReadExceptionKind::Allocation);
    } catch (...) {
      // Unknown nature is explicit, never silently mapped to a known class.
      capture(WorkchainReadExceptionKind::Other);
    }
  }  // Observer is removed before returning or exposing any result.
  if (forbidden) return {WorkchainReadPhaseReason::OutsideFootprint, std::move(status), attempts, kind, captured};
  if (exception) return {WorkchainReadPhaseReason::ReadException, std::move(status), attempts, kind, captured};
  if (status.is_error()) return {WorkchainReadPhaseReason::CallbackFailure, std::move(status), attempts};
  return {WorkchainReadPhaseReason::Complete, std::move(status), attempts};
}
}  // namespace block
