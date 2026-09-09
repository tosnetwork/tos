#pragma once

#include "vm/cells/CellHash.h"
#include <memory>
#include <new>
#include <set>
#include <cstdint>

namespace block {

// Host attempt identities, not candidate validity or wire error codes. A
// duplicate is a host execution-contract failure; allocation failure is local.
// Exceeding the authenticated root bound is a distinct candidate-bound outcome,
// to be classified CandidateInvalid (reject), never allocator/local failure.
// Live classification remains unwired.
enum class WorkchainExecutionClaim { Recorded, DuplicateInput, BoundExceeded, AllocationFailure };

template <class Allocator = std::allocator<vm::CellHash>>
class BasicWorkchainExecutionLedger {
 public:
  explicit BasicWorkchainExecutionLedger(std::uint64_t authenticated_root_limit,
                                        const Allocator& allocator = Allocator{})
      : authenticated_root_limit_(authenticated_root_limit), roots_(allocator) {}
  BasicWorkchainExecutionLedger(const BasicWorkchainExecutionLedger&) = delete;
  BasicWorkchainExecutionLedger& operator=(const BasicWorkchainExecutionLedger&) = delete;
  BasicWorkchainExecutionLedger(BasicWorkchainExecutionLedger&&) = delete;
  BasicWorkchainExecutionLedger& operator=(BasicWorkchainExecutionLedger&&) = delete;

  // Call immediately before stateful execution with ProofAdmittedBatchInput's
  // root()->get_hash(), never an account address or a batch identity. There is
  // no erase/refund: a failed execution attempt remains recorded in this scope.
  // Construction fixes the candidate-scope bound; attempts cannot change it.
  // Mechanism tests supply synthetic bounds;
  // accepting this integer does not establish its authenticated provenance.
  WorkchainExecutionClaim record_attempt(const vm::CellHash& admitted_input_root_hash) {
    if (contains(admitted_input_root_hash)) {
      return WorkchainExecutionClaim::DuplicateInput;
    }
    // Lookup does not allocate. Check capacity before attempting node insertion;
    // even a genuinely failing allocator must not mask a candidate bound error.
    if (roots_.size() >= authenticated_root_limit_) {
      return WorkchainExecutionClaim::BoundExceeded;
    }
    try {
      const auto inserted = roots_.insert(admitted_input_root_hash).second;
      return inserted ? WorkchainExecutionClaim::Recorded : WorkchainExecutionClaim::DuplicateInput;
    } catch (const std::bad_alloc&) {
      // Supported allocators report allocation exhaustion with bad_alloc.
      // Other allocator exceptions are contract faults and propagate; they are
      // deliberately not translated into a resource-exhaustion outcome.
      // std::set insertion has no effect on allocation failure. No execution
      // permission is returned if the attempt could not be recorded.
      return WorkchainExecutionClaim::AllocationFailure;
    }
  }
  bool contains(const vm::CellHash& hash) const { return roots_.find(hash) != roots_.end(); }
  std::size_t size() const { return roots_.size(); }

 private:
  // One node per distinct admitted root, O(log U) lookup and O(U) auxiliary
  // storage, U <= the explicitly supplied authenticated bound. Live integration
  // must bind construction to authenticated admission; there is no default.
  const std::uint64_t authenticated_root_limit_;
  std::set<vm::CellHash, std::less<vm::CellHash>, Allocator> roots_;
};

using WorkchainExecutionLedger = BasicWorkchainExecutionLedger<>;

}  // namespace block
