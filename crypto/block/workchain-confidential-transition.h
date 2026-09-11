#pragma once

#include "block/workchain-confidential-state.h"
#include "block/workchain-execution-errors.h"
#include <limits>

namespace block {

struct WorkchainConfidentialNextCounters {
  std::uint64_t auth_nonce;
  std::uint64_t available_revision;
};

// No writes occur here. A completed transition publishes these two counters
// together with its new available and pending records, never separately.
inline td::Result<WorkchainConfidentialNextCounters> next_workchain_confidential_counters(
    const WorkchainConfidentialAccount& authenticated_account,
    std::uint64_t consumed_nonce, std::uint64_t expected_revision) {
  if (consumed_nonce != authenticated_account.auth_nonce ||
      expected_revision != authenticated_account.available_revision) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                            "confidential nonce or available revision mismatch");
  }
  if (consumed_nonce == std::numeric_limits<std::uint64_t>::max() ||
      expected_revision == std::numeric_limits<std::uint64_t>::max()) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                            "confidential nonce or available revision exhausted");
  }
  return WorkchainConfidentialNextCounters{consumed_nonce + 1, expected_revision + 1};
}

// This consumes an already acquired authenticated account, not a missing-state
// sentinel. Capacity is uniquely determined by that state and the authenticated
// policy, so exhaustion makes a candidate invalid. Failure to acquire the state
// belongs to LocalUnavailable at the acquisition boundary, not this predicate.
// This check must run on the same immutable snapshot used to prepare the pending
// insertion. It does not reserve a slot or authorize a separately committed write.
inline td::Status check_workchain_pending_capacity(
    const WorkchainConfidentialAccount& authenticated_target,
    std::uint64_t authenticated_capacity) {
  if (authenticated_capacity == 0 || authenticated_capacity > 16) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                            "unsupported authenticated pending capacity");
  }
  if (authenticated_target.pending.size() >= authenticated_capacity) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                            "target confidential pending capacity exhausted");
  }
  return td::Status::OK();
}

}  // namespace block
