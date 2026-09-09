#pragma once

#include "td/utils/Status.h"
#include "block/workchain-execution-errors.h"

namespace uno_workchain {

// Dedicated codes survive Result/TRY_RESULT propagation through state assembly.
// Unknown errors are never evidence against a candidate. Authentication is a
// caller obligation; a hash or a successful decode alone does not establish it.
enum class TreeFailure : int {
  CandidateInvalid = static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid),
  AuthenticatedStateCorrupt = static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt),
  LocalFailure = static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable),
};

inline td::Status tree_error(TreeFailure kind, td::Slice message) {
  return td::Status::Error(static_cast<int>(kind), message);
}

// Call only on an error, not a successful Status.
inline TreeFailure tree_failure(const td::Status& error) {
  switch (error.code()) {
    case static_cast<int>(TreeFailure::CandidateInvalid): return TreeFailure::CandidateInvalid;
    case static_cast<int>(TreeFailure::AuthenticatedStateCorrupt): return TreeFailure::AuthenticatedStateCorrupt;
    default: return TreeFailure::LocalFailure;
  }
}

}  // namespace uno_workchain
