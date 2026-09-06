#pragma once

#include "td/utils/Status.h"

namespace block {

// Local control-flow categories, never serialized as protocol tags.
enum class WorkchainExecutionFailure : int {
  CandidateInvalid = -7200,
  LocalUnavailable = -7201,
  AuthenticatedStateCorrupt = -7202,
};

inline bool workchain_execution_requires_local_failure(const td::Status& status) {
  return status.is_error() &&
         (status.code() == static_cast<int>(WorkchainExecutionFailure::LocalUnavailable) ||
          status.code() == static_cast<int>(WorkchainExecutionFailure::AuthenticatedStateCorrupt));
}

}  // namespace block
