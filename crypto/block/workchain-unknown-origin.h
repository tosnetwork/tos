#pragma once

#include "block/workchain-execution-errors.h"
#include "td/utils/logging.h"
#include <atomic>
#include <limits>

namespace block {
namespace unknown_origin_detail {
inline std::atomic<std::uint64_t> count{0};
}

// Process-local diagnostic, never consensus state. Zero only describes observed
// paths, not the correctness/completeness of their existing classifications.
inline std::uint64_t workchain_unknown_origin_count() {
  return unknown_origin_detail::count.load(std::memory_order_relaxed);
}

// Use only at a mixed-origin account-execution boundary. A codec's neutral code
// does not establish provenance; already source-classified codes are preserved.
inline td::Status observe_workchain_execution_status(td::Status status, const char* boundary) {
  if (status.is_ok() || status.code() == static_cast<int>(WorkchainExecutionFailure::CandidateInvalid) ||
      workchain_execution_requires_local_failure(status)) return status;
  auto previous = unknown_origin_detail::count.load(std::memory_order_relaxed);
  while (previous != std::numeric_limits<std::uint64_t>::max() &&
         !unknown_origin_detail::count.compare_exchange_weak(previous, previous + 1,
                                                            std::memory_order_relaxed)) {}
  // Saturate rather than wrap to zero. Counting is independent of log filters.
  LOG(ERROR) << "WORKCHAIN_UNKNOWN_ORIGIN boundary=" << boundary
             << " code=" << status.code() << " cause=" << status.message();
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                          "unclassified workchain execution failure");
}
} // namespace block
