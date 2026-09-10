#pragma once

#include <cstdint>

namespace block {
// Diagnostic events, never an authorization or consensus outcome. Zero means
// not entered, not successful. Readers must reject unknown values and require
// independent delivery confirmation plus the final typed actor result.
enum class WorkchainReadinessPhase : std::uint8_t {
  NotEntered = 0,
  Entered = 1,
  AccountBindingResolved = 2,
  AccountBindingRefused = 3,
  Complete = 4
};
struct WorkchainReadinessObservation {
  WorkchainReadinessPhase phase{WorkchainReadinessPhase::NotEntered};
  std::int32_t workchain{-1};
};
}  // namespace block
