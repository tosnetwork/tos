/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <cstdint>
#include <functional>

#include "td/utils/Status.h"
#include "td/utils/optional.h"

namespace tos::services {

// Masterchain lookups one replayed interval may spend moving the retention
// window base. The base normally moves by about one block per interval; a
// longer lag is caught up over later intervals.
constexpr uint32_t kWindowBaseStepsPerInterval = 4096;

// The generation time of masterchain block `seqno` as the source holds it, or
// nothing when the source does not hold that block. Any other failure is an
// error and must not be read as "not held".
using MasterchainTime = std::function<td::Result<td::optional<uint32_t>>(uint32_t seqno)>;

// The window base after one step, and whether it stopped at a masterchain
// block the source does not hold.
struct WindowBaseStep {
  uint32_t base = 0;
  bool stalled = false;
};

// Move the retention window base after replaying masterchain block `newest`
// generated at `newest_time`: the base becomes the last masterchain block
// generated more than `retention` seconds earlier. It never moves back and
// stays below `newest`.
//
// A block the source does not hold stops the base where it is (`stalled`):
// it never jumps over a gap, because which blocks a source holds is not
// known to be a contiguous suffix. A stalled base only keeps more history
// than the window, never less. An index imported onto a source that joined
// later starts with its base at the first block of the source's contiguous
// history, so a fresh gap below it is never needed.
inline td::Result<WindowBaseStep> advance_window_base(uint32_t base, uint32_t newest, uint32_t newest_time,
                                                      uint32_t retention, const MasterchainTime& time_of) {
  WindowBaseStep step{base, false};
  if (newest_time <= retention) {
    return step;
  }
  uint32_t cutoff = newest_time - retention;
  for (uint32_t steps = 0; step.base + 1 < newest && steps < kWindowBaseStepsPerInterval; ++steps) {
    TRY_RESULT(time, time_of(step.base + 1));
    if (!time) {
      step.stalled = true;
      break;
    }
    if (time.value() >= cutoff) {
      break;
    }
    ++step.base;
  }
  return step;
}

}  // namespace tos::services
