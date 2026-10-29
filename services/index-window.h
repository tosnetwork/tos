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

// Move the retention window base after replaying masterchain block `newest`
// generated at `newest_time`: the base becomes the last masterchain block
// generated more than `retention` seconds earlier. It never moves back and
// stays below `newest`.
//
// A source that joined later than the base holds no block from before its
// first one. Then everything it holds is inside the window, so the base is
// set just below the first block it holds, found by binary search; the
// blocks it holds are a suffix of the chain ending at `newest`.
inline td::Result<uint32_t> advance_window_base(uint32_t base, uint32_t newest, uint32_t newest_time,
                                                uint32_t retention, const MasterchainTime& time_of) {
  if (newest_time <= retention) {
    return base;
  }
  uint32_t cutoff = newest_time - retention;
  for (uint32_t steps = 0; base + 1 < newest && steps < kWindowBaseStepsPerInterval; ++steps) {
    TRY_RESULT(time, time_of(base + 1));
    if (!time) {
      // Lowest held block in (base + 1, newest]; newest is held.
      uint32_t lo = base + 2, hi = newest;
      while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        TRY_RESULT(held, time_of(mid));
        if (held) {
          hi = mid;
        } else {
          lo = mid + 1;
        }
      }
      TRY_RESULT(first, time_of(lo));
      if (!first) {
        return td::Status::Error("the source does not hold the newest replayed masterchain block");
      }
      if (first.value() >= cutoff) {
        return lo - 1;
      }
      base = lo - 1;
      continue;
    }
    if (time.value() >= cutoff) {
      break;
    }
    ++base;
  }
  return base;
}

}  // namespace tos::services
