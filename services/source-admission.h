/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <cstddef>
#include <cstdint>

#include "td/utils/Status.h"
#include "validator/db/archive-lru-policy.h"

namespace tos::services {

// Descriptors a source read may need besides the archive slices it opens:
// table files the cell and state databases open on catch-up, block readers.
// Archive slice opens admit their own demand, counted from the files they are
// about to open (ArchiveSlice::before_query), so no estimate from slices seen
// before is involved.
constexpr std::size_t kSourceReadReserve = 128;

// Admit one source read against the process-wide descriptor budget. A refusal
// is either a wait (closing archive slices would make room; the caller asks
// the archive LRU to rebalance and retries) or a shortage (nothing the
// process can close would make room; only a higher descriptor limit helps).
inline td::Status admit_source_request() {
  return validator::admit_archive_descriptors(kSourceReadReserve, "source read");
}

// Consecutive shortages, with no read admitted in between, after which replay
// stops instead of retrying: the limit has to be raised by the operator.
constexpr int kShortagesBeforeStop = 3;

// Tracks whether replay is blocked by a descriptor shortage. `observe` is
// called once per replay step with the process-wide refusal counts after the
// step; it returns true once kShortagesBeforeStop consecutive steps each
// recorded a new shortage and nothing else.
class ShortageTracker {
 public:
  bool observe(const validator::DescriptorRefusals& refusals) {
    bool new_shortage = refusals.shortages > shortages_ && refusals.last_was_shortage;
    shortages_ = refusals.shortages;
    consecutive_ = new_shortage ? consecutive_ + 1 : 0;
    return consecutive_ >= kShortagesBeforeStop;
  }
  // A step that succeeded: replay is not blocked, whatever it was refused
  // on the way.
  void progressed(const validator::DescriptorRefusals& refusals) {
    shortages_ = refusals.shortages;
    consecutive_ = 0;
  }
  int consecutive() const {
    return consecutive_;
  }

 private:
  std::uint64_t shortages_ = 0;
  int consecutive_ = 0;
};

}  // namespace tos::services
