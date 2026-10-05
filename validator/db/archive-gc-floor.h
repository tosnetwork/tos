/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

namespace tos {
namespace validator {

// No block needs keeping beyond the archive TTL.
constexpr uint32_t kNoArchiveGcFloor = std::numeric_limits<uint32_t>::max();

// What archive pruning must keep for a reader outside the archive (the wallet
// index, for applied blocks whose token candidates it has not extracted), and
// what pruning has already given up. Both change only under `mutex`, which is
// held for a few comparisons and never across I/O:
//  - a reader asks to retain blocks generated from some time on
//    (archive_retain), and learns whether a given block may already be gone;
//  - pruning admits each package deletion under the same lock
//    (prune_archive_packages), raising `deleted_below` before it deletes.
// Whichever comes first in that order, the reader either holds the package or
// is told it cannot rely on it.
struct ArchiveRetention {
  std::mutex mutex;
  // Keep every package that may hold a block generated at or after this.
  uint32_t floor = kNoArchiveGcFloor;
  // Blocks generated before this may already be deleted.
  double deleted_below = 0;
};
inline ArchiveRetention g_archive_retention;

// Retain blocks generated at or after `from` (a reader computes it with a
// margin below the block's own generation time `gen_utime`). False, and
// nothing retained, when packages that may hold that block were already
// admitted for deletion.
inline bool archive_retain(uint32_t from, uint32_t gen_utime) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  // The block's package began no earlier than `from` (generation time less
  // the margin); if a package that ended after that was given up, the block
  // may have been in it.
  (void)gen_utime;
  if (static_cast<double>(from) < g_archive_retention.deleted_below) {
    return false;
  }
  g_archive_retention.floor = std::min(g_archive_retention.floor, from);
  return true;
}

// Set the floor outright: the reader's recomputation from everything it
// still needs (it may raise the floor as needs are met).
inline void archive_set_floor(uint32_t floor) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  g_archive_retention.floor = floor;
}

inline uint32_t archive_floor() {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  return g_archive_retention.floor;
}

// Which archive packages pruning may delete. `first_ts` gives, in package
// order, the generation time of each candidate package's first masterchain
// block. A package qualifies when that time is before the cutoff: the TTL
// cutoff, or the floor when it is earlier. The newest qualifying package is
// kept anyway: it may hold blocks generated after the cutoff, while every
// older one holds only blocks generated before the next package began.
inline std::vector<size_t> archive_packages_to_delete(const std::vector<double>& first_ts, double gc_ts,
                                                      double archive_ttl, uint32_t floor) {
  double cutoff = gc_ts - archive_ttl;
  if (floor != kNoArchiveGcFloor) {
    cutoff = std::min(cutoff, static_cast<double>(floor));
  }
  std::vector<size_t> out;
  for (size_t i = 0; i < first_ts.size(); ++i) {
    if (first_ts[i] < cutoff) {
      out.push_back(i);
    }
  }
  if (out.size() > 1) {
    out.pop_back();
  } else {
    out.clear();
  }
  return out;
}

// Delete the packages pruning selects. Each deletion is admitted under the
// retention lock, against the floor as it is then, and recorded there (every
// block generated before the next package began may be gone) before the lock
// is released; the deletion itself (`remove`, which does the I/O) runs after.
// `before_admit` is a test hook run just before each admission. Returns how
// many packages were deleted.
template <class Remove, class BeforeAdmit>
size_t prune_archive_packages(const std::vector<double>& first_ts, double gc_ts, double archive_ttl, Remove&& remove,
                              BeforeAdmit&& before_admit) {
  size_t removed = 0;
  for (auto index : archive_packages_to_delete(first_ts, gc_ts, archive_ttl, archive_floor())) {
    before_admit(index);
    bool admitted = false;
    {
      std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
      auto still = archive_packages_to_delete(first_ts, gc_ts, archive_ttl, g_archive_retention.floor);
      if (std::find(still.begin(), still.end(), index) != still.end() && index + 1 < first_ts.size()) {
        g_archive_retention.deleted_below = std::max(g_archive_retention.deleted_below, first_ts[index + 1]);
        admitted = true;
      }
    }
    if (admitted) {
      remove(index);
      ++removed;
    }
  }
  return removed;
}

template <class Remove>
size_t prune_archive_packages(const std::vector<double>& first_ts, double gc_ts, double archive_ttl, Remove&& remove) {
  return prune_archive_packages(first_ts, gc_ts, archive_ttl, std::forward<Remove>(remove), [](size_t) {});
}

// Tests only: forget what pruning gave up and any floor.
inline void reset_archive_retention_for_testing() {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  g_archive_retention.floor = kNoArchiveGcFloor;
  g_archive_retention.deleted_below = 0;
}

}  // namespace validator
}  // namespace tos
