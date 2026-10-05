/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace tos {
namespace validator {

// No block needs keeping beyond the archive TTL.
constexpr uint32_t kNoArchiveGcFloor = std::numeric_limits<uint32_t>::max();

// The earliest block generation time something outside the archive still
// needs to read back (for the wallet index: applied blocks whose token
// candidates it has not yet extracted). Archive pruning keeps every package
// that may hold a block generated at or after it, whatever the archive TTL
// says. Set by the index from its durable markers, so it holds across
// restarts once the index has started.
inline std::atomic<uint32_t> g_archive_gc_floor{kNoArchiveGcFloor};

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

}  // namespace validator
}  // namespace tos
