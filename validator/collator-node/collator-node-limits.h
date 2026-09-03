/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/
#pragma once

#include <cstddef>

namespace tos::validator {

// The resource-admission rules for remote collation, factored out of the
// actor code so they can be unit-tested in isolation. An authorized-but-hostile
// validator can otherwise drive these paths without bound (distinct prev-block
// vectors each start a Collator; future-group requests park closures), so the
// exact counting rule is load-bearing.

// One collation occupies a concurrency slot from the moment it starts until it
// produces a result. A finished entry holds only a cached result and must NOT
// count against the cap -- otherwise a shard that stops finalizing would keep
// its cached results forever and block every new collation.
struct CollationSlot {
  bool started = false;
  bool has_result = false;
};

inline bool collation_slot_in_flight(const CollationSlot& slot) {
  return slot.started && !slot.has_result;
}

template <typename Range>
size_t count_in_flight_collations(const Range& slots) {
  size_t count = 0;
  for (const auto& slot : slots) {
    if (collation_slot_in_flight(slot)) {
      ++count;
    }
  }
  return count;
}

// Admission is refused once the cap is reached (inclusive): with the cap at N,
// the N+1'th concurrent collation is rejected, so at most N run at once.
inline bool at_capacity(size_t current, size_t cap) {
  return current >= cap;
}

}  // namespace tos::validator
