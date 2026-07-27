/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <map>
#include <optional>

#include "consensus/types.h"
#include "td/utils/check.h"

namespace tos::validator::consensus::simplex {

// Snapshot of every lifetime condition that must hold before
// CandidateResolver may erase a map entry. Keeping this predicate outside the
// actor makes the exact finalization/network/persistence interleavings
// deterministic to test without weakening the production invariant.
struct CandidateEvictionState {
  size_t active_operations = 0;
  size_t resolve_waiters = 0;
  size_t store_waiters = 0;
  bool notar_store_in_flight = false;
  bool candidate_durable = true;
  bool notar_durable = true;

  bool can_evict() const {
    return active_operations == 0 && resolve_waiters == 0 && store_waiters == 0 &&
           !notar_store_in_flight && candidate_durable && notar_durable;
  }
};

// Keeps a bounded number of finalized slots in CandidateResolver. Entries in
// newer, non-finalized slots are never selected by this policy.
class CandidateRetentionPolicy {
 public:
  explicit CandidateRetentionPolicy(td::uint32 retained_slots) : retained_slots_(retained_slots) {
    CHECK(retained_slots_ > 0);
  }

  void observe_finalized(td::uint32 slot) {
    if (!latest_finalized_slot_.has_value() || *latest_finalized_slot_ < slot) {
      latest_finalized_slot_ = slot;
    }
  }

  std::optional<td::uint32> latest_finalized_slot() const {
    return latest_finalized_slot_;
  }

  td::uint32 first_retained_slot() const {
    if (!latest_finalized_slot_.has_value() || *latest_finalized_slot_ < retained_slots_) {
      return 0;
    }
    return *latest_finalized_slot_ - retained_slots_ + 1;
  }

  bool is_before_retained_window(const CandidateId& id) const {
    return id.slot < first_retained_slot();
  }

  td::uint32 retained_slots() const {
    return retained_slots_;
  }

 private:
  td::uint32 retained_slots_;
  std::optional<td::uint32> latest_finalized_slot_;
};

// `can_evict` must reject entries referenced by an in-flight coroutine. The
// helper deliberately leaves rejected old entries in place so a later
// finalization/alarm pass can remove them after the operation completes.
template <class State, class CanEvict>
size_t prune_candidate_states(std::map<CandidateId, State>& states, td::uint32 first_retained_slot,
                              CanEvict&& can_evict) {
  size_t erased = 0;
  auto end = states.lower_bound(CandidateId{first_retained_slot, {}});
  for (auto it = states.begin(); it != end;) {
    if (can_evict(it->second)) {
      it = states.erase(it);
      ++erased;
    } else {
      ++it;
    }
  }
  return erased;
}

}  // namespace tos::validator::consensus::simplex
