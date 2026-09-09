#pragma once

#include <limits>

#include "td/utils/Status.h"
#include "td/utils/common.h"

namespace uno_workchain {

// Arithmetic only. The caller authenticates the configuration epoch and the
// masterchain time, selects the applicable epoch, and enforces reference lag.
// No wall clock, production timer, or default slot duration is used here.
class SlotEpoch {
 public:
  static td::Result<SlotEpoch> genesis(td::uint64 time, td::uint64 seconds) {
    if (seconds == 0) {
      return td::Status::Error("UNO slot duration must be positive");
    }
    return SlotEpoch(time, 0, seconds);
  }

  td::Result<td::uint64> slot_at(td::uint64 authenticated_time) const {
    if (authenticated_time < start_time_) {
      return td::Status::Error("UNO time precedes scheduling epoch");
    }
    const auto elapsed_slots = (authenticated_time - start_time_) / seconds_;
    // Private construction preserves first_slot_ <= start_time_ and seconds_
    // >= 1, so this sum cannot exceed authenticated_time (including UINT64_MAX).
    return first_slot_ + elapsed_slots;
  }

  // Candidate migration rule: switch only at a future old-epoch boundary.
  // Carry the slot number forward rather than replacing the genesis divisor.
  // Activation authority and persistence of epoch history are external.
  td::Result<SlotEpoch> checked_next_epoch(td::uint64 boundary, td::uint64 seconds) const {
    if (seconds == 0 || boundary <= start_time_ || (boundary - start_time_) % seconds_ != 0) {
      return td::Status::Error("UNO epoch change requires a later slot boundary and positive duration");
    }
    TRY_RESULT(first, slot_at(boundary));
    return SlotEpoch(boundary, first, seconds);
  }

  // Previous height/slot must come from the authenticated predecessor. Missed
  // slots are allowed, but neither height gaps nor backfilled slots are valid.
  td::Status validate_successor(td::uint64 previous_height, td::uint64 previous_slot,
                               td::uint64 height, td::uint64 slot, td::uint64 authenticated_time) const {
    if (previous_height == std::numeric_limits<td::uint64>::max() || height != previous_height + 1) {
      return td::Status::Error("UNO successor height must advance exactly once");
    }
    TRY_RESULT(expected_slot, slot_at(authenticated_time));
    if (slot != expected_slot || slot <= previous_slot) {
      return td::Status::Error("UNO successor must use the current strictly later slot");
    }
    return td::Status::OK();
  }

 private:
  SlotEpoch(td::uint64 time, td::uint64 first, td::uint64 seconds)
      : start_time_(time), first_slot_(first), seconds_(seconds) {}
  td::uint64 start_time_;
  td::uint64 first_slot_;
  td::uint64 seconds_;
};

}  // namespace uno_workchain
