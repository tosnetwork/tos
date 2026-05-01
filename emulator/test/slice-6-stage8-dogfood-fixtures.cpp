/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

// Slice 6 Stage 8 dogfood predicate fixtures.

#include "td/utils/tests.h"

#include <cstdint>

namespace {

struct DogfoodState {
  td::uint16 restart_count = 0;
  td::uint16 max_restarts = 1;
  td::uint16 dead_letter_count = 0;
  td::uint64 dropped_count = 0;
  bool final_failure = false;

  void child_down(bool escrow_funded) {
    if (restart_count >= max_restarts) {
      final_failure = true;
    } else {
      ++restart_count;
    }
    if (escrow_funded) {
      ++dead_letter_count;
    } else {
      ++dropped_count;
    }
  }
};

td::uint32 scheduled_not_before(td::uint32 now, td::uint32 delay) {
  return now + delay;
}

}  // namespace

TEST(Slice6Stage8DogfoodFixtures, ScheduledHeartbeatUsesMasterchainSeqnoDelay) {
  CHECK(scheduled_not_before(100, 20) == 120);
}

TEST(Slice6Stage8DogfoodFixtures, FundedFailureCreatesBoundedDeadLetterRecord) {
  DogfoodState state;
  state.child_down(true);
  CHECK(state.dead_letter_count == 1);
  CHECK(state.dropped_count == 0);
}

TEST(Slice6Stage8DogfoodFixtures, UnfundedFailureDoesNotCreateFreeRecord) {
  DogfoodState state;
  state.child_down(false);
  CHECK(state.dead_letter_count == 0);
  CHECK(state.dropped_count == 1);
}

TEST(Slice6Stage8DogfoodFixtures, RestartStormEscalates) {
  DogfoodState state;
  state.child_down(true);
  state.child_down(true);
  CHECK(state.final_failure);
}
