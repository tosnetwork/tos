/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

// Slice 6 Stage 2 scheduled-message predicate fixtures.

#include "td/utils/tests.h"

#include <cstdint>

namespace {

constexpr td::uint8 kCancelOk = 0;
constexpr td::uint8 kCancelUnknown = 1;
constexpr td::uint8 kCancelNotAuthorized = 2;
constexpr td::uint8 kCancelDelivered = 3;
constexpr td::uint8 kCancelExpired = 4;
constexpr td::uint8 kCancelAlreadyCanceled = 5;
constexpr td::uint32 kUint32Max = 0xffffffffu;

td::uint32 deliver_by(td::uint32 not_before, td::uint32 expire_after) {
  CHECK(expire_after != 0);
  CHECK(not_before <= kUint32Max - expire_after);
  return not_before + expire_after;
}

bool valid_schedule_window(td::uint32 not_before, td::uint32 expire_after) {
  return expire_after != 0 && not_before <= kUint32Max - expire_after;
}

bool is_due(td::uint32 now, td::uint32 not_before) {
  return now >= not_before;
}

bool is_expired(td::uint32 now, td::uint32 not_before, td::uint32 expire_after) {
  return now >= deliver_by(not_before, expire_after);
}

struct ScheduledState {
  bool pending = true;
  bool delivered = false;
  bool expired = false;
  bool canceled = false;
  td::uint32 cancel_authority = 1;
  td::uint32 escrow_covered_until = 0;

  td::uint8 cancel(td::uint32 caller) {
    if (delivered) {
      return kCancelDelivered;
    }
    if (expired) {
      return kCancelExpired;
    }
    if (canceled) {
      return kCancelAlreadyCanceled;
    }
    if (!pending) {
      return kCancelUnknown;
    }
    if (caller != cancel_authority) {
      return kCancelNotAuthorized;
    }
    pending = false;
    canceled = true;
    return kCancelOk;
  }

  bool force_expire_if_escrow_depleted(td::uint32 now) {
    if (!pending || now <= escrow_covered_until) {
      return false;
    }
    pending = false;
    expired = true;
    return true;
  }
};

}  // namespace

TEST(Slice6Stage2ScheduleFixtures, DeliverByArithmeticAndOverflowBoundary) {
  CHECK(deliver_by(100, 20) == 120);
  CHECK(deliver_by(kUint32Max - 1, 1) == kUint32Max);
}

TEST(Slice6Stage2ScheduleFixtures, DeliverByOverflowRejected) {
  CHECK(valid_schedule_window(100, 20));
  CHECK(!valid_schedule_window(100, 0));
  CHECK(!valid_schedule_window(kUint32Max, 1));
  CHECK(!valid_schedule_window(kUint32Max - 1, 2));
}

TEST(Slice6Stage2ScheduleFixtures, DueAndExpiryPredicatesUseMasterchainSeqno) {
  CHECK(!is_due(99, 100));
  CHECK(is_due(100, 100));
  CHECK(!is_expired(119, 100, 20));
  CHECK(is_expired(120, 100, 20));
}

TEST(Slice6Stage2ScheduleFixtures, CancellationAuthorizationAndRaceStates) {
  ScheduledState state;
  CHECK(state.cancel(/*caller=*/2) == kCancelNotAuthorized);
  CHECK(state.pending);
  CHECK(!state.canceled);
  CHECK(state.cancel(/*caller=*/1) == kCancelOk);
  CHECK(!state.pending);
  CHECK(state.canceled);

  ScheduledState delivered;
  delivered.pending = false;
  delivered.delivered = true;
  CHECK(delivered.cancel(/*caller=*/1) == kCancelDelivered);

  ScheduledState expired;
  expired.pending = false;
  expired.expired = true;
  CHECK(expired.cancel(/*caller=*/1) == kCancelExpired);

  ScheduledState canceled;
  CHECK(canceled.cancel(/*caller=*/1) == kCancelOk);
  CHECK(canceled.cancel(/*caller=*/1) == kCancelAlreadyCanceled);
  CHECK(canceled.cancel(/*caller=*/2) == kCancelAlreadyCanceled);

  ScheduledState unknown;
  unknown.pending = false;
  CHECK(unknown.cancel(/*caller=*/1) == kCancelUnknown);
}

TEST(Slice6Stage2ScheduleFixtures, DeadLetterDoesNotInheritCancellationAuthority) {
  constexpr td::uint32 cancel_authority = 7;
  constexpr td::uint32 dead_letter = 9;
  ScheduledState state;
  state.cancel_authority = cancel_authority;
  CHECK(state.cancel(dead_letter) == kCancelNotAuthorized);

  ScheduledState delegated;
  delegated.cancel_authority = dead_letter;
  CHECK(delegated.cancel(dead_letter) == kCancelOk);
}

TEST(Slice6Stage2ScheduleFixtures, ForceExpiryOnEscrowDepletion) {
  ScheduledState state;
  state.escrow_covered_until = 110;
  CHECK(!state.force_expire_if_escrow_depleted(110));
  CHECK(state.force_expire_if_escrow_depleted(111));
  CHECK(state.expired);
  CHECK(!state.pending);
}
