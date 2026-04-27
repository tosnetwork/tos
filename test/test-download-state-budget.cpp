/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Pin the persistent-state download memory-budget invariant from the audit:
//
//   Two completed 256 MiB downloads held downstream must consume the entire
//   512 MiB total budget. A third 1 MiB reservation must be rejected until
//   one of the held buffers (and its RAII reservation) is dropped, at which
//   point the next reservation succeeds.
//
// Before the RAII fix, DownloadState::finish_query() released the budget
// the moment the buffer was handed to the downstream promise, even though
// downstream still held the buffer alive. That made the budget account
// "buffer en route" rather than "buffer resident", and concurrent downloads
// + held buffers could push process memory past the documented 512 MiB
// ceiling.
//
// The full-node Callback regression also pins the manager-side handoff:
// the adapter from the full-node Callback into ValidatorManagerInterface
// used to convert BudgetedBufferSlice back into a plain BufferSlice and
// drop the reservation in the lambda's local scope, releasing the budget
// before the manager/downstream had finished holding the buffer alive.

#include "validator/net/download-state.hpp"
#include "validator/state-download-buffer.h"

#include "td/actor/PromiseFuture.h"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <utility>

namespace {

constexpr td::uint64 kMiB = 1ULL << 20;

#define EXPECT_TRUE(cond)                                                                                       \
  do {                                                                                                          \
    if (!(cond)) {                                                                                              \
      std::fprintf(stderr, "FAIL %s:%d  expected true: %s\n", __FILE__, __LINE__, #cond);                       \
      std::exit(1);                                                                                             \
    }                                                                                                           \
  } while (0)

#define EXPECT_FALSE(cond)                                                                                      \
  do {                                                                                                          \
    if (cond) {                                                                                                 \
      std::fprintf(stderr, "FAIL %s:%d  expected false: %s\n", __FILE__, __LINE__, #cond);                      \
      std::exit(1);                                                                                             \
    }                                                                                                           \
  } while (0)

#define EXPECT_EQ(a, b)                                                                                         \
  do {                                                                                                          \
    auto _va = (a);                                                                                             \
    auto _vb = (b);                                                                                             \
    if (_va != _vb) {                                                                                           \
      std::fprintf(stderr, "FAIL %s:%d  expected equal: %s == %s (got %llu vs %llu)\n", __FILE__, __LINE__,     \
                   #a, #b, static_cast<unsigned long long>(_va), static_cast<unsigned long long>(_vb));         \
      std::exit(1);                                                                                             \
    }                                                                                                           \
  } while (0)

using tos::validator::fullnode::BudgetedBufferSlice;
using tos::validator::fullnode::PersistentStateDownloadReservation;
using tos::validator::fullnode::testing::test_get_persistent_state_download_bytes;
using tos::validator::fullnode::testing::test_try_reserve_persistent_state_download_memory;

// Helper: reserve `size` bytes against the global download budget and wrap
// the reservation in a shared_ptr that releases via the same RAII destructor
// the production code uses. Returns null on rejection.
std::shared_ptr<PersistentStateDownloadReservation> try_reserve(td::uint64 size) {
  if (!test_try_reserve_persistent_state_download_memory(size)) {
    return {};
  }
  return std::make_shared<PersistentStateDownloadReservation>(size);
}

void test_budget_covers_downstream_lifetime() {
  std::printf("=== test_budget_covers_downstream_lifetime ===\n");

  // Pre-condition: budget should start clean. We don't assume "exactly 0"
  // (in case other tests run in the same process), but we record the
  // baseline and assert each delta against it.
  const td::uint64 baseline = test_get_persistent_state_download_bytes();

  // Step 1: hold two completed 256 MiB downloads downstream.
  auto first = try_reserve(256 * kMiB);
  EXPECT_TRUE(first != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 256 * kMiB);

  auto second = try_reserve(256 * kMiB);
  EXPECT_TRUE(second != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 512 * kMiB);

  // Step 2: a third 1 MiB reservation must be rejected because the 512 MiB
  // total budget is fully consumed by the two held buffers.
  auto rejected = try_reserve(1 * kMiB);
  EXPECT_FALSE(rejected != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 512 * kMiB);

  // Step 3: drop one of the held reservations. The destructor releases the
  // bytes back to the global budget — this is the invariant the RAII fix
  // exists to guarantee.
  first.reset();
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 256 * kMiB);

  // Step 4: a new 1 MiB reservation must now succeed.
  auto third = try_reserve(1 * kMiB);
  EXPECT_TRUE(third != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 256 * kMiB + 1 * kMiB);

  // Cleanup: drop the remaining reservations and confirm the budget returns
  // to the baseline.
  second.reset();
  third.reset();
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  std::printf("  PASSED\n");
}

void test_oversize_single_reservation_is_rejected() {
  std::printf("=== test_oversize_single_reservation_is_rejected ===\n");

  const td::uint64 baseline = test_get_persistent_state_download_bytes();

  // The total budget is 512 MiB. A single 513 MiB reservation must be
  // refused without affecting the global counter.
  auto huge = try_reserve(513 * kMiB);
  EXPECT_FALSE(huge != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  std::printf("  PASSED\n");
}

void test_budgeted_buffer_slice_extends_lifetime() {
  std::printf("=== test_budgeted_buffer_slice_extends_lifetime ===\n");

  const td::uint64 baseline = test_get_persistent_state_download_bytes();

  // Simulate the production handoff: DownloadState::finish_query() builds a
  // BudgetedBufferSlice that bundles the downloaded BufferSlice with the
  // reservation. Downstream copies the BufferSlice and the shared_ptr; only
  // when both copies drop should the budget be released.
  auto reservation = try_reserve(64 * kMiB);
  EXPECT_TRUE(reservation != nullptr);

  td::BufferSlice payload(64 * kMiB);
  BudgetedBufferSlice handed_off{std::move(payload), reservation};
  // The producer may also drop its local reference after handing off.
  reservation.reset();

  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 64 * kMiB);

  // Downstream consumer keeps the slice alive. Budget must remain charged.
  BudgetedBufferSlice copy_to_consumer = std::move(handed_off);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 64 * kMiB);

  // Consumer finishes processing. Dropping the last shared_ptr releases the
  // budget — proving the reservation outlived the original DownloadState.
  copy_to_consumer.reservation.reset();
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  std::printf("  PASSED\n");
}

void test_full_node_callback_does_not_release_budget_prematurely() {
  std::printf("=== test_full_node_callback_does_not_release_budget_prematurely ===\n");

  // Models the new full-node -> ValidatorManagerInterface boundary:
  // both the FullNode Callback and the manager carry BudgetedBufferSlice
  // promises end-to-end. Before this round's fix the Callback adapter
  // converted BudgetedBufferSlice -> BufferSlice in a local lambda and
  // dropped the reservation as soon as set_value() returned, which
  // released the global budget while the manager still held the buffer
  // resident.
  //
  // The simulation below mirrors that handoff: a producer-side promise
  // is fulfilled with a BudgetedBufferSlice, the manager-side handler
  // captures it into an external "manager state" variable, and we
  // assert the global budget remains charged for as long as that
  // variable is alive — and only that.

  const td::uint64 baseline = test_get_persistent_state_download_bytes();
  constexpr td::uint64 kPayload = 256 * kMiB;

  // Step 1: reserve and wrap a 256 MiB buffer just like
  // DownloadState::finish_query() does.
  auto reservation = try_reserve(kPayload);
  EXPECT_TRUE(reservation != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kPayload);

  td::BufferSlice payload(kPayload);
  BudgetedBufferSlice produced{std::move(payload), std::move(reservation)};

  // Step 2: simulate the new full-node -> manager promise plumbing. The
  // manager-side holder lives outside the producer's lambda — exactly
  // the case the old adapter mishandled.
  BudgetedBufferSlice manager_held;
  td::Promise<BudgetedBufferSlice> manager_promise = [&manager_held](td::Result<BudgetedBufferSlice> R) {
    if (R.is_error()) {
      std::fprintf(stderr, "FAIL manager_promise unexpectedly errored\n");
      std::exit(1);
    }
    // Manager handler stores the entire BudgetedBufferSlice (including
    // the reservation shared_ptr) into a long-lived field. The
    // reservation lifetime now follows the manager state, not the
    // lambda scope.
    manager_held = R.move_as_ok();
  };

  // Step 3: producer fulfills the promise (the moral equivalent of
  // promise_.set_value() inside DownloadState::finish_query()).
  manager_promise.set_value(std::move(produced));

  // The producer's local references are gone; only the manager-side
  // BudgetedBufferSlice is keeping the reservation alive. Under the old
  // adapter this would already be `baseline` because the reservation
  // would have been dropped in the lambda.
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kPayload);
  EXPECT_TRUE(manager_held.reservation != nullptr);
  EXPECT_EQ(manager_held.data.size(), static_cast<std::size_t>(kPayload));

  // Step 4: manager finishes processing the buffer (writes to disk,
  // deserializes into ShardState, etc.) and releases its handle. The
  // reservation drops to zero refcount and the global budget returns to
  // baseline.
  manager_held = BudgetedBufferSlice{};
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  std::printf("  PASSED\n");
}

}  // namespace

int main() {
  std::printf("test-download-state-budget: persistent-state download RAII budget regression\n");
  test_budget_covers_downstream_lifetime();
  test_oversize_single_reservation_is_rejected();
  test_budgeted_buffer_slice_extends_lifetime();
  test_full_node_callback_does_not_release_budget_prematurely();
  std::printf("All tests completed.\n");
  return 0;
}
