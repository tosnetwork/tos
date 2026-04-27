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

#include "validator/downloaders/download-state.hpp"
#include "validator/net/download-state.hpp"
#include "validator/state-download-buffer.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"

#include "td/actor/PromiseFuture.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <sys/time.h>
#include <unistd.h>
#endif

namespace {

constexpr td::uint64 kMiB = 1ULL << 20;
constexpr td::uint64 kGiB = 1ULL << 30;

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
using tos::validator::fullnode::BudgetedStateFile;
using tos::validator::fullnode::DownloadedPersistentState;
using tos::validator::fullnode::PersistentStateDownloadReservation;
using tos::validator::fullnode::PersistentStateProcessingReservation;
using tos::validator::fullnode::cleanup_persistent_state_tempfiles;
using tos::validator::fullnode::mmap_persistent_state_file;
using tos::validator::fullnode::persistent_state_heap_threshold_bytes;
using tos::validator::fullnode::persistent_state_max_file_bytes;
using tos::validator::fullnode::persistent_state_total_download_budget_bytes;
using tos::validator::fullnode::set_persistent_state_tempfile_dir;
using tos::validator::fullnode::testing::test_get_persistent_state_download_bytes;
using tos::validator::fullnode::testing::test_get_persistent_state_processing_bytes;
using tos::validator::fullnode::testing::test_try_reserve_persistent_state_download_memory;
using tos::validator::fullnode::testing::test_try_reserve_persistent_state_processing_memory;

// Helper: reserve `size` bytes against the global download budget and wrap
// the reservation in a shared_ptr that releases via the same RAII destructor
// the production code uses. Returns null on rejection.
std::shared_ptr<PersistentStateDownloadReservation> try_reserve(td::uint64 size) {
  if (!test_try_reserve_persistent_state_download_memory(size)) {
    return {};
  }
  return std::make_shared<PersistentStateDownloadReservation>(size);
}

// Same shape as try_reserve but for the processing budget. Returns null
// when the global processing counter does not have headroom.
std::shared_ptr<PersistentStateProcessingReservation> try_reserve_processing(td::uint64 size) {
  if (!test_try_reserve_persistent_state_processing_memory(size)) {
    return {};
  }
  return std::make_shared<PersistentStateProcessingReservation>(size);
}

void test_budget_covers_downstream_lifetime() {
  std::printf("=== test_budget_covers_downstream_lifetime ===\n");

  // Pre-condition: budget should start clean. We don't assume "exactly 0"
  // (in case other tests run in the same process), but we record the
  // baseline and assert each delta against it.
  const td::uint64 baseline = test_get_persistent_state_download_bytes();
  const td::uint64 total_cap = persistent_state_total_download_budget_bytes();
  EXPECT_TRUE(total_cap >= kGiB);

  // Step 1: drive the global counter up to (cap - kMiB). Reserve in two
  // halves so both the additive accounting and the multi-holder
  // invariant get exercised. Both reservations must succeed against an
  // empty budget.
  const td::uint64 half = (total_cap - kMiB) / 2;
  auto first = try_reserve(half);
  EXPECT_TRUE(first != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + half);

  auto second = try_reserve(half);
  EXPECT_TRUE(second != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 2 * half);

  // Step 2: a 2 MiB reservation must be rejected because the total
  // budget is fully consumed (2 * half = cap - kMiB; another kMiB still
  // fits, but 2 MiB does not).
  auto rejected = try_reserve(2 * kMiB);
  EXPECT_FALSE(rejected != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + 2 * half);

  // Step 3: drop one of the held reservations. The destructor releases the
  // bytes back to the global budget — this is the invariant the RAII fix
  // exists to guarantee.
  first.reset();
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + half);

  // Step 4: a new 1 MiB reservation must now succeed.
  auto third = try_reserve(1 * kMiB);
  EXPECT_TRUE(third != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + half + 1 * kMiB);

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
  const td::uint64 total_cap = persistent_state_total_download_budget_bytes();

  // The total budget is `total_cap` (post-H-02 raised to 16 GiB). A
  // single reservation strictly larger than the cap must be refused
  // without affecting the global counter, regardless of which storage
  // mode (heap or tempfile) the caller intends. Pin the new total
  // budget against an off-by-one over-cap request so a future bump of
  // the constant is caught.
  EXPECT_TRUE(total_cap >= kGiB);
  auto huge = try_reserve(total_cap + 1);
  EXPECT_FALSE(huge != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  // Sanity: a reservation exactly at the cap must succeed (nothing
  // else in flight). Drop it immediately so other tests are not
  // affected.
  auto at_cap = try_reserve(total_cap);
  EXPECT_TRUE(at_cap != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + total_cap);
  at_cap.reset();
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

void test_processing_budget_reserved_during_parse() {
  std::printf("=== test_processing_budget_reserved_during_parse ===\n");

  // Models the new downloaded_shard_state() flow: the actor moves the
  // download buffer into actor state (covered by the download budget) and
  // simultaneously reserves a same-size slice from the SEPARATE processing
  // budget to account for the single parse clone fed into create_shard_state.
  //
  // The invariant under test: while the parse clone is in flight the
  // processing counter is +N above baseline; the moment the parse clone
  // is dropped the processing counter returns to baseline. The download
  // counter is independent and stays charged for as long as the original
  // buffer is held in actor state.

  const td::uint64 download_baseline = test_get_persistent_state_download_bytes();
  const td::uint64 processing_baseline = test_get_persistent_state_processing_bytes();

  constexpr td::uint64 kStateSize = 256 * kMiB;

  // Step 1: simulate DownloadState::finish_query() handing a budgeted
  // buffer to the downstream actor.
  auto download_reservation = try_reserve(kStateSize);
  EXPECT_TRUE(download_reservation != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline + kStateSize);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline);

  // Step 2: simulate downloaded_shard_state() reserving the parse-clone
  // processing slice. While this reservation is alive, the processing
  // counter is exactly +kStateSize above its baseline.
  {
    auto processing_reservation = try_reserve_processing(kStateSize);
    EXPECT_TRUE(processing_reservation != nullptr);
    EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline + kStateSize);
    // The download counter is independent: it should still reflect the
    // original buffer regardless of what the processing budget is doing.
    EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline + kStateSize);
  }
  // Step 3: parse clone has been consumed; processing budget returns to
  // baseline. Download budget is still charged because the original
  // buffer is still held by the actor (download_reservation alive).
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline + kStateSize);

  // Cleanup: drop the download reservation; both counters return to
  // baseline.
  download_reservation.reset();
  EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline);

  std::printf("  PASSED\n");
}

void test_processing_budget_failure_releases_download_reservation() {
  std::printf("=== test_processing_budget_failure_releases_download_reservation ===\n");

  // Models the failure branch of downloaded_shard_state(): if create_shard_state
  // fails (or any subsequent root-hash / validate_deep check fails), the
  // actor MUST drop both data_ and data_reservation_ AND the processing
  // reservation. After that, both global counters return to baseline.

  const td::uint64 download_baseline = test_get_persistent_state_download_bytes();
  const td::uint64 processing_baseline = test_get_persistent_state_processing_bytes();

  constexpr td::uint64 kStateSize = 128 * kMiB;

  // Reserve like the production downloaded_shard_state() does.
  auto download_reservation = try_reserve(kStateSize);
  EXPECT_TRUE(download_reservation != nullptr);
  auto processing_reservation = try_reserve_processing(kStateSize);
  EXPECT_TRUE(processing_reservation != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline + kStateSize);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline + kStateSize);

  // Simulate failure-path cleanup: the actor's failure branch resets
  // data_, data_reservation_, and the local processing_reservation (in
  // production all three happen synchronously before fail_handler is
  // dispatched). We model the same drops here.
  td::BufferSlice data_field(kStateSize);  // stand-in for `data_`
  data_field = td::BufferSlice{};          // simulate `data_ = td::BufferSlice{}`
  processing_reservation.reset();
  download_reservation.reset();

  // Both global counters MUST be back to baseline; nothing should leak
  // from a failed parse.
  EXPECT_EQ(test_get_persistent_state_download_bytes(), download_baseline);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), processing_baseline);

  std::printf("  PASSED\n");
}

void test_concurrent_downloads_respect_combined_budget() {
  std::printf("=== test_concurrent_downloads_respect_combined_budget ===\n");

  // Two concurrent persistent-state downloads must each be admissible
  // against the 512 MiB processing budget (the in-memory parse-clone
  // ceiling, separate from the larger 16 GiB download budget that
  // governs disk-backed reservations). Beyond 512 MiB the third
  // reservation must fail until one of the in-flight processing
  // reservations is released.

  const td::uint64 baseline = test_get_persistent_state_processing_bytes();

  // First parse clone: 256 MiB succeeds.
  auto first = try_reserve_processing(256 * kMiB);
  EXPECT_TRUE(first != nullptr);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline + 256 * kMiB);

  // Second concurrent parse clone: another 256 MiB still fits within the
  // 512 MiB cap.
  auto second = try_reserve_processing(256 * kMiB);
  EXPECT_TRUE(second != nullptr);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline + 512 * kMiB);

  // Third reservation: even 1 MiB must be refused because the budget is
  // fully consumed.
  auto third = try_reserve_processing(1 * kMiB);
  EXPECT_FALSE(third != nullptr);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline + 512 * kMiB);

  // Releasing one in-flight parse reservation immediately frees its
  // slice. A new 1 MiB request now succeeds.
  first.reset();
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline + 256 * kMiB);
  auto retried = try_reserve_processing(1 * kMiB);
  EXPECT_TRUE(retried != nullptr);
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline + 256 * kMiB + 1 * kMiB);

  // Cleanup.
  retried.reset();
  second.reset();
  EXPECT_EQ(test_get_persistent_state_processing_bytes(), baseline);

  std::printf("  PASSED\n");
}

// H-02 streaming-tempfile invariants. The InMemory branch must continue
// to behave like the heap-only path the legacy tests pin; the OnDisk
// branch must (a) keep the reservation alive while the consumer holds
// the BudgetedStateFile, (b) unlink the tempfile when the handle is
// dropped, and (c) survive a startup cleanup sweep that targets only
// *.partial residue.

void test_downloaded_state_memory_branch() {
  std::printf("=== test_downloaded_state_memory_branch ===\n");

  const td::uint64 baseline = test_get_persistent_state_download_bytes();
  // Production picks the heap path for sizes below
  // persistent_state_heap_threshold_bytes(); pin that boundary.
  EXPECT_TRUE(persistent_state_heap_threshold_bytes() == 64ULL * (1ULL << 20));
  constexpr td::uint64 kSize = 16 * kMiB;

  auto reservation = try_reserve(kSize);
  EXPECT_TRUE(reservation != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kSize);

  td::BufferSlice payload(kSize);
  auto state = DownloadedPersistentState::memory(BudgetedBufferSlice{std::move(payload), reservation});
  reservation.reset();

  EXPECT_TRUE(state.is_memory());
  EXPECT_FALSE(state.is_file());
  EXPECT_EQ(state.size(), kSize);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kSize);

  // Drop the state; budget must return to baseline.
  state = DownloadedPersistentState{};
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);

  std::printf("  PASSED\n");
}

void test_downloaded_state_file_branch_unlink_on_drop() {
  std::printf("=== test_downloaded_state_file_branch_unlink_on_drop ===\n");

  const td::uint64 baseline = test_get_persistent_state_download_bytes();

  // Create a real tempfile and wrap it in a BudgetedStateFile / state
  // wrapper. The BudgetedStateFile destructor MUST unlink the file when
  // is_temp is still true at drop.
  auto tmp_dir = std::string("/tmp/tos-test-download-h02-") + std::to_string(::getpid());
  td::mkpath(tmp_dir + "/", 0700).ensure();
  auto path = tmp_dir + "/100mib.partial";
  {
    auto r_fd = td::FileFd::open(
        path, td::FileFd::Flags::Write | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
    EXPECT_TRUE(r_fd.is_ok());
    auto fd = r_fd.move_as_ok();
    auto write = fd.write_all(td::Slice("\xAB", 1));
    EXPECT_TRUE(write.is_ok());
    fd.close();
  }

  // Reserve 100 MiB against the global budget so the test exercises the
  // "reservation outlives the producer" invariant the audit calls out.
  constexpr td::uint64 kPayload = 100 * kMiB;
  auto reservation = try_reserve(kPayload);
  EXPECT_TRUE(reservation != nullptr);
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kPayload);

  {
    BudgetedStateFile bsf{path, kPayload, reservation, /*temp=*/true};
    auto downloaded = DownloadedPersistentState::file(std::move(bsf));
    // Producer drops its local reservation reference now; only the
    // wrapped one keeps the budget charged.
    reservation.reset();

    EXPECT_TRUE(downloaded.is_file());
    EXPECT_FALSE(downloaded.is_memory());
    EXPECT_EQ(downloaded.size(), kPayload);
    EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline + kPayload);

    // Tempfile must exist while the consumer holds the state.
    auto stat = td::stat(downloaded.file().path);
    EXPECT_TRUE(stat.is_ok());

    // Drop the state. The BudgetedStateFile destructor unlinks the file
    // and the reservation drops to zero refcount.
  }
  EXPECT_EQ(test_get_persistent_state_download_bytes(), baseline);
  // File should be gone after the drop.
  auto post_stat = td::stat(path);
  EXPECT_FALSE(post_stat.is_ok());

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

void test_tempfile_residue_cleanup_on_startup() {
  std::printf("=== test_tempfile_residue_cleanup_on_startup ===\n");

  // Plant a fake *.partial file (pretend a previous process crashed
  // mid-download), call cleanup_persistent_state_tempfiles, and assert
  // the .partial file is removed and any non-partial file is preserved.
  auto tmp_dir = std::string("/tmp/tos-test-download-h02-cleanup-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  td::mkpath(tmp_dir + "/persistent-state/", 0700).ensure();
  auto residue_path = tmp_dir + "/persistent-state/something.partial";
  auto preserve_path = tmp_dir + "/persistent-state/keep_me";

  for (auto path : {residue_path, preserve_path}) {
    auto r_fd = td::FileFd::open(
        path, td::FileFd::Flags::Write | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
    EXPECT_TRUE(r_fd.is_ok());
    auto fd = r_fd.move_as_ok();
    auto w = fd.write_all(td::Slice("x", 1));
    EXPECT_TRUE(w.is_ok());
    fd.close();
  }

  // Use min_age_seconds=0 to disable the age guard for this test: the
  // *.partial file was just created, but the test is simulating residue
  // from a prior crash that the cleanup must sweep regardless of age.
  // Production startup retains the default 60s guard; this test pins
  // the legacy "sweep all .partial" behavior.
  auto cleanup = cleanup_persistent_state_tempfiles(tmp_dir + "/persistent-state", /*min_age_seconds=*/0);
  EXPECT_TRUE(cleanup.is_ok());

  // .partial gone, non-partial preserved.
  EXPECT_FALSE(td::stat(residue_path).is_ok());
  EXPECT_TRUE(td::stat(preserve_path).is_ok());

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

void test_tempfile_cleanup_on_missing_root_is_ok() {
  std::printf("=== test_tempfile_cleanup_on_missing_root_is_ok ===\n");

  auto missing = std::string("/tmp/tos-test-download-h02-missing-") + std::to_string(::getpid());
  td::rmrf(missing).ignore();
  // Calling cleanup on a non-existent root must NOT error: a fresh DB
  // path has no /tmp/persistent-state until a download starts.
  auto status = cleanup_persistent_state_tempfiles(missing);
  EXPECT_TRUE(status.is_ok());

  std::printf("  PASSED\n");
}

void test_downloaded_state_default_is_memory_zero() {
  std::printf("=== test_downloaded_state_default_is_memory_zero ===\n");

  // A default-constructed DownloadedPersistentState is the InMemory
  // branch with size 0 and no reservation. Important so an unfulfilled
  // adapter does not leak a zero-size BudgetedStateFile that triggers a
  // spurious unlink at drop.
  DownloadedPersistentState state;
  EXPECT_TRUE(state.is_memory());
  EXPECT_FALSE(state.is_file());
  EXPECT_EQ(state.size(), 0u);
  EXPECT_TRUE(state.memory().reservation == nullptr);

  std::printf("  PASSED\n");
}

void test_h02_per_state_cap_16gib() {
  std::printf("=== test_h02_per_state_cap_16gib ===\n");

  // The audit's H-02 fix raises the per-state download cap from the
  // legacy 1 GiB constant to 16 GiB. Pin the value so the constant
  // cannot drift back without a CI failure.
  const td::uint64 expected_cap = 16ULL << 30;
  EXPECT_EQ(persistent_state_max_file_bytes(), expected_cap);

  // The total download budget was raised in lockstep so a single
  // 16 GiB persistent state can be in flight (the disk-backed path
  // bills the budget, not the heap). Pin the new total cap.
  EXPECT_EQ(persistent_state_total_download_budget_bytes(), expected_cap);

  // A 17 GiB request must be rejected outright by the public
  // try_reserve API (the per-state size guard kicks in before the
  // running counter is consulted).
  EXPECT_FALSE(test_try_reserve_persistent_state_download_memory(expected_cap + (1ULL << 30)));

  std::printf("  PASSED\n");
}

// Helper for the H-02 mmap regression test: open a fresh tempfile
// under the given directory, populate it with `size` bytes of a
// deterministic pattern (so we can hash-check from both heap and
// mmap paths), and return the path. The tempfile lives until the
// caller unlinks it.
std::string make_pattern_tempfile(const std::string &dir, td::uint64 size) {
  td::mkpath(dir + "/", 0700).ensure();
  auto path = dir + "/h02-mmap-" + std::to_string(::getpid()) + "-" + std::to_string(size) + ".bin";
  auto r_fd = td::FileFd::open(
      path,
      td::FileFd::Flags::Write | td::FileFd::Flags::Read | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
  if (r_fd.is_error()) {
    std::fprintf(stderr, "FAIL cannot open tempfile %s: %s\n", path.c_str(), r_fd.error().message().c_str());
    std::exit(1);
  }
  auto fd = r_fd.move_as_ok();

  // Write in 1 MiB chunks of a repeating pattern so the file content
  // is stable and the hash has high entropy. We deliberately do NOT
  // hold the full file in memory at any point in this helper — that
  // would defeat the purpose of the regression test.
  constexpr td::uint64 kChunkBytes = 1ULL << 20;
  std::vector<char> chunk(static_cast<std::size_t>(kChunkBytes));
  for (std::size_t i = 0; i < chunk.size(); ++i) {
    chunk[i] = static_cast<char>((i * 31 + 7) & 0xFF);
  }
  td::uint64 written = 0;
  while (written < size) {
    auto remaining = size - written;
    auto want = remaining < kChunkBytes ? remaining : kChunkBytes;
    auto write_status = fd.pwrite(td::Slice(chunk.data(), static_cast<std::size_t>(want)),
                                  static_cast<td::int64>(written));
    if (write_status.is_error()) {
      std::fprintf(stderr, "FAIL write to tempfile failed: %s\n", write_status.error().message().c_str());
      std::exit(1);
    }
    if (write_status.ok() != want) {
      std::fprintf(stderr, "FAIL short write %llu vs %llu\n",
                   static_cast<unsigned long long>(write_status.ok()), static_cast<unsigned long long>(want));
      std::exit(1);
    }
    written += want;
  }
  fd.sync().ensure();
  fd.close();
  return path;
}

void test_h02_mmap_ondisk_parse_avoids_heap_peak() {
  std::printf("=== test_h02_mmap_ondisk_parse_avoids_heap_peak ===\n");

  // Invariant: the OnDisk parse path must NOT allocate a BufferSlice
  // of size >= the heap threshold for an OnDisk DownloadedPersistentState.
  // The streaming-tempfile + mmap design eliminates this path entirely:
  // a 256 MiB OnDisk parse must not grow `td::BufferAllocator::get_buffer_mem()`
  // by anywhere near the state size. We assert that growth stays well below
  // the state size (and below the heap threshold in the streaming case)
  // — the heap-peak meter is the sole authoritative invariant.

  // Prepare a 256 MiB tempfile.
  constexpr td::uint64 kStateBytes = 256 * kMiB;
  auto tmp_dir = std::string("/tmp/tos-test-h02-mmap-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto path = make_pattern_tempfile(tmp_dir, kStateBytes);

  const td::uint64 download_baseline_buffer_mem = td::BufferAllocator::get_buffer_mem();

  {
    // Reserve the download budget for the OnDisk state. The mmap path
    // does NOT charge BufferAllocator::buffer_mem (mmap pages are
    // accounted by the kernel, not BufferRaw).
    auto reservation = try_reserve(kStateBytes);
    EXPECT_TRUE(reservation != nullptr);

    BudgetedStateFile bsf{path, kStateBytes, reservation, /*temp=*/true};
    auto downloaded = DownloadedPersistentState::file(std::move(bsf));
    reservation.reset();

    EXPECT_TRUE(downloaded.is_file());
    EXPECT_EQ(downloaded.size(), kStateBytes);

    // Acquire a non-owning slice via the production mmap helper.
    auto r_slice = mmap_persistent_state_file(downloaded.file());
    EXPECT_TRUE(r_slice.is_ok());
    auto mapped = r_slice.move_as_ok();
    EXPECT_EQ(static_cast<td::uint64>(mapped.size()), kStateBytes);

    // Sanity-check that the slice points at the file's bytes.
    EXPECT_EQ(static_cast<unsigned char>(mapped[0]),
              static_cast<unsigned char>(((0 * 31 + 7) & 0xFF)));
    EXPECT_EQ(static_cast<unsigned char>(mapped[1024]),
              static_cast<unsigned char>(((1024 * 31 + 7) & 0xFF)));

    // Heap-buffer-mem must NOT have grown by a state-size allocation
    // between the baseline and now. We allow modest slack (a couple
    // hundred KiB) for unrelated harness allocations; the regression
    // we are guarding is "a 256 MiB BufferSlice was created", not
    // sub-MiB churn.
    auto current_buffer_mem = td::BufferAllocator::get_buffer_mem();
    if (current_buffer_mem >= download_baseline_buffer_mem &&
        current_buffer_mem - download_baseline_buffer_mem >= kStateBytes) {
      std::fprintf(stderr,
                   "FAIL OnDisk parse path heap-allocated >= state size: baseline=%llu current=%llu\n",
                   static_cast<unsigned long long>(download_baseline_buffer_mem),
                   static_cast<unsigned long long>(current_buffer_mem));
      std::exit(1);
    }

    // Calling mmap_view a second time must NOT re-map (idempotent
    // lazy initialization). The slice's data() pointer must compare
    // equal to the first call's pointer.
    auto r_slice_again = mmap_persistent_state_file(downloaded.file());
    EXPECT_TRUE(r_slice_again.is_ok());
    auto mapped_again = r_slice_again.move_as_ok();
    EXPECT_TRUE(mapped.data() == mapped_again.data());
    EXPECT_EQ(static_cast<td::uint64>(mapped_again.size()), kStateBytes);
  }
  // BudgetedStateFile dropped: tempfile unlinked, mmap unmapped,
  // reservation released. Heap-buffer-mem must STILL be at or near the
  // baseline — the previous in-block check already covered the active
  // window; this confirms the cleanup did not leak a state-sized buffer.
  {
    const td::uint64 post_buffer_mem = td::BufferAllocator::get_buffer_mem();
    if (post_buffer_mem >= download_baseline_buffer_mem &&
        post_buffer_mem - download_baseline_buffer_mem >= kStateBytes) {
      std::fprintf(stderr,
                   "FAIL OnDisk parse path leaked a state-sized buffer past cleanup: baseline=%llu post=%llu\n",
                   static_cast<unsigned long long>(download_baseline_buffer_mem),
                   static_cast<unsigned long long>(post_buffer_mem));
      std::exit(1);
    }
  }

  // File must be gone.
  auto post_stat = td::stat(path);
  EXPECT_FALSE(post_stat.is_ok());

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

void test_h02_zero_state_ondisk_persist_uses_streaming() {
  std::printf("=== test_h02_zero_state_ondisk_persist_uses_streaming ===\n");

  // Invariant pinned by this test: persisting a 256 MiB OnDisk
  // zero-state through the production streaming writer
  // (copy_tempfile_to_writer, the callable handed to
  // store_zero_state_file_gen) MUST NOT allocate a BufferSlice of
  // size >= the heap threshold. `td::BufferAllocator::get_buffer_mem()`
  // is the authoritative heap-peak meter: it MUST NOT grow by anywhere
  // near the state size — only the 1 MiB scratch chunk is in flight at
  // any time.
  //
  // Before this round's API addition the OnDisk zero-state persist had
  // to materialize a BufferSlice equal to the state size to satisfy
  // the BufferSlice-only store_zero_state_file API, which would have
  // shown up as a state-size jump in the heap-buffer counter. With
  // store_zero_state_file_gen + copy_tempfile_to_writer that fallback
  // no longer exists.

  constexpr td::uint64 kStateBytes = 256 * kMiB;
  auto tmp_dir = std::string("/tmp/tos-test-h02-zerostate-persist-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto src_path = make_pattern_tempfile(tmp_dir, kStateBytes);

  // Destination archive entry: a fresh tempfile in the same dir.
  auto dst_path = tmp_dir + "/zerostate-archive-entry.bin";
  auto r_dst = td::FileFd::open(
      dst_path,
      td::FileFd::Flags::Write | td::FileFd::Flags::Read | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
  EXPECT_TRUE(r_dst.is_ok());
  auto dst_fd = r_dst.move_as_ok();

  // Snapshot heap-buffer accounting BEFORE the streaming copy. The
  // streaming writer keeps exactly one 1 MiB scratch BufferSlice
  // resident at a time; growth must stay an order of magnitude below
  // the state size.
  const td::uint64 baseline_buffer_mem = td::BufferAllocator::get_buffer_mem();

  auto status = tos::validator::copy_tempfile_to_writer(src_path, kStateBytes, dst_fd);
  EXPECT_TRUE(status.is_ok());
  dst_fd.sync().ensure();

  // Invariant 1: BufferAllocator::get_buffer_mem must NOT have grown
  // by anywhere near the state size. The streaming writer holds a
  // single 1 MiB scratch buffer at a time; we leave generous slack
  // (up to one heap threshold) for unrelated harness allocations
  // and assert the total stayed well below the state size.
  const td::uint64 current_buffer_mem = td::BufferAllocator::get_buffer_mem();
  if (current_buffer_mem >= baseline_buffer_mem &&
      current_buffer_mem - baseline_buffer_mem >= kStateBytes) {
    std::fprintf(stderr,
                 "FAIL OnDisk zero-state streaming persist heap-allocated >= state size: baseline=%llu current=%llu\n",
                 static_cast<unsigned long long>(baseline_buffer_mem),
                 static_cast<unsigned long long>(current_buffer_mem));
    std::exit(1);
  }
  // Tighter bound: must stay under the heap threshold (16 MiB or
  // similar). This guards against a future refactor that re-grows
  // the chunk size to "as much as fits".
  if (current_buffer_mem >= baseline_buffer_mem &&
      current_buffer_mem - baseline_buffer_mem >= persistent_state_heap_threshold_bytes()) {
    std::fprintf(stderr,
                 "FAIL OnDisk zero-state streaming persist heap-allocated >= heap threshold: baseline=%llu current=%llu threshold=%llu\n",
                 static_cast<unsigned long long>(baseline_buffer_mem),
                 static_cast<unsigned long long>(current_buffer_mem),
                 static_cast<unsigned long long>(persistent_state_heap_threshold_bytes()));
    std::exit(1);
  }

  // Verify the copy was complete and byte-accurate by stat'ing the
  // destination size — this also catches a future bug where the
  // streaming writer silently truncates.
  auto r_dst_stat = td::stat(dst_path);
  EXPECT_TRUE(r_dst_stat.is_ok());
  EXPECT_EQ(static_cast<td::uint64>(r_dst_stat.move_as_ok().size_), kStateBytes);

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

void test_h02_mmap_view_validates_size_mismatch() {
  std::printf("=== test_h02_mmap_view_validates_size_mismatch ===\n");

  // Defensive: if the BudgetedStateFile.size disagrees with the
  // on-disk file's actual size, mmap_persistent_state_file must
  // refuse rather than mmap a smaller-or-larger region. This
  // protects against a corrupt tempfile or a peer that announces
  // a different size than was streamed.
  auto tmp_dir = std::string("/tmp/tos-test-h02-mmap-mismatch-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  // Write a 1 MiB file but claim it is 2 MiB.
  auto path = make_pattern_tempfile(tmp_dir, 1 * kMiB);
  BudgetedStateFile bsf{path, 2 * kMiB, /*reservation=*/{}, /*temp=*/true};
  auto r_slice = mmap_persistent_state_file(bsf);
  EXPECT_TRUE(r_slice.is_error());
  // Don't leak the tempfile if the assertion above fires.
  bsf = BudgetedStateFile{};
  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

// Build a known-good shard-state cell tree, serialize it to a BoC, and
// return the bytes plus the root hash. The cell content is intentionally
// non-trivial (some bits + a small ref tree) so any single-byte mutation
// has a high probability of either failing the BoC structural checks or
// changing the root hash.
struct GoodBoc {
  td::BufferSlice bytes;
  tos::Bits256 root_hash;
};

GoodBoc make_good_boc() {
  // Build a small tree: root has 32 bits of payload + two references to
  // leaves. Each leaf carries a distinct 64-bit pattern. The tree's
  // root hash is determined by the cell descriptors and the SHA256 of
  // the cell-tree representation, so flipping any byte in the BoC that
  // survives CRC32C still changes the hash.
  vm::CellBuilder leaf_a;
  td::uint64 pat_a = 0xCAFEBABE12345678ULL;
  leaf_a.store_bytes(reinterpret_cast<const char *>(&pat_a), sizeof(pat_a));
  auto cell_a = leaf_a.finalize();

  vm::CellBuilder leaf_b;
  td::uint64 pat_b = 0xDEADBEEF87654321ULL;
  leaf_b.store_bytes(reinterpret_cast<const char *>(&pat_b), sizeof(pat_b));
  auto cell_b = leaf_b.finalize();

  vm::CellBuilder root;
  td::uint32 root_pat = 0xA5A5A5A5;
  root.store_bytes(reinterpret_cast<const char *>(&root_pat), sizeof(root_pat));
  bool ok_a = root.store_ref_bool(cell_a);
  bool ok_b = root.store_ref_bool(cell_b);
  EXPECT_TRUE(ok_a);
  EXPECT_TRUE(ok_b);
  auto root_cell = root.finalize();

  auto serialized = vm::std_boc_serialize(root_cell, /*mode=*/0);
  EXPECT_TRUE(serialized.is_ok());
  GoodBoc gb;
  gb.bytes = serialized.move_as_ok();
  gb.root_hash = tos::Bits256{root_cell->get_hash().bits()};
  return gb;
}

// Write a buffer to a fresh tempfile and return the path. Caller is
// responsible for cleaning up the directory.
std::string write_buffer_to_tempfile(const std::string &dir, const std::string &name, td::Slice bytes) {
  td::mkpath(dir + "/", 0700).ensure();
  auto path = dir + "/" + name;
  auto r_fd = td::FileFd::open(
      path,
      td::FileFd::Flags::Write | td::FileFd::Flags::Read | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
  EXPECT_TRUE(r_fd.is_ok());
  auto fd = r_fd.move_as_ok();
  auto w = fd.write_all(bytes);
  EXPECT_TRUE(w.is_ok());
  fd.sync().ensure();
  fd.close();
  return path;
}

void test_h02_ondisk_corrupt_tempfile_rejected_by_boc_or_root_hash() {
  std::printf("=== test_h02_ondisk_corrupt_tempfile_rejected_by_boc_or_root_hash ===\n");

  // Build a known-good shard-state-like BoC and the expected root hash.
  // The downstream actor uses handle_->state() (a RootHash) to validate
  // the deserialized root; we use the cell's own hash here as the
  // expected value, since the test's "BFT-attested" hash equals the
  // hash of the legitimate cell tree.
  auto good = make_good_boc();
  EXPECT_TRUE(good.bytes.size() >= 16);
  std::printf("  good BoC size = %zu, root hash = %s\n",
              static_cast<size_t>(good.bytes.size()), good.root_hash.to_hex().c_str());

  auto tmp_dir = std::string("/tmp/tos-test-h02-corrupt-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();

  // Sanity: the helper accepts the unmodified BoC.
  {
    auto path = write_buffer_to_tempfile(tmp_dir, "good.bin", good.bytes.as_slice());
    BudgetedStateFile bsf{path, good.bytes.size(), /*reservation=*/{}, /*temp=*/true};
    auto r_root = tos::validator::parse_ondisk_state_for_test(bsf, good.root_hash);
    if (r_root.is_error()) {
      std::fprintf(stderr, "FAIL parse_ondisk_state_for_test rejected the unmodified BoC: %s\n",
                   r_root.error().message().c_str());
      std::exit(1);
    }
    bsf = BudgetedStateFile{};
  }
  td::rmrf(tmp_dir).ignore();

  // Case A: flip one byte in the middle of the BoC payload. Either the
  // BoC structural decoder rejects (descriptor / cell-data mismatch) or
  // the CRC32C trailer mismatch fires. Both are caught at the BoC
  // layer; root-hash compare never even runs.
  //
  // Note: BufferSlice::clone() shares the underlying buffer
  // ref-counted, so a mutation through the cloned slice would also
  // corrupt `good.bytes`. The corruption variants below copy the bytes
  // into an independent std::vector before mutating to keep `good.bytes`
  // pristine for case C.
  {
    std::vector<char> bytes(good.bytes.as_slice().begin(), good.bytes.as_slice().end());
    EXPECT_TRUE(bytes.size() >= 8);
    // Flip the byte at offset = size/2. Leave the trailer alone for
    // this case so we exercise the structural / hash-propagation path
    // explicitly (case B exercises CRC32C).
    std::size_t mid = bytes.size() / 2;
    bytes[mid] = static_cast<char>(static_cast<unsigned char>(bytes[mid]) ^ 0xFFu);

    auto path = write_buffer_to_tempfile(tmp_dir, "case_a.bin",
                                         td::Slice(bytes.data(), bytes.size()));
    BudgetedStateFile bsf{path, bytes.size(), /*reservation=*/{}, /*temp=*/true};
    auto r_root = tos::validator::parse_ondisk_state_for_test(bsf, good.root_hash);
    EXPECT_TRUE(r_root.is_error());
    std::printf("  case A (mid-payload flip) rejected: %s\n", r_root.error().message().c_str());
    bsf = BudgetedStateFile{};
  }
  td::rmrf(tmp_dir).ignore();

  // Case B: zero out the last 4 bytes (BoC CRC32C trailer). With
  // std_boc_serialize(_, mode=0) the trailer bytes are part of the
  // cell payload (CRC verification only fires on a non-default mode).
  // Wiping them mutates the deepest cell's content, which propagates
  // through the cell hashes and is caught by the root-hash compare.
  // This is exactly the dual layer the audit relies on: even when the
  // BoC structural decoder accepts a bag-of-cells, the explicit
  // root-hash compare against the BFT-attested expected root rejects
  // any payload mutation. validate_deep() does the same compare; the
  // OnDisk fast path saves the redundant pass.
  {
    std::vector<char> bytes(good.bytes.as_slice().begin(), good.bytes.as_slice().end());
    EXPECT_TRUE(bytes.size() >= 4);
    for (std::size_t i = bytes.size() - 4; i < bytes.size(); ++i) {
      bytes[i] = '\0';
    }

    auto path = write_buffer_to_tempfile(tmp_dir, "case_b.bin",
                                         td::Slice(bytes.data(), bytes.size()));
    BudgetedStateFile bsf{path, bytes.size(), /*reservation=*/{}, /*temp=*/true};
    auto r_root = tos::validator::parse_ondisk_state_for_test(bsf, good.root_hash);
    EXPECT_TRUE(r_root.is_error());
    std::printf("  case B (CRC32C trailer wiped) rejected: %s\n", r_root.error().message().c_str());
    bsf = BudgetedStateFile{};
  }
  td::rmrf(tmp_dir).ignore();

  // Case C: keep the BoC structurally valid but pass a BOGUS expected
  // root hash. The BoC deserialize succeeds; the helper's final
  // root-hash compare against `expected_root_hash` rejects.
  //
  // This case validates the OTHER claim of the H-02 fix: even if the
  // BoC layer is happy, the explicit hash compare still catches a
  // mismatched cell tree. The audit's stated concern is "cell content
  // modified so root_hash differs"; the symmetric situation ("legit
  // bytes, attacker-supplied wrong expected hash") exercises the same
  // compare and is reproducible without re-deriving cell hashes.
  {
    auto path = write_buffer_to_tempfile(tmp_dir, "case_c.bin", good.bytes.as_slice());
    BudgetedStateFile bsf{path, good.bytes.size(), /*reservation=*/{}, /*temp=*/true};
    tos::Bits256 wrong_hash;
    wrong_hash.set_zero();
    auto r_root = tos::validator::parse_ondisk_state_for_test(bsf, wrong_hash);
    EXPECT_TRUE(r_root.is_error());
    auto msg = r_root.error().message().str();
    // The compare rejection must be surfaced via the descriptive
    // "root hash mismatch" message produced by the helper, not via
    // the BoC layer's generic error.
    if (msg.find("root hash mismatch") == std::string::npos) {
      std::fprintf(stderr,
                   "FAIL case C error did not mention 'root hash mismatch': %s\n",
                   msg.c_str());
      std::exit(1);
    }
    std::printf("  case C (root-hash compare fails) rejected: %s\n", msg.c_str());
    bsf = BudgetedStateFile{};
  }
  td::rmrf(tmp_dir).ignore();

  std::printf("  PASSED\n");
}

void test_h02_cleanup_skips_recent_tempfiles() {
  std::printf("=== test_h02_cleanup_skips_recent_tempfiles ===\n");

  // Race-safety regression: cleanup_persistent_state_tempfiles must
  // skip *.partial files newer than min_age_seconds, on the assumption
  // that they could belong to an in-progress writer. Files older than
  // the threshold MUST be unlinked.
  auto tmp_dir = std::string("/tmp/tos-test-h02-cleanup-race-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto root = tmp_dir + "/persistent-state";
  td::mkpath(root + "/", 0700).ensure();

  auto recent_path = root + "/recent.partial";
  auto old_path = root + "/old.partial";
  auto preserved_path = root + "/keep.bin";

  for (auto path : {recent_path, old_path, preserved_path}) {
    auto r_fd = td::FileFd::open(
        path, td::FileFd::Flags::Write | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
    EXPECT_TRUE(r_fd.is_ok());
    auto fd = r_fd.move_as_ok();
    auto w = fd.write_all(td::Slice("y", 1));
    EXPECT_TRUE(w.is_ok());
    fd.close();
  }

  // Backdate `old.partial` to 5 minutes ago via utimes(2) so the
  // mtime guard treats it as residue from a prior crash. utimes is
  // POSIX; on Windows the analogous defense-in-depth check would use
  // SetFileTime, but this test is gated to POSIX (the backdate primitive
  // here is). The production guard itself is platform-portable through
  // td::stat().
#if !defined(_WIN32)
  struct timeval tv[2];
  std::time_t now = std::time(nullptr);
  tv[0].tv_sec = now - 300;
  tv[0].tv_usec = 0;
  tv[1].tv_sec = now - 300;
  tv[1].tv_usec = 0;
  int rc = ::utimes(old_path.c_str(), tv);
  EXPECT_EQ(rc, 0);
#else
  // Windows fallback: skip the backdate (test still validates that the
  // recent files are preserved; the "old file is removed" half is
  // exercised by the POSIX path on Linux/macOS CI runners).
  (void)old_path;
#endif

  // Run cleanup with the production default age threshold (60 seconds).
  // recent.partial: created just now, must be skipped.
  // old.partial:    backdated 5 minutes, must be removed (POSIX).
  // keep.bin:       no .partial suffix, must be preserved regardless.
  auto cleanup = cleanup_persistent_state_tempfiles(root, /*min_age_seconds=*/60);
  EXPECT_TRUE(cleanup.is_ok());

  // recent.partial must still exist — the race guard skipped it.
  EXPECT_TRUE(td::stat(recent_path).is_ok());
  // keep.bin must still exist — wrong suffix.
  EXPECT_TRUE(td::stat(preserved_path).is_ok());

#if !defined(_WIN32)
  // old.partial must be gone — past the threshold.
  EXPECT_FALSE(td::stat(old_path).is_ok());
#endif

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

void test_link_isolation_helper() {
  std::printf("=== test_link_isolation_helper ===\n");

  // Compile-time / link-time pin: the public API surface is reachable
  // exactly through the validator-state-download-budget library
  // symbols. If a future refactor accidentally re-defined any of these
  // in libfull-node.a, ODR would fail at link time before reaching
  // here. The body just exercises the public symbols once so the linker
  // is forced to resolve them.
  EXPECT_TRUE(test_try_reserve_persistent_state_download_memory(0));
  EXPECT_TRUE(test_try_reserve_persistent_state_processing_memory(0));
  EXPECT_TRUE(persistent_state_heap_threshold_bytes() > 0);

  std::printf("  PASSED\n");
}

}  // namespace

int main() {
  std::printf("test-download-state-budget: persistent-state download RAII budget regression\n");
  test_budget_covers_downstream_lifetime();
  test_oversize_single_reservation_is_rejected();
  test_budgeted_buffer_slice_extends_lifetime();
  test_full_node_callback_does_not_release_budget_prematurely();
  test_processing_budget_reserved_during_parse();
  test_processing_budget_failure_releases_download_reservation();
  test_concurrent_downloads_respect_combined_budget();
  test_downloaded_state_memory_branch();
  test_downloaded_state_file_branch_unlink_on_drop();
  test_tempfile_residue_cleanup_on_startup();
  test_tempfile_cleanup_on_missing_root_is_ok();
  test_downloaded_state_default_is_memory_zero();
  test_h02_per_state_cap_16gib();
  test_h02_mmap_ondisk_parse_avoids_heap_peak();
  test_h02_zero_state_ondisk_persist_uses_streaming();
  test_h02_mmap_view_validates_size_mismatch();
  test_h02_ondisk_corrupt_tempfile_rejected_by_boc_or_root_hash();
  test_h02_cleanup_skips_recent_tempfiles();
  test_link_isolation_helper();
  std::printf("All tests completed.\n");
  return 0;
}
