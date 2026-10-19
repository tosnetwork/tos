/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The retry policy of a consensus group, under a frozen clock the test
// advances:
//
//   - the initial chain-state resolution waits once at a time, retries a
//     timed-out wait after 10, 20, 40 ... s capped at 5 minutes, and ends at
//     once, from the wait or from the delay, when the group stops; a stopped
//     group is never started;
//   - accepting a finalized block retries timeout and notready after 1, 2,
//     4, 5, 5 ... s, and returns a cancellation or a permanent error instead
//     of reporting the block accepted;
//   - retry logging lets the first failure through and then one line per
//     interval, however many failures come in between.

#include <memory>
#include <vector>

#include "td/actor/TestScheduler.h"
#include "td/utils/tests.h"
#include "validator/consensus/retry-backoff.h"

namespace tos::validator::consensus {
namespace {

using td::actor::StartedTask;
using td::actor::Task;

std::vector<td::uint32> delays(BackoffPolicy policy, size_t count) {
  Backoff backoff(policy);
  std::vector<td::uint32> result;
  for (size_t i = 0; i < count; i++) {
    result.push_back(backoff.next_delay());
  }
  return result;
}

// Waits started by a loop under test: each is completed by the test.
struct Waits {
  std::vector<StartedTask<int>::ExternalPromise> pending;
  std::vector<double> started_at;
  size_t in_flight = 0;
  size_t most_in_flight = 0;

  Task<int> start() {
    auto [task, promise] = StartedTask<int>::make_bridge();
    pending.push_back(std::move(promise));
    started_at.push_back(td::Time::now());
    in_flight++;
    most_in_flight = std::max(most_in_flight, in_flight);
    auto result = co_await std::move(task).wrap();
    in_flight--;
    co_return std::move(result);
  }

  void fail_last(int code) {
    pending.back().set_error(td::Status::Error(code, "wait failed"));
  }
};

}  // namespace

TEST(ConsensusRetryBackoff, DelaysDoubleUpToTheirCap) {
  ASSERT_TRUE(delays(INITIAL_STATE_BACKOFF, 9) == (std::vector<td::uint32>{10, 20, 40, 80, 160, 300, 300, 300, 300}));
  ASSERT_TRUE(delays(ACCEPT_BLOCK_BACKOFF, 6) == (std::vector<td::uint32>{1, 2, 4, 5, 5, 5}));
  // Doubling never wraps around, even next to the largest delay.
  ASSERT_TRUE(delays(BackoffPolicy{0x80000005u, 0xffffffffu}, 3) ==
              (std::vector<td::uint32>{0x80000005u, 0xffffffffu, 0xffffffffu}));
  ASSERT_TRUE(delays(BackoffPolicy{7, 3}, 2) == (std::vector<td::uint32>{3, 3}));
  // A new operation starts again at the initial delay.
  ASSERT_EQ(10u, Backoff(INITIAL_STATE_BACKOFF).next_delay());
  ASSERT_EQ(1500.0, INITIAL_STATE_WAIT_TIMEOUT);
}

TEST(ConsensusRetryBackoff, RetryLoggingIsBounded) {
  RetryLogLimiter limiter(INITIAL_STATE_RETRY_LOG_INTERVAL);
  td::uint64 held_back = 99;
  auto t = [](double s) { return td::Timestamp::at(10000.0 + s); };
  ASSERT_TRUE(limiter.allow(t(0), held_back));
  ASSERT_EQ(0u, held_back);
  // A burst of failures inside the interval logs nothing more.
  size_t logged = 0;
  for (int i = 1; i <= 1000; i++) {
    logged += limiter.allow(t(i * 0.2), held_back) ? 1 : 0;
  }
  ASSERT_EQ(0u, logged);
  // The next line, an interval after the first, reports what was held back.
  ASSERT_TRUE(limiter.allow(t(300.0), held_back));
  ASSERT_EQ(1000u, held_back);
  // Over a long run of failures, one line per interval.
  logged = 0;
  for (int i = 1; i <= 3000; i++) {
    logged += limiter.allow(t(300.0 + i), held_back) ? 1 : 0;
  }
  ASSERT_EQ(10u, logged);
}

TEST(ConsensusRetryBackoff, InitialStateRetriesWithBackoffOneWaitAtATime) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    auto cancellation = std::make_shared<Cancellation>();
    Waits waits;
    std::vector<td::uint32> retried_after;
    auto loop = resolve_initial_state<int>(
                    cancellation, [&]() { return waits.start(); },
                    [&](const td::Status &error, td::uint32 delay) { retried_after.push_back(delay); })
                    .start();
    co_await scheduler.wait_sync_work();
    ASSERT_EQ(1u, waits.started_at.size());

    const std::vector<td::uint32> expected{10, 20, 40, 80, 160, 300, 300};
    for (size_t i = 0; i < expected.size(); i++) {
      waits.fail_last(ErrorCode::timeout);
      co_await scheduler.wait_sync_work();
      // Nothing is retried before the delay is over.
      scheduler.advance_time(expected[i] - 0.5);
      co_await scheduler.wait_sync_work();
      ASSERT_EQ(i + 1, waits.started_at.size());
      scheduler.advance_time(0.5);
      co_await scheduler.wait_sync_work();
      ASSERT_EQ(i + 2, waits.started_at.size());
      auto gap = waits.started_at[i + 1] - waits.started_at[i];
      ASSERT_TRUE(gap >= expected[i] - 1e-6 && gap <= expected[i] + 1e-6);
    }
    ASSERT_TRUE(retried_after == expected);
    ASSERT_EQ(1u, waits.most_in_flight);

    // Any answer but a timeout ends the loop: a result...
    waits.pending.back().set_value(42);
    auto result = co_await std::move(loop).wrap();
    ASSERT_TRUE(result.is_ok());
    ASSERT_EQ(42, result.ok());

    // ... or a permanent error, which is not retried.
    Waits other;
    auto failing = resolve_initial_state<int>(
                       cancellation, [&]() { return other.start(); }, [](const td::Status &, td::uint32) {})
                       .start();
    co_await scheduler.wait_sync_work();
    other.fail_last(ErrorCode::error);
    auto failed = co_await std::move(failing).wrap();
    ASSERT_TRUE(failed.is_error());
    ASSERT_EQ(ErrorCode::error, failed.error().code());
    ASSERT_EQ(1u, other.started_at.size());
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, StoppingEndsTheWaitAtOnce) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    auto cancellation = std::make_shared<Cancellation>();
    Waits waits;
    bool started = false;
    // Mirrors the group: it starts only on a resolved state from a group
    // that has not been stopped.
    auto start_group = [&]() -> Task<td::Unit> {
      auto r = co_await resolve_initial_state<int>(
                   cancellation, [&]() { return waits.start(); }, [](const td::Status &, td::uint32) {})
                   .wrap();
      if (cancellation->is_cancelled()) {
        co_return td::Status::Error(ErrorCode::cancelled, "stopped");
      }
      CO_TRY(std::move(r));
      started = true;
      co_return td::Unit{};
    };
    auto group = start_group().start();
    co_await scheduler.wait_sync_work();
    ASSERT_EQ(1u, waits.started_at.size());
    auto before = td::Time::now();
    cancellation->cancel();
    // The clock does not move: the stop alone ends the wait.
    auto result = co_await std::move(group).wrap();
    ASSERT_EQ(before, td::Time::now());
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(ErrorCode::cancelled, result.error().code());
    ASSERT_TRUE(!started);
    // A late answer to the abandoned wait starts nothing either.
    waits.pending.back().set_value(7);
    co_await scheduler.wait_sync_work();
    ASSERT_TRUE(!started);
    ASSERT_EQ(1u, waits.started_at.size());
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, StoppingEndsTheDelayAtOnce) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    auto cancellation = std::make_shared<Cancellation>();
    Waits waits;
    auto loop = resolve_initial_state<int>(
                    cancellation, [&]() { return waits.start(); }, [](const td::Status &, td::uint32) {})
                    .start();
    co_await scheduler.wait_sync_work();
    waits.fail_last(ErrorCode::timeout);
    co_await scheduler.wait_sync_work();
    // Now in the 10 s delay.
    scheduler.advance_time(3.0);
    co_await scheduler.wait_sync_work();
    ASSERT_EQ(1u, waits.started_at.size());
    auto before = td::Time::now();
    cancellation->cancel();
    auto result = co_await std::move(loop).wrap();
    ASSERT_EQ(before, td::Time::now());
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(ErrorCode::cancelled, result.error().code());
    // No wait starts after the stop, even once the delay would have ended.
    scheduler.advance_time(600.0);
    co_await scheduler.wait_sync_work();
    ASSERT_EQ(1u, waits.started_at.size());
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, StoppedBeforeTheFirstWait) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    auto cancellation = std::make_shared<Cancellation>();
    cancellation->cancel();
    Waits waits;
    size_t constructed = 0;
    auto result = co_await resolve_initial_state<int>(
                      cancellation,
                      [&]() {
                        constructed++;
                        return waits.start();
                      },
                      [](const td::Status &, td::uint32) {})
                      .wrap();
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(ErrorCode::cancelled, result.error().code());
    co_await scheduler.wait_sync_work();
    // A cancelled resolution neither builds nor starts a wait.
    ASSERT_EQ(0u, constructed);
    ASSERT_EQ(0u, waits.started_at.size());
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, AcceptanceRetriesTransientFailures) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    // timeout, notready, timeout, notready, timeout, then accepted.
    std::vector<int> failures{ErrorCode::timeout, ErrorCode::notready, ErrorCode::timeout, ErrorCode::notready,
                              ErrorCode::timeout};
    std::vector<double> attempts;
    std::vector<td::uint32> retried_after;
    auto accept = accept_with_retries(
                      [&]() -> Task<td::Unit> {
                        attempts.push_back(td::Time::now());
                        if (attempts.size() <= failures.size()) {
                          co_return td::Status::Error(failures[attempts.size() - 1], "not yet");
                        }
                        co_return td::Unit{};
                      },
                      [&](const td::Status &, td::uint32 delay) { retried_after.push_back(delay); })
                      .start();
    double total = 0;
    for (td::uint32 delay : {1u, 2u, 4u, 5u, 5u}) {
      co_await scheduler.wait_sync_work();
      scheduler.advance_time(static_cast<double>(delay));
      total += delay;
    }
    auto result = co_await std::move(accept).wrap();
    ASSERT_TRUE(result.is_ok());
    ASSERT_EQ(6u, attempts.size());
    ASSERT_TRUE(retried_after == (std::vector<td::uint32>{1, 2, 4, 5, 5}));
    ASSERT_TRUE(attempts.back() - attempts.front() >= total - 1e-6);
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, CancelledAcceptanceIsNotReportedAccepted) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    for (int code : {static_cast<int>(ErrorCode::cancelled), static_cast<int>(ErrorCode::error),
                     static_cast<int>(ErrorCode::protoviolation)}) {
      size_t attempts = 0;
      bool reported_accepted = false;
      // The caller reports the block accepted only after the acceptance
      // completes, as the block accepter does.
      auto caller = [&]() -> Task<td::Unit> {
        co_await accept_with_retries(
            [&]() -> Task<td::Unit> {
              attempts++;
              co_return td::Status::Error(code, "acceptance ended");
            },
            [](const td::Status &, td::uint32) {});
        reported_accepted = true;
        co_return td::Unit{};
      };
      auto result = co_await caller().wrap();
      ASSERT_TRUE(result.is_error());
      ASSERT_EQ(code, result.error().code());
      ASSERT_TRUE(!reported_accepted);
      ASSERT_EQ(1u, attempts);
    }
    co_return td::Unit{};
  });
}

TEST(ConsensusRetryBackoff, CancellableSleepEndsAtItsTime) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> Task<td::Unit> {
    auto cancellation = std::make_shared<Cancellation>();
    auto sleep = cancellable_sleep(cancellation, td::Timestamp::in(5.0)).start();
    co_await scheduler.wait_sync_work();
    ASSERT_TRUE(!sleep.await_ready());
    scheduler.advance_time(5.0);
    auto slept = co_await std::move(sleep).wrap();
    ASSERT_TRUE(slept.is_ok());
    // A completed wait leaves nothing behind for a later cancellation.
    auto value = co_await cancellable(cancellation, []() -> Task<int> { co_return 5; }()).wrap();
    ASSERT_TRUE(value.is_ok());
    cancellation->cancel();
    co_return td::Unit{};
  });
}

}  // namespace tos::validator::consensus
