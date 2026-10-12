/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

#include "common/errorcode.h"
#include "td/actor/actor.h"
#include "td/actor/coro_task.h"
#include "td/actor/coro_utils.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"

namespace tos::validator::consensus {

// Delays between retries, in whole seconds: `initial` first, doubled after
// each retry, never above `cap`.
struct BackoffPolicy {
  td::uint32 initial;
  td::uint32 cap;
};

// A consensus group resolving its initial chain state waits once for as long
// as the shard client waits for a state, then retries with these delays for
// as long as it lives, logging at most one retry line per interval.
constexpr double INITIAL_STATE_WAIT_TIMEOUT = 1500.0;
constexpr BackoffPolicy INITIAL_STATE_BACKOFF{10, 300};
constexpr double INITIAL_STATE_RETRY_LOG_INTERVAL = 300.0;

// Accepting a finalized block retries a transient failure quickly.
constexpr BackoffPolicy ACCEPT_BLOCK_BACKOFF{1, 5};

// Only a timed-out wait is worth another initial resolution; anything else
// is the group's answer.
inline bool is_transient_initial_state_error(const td::Status &error) {
  return error.code() == ErrorCode::timeout;
}

// The manager could not accept the block yet. A cancellation or any other
// error ends the acceptance with that error.
inline bool is_transient_accept_error(const td::Status &error) {
  return error.code() == ErrorCode::timeout || error.code() == ErrorCode::notready;
}

class Backoff {
 public:
  explicit Backoff(BackoffPolicy policy) : cap_(policy.cap), next_(std::min(policy.initial, policy.cap)) {
  }

  td::uint32 next_delay() {
    td::uint32 delay = next_;
    next_ = next_ > cap_ / 2 ? cap_ : next_ * 2;
    return delay;
  }

 private:
  td::uint32 cap_;
  td::uint32 next_;
};

// Lets the first retry of an operation log, then at most one line per
// `interval`, and counts the lines it held back. It lives as long as the
// operation, so a long run of failures shares one budget.
class RetryLogLimiter {
 public:
  explicit RetryLogLimiter(double interval) : interval_(interval) {
  }

  // True when this retry may log; `held_back` is then the number of retries
  // that did not since the previous line.
  bool allow(td::Timestamp now, td::uint64 &held_back) {
    if (last_ && now.at() - last_.at() < interval_) {
      held_back_++;
      return false;
    }
    held_back = held_back_;
    held_back_ = 0;
    last_ = now;
    return true;
  }

 private:
  double interval_;
  td::Timestamp last_;
  td::uint64 held_back_ = 0;
};

// A one-shot cancellation that wakes whatever waits on it at once, instead of
// leaving it to notice at its next step. Safe to use from any thread.
class Cancellation {
 public:
  void cancel() {
    std::map<td::uint64, std::function<void()>> waiters;
    {
      std::unique_lock lock(mutex_);
      if (cancelled_) {
        return;
      }
      cancelled_ = true;
      waiters.swap(waiters_);
    }
    for (auto &[id, waiter] : waiters) {
      waiter();
    }
  }

  bool is_cancelled() const {
    std::unique_lock lock(mutex_);
    return cancelled_;
  }

  // Registers `waiter` to run once on cancellation; if that has already
  // happened it runs now and nothing is registered.
  std::optional<td::uint64> subscribe(std::function<void()> waiter) {
    {
      std::unique_lock lock(mutex_);
      if (!cancelled_) {
        auto id = next_id_++;
        waiters_.emplace(id, std::move(waiter));
        return id;
      }
    }
    waiter();
    return std::nullopt;
  }

  void unsubscribe(std::optional<td::uint64> id) {
    if (!id) {
      return;
    }
    std::unique_lock lock(mutex_);
    waiters_.erase(*id);
  }

 private:
  mutable std::mutex mutex_;
  bool cancelled_ = false;
  td::uint64 next_id_ = 0;
  std::map<td::uint64, std::function<void()>> waiters_;
};

inline td::Status cancelled_error() {
  return td::Status::Error(ErrorCode::cancelled, "cancelled");
}

// The result of `task`, or `cancelled` as soon as `cancellation` fires,
// whichever comes first. A cancelled task runs on to its own end; only its
// result is dropped.
template <class T>
td::actor::Task<T> cancellable(std::shared_ptr<Cancellation> cancellation, td::actor::StartedTask<T> task) {
  auto [result, promise] = td::actor::StartedTask<T>::make_bridge();
  struct Shared {
    explicit Shared(td::Promise<T> promise) : promise(std::move(promise)) {
    }
    td::Promise<T> promise;
    std::atomic_flag settled;
  };
  auto shared = std::make_shared<Shared>(std::move(promise));
  auto id = cancellation->subscribe([shared] {
    if (!shared->settled.test_and_set()) {
      shared->promise.set_error(cancelled_error());
    }
  });
  auto wait = [](td::actor::StartedTask<T> task, std::shared_ptr<Shared> shared,
                 std::shared_ptr<Cancellation> cancellation, std::optional<td::uint64> id) -> td::actor::Task<> {
    co_await td::actor::detach_from_actor();
    auto r = co_await std::move(task).wrap();
    cancellation->unsubscribe(id);
    if (!shared->settled.test_and_set()) {
      shared->promise.set_result(std::move(r));
    }
    co_return td::Unit{};
  };
  wait(std::move(task), shared, cancellation, id).start().detach_silent();
  co_return co_await std::move(result);
}

template <class T>
td::actor::Task<T> cancellable(std::shared_ptr<Cancellation> cancellation, td::actor::Task<T> task) {
  co_return co_await cancellable(std::move(cancellation), std::move(task).start());
}

// Sleeps until `at`, or fails with `cancelled` as soon as `cancellation`
// fires; the timer does not outlive a cancellation.
inline td::actor::Task<td::Unit> cancellable_sleep(std::shared_ptr<Cancellation> cancellation, td::Timestamp at) {
  class Timer : public td::actor::Actor {
   public:
    Timer(td::actor::StartedTask<td::Unit>::ExternalPromise promise, td::Timestamp at)
        : promise_(std::move(promise)), at_(at) {
    }
    void cancel() {
      if (promise_) {
        promise_.set_error(cancelled_error());
      }
      stop();
    }

   private:
    void start_up() override {
      alarm_timestamp() = at_;
    }
    void alarm() override {
      if (promise_) {
        promise_.set_value(td::Unit{});
      }
      stop();
    }

    td::actor::StartedTask<td::Unit>::ExternalPromise promise_;
    td::Timestamp at_;
  };
  auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
  auto timer = td::actor::create_actor<Timer>("cancellable-sleep", std::move(promise), at).release();
  auto id = cancellation->subscribe([timer] { td::actor::send_closure(timer, &Timer::cancel); });
  auto r = co_await std::move(task).wrap();
  cancellation->unsubscribe(id);
  co_return std::move(r);
}

// Runs `attempt` until it succeeds or fails with an error `transient` does
// not accept, sleeping between attempts for the delays `backoff` gives. One
// attempt runs at a time. `on_retry` sees each retried error with the delay
// before the next attempt; a sleep that fails (a cancellation) ends the loop
// with its error.
template <class T, class Attempt, class Transient, class Sleep, class OnRetry>
td::actor::Task<T> retry_with_backoff(Attempt attempt, Transient transient, Backoff backoff, Sleep sleep,
                                      OnRetry on_retry) {
  while (true) {
    auto result = co_await attempt().wrap();
    if (result.is_ok() || !transient(result.error())) {
      co_return std::move(result);
    }
    td::uint32 delay = backoff.next_delay();
    on_retry(result.error(), delay);
    auto slept = co_await sleep(delay).wrap();
    if (slept.is_error()) {
      co_return slept.move_as_error();
    }
  }
}

// The initial chain-state resolution of a consensus group. `wait` starts one
// wait bounded by INITIAL_STATE_WAIT_TIMEOUT; a timed-out wait is retried with
// INITIAL_STATE_BACKOFF for as long as it takes, any other result ends it. A
// cancellation ends the wait or the delay between waits at once.
template <class T, class Wait, class OnRetry>
td::actor::Task<T> resolve_initial_state(std::shared_ptr<Cancellation> cancellation, Wait wait, OnRetry on_retry) {
  co_return co_await retry_with_backoff<T>(
      [&]() { return cancellable(cancellation, wait()); }, is_transient_initial_state_error,
      Backoff{INITIAL_STATE_BACKOFF},
      [&](td::uint32 delay) { return cancellable_sleep(cancellation, td::Timestamp::in(delay)); }, std::move(on_retry));
}

// Acceptance of a finalized block. `attempt` makes one acceptance attempt;
// a transient failure is retried with ACCEPT_BLOCK_BACKOFF, and a
// cancellation or a permanent error is returned, so the caller never reports
// the block accepted when it was not.
template <class Attempt, class OnRetry>
td::actor::Task<td::Unit> accept_with_retries(Attempt attempt, OnRetry on_retry) {
  co_return co_await retry_with_backoff<td::Unit>(
      std::move(attempt), is_transient_accept_error, Backoff{ACCEPT_BLOCK_BACKOFF},
      [](td::uint32 delay) { return td::actor::coro_sleep(td::Timestamp::in(delay)); }, std::move(on_retry));
}

}  // namespace tos::validator::consensus
