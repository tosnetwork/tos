/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <utility>

#include "td/actor/actor.h"
#include "td/utils/MpscPollableQueue.h"
#include "td/utils/Observer.h"
#include "td/utils/Status.h"

#include "index-progress.h"

namespace tos::services {

// Who is asking. The replay thread's own reads (the tip, the newest state for
// a drain) use the consumer lane; reads ahead of the replay cursor use the
// prefetch lane, which can be reset without stopping the process.
enum class SourceLane { Consumer, Prefetch };

struct SourceLimits {
  // Source requests outstanding at once, over both lanes: queued for dispatch,
  // dispatched, or completed with a result that has not been taken and
  // released yet. A request keeps its place until its reply object is gone,
  // so a reset or cancelled request still counts until its callback has run.
  size_t requests = 8;
  // Places the prefetch lane can never take, so the replay thread is never
  // refused a read because results it has not reached yet hold every place.
  size_t consumer_reserve = 1;
  // Bytes the prefetch lane may hold: reserved before a request is issued
  // and set to the result's own size when it completes (SourceTicket). A
  // block read reserves the most a block result can hold (4 MiB + 4 KiB), so
  // completions never grow the total: in-flight and completed-but-not-taken
  // block results together are at most min(prefetch places, 15) worst-case
  // reservations, 15 being how many fit in 64 MiB. With the default limit of
  // 8 requests and 1 consumer place that is 7, about 28 MiB. Results hold raw
  // bytes only; cells are decoded by the thread that uses a block.
  size_t prefetch_bytes = size_t{64} << 20;
};

class SourceCore;

// One place in the outstanding-request limit, plus the prefetch bytes it
// holds and the request's deadline. Released when destroyed, on whatever
// thread drops the last owner.
class SourceTicket {
 public:
  using Deadline = std::chrono::steady_clock::time_point;
  SourceTicket() = default;
  SourceTicket(std::shared_ptr<SourceCore> core, SourceLane lane, uint64_t generation, size_t bytes, Deadline deadline,
               uint64_t serial);
  SourceTicket(SourceTicket&& other) noexcept;
  SourceTicket& operator=(SourceTicket&& other) noexcept;
  SourceTicket(const SourceTicket&) = delete;
  SourceTicket& operator=(const SourceTicket&) = delete;
  ~SourceTicket();
  // Replace the bytes held with `bytes`. The caller holds the core mutex.
  void set_bytes_locked(size_t bytes);
  // The request has completed: its deadline no longer applies, though its
  // place is kept until the result is released. The caller holds the mutex.
  void completed_locked();
  bool empty() const {
    return core_ == nullptr;
  }
  Deadline deadline() const {
    return deadline_;
  }

 private:
  void release();
  std::shared_ptr<SourceCore> core_;
  SourceLane lane_ = SourceLane::Consumer;
  uint64_t generation_ = 0;
  size_t bytes_ = 0;
  Deadline deadline_{};
  uint64_t serial_ = 0;
};

// Prefetch bytes held without a request place, such as handles a prefetched
// interval keeps until the replay thread has walked it. Never blocks.
class SourceCharge {
 public:
  SourceCharge() = default;
  SourceCharge(std::shared_ptr<SourceCore> core, size_t bytes);
  SourceCharge(SourceCharge&& other) noexcept;
  SourceCharge& operator=(SourceCharge&& other) noexcept;
  SourceCharge(const SourceCharge&) = delete;
  SourceCharge& operator=(const SourceCharge&) = delete;
  ~SourceCharge();

 private:
  void release();
  std::shared_ptr<SourceCore> core_;
  size_t bytes_ = 0;
};

// The state shared by the replay thread, the prefetch thread, the inbox actor
// and every request callback. One mutex and one condition variable cover the
// request limit, the byte budget, every reply and the prefetch buffer, so a
// shutdown or a reset wakes every waiter with one notification.
class SourceCore : public std::enable_shared_from_this<SourceCore> {
 public:
  static td::Result<std::shared_ptr<SourceCore>> create(SourceLimits limits);
  ~SourceCore();
  SourceCore(const SourceCore&) = delete;
  SourceCore& operator=(const SourceCore&) = delete;

  std::mutex& mutex() {
    return mutex_;
  }
  std::condition_variable& cv() {
    return cv_;
  }
  const SourceLimits& limits() const {
    return limits_;
  }
  SourceCounters& counters() {
    return counters_;
  }

  // Terminal: refuse new requests, cancel every waiter, drop queued closures
  // unrun. Also reached through the process stop flag.
  void shutdown();
  // Start a new prefetch generation: waiters of the previous one return
  // cancelled, and its late results can only reach replies nobody holds.
  uint64_t reset_prefetch();
  uint64_t reset_prefetch_locked();
  uint64_t generation();

  // The caller holds mutex().
  bool stopping_locked() const;
  uint64_t generation_locked() const {
    return generation_;
  }
  bool current_locked(SourceLane lane, uint64_t generation) const {
    return lane == SourceLane::Consumer || generation == generation_;
  }
  // Block until a request place (and, for the prefetch lane, `reserve_bytes`)
  // is available. Cancelled by shutdown, and for the prefetch lane by a reset.
  // The request must complete within `timeout` of being admitted.
  td::Result<SourceTicket> acquire(SourceLane lane, uint64_t generation, size_t reserve_bytes,
                                   std::chrono::milliseconds timeout);
  // Wait on the shared condition variable for at most `limit`, and at most
  // 100 ms, so a stop flag set by a signal handler is noticed without a
  // notification. Every wait also enforces the deadline of every
  // outstanding request, including ones nobody waits for any more: a request
  // that outlives it stops the process.
  void wait_locked(std::unique_lock<std::mutex>& lock, std::chrono::steady_clock::time_point limit);
  // Why a wait was cut short: a request timed out, or the process stops.
  td::Status cancelled_locked() const;

  // Queue a closure for the inbox actor, waking it. Refused after shutdown;
  // a refused or never-run closure is destroyed, releasing what it holds.
  bool push(std::function<void()> closure);
  // Run every queued closure. Only the inbox actor calls this.
  void run_inbox();
  td::EventFd& inbox_event_fd() {
    return inbox_.reader_get_event_fd();
  }

  bool timed_out() const {
    return timed_out_.load();
  }
  // A request outlived its deadline: the process stops and exits nonzero.
  void mark_timed_out_locked();

  // Accounting, for tests and statistics. The caller holds mutex().
  size_t outstanding_locked() const {
    return outstanding_;
  }
  size_t prefetch_outstanding_locked() const {
    return prefetch_outstanding_;
  }
  size_t prefetch_bytes_locked() const {
    return prefetch_bytes_;
  }

 private:
  friend class SourceTicket;
  friend class SourceCharge;
  explicit SourceCore(SourceLimits limits);
  void add_bytes_locked(size_t bytes);
  void remove_bytes_locked(size_t bytes);
  void release_ticket(SourceLane lane, uint64_t generation, size_t bytes, SourceTicket::Deadline deadline,
                      uint64_t serial);
  void clear_deadline_locked(SourceTicket::Deadline deadline, uint64_t serial);

  SourceLimits limits_;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool shut_down_ = false;
  uint64_t generation_ = 1;
  size_t outstanding_ = 0;
  size_t prefetch_outstanding_ = 0;
  // Prefetch-lane places of the current generation; when there are none, the
  // next prefetch request is admitted whatever the byte budget says, so the
  // result the replay thread needs next can always be fetched.
  size_t current_prefetch_ = 0;
  size_t prefetch_bytes_ = 0;
  // The deadline of every outstanding request, earliest first.
  std::set<std::pair<SourceTicket::Deadline, uint64_t>> deadlines_;
  uint64_t next_serial_ = 0;
  std::atomic<bool> timed_out_{false};
  SourceCounters counters_;
  td::MpscPollableQueue<std::function<void()>> inbox_;
};

// The result of one request. Completion, cancellation and timeout are each
// decided once, under the core mutex; whichever comes first wins.
template <class T>
class SourceReply {
 public:
  enum class State { Pending, Completed, Cancelled, TimedOut, Taken };
  SourceReply(std::shared_ptr<SourceCore> core, SourceTicket ticket, SourceLane lane, uint64_t generation)
      : core_(std::move(core))
      , ticket_(std::move(ticket))
      , lane_(lane)
      , generation_(generation)
      , submitted_(std::chrono::steady_clock::now())
      , deadline_(ticket_.deadline()) {
  }
  SourceReply(const SourceReply&) = delete;
  SourceReply& operator=(const SourceReply&) = delete;

  // From the request's promise. `bytes` is the prefetch charge the result
  // keeps while it waits to be taken; a result that lost is dropped.
  void complete(td::Result<T> result, size_t bytes) {
    std::unique_lock<std::mutex> lock(core_->mutex());
    complete_locked(std::move(result), bytes);
    lock.unlock();
    // `result` may still hold a dropped late result: it is destroyed here,
    // outside the mutex.
  }
  // The same with the core mutex held, for completing at a chosen moment.
  void complete_locked(td::Result<T>&& result, size_t bytes) {
    if (state_ != State::Pending) {
      return;
    }
    if (std::chrono::steady_clock::now() >= deadline_) {
      // Too late: the request timed out, whether or not a waiter has seen it
      // yet. The result is never published; the deadline is cleared so it is
      // not reported again, and the reservation stays with the ticket until
      // the reply is released.
      state_ = State::TimedOut;
      ticket_.completed_locked();
      core_->mark_timed_out_locked();
      return;
    }
    state_ = State::Completed;
    result_ = std::move(result);
    ticket_.completed_locked();
    if (lane_ == SourceLane::Prefetch) {
      ticket_.set_bytes_locked(bytes);
    }
    auto elapsed = std::chrono::steady_clock::now() - submitted_;
    core_->counters().completed.fetch_add(1, std::memory_order_relaxed);
    core_->counters().service_us.fetch_add(
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count()),
        std::memory_order_relaxed);
    core_->cv().notify_all();
  }

  // Block until the reply is decided and take its result once. A shutdown,
  // or for a prefetch request a reset, cancels it; the deadline times it out.
  td::Result<T> take() {
    std::unique_lock<std::mutex> lock(core_->mutex());
    while (state_ == State::Pending) {
      if (core_->stopping_locked() || !core_->current_locked(lane_, generation_)) {
        state_ = core_->timed_out() ? State::TimedOut : State::Cancelled;
        break;
      }
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline_) {
        state_ = State::TimedOut;
        core_->mark_timed_out_locked();
        break;
      }
      core_->wait_locked(lock, deadline_);
    }
    switch (state_) {
      case State::Completed: {
        state_ = State::Taken;
        auto result = std::move(result_);
        result_ = td::Status::Error("source result already taken");
        return result;
      }
      case State::TimedOut:
        return td::Status::Error("source request timed out; restart to retry from the durable checkpoint");
      case State::Cancelled:
        return td::Status::Error("source request cancelled");
      case State::Taken:
        return td::Status::Error("source result already taken");
      case State::Pending:
        break;
    }
    return td::Status::Error("source request cancelled");
  }

 private:
  std::shared_ptr<SourceCore> core_;
  SourceTicket ticket_;
  SourceLane lane_;
  uint64_t generation_;
  std::chrono::steady_clock::time_point submitted_;
  std::chrono::steady_clock::time_point deadline_;
  State state_ = State::Pending;
  td::Result<T> result_ = td::Status::Error("source request pending");
};

// Runs queued source requests in actor context as soon as they are queued:
// the queue's event descriptor is in the io worker's poll set, so a request
// never waits for the scheduler loop to come round.
class SourceInbox final : public td::actor::Actor, public td::ObserverBase {
 public:
  explicit SourceInbox(std::shared_ptr<SourceCore> core) : core_(std::move(core)) {
  }
  void start_up() override;
  void tear_down() override;
  void loop() override;
  void notify() override;

  static td::actor::ActorOwn<SourceInbox> create(std::shared_ptr<SourceCore> core);

 private:
  std::shared_ptr<SourceCore> core_;
  td::actor::ActorId<SourceInbox> self_;
};

}  // namespace tos::services
