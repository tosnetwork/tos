/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace tos_wallet_index {

// Work handed off by a caller that must not wait for it. push() takes a lock
// briefly and never does I/O.
//
// Every pushed id is first recorded, in batches, by `record` on a recorder
// thread: for the wallet index that is the durable "not yet indexed" mark that
// startup recovery reads. Only once `record` reports success is the matching
// item handed to `process` on a worker thread, in push order. A batch that
// fails is kept and retried with a growing pause, and nothing it covers is
// processed meanwhile.
//
// At most `capacity` items wait for the worker; an item that does not fit is
// dropped, and its id still waits to be recorded, so the gap is known. Ids
// are small, so more of them, `record_capacity`, may wait. An id that cannot be
// recorded at all (the id list is full, or recording still fails at shutdown)
// is a gap nobody can find later: the queue then latches `degraded()`, and the
// recorder thread calls `persist_degraded` until it succeeds, so the owner can
// say durably that the work is incomplete.
//
// The worker can be held (start paused, pause()) and released (resume());
// pushes are still recorded meanwhile. Items not processed by destruction stay
// recorded and unprocessed.
//
// While no item is ready and the worker is not held, it calls `idle` (when
// given), which does a bounded piece of background work and returns whether
// more may be ready at once; after a pass that found nothing, it waits for an
// item, or kIdleRecheck, before trying again.
template <class Id, class Item>
class BoundedWorkQueue {
 public:
  BoundedWorkQueue(size_t capacity, std::function<bool(const std::vector<Id> &)> record,
                   std::function<void(Item &)> process, std::function<bool()> persist_degraded = nullptr,
                   size_t record_capacity = 0, bool start_paused = false, std::function<bool()> idle = nullptr)
      : capacity_(capacity)
      , record_capacity_(record_capacity != 0 ? record_capacity : 16 * capacity)
      , record_(std::move(record))
      , process_(std::move(process))
      , persist_degraded_(std::move(persist_degraded))
      , idle_(std::move(idle))
      , paused_(start_paused) {
    recorder_ = std::thread([this] { run_recorder(); });
    worker_ = std::thread([this] { run_worker(); });
  }

  BoundedWorkQueue(const BoundedWorkQueue &) = delete;
  BoundedWorkQueue &operator=(const BoundedWorkQueue &) = delete;

  ~BoundedWorkQueue() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    wake_.notify_all();
    worker_.join();
    recorder_.join();
  }

  // Returns at once. False when the item was dropped.
  bool push(Id id, Item item) {
    bool kept = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto seq = next_seq_++;
      if (to_record_.size() < record_capacity_) {
        to_record_.emplace_back(seq, std::move(id));
      } else {
        latch_degraded();
      }
      if (items_.size() < capacity_) {
        items_.emplace_back(seq, std::move(item));
        kept = true;
      } else {
        dropped_++;
      }
    }
    wake_.notify_all();
    return kept;
  }

  // Returns at once. Records `id` without any work to go with it: the work
  // is not done in this run, and the record is what keeps it findable.
  void record(Id id) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto seq = next_seq_++;
      if (to_record_.size() < record_capacity_) {
        to_record_.emplace_back(seq, std::move(id));
      } else {
        latch_degraded();
      }
    }
    wake_.notify_all();
  }

  // Returns at once. Records that some work was lost beyond recovery: the
  // queue latches degraded, and the recorder persists it.
  void latch_lost() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      latch_degraded();
    }
    wake_.notify_all();
  }

  void pause() {
    std::lock_guard<std::mutex> lock(mutex_);
    paused_ = true;
  }

  void resume() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      paused_ = false;
    }
    wake_.notify_all();
  }

  // Wait, at most `limit`, until every id pushed so far is recorded and any
  // degraded state is persisted. True when that happened in time.
  bool wait_recorded(std::chrono::milliseconds limit) {
    std::unique_lock<std::mutex> lock(mutex_);
    return wake_.wait_for(lock, limit, [this] { return to_record_.empty() && !degraded_unpersisted_; });
  }

  size_t dropped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
  }
  bool degraded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return degraded_;
  }

 private:
  static constexpr auto kFirstRetryPause = std::chrono::milliseconds(50);
  static constexpr auto kIdleRecheck = std::chrono::milliseconds(1000);
  static constexpr auto kLongestRetryPause = std::chrono::milliseconds(5000);

  void latch_degraded() {
    if (!degraded_) {
      degraded_ = true;
      degraded_unpersisted_ = persist_degraded_ != nullptr;
    }
  }

  template <class F>
  static bool call_safely(F &&f) {
    try {
      return f();
    } catch (...) {
      return false;
    }
  }

  void run_recorder() {
    std::unique_lock<std::mutex> lock(mutex_);
    auto pause = kFirstRetryPause;
    while (true) {
      wake_.wait(lock, [this] { return stopping_ || !to_record_.empty() || degraded_unpersisted_; });
      bool failed = false;
      if (!to_record_.empty()) {
        // The ids stay queued until recorded, so a failure loses nothing and
        // later pushes join the retry.
        std::vector<Id> batch;
        batch.reserve(to_record_.size());
        for (auto &entry : to_record_) {
          batch.push_back(entry.second);
        }
        auto count = to_record_.size();
        auto last_seq = to_record_.back().first;
        lock.unlock();
        bool recorded = call_safely([&] { return record_(batch); });
        lock.lock();
        if (recorded) {
          to_record_.erase(to_record_.begin(), to_record_.begin() + static_cast<std::ptrdiff_t>(count));
          recorded_through_ = last_seq + 1;
        } else {
          failed = true;
          if (stopping_) {
            // Last chance gone: these ids are lost to recovery.
            to_record_.clear();
            latch_degraded();
          }
        }
      }
      if (degraded_unpersisted_) {
        lock.unlock();
        bool persisted = call_safely([&] { return persist_degraded_(); });
        lock.lock();
        if (persisted) {
          degraded_unpersisted_ = false;
        } else {
          failed = true;
        }
      }
      wake_.notify_all();
      if (stopping_ && (to_record_.empty() || failed) && (!degraded_unpersisted_ || failed)) {
        return;
      }
      if (failed) {
        wake_.wait_for(lock, pause, [this] { return stopping_; });
        pause = std::min(pause * 2, kLongestRetryPause);
      } else {
        pause = kFirstRetryPause;
      }
    }
  }

  bool item_ready() const {
    // An item whose id was never queued for recording (the id list was
    // full) is past recorded_through_ once a later id is recorded; the gap
    // is already latched as degraded.
    return !paused_ && !items_.empty() && items_.front().first < recorded_through_;
  }

  void run_worker() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (true) {
      if (stopping_) {
        return;
      }
      if (item_ready()) {
        auto entry = std::move(items_.front());
        items_.pop_front();
        lock.unlock();
        try {
          process_(entry.second);
        } catch (...) {
        }
        lock.lock();
        continue;
      }
      if (idle_ && !paused_) {
        lock.unlock();
        bool more = call_safely(idle_);
        lock.lock();
        if (more) {
          continue;
        }
        wake_.wait_for(lock, kIdleRecheck, [this] { return stopping_ || item_ready(); });
        continue;
      }
      wake_.wait(lock, [this] { return stopping_ || item_ready() || (idle_ && !paused_); });
    }
  }

  const size_t capacity_;
  const size_t record_capacity_;
  std::function<bool(const std::vector<Id> &)> record_;
  std::function<void(Item &)> process_;
  std::function<bool()> persist_degraded_;
  std::function<bool()> idle_;
  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<std::pair<uint64_t, Id>> to_record_;
  std::deque<std::pair<uint64_t, Item>> items_;
  uint64_t next_seq_ = 0;
  uint64_t recorded_through_ = 0;  // every seq below this is recorded, or latched as lost
  size_t dropped_ = 0;
  bool degraded_ = false;
  bool degraded_unpersisted_ = false;
  bool paused_ = false;
  bool stopping_ = false;
  std::thread recorder_;
  std::thread worker_;
};

}  // namespace tos_wallet_index
