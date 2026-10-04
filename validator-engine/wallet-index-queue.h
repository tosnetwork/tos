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

// Work handed off by a caller that must not wait for it.
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
// is a gap nobody can find later: the queue then latches `degraded()` and
// calls `on_degraded` once, so the owner can say the work is incomplete.
//
// Items not processed by destruction stay recorded and unprocessed.
template <class Id, class Item>
class BoundedWorkQueue {
 public:
  BoundedWorkQueue(size_t capacity, std::function<bool(const std::vector<Id> &)> record,
                   std::function<void(Item &)> process, std::function<void()> on_degraded = nullptr,
                   size_t record_capacity = 0)
      : capacity_(capacity)
      , record_capacity_(record_capacity != 0 ? record_capacity : 16 * capacity)
      , record_(std::move(record))
      , process_(std::move(process))
      , on_degraded_(std::move(on_degraded)) {
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
    bool newly_degraded = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto seq = next_seq_++;
      if (to_record_.size() < record_capacity_) {
        to_record_.emplace_back(seq, std::move(id));
      } else {
        newly_degraded = latch_degraded();
      }
      if (items_.size() < capacity_) {
        items_.emplace_back(seq, std::move(item));
        kept = true;
      } else {
        dropped_++;
      }
    }
    wake_.notify_all();
    if (newly_degraded) {
      notify_degraded();
    }
    return kept;
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
  static constexpr auto kLongestRetryPause = std::chrono::seconds(5);

  // Returns true the first time.
  bool latch_degraded() {
    if (degraded_) {
      return false;
    }
    degraded_ = true;
    return true;
  }

  void notify_degraded() {
    if (!on_degraded_) {
      return;
    }
    try {
      on_degraded_();
    } catch (...) {
    }
  }

  bool call_record(const std::vector<Id> &batch) {
    try {
      return record_(batch);
    } catch (...) {
      return false;
    }
  }

  void run_recorder() {
    std::unique_lock<std::mutex> lock(mutex_);
    auto pause = std::chrono::duration_cast<std::chrono::milliseconds>(kFirstRetryPause);
    while (true) {
      wake_.wait(lock, [this] { return stopping_ || !to_record_.empty(); });
      if (to_record_.empty()) {
        return;  // stopping, nothing left to record
      }
      // The ids stay queued until recorded, so a failure loses nothing and a
      // later push can still join the retry.
      std::vector<Id> batch;
      batch.reserve(to_record_.size());
      for (auto &entry : to_record_) {
        batch.push_back(entry.second);
      }
      auto count = to_record_.size();
      auto last_seq = to_record_.back().first;
      lock.unlock();
      bool recorded = call_record(batch);
      lock.lock();
      if (recorded) {
        to_record_.erase(to_record_.begin(), to_record_.begin() + static_cast<std::ptrdiff_t>(count));
        recorded_through_ = last_seq + 1;
        pause = std::chrono::duration_cast<std::chrono::milliseconds>(kFirstRetryPause);
        wake_.notify_all();
        continue;
      }
      if (stopping_) {
        // Last chance gone: these ids are lost to recovery.
        to_record_.clear();
        bool newly = latch_degraded();
        lock.unlock();
        if (newly) {
          notify_degraded();
        }
        return;
      }
      wake_.wait_for(lock, pause, [this] { return stopping_; });
      pause = std::min(pause * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kLongestRetryPause));
    }
  }

  void run_worker() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (true) {
      // An item whose id was never queued for recording (the id list was
      // full) is past recorded_through_ once a later id is recorded; the gap
      // is already latched as degraded.
      wake_.wait(lock, [this] { return stopping_ || (!items_.empty() && items_.front().first < recorded_through_); });
      if (stopping_) {
        return;
      }
      auto entry = std::move(items_.front());
      items_.pop_front();
      lock.unlock();
      try {
        process_(entry.second);
      } catch (...) {
      }
      lock.lock();
    }
  }

  const size_t capacity_;
  const size_t record_capacity_;
  std::function<bool(const std::vector<Id> &)> record_;
  std::function<void(Item &)> process_;
  std::function<void()> on_degraded_;
  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<std::pair<uint64_t, Id>> to_record_;
  std::deque<std::pair<uint64_t, Item>> items_;
  uint64_t next_seq_ = 0;
  uint64_t recorded_through_ = 0;  // every seq below this is recorded, or latched as lost
  size_t dropped_ = 0;
  bool degraded_ = false;
  bool stopping_ = false;
  std::thread recorder_;
  std::thread worker_;
};

}  // namespace tos_wallet_index
