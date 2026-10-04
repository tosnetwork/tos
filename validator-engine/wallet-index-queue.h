/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

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
// startup recovery reads. Only then is its item handed to `process` on a
// worker thread, in push order, so work is never done before the record that
// covers it exists. At most `capacity` items wait for the worker; an item that
// does not fit is dropped (its id is still recorded, so the gap is known). Ids
// are small, so more of them, `record_capacity`, may wait for the recorder;
// past that they are only counted. Items not processed by destruction stay
// recorded and unprocessed.
template <class Id, class Item>
class BoundedWorkQueue {
 public:
  BoundedWorkQueue(size_t capacity, std::function<void(const std::vector<Id> &)> record,
                   std::function<void(Item &)> process, size_t record_capacity = 0)
      : capacity_(capacity)
      , record_capacity_(record_capacity != 0 ? record_capacity : 16 * capacity)
      , record_(std::move(record))
      , process_(std::move(process)) {
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
        unrecorded_++;
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

  size_t dropped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
  }
  // Ids that could not be recorded because the recorder was too far behind.
  size_t unrecorded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return unrecorded_;
  }

 private:
  void run_recorder() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (true) {
      wake_.wait(lock, [this] { return stopping_ || !to_record_.empty(); });
      if (to_record_.empty()) {
        return;  // stopping, nothing left to record
      }
      std::vector<Id> batch;
      uint64_t last_seq = 0;
      batch.reserve(to_record_.size());
      for (auto &entry : to_record_) {
        last_seq = entry.first;
        batch.push_back(std::move(entry.second));
      }
      to_record_.clear();
      lock.unlock();
      record_(batch);
      lock.lock();
      recorded_through_ = last_seq + 1;
      wake_.notify_all();
    }
  }

  void run_worker() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (true) {
      wake_.wait(lock, [this] { return stopping_ || (!items_.empty() && items_.front().first < recorded_through_); });
      if (stopping_) {
        return;
      }
      auto entry = std::move(items_.front());
      items_.pop_front();
      lock.unlock();
      process_(entry.second);
      lock.lock();
    }
  }

  const size_t capacity_;
  const size_t record_capacity_;
  std::function<void(const std::vector<Id> &)> record_;
  std::function<void(Item &)> process_;
  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<std::pair<uint64_t, Id>> to_record_;
  std::deque<std::pair<uint64_t, Item>> items_;
  uint64_t next_seq_ = 0;
  uint64_t recorded_through_ = 0;  // every seq below this is recorded
  size_t dropped_ = 0;
  size_t unrecorded_ = 0;
  bool stopping_ = false;
  std::thread recorder_;
  std::thread worker_;
};

}  // namespace tos_wallet_index
