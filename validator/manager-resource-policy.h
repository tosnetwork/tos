/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <utility>

#include "td/utils/check.h"

namespace tos::validator {

// Actor-owned admission control for distinct asynchronous operations. This
// class is deliberately not thread-safe: callers must mutate it on the owning
// actor and release every admitted key on all completion paths.
template <class Key>
class BoundedActiveOperations {
 public:
  enum class StartResult { Started, AlreadyActive, Full };

  explicit BoundedActiveOperations(std::size_t capacity) : capacity_(capacity) {
    CHECK(capacity_ > 0);
  }

  StartResult try_start(const Key &key) {
    if (active_.contains(key)) {
      return StartResult::AlreadyActive;
    }
    if (active_.size() >= capacity_) {
      return StartResult::Full;
    }
    active_.insert(key);
    return StartResult::Started;
  }

  void finish(const Key &key) {
    CHECK(active_.erase(key) == 1);
  }

  bool contains(const Key &key) const {
    return active_.contains(key);
  }

  std::size_t size() const {
    return active_.size();
  }

  std::size_t capacity() const {
    return capacity_;
  }

 private:
  std::size_t capacity_;
  std::set<Key> active_;
};

// Bounded exact-key idempotence for operations that have separate in-flight
// and completed lifetimes. The completed LRU bounds retained history; callers
// may additionally prune completed entries when their protocol group expires.
template <class Key>
class BoundedIdempotentOperations {
 public:
  enum class StartResult { Started, AlreadyInFlight, AlreadyProcessed, Full };

  BoundedIdempotentOperations(std::size_t max_in_flight, std::size_t max_processed)
      : max_in_flight_(max_in_flight), max_processed_(max_processed) {
    CHECK(max_in_flight_ > 0);
    CHECK(max_processed_ > 0);
  }

  StartResult try_start(const Key &key) {
    if (processed_positions_.contains(key)) {
      touch_processed(key);
      return StartResult::AlreadyProcessed;
    }
    if (in_flight_.contains(key)) {
      return StartResult::AlreadyInFlight;
    }
    if (in_flight_.size() >= max_in_flight_) {
      return StartResult::Full;
    }
    in_flight_.insert(key);
    return StartResult::Started;
  }

  std::optional<Key> finish_success(const Key &key) {
    CHECK(in_flight_.erase(key) == 1);
    processed_order_.push_back(key);
    bool inserted = processed_positions_.emplace(key, std::prev(processed_order_.end())).second;
    CHECK(inserted);
    if (processed_positions_.size() <= max_processed_) {
      return std::nullopt;
    }

    Key evicted = std::move(processed_order_.front());
    processed_positions_.erase(evicted);
    processed_order_.pop_front();
    return evicted;
  }

  void finish_failure(const Key &key) {
    CHECK(in_flight_.erase(key) == 1);
  }

  bool finish_failure_if_present(const Key &key) {
    return in_flight_.erase(key) == 1;
  }

  template <class Predicate>
  std::size_t prune_in_flight(Predicate should_remove) {
    std::size_t removed = 0;
    for (auto it = in_flight_.begin(); it != in_flight_.end();) {
      if (should_remove(*it)) {
        it = in_flight_.erase(it);
        ++removed;
      } else {
        ++it;
      }
    }
    return removed;
  }

  template <class Predicate>
  void prune_processed(Predicate should_remove) {
    for (auto it = processed_positions_.begin(); it != processed_positions_.end();) {
      if (!should_remove(it->first)) {
        ++it;
        continue;
      }
      processed_order_.erase(it->second);
      it = processed_positions_.erase(it);
    }
  }

  bool is_in_flight(const Key &key) const {
    return in_flight_.contains(key);
  }

  bool is_processed(const Key &key) const {
    return processed_positions_.contains(key);
  }

  std::size_t in_flight_size() const {
    return in_flight_.size();
  }

  std::size_t processed_size() const {
    return processed_positions_.size();
  }

  std::size_t in_flight_capacity() const {
    return max_in_flight_;
  }

  std::size_t processed_capacity() const {
    return max_processed_;
  }

 private:
  void touch_processed(const Key &key) {
    auto it = processed_positions_.find(key);
    CHECK(it != processed_positions_.end());
    processed_order_.splice(processed_order_.end(), processed_order_, it->second);
  }

  std::size_t max_in_flight_;
  std::size_t max_processed_;
  std::set<Key> in_flight_;
  std::list<Key> processed_order_;
  std::map<Key, typename std::list<Key>::iterator> processed_positions_;
};

}  // namespace tos::validator
