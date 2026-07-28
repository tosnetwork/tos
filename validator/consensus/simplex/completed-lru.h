/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <list>
#include <map>
#include <optional>
#include <utility>

#include "td/utils/check.h"

namespace tos::validator::consensus::simplex {

// Tracks only completed cache entries. In-flight entries deliberately never
// enter this index, so callers can evict the returned key without invalidating
// a coroutine that still owns a reference to its map element.
template <class Key>
class CompletedLru {
 public:
  explicit CompletedLru(size_t capacity) : capacity_(capacity) {
    CHECK(capacity_ > 0);
  }

  std::optional<Key> touch(const Key& key) {
    auto it = positions_.find(key);
    if (it != positions_.end()) {
      order_.splice(order_.end(), order_, it->second);
      return std::nullopt;
    }

    order_.push_back(key);
    positions_.emplace(key, std::prev(order_.end()));
    if (positions_.size() <= capacity_) {
      return std::nullopt;
    }

    Key evicted = std::move(order_.front());
    positions_.erase(evicted);
    order_.pop_front();
    return evicted;
  }

  void erase(const Key& key) {
    auto it = positions_.find(key);
    if (it == positions_.end()) {
      return;
    }
    order_.erase(it->second);
    positions_.erase(it);
  }

  bool contains(const Key& key) const {
    return positions_.contains(key);
  }

  size_t size() const {
    return positions_.size();
  }

  size_t capacity() const {
    return capacity_;
  }

 private:
  size_t capacity_;
  std::list<Key> order_;
  std::map<Key, typename std::list<Key>::iterator> positions_;
};

}  // namespace tos::validator::consensus::simplex
