/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <algorithm>
#include <map>
#include <tuple>
#include <utility>

#include "td/utils/check.h"

namespace tos::validator::consensus::simplex {

// A map of finalization entries that keeps, as it changes, the number of entries not yet in
// the terminal Finalized state and the most there have been at once. Counting by walking the
// map costs a pass over up to the whole finalized cache on every call; this keeps the same
// number current at each state change instead.
//
// Every insertion goes through entry_for() and every state change through set_state(), so
// the count cannot drift from the entries. Entry is default-constructible and has a public
// `state` member.
template <typename Key, typename Entry, typename State, State Finalized>
class CountedFinalizations {
 public:
  using Map = std::map<Key, Entry>;
  using iterator = typename Map::iterator;
  using const_iterator = typename Map::const_iterator;

  // The entry for `key`. A new entry is constructed directly in `initial`; an existing one
  // is returned untouched, whatever `initial` says.
  Entry& entry_for(const Key& key, State initial) {
    auto it = map_.find(key);
    if (it != map_.end()) {
      return it->second;
    }
    Entry entry{};
    entry.state = initial;
    bool inserted = false;
    std::tie(it, inserted) = map_.emplace(key, std::move(entry));
    CHECK(inserted);
    if (initial != Finalized) {
      increment();
    }
    return it->second;
  }

  // Moves `entry` to `next`, counting a crossing of the Finalized boundary in either
  // direction. Assigning the state it already has changes nothing.
  void set_state(Entry& entry, State next) {
    const bool was_unfinalized = entry.state != Finalized;
    const bool is_unfinalized = next != Finalized;
    entry.state = next;
    if (was_unfinalized && !is_unfinalized) {
      decrement();
    } else if (!was_unfinalized && is_unfinalized) {
      increment();
    }
  }

  // Removes a Finalized entry. A Finalized entry is not counted, so the count is unchanged.
  void erase_finalized(iterator it) {
    CHECK(it->second.state == Finalized);
    map_.erase(it);
  }

  iterator find(const Key& key) {
    return map_.find(key);
  }
  iterator begin() {
    return map_.begin();
  }
  iterator end() {
    return map_.end();
  }
  const_iterator begin() const {
    return map_.begin();
  }
  const_iterator end() const {
    return map_.end();
  }
  size_t size() const {
    return map_.size();
  }

  size_t unfinalized() const {
    return unfinalized_;
  }
  size_t unfinalized_peak() const {
    return unfinalized_peak_;
  }

  // The same number counted the slow way, for cross-checks only.
  size_t count_by_walk() const {
    size_t held = 0;
    for (const auto& [_, entry] : map_) {
      held += entry.state != Finalized ? 1 : 0;
    }
    return held;
  }

 private:
  void increment() {
    // The count is bounded by the number of entries, so it cannot reach the maximum while
    // the map holds them; the check keeps that a stated invariant rather than an assumption.
    CHECK(unfinalized_ < map_.size());
    ++unfinalized_;
    unfinalized_peak_ = std::max(unfinalized_peak_, unfinalized_);
  }
  void decrement() {
    CHECK(unfinalized_ > 0);
    --unfinalized_;
  }

  Map map_;
  size_t unfinalized_ = 0;
  size_t unfinalized_peak_ = 0;
};

}  // namespace tos::validator::consensus::simplex
