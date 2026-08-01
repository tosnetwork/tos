/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <utility>

namespace tos::validator {

// Keeps one weak reference per key while allowing expired entries to be
// reclaimed incrementally. A key cursor is used instead of a persistent map
// iterator because ordinary lookups are also allowed to erase expired entries.
template <class Key, class Value>
class WeakPtrRegistry {
 public:
  struct Stats {
    std::size_t entries{0};
    std::uint64_t sweep_scanned{0};
    std::uint64_t sweep_removed{0};
    std::uint64_t lookup_removed{0};
    std::uint64_t sweep_passes{0};
  };

  std::shared_ptr<Value> get(const Key &key) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return {};
    }
    auto value = it->second.lock();
    if (value) {
      return value;
    }
    entries_.erase(it);
    ++lookup_removed_;
    return {};
  }

  bool insert(const Key &key, const std::shared_ptr<Value> &value) {
    return entries_.emplace(key, std::weak_ptr<Value>(value)).second;
  }

  void sweep_expired(std::size_t budget) {
    if (budget == 0 || entries_.empty()) {
      if (entries_.empty()) {
        sweep_after_.reset();
      }
      return;
    }

    auto it = sweep_after_ ? entries_.upper_bound(*sweep_after_) : entries_.begin();
    if (it == entries_.end()) {
      sweep_after_.reset();
      ++sweep_passes_;
      it = entries_.begin();
    }

    while (it != entries_.end() && budget-- > 0) {
      Key inspected_key = it->first;
      ++sweep_scanned_;
      if (it->second.expired()) {
        it = entries_.erase(it);
        ++sweep_removed_;
      } else {
        ++it;
      }
      sweep_after_ = std::move(inspected_key);
    }

    if (it == entries_.end()) {
      sweep_after_.reset();
      ++sweep_passes_;
    }
  }

  std::size_t size() const {
    return entries_.size();
  }

  Stats stats() const {
    return Stats{entries_.size(), sweep_scanned_, sweep_removed_, lookup_removed_, sweep_passes_};
  }

 private:
  std::map<Key, std::weak_ptr<Value>> entries_;
  std::optional<Key> sweep_after_;
  std::uint64_t sweep_scanned_{0};
  std::uint64_t sweep_removed_{0};
  std::uint64_t lookup_removed_{0};
  std::uint64_t sweep_passes_{0};
};

}  // namespace tos::validator
