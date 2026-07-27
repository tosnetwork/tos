/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "td/utils/int_types.h"

namespace tos::validator::consensus::simplex {

// Deduplicates values while keeping enough slot information to discard
// entries that can no longer be referenced after finalization.
template <class Value>
class FinalizedSlotDedup {
 public:
  bool insert(td::uint32 slot, const Value& value) {
    if (finalized_through_.has_value() && slot <= *finalized_through_) {
      return false;
    }
    auto [_, inserted] = values_.insert(value);
    if (inserted) {
      values_by_slot_[slot].push_back(value);
    }
    return inserted;
  }

  bool contains(const Value& value) const {
    return values_.contains(value);
  }

  size_t prune_through(td::uint32 finalized_slot) {
    if (!finalized_through_.has_value() || *finalized_through_ < finalized_slot) {
      finalized_through_ = finalized_slot;
    }
    size_t erased = 0;
    auto end = values_by_slot_.upper_bound(*finalized_through_);
    for (auto it = values_by_slot_.begin(); it != end;) {
      for (const auto& value : it->second) {
        erased += values_.erase(value);
      }
      it = values_by_slot_.erase(it);
    }
    return erased;
  }

  size_t size() const {
    return values_.size();
  }

  size_t slot_count() const {
    return values_by_slot_.size();
  }

 private:
  std::set<Value> values_;
  std::map<td::uint32, std::vector<Value>> values_by_slot_;
  std::optional<td::uint32> finalized_through_;
};

}  // namespace tos::validator::consensus::simplex
