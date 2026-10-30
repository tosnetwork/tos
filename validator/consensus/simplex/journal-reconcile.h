/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

// The startup check between a session's journal and its own-decision log, as hashed
// lookups: linear in the sizes of both, so a log near its ceiling restarts in time
// proportional to its records.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../signing-ledger.h"

namespace tos::validator::consensus::simplex {

// The index of the first journal vote, in journal order, whose decision the log does not
// hold; nullopt when the log holds every one.
inline std::optional<std::size_t> first_unlogged(
    const std::vector<signing::Decision>& journal,
    const std::vector<std::pair<std::int64_t, signing::Decision>>& logged) {
  std::unordered_set<signing::Decision, signing::DecisionHash> recorded;
  recorded.reserve(logged.size());
  for (const auto& entry : logged) {
    recorded.insert(entry.second);
  }
  for (std::size_t i = 0; i < journal.size(); ++i) {
    if (!recorded.contains(journal[i])) {
      return i;
    }
  }
  return std::nullopt;
}

// For each decision with a signed journal entry, the index of its first such entry in
// journal order. `signed_entry[i]` tells whether entry i kept its signature.
inline std::unordered_map<signing::Decision, std::size_t, signing::DecisionHash> first_signed_index(
    const std::vector<signing::Decision>& journal, const std::vector<bool>& signed_entry) {
  std::unordered_map<signing::Decision, std::size_t, signing::DecisionHash> first;
  for (std::size_t i = 0; i < journal.size() && i < signed_entry.size(); ++i) {
    if (signed_entry[i]) {
      first.try_emplace(journal[i], i);
    }
  }
  return first;
}

}  // namespace tos::validator::consensus::simplex
