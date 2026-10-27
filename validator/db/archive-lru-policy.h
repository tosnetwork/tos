/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <tuple>
#include <vector>

namespace tos::validator {

// Which open archive slices to close. Kept free of actors so every decision can
// be tested directly; ArchiveLru applies the result.
//
// Each slice is weighed by the descriptors it is estimated to hold (its
// packages plus the files of its index database). The newest normal, key and
// temp slices are permanent: they are written to and never closed.
//
// Default (keep_most_recent = 0, descriptor_budget = 0), used by validators and
// full nodes: close the least recently used non-permanent slices while the
// total weight exceeds max_total_files, including the slice just queried. The
// configured value is then a real ceiling on evictable slices.
//
// A sequential reader (the standalone wallet index) reads one old slice many
// times in a row. When that slice alone outweighs the target, the default
// closes it after every read, and every read reopens its database. Such a
// reader sets keep_most_recent: the most recently used non-permanent slices,
// up to that many, are not closed for exceeding the target. The weight held is
// then at most
//   permanent slices + keep_most_recent retained slices + max_total_files
// plus whatever a slice being opened concurrently adds before it is reported.
// That sum is not bounded by the target, so the reader also sets
// descriptor_budget and reports the descriptors the process actually holds.
// Room for one more slice to open is kept: the reserve is the larger of
// descriptor_reserve and the largest slice weight seen. While the descriptors
// held plus that reserve exceed the budget, retention is withdrawn: retained
// slices, and any other non-permanent slices, are closed oldest first until
// the estimate fits or only permanent slices are left. over_budget() is then
// true. The reader refuses new reads against the same formula on its actual
// descriptor count, and asks for rebalance() while it refuses, so a slice
// whose weight overstated its descriptors cannot leave reads refused while
// retained slices could still be closed.
class ArchiveLruPolicy {
 public:
  // (archive id, temp, key)
  using Key = std::tuple<std::uint32_t, bool, bool>;
  struct Options {
    std::size_t max_total_files = 1;
    std::size_t keep_most_recent = 0;
    // 0: no budget (open descriptor counts are ignored).
    std::size_t descriptor_budget = 0;
    std::size_t descriptor_reserve = 512;
  };

  explicit ArchiveLruPolicy(Options options);

  // A slice was opened or queried, holding `files_count` files. `open_fds` is
  // the number of descriptors the process holds, or negative when unknown.
  // Returns the slices to close, oldest first.
  std::vector<Key> on_query(Key key, std::size_t files_count, std::int64_t open_fds = -1);
  // The set of permanent slices changed. Returns the slices to close.
  std::vector<Key> set_permanent(const std::vector<Key>& keys, std::int64_t open_fds = -1);
  // Decide again with a fresh descriptor count. Returns the slices to close.
  std::vector<Key> rebalance(std::int64_t open_fds) {
    return enforce(open_fds);
  }
  // Descriptors kept free for one more slice to open.
  std::size_t reserve() const;

  std::size_t total_files() const {
    return total_files_;
  }
  // Weight of the open non-permanent slices.
  std::size_t evictable_files() const;
  std::size_t evictable_count() const {
    return lru_.size();
  }
  // The largest weight any slice has reported (permanent ones included).
  std::size_t largest_slice_files() const {
    return largest_slice_files_;
  }
  // Retained slices closed because the descriptor budget was exceeded.
  std::uint64_t retention_withdrawn() const {
    return retention_withdrawn_;
  }
  // Whether the last decision left the estimated descriptors above the budget.
  bool over_budget() const {
    return over_budget_;
  }
  const Options& options() const {
    return options_;
  }

 private:
  struct SliceInfo {
    std::size_t files_count = 0;
    std::size_t opened_idx = 0;  // 0: not open
    bool is_permanent = false;
  };

  std::vector<Key> enforce(std::int64_t open_fds);

  Options options_;
  std::size_t current_idx_ = 1;
  std::map<Key, SliceInfo> slices_;
  std::map<std::size_t, Key> lru_;
  std::vector<Key> permanent_;
  std::size_t total_files_ = 0;
  std::size_t largest_slice_files_ = 0;
  std::uint64_t retention_withdrawn_ = 0;
  bool over_budget_ = false;
};

// Number of descriptors this process holds, or -1 when it cannot be counted.
std::int64_t count_process_open_fds();

}  // namespace tos::validator
