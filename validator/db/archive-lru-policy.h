/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

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
// up to that many, are not closed for exceeding the target. That is bounded
// by descriptor_budget instead: while the descriptors the process holds plus
// descriptor_reserve exceed the budget, retained and other non-permanent
// slices are closed oldest first, until the estimate fits or only permanent
// slices are left. A slice that is refused an open asks for rebalance() with
// the descriptors its open needs, so exactly that much is freed if it can be.
// Opens themselves are admitted by admit_archive_descriptors() below, against
// the demand of the open about to happen, never against weights seen before.
class ArchiveLruPolicy {
 public:
  // (archive id, temp, key)
  using Key = std::tuple<std::uint32_t, bool, bool>;
  struct Options {
    std::size_t max_total_files = 1;
    std::size_t keep_most_recent = 0;
    // 0: no budget (open descriptor counts are ignored).
    std::size_t descriptor_budget = 0;
    // Descriptors kept free for files other than archive slices.
    std::size_t descriptor_reserve = 128;
  };

  explicit ArchiveLruPolicy(Options options);

  // A slice was opened or queried, holding `files_count` files. `open_fds` is
  // the number of descriptors the process holds, or negative when unknown.
  // Returns the slices to close, oldest first.
  std::vector<Key> on_query(Key key, std::size_t files_count, std::int64_t open_fds = -1);
  // The set of permanent slices changed. Returns the slices to close.
  std::vector<Key> set_permanent(const std::vector<Key>& keys, std::int64_t open_fds = -1);
  // Decide again with a fresh descriptor count, keeping `demand` descriptors
  // free for an operation waiting to run. Returns the slices to close.
  std::vector<Key> rebalance(std::int64_t open_fds, std::size_t demand = 0);

  std::size_t total_files() const {
    return total_files_;
  }
  // Weight of the open non-permanent slices: what closing could release.
  std::size_t evictable_files() const;
  std::size_t evictable_count() const {
    return lru_.size();
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

  std::vector<Key> enforce(std::int64_t open_fds, std::size_t demand);

  Options options_;
  std::size_t current_idx_ = 1;
  std::map<Key, SliceInfo> slices_;
  std::map<std::size_t, Key> lru_;
  std::vector<Key> permanent_;
  std::size_t total_files_ = 0;
  std::uint64_t retention_withdrawn_ = 0;
  bool over_budget_ = false;
};

// Number of descriptors this process holds, or -1 when it cannot be counted.
std::int64_t count_process_open_fds();

// Whether an operation needing `demand` more descriptors may run now, with
// `held` descriptors held, of which closing slices could release `releasable`.
// Admit: it fits now. Wait: it would fit once closable slices have closed.
// Shortage: it cannot fit even then; only a higher descriptor limit helps.
enum class DescriptorVerdict { Admit, Wait, Shortage };
DescriptorVerdict decide_descriptors(std::size_t budget, std::size_t held, std::size_t demand, std::size_t releasable);

// Process-wide descriptor budget of a reader that opens archive slices;
// 0 (the default, and what validators and full nodes keep) disables every
// check below.
void set_archive_descriptor_budget(std::size_t budget);
std::size_t archive_descriptor_budget();
// What the archive LRU could release by closing its non-permanent slices.
void publish_archive_releasable_descriptors(std::size_t files);
std::size_t archive_releasable_descriptors();

// Admit an operation about to open `demand` descriptors (`what` names it for
// the refusal). Counts the descriptors held now; OK without a budget. A
// refusal is an error and is recorded; the caller must not open anything.
td::Status admit_archive_descriptors(std::size_t demand, td::Slice what);

struct DescriptorRefusals {
  std::uint64_t waits = 0;
  std::uint64_t shortages = 0;
  // The most recent refusal.
  bool last_was_shortage = false;
  std::string last_message;
};
DescriptorRefusals archive_descriptor_refusals();

// Files in `directory` (an upper bound on what opening a RocksDB instance
// there can hold open), or 0 when it cannot be listed.
std::size_t count_directory_files(const std::string& directory);

}  // namespace tos::validator
