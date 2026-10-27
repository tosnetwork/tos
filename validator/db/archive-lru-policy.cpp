/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <dirent.h>

#include "archive-lru-policy.h"

namespace tos::validator {

ArchiveLruPolicy::ArchiveLruPolicy(Options options) : options_(options) {
  if (options_.max_total_files == 0) {
    options_.max_total_files = 1;
  }
}

std::vector<ArchiveLruPolicy::Key> ArchiveLruPolicy::on_query(Key key, std::size_t files_count, std::int64_t open_fds) {
  SliceInfo& info = slices_[key];
  if (info.opened_idx != 0) {
    total_files_ -= std::min(total_files_, info.files_count);
    lru_.erase(info.opened_idx);
  }
  info.files_count = files_count;
  total_files_ += files_count;
  info.opened_idx = current_idx_++;
  largest_slice_files_ = std::max(largest_slice_files_, files_count);
  if (!info.is_permanent) {
    lru_.emplace(info.opened_idx, key);
  }
  return enforce(open_fds);
}

std::vector<ArchiveLruPolicy::Key> ArchiveLruPolicy::set_permanent(const std::vector<Key>& keys,
                                                                   std::int64_t open_fds) {
  for (const auto& key : permanent_) {
    SliceInfo& info = slices_[key];
    if (!info.is_permanent) {
      continue;
    }
    info.is_permanent = false;
    if (info.opened_idx != 0) {
      lru_.emplace(info.opened_idx, key);
    }
  }
  permanent_ = keys;
  for (const auto& key : permanent_) {
    SliceInfo& info = slices_[key];
    if (info.is_permanent) {
      continue;
    }
    info.is_permanent = true;
    if (info.opened_idx != 0) {
      lru_.erase(info.opened_idx);
    }
  }
  return enforce(open_fds);
}

std::size_t ArchiveLruPolicy::evictable_files() const {
  std::size_t result = 0;
  for (const auto& entry : lru_) {
    auto it = slices_.find(entry.second);
    if (it != slices_.end()) {
      result += it->second.files_count;
    }
  }
  return result;
}

std::size_t ArchiveLruPolicy::reserve() const {
  return std::max(options_.descriptor_reserve, largest_slice_files_);
}

std::vector<ArchiveLruPolicy::Key> ArchiveLruPolicy::enforce(std::int64_t open_fds) {
  std::vector<Key> closed;
  const bool budgeted = options_.descriptor_budget > 0 && open_fds >= 0;
  auto estimate = budgeted ? static_cast<std::size_t>(open_fds) : 0;
  const auto room = reserve();
  auto over = [&] {
    return budgeted && (estimate > options_.descriptor_budget || options_.descriptor_budget - estimate < room);
  };
  while (!lru_.empty()) {
    const bool over_target = total_files_ > options_.max_total_files;
    const bool withdraw = over();
    if (!over_target && !withdraw) {
      break;
    }
    // Without budget pressure the most recent keep_most_recent slices stay
    // open; lru_ is ordered oldest first, so they are the last entries.
    if (!withdraw && lru_.size() <= options_.keep_most_recent) {
      break;
    }
    if (lru_.size() <= options_.keep_most_recent) {
      ++retention_withdrawn_;
    }
    auto it = lru_.begin();
    auto key = it->second;
    lru_.erase(it);
    SliceInfo& info = slices_[key];
    total_files_ -= std::min(total_files_, info.files_count);
    estimate -= std::min(estimate, info.files_count);
    info.opened_idx = 0;
    closed.push_back(key);
  }
  over_budget_ = over();
  return closed;
}

std::int64_t count_process_open_fds() {
  auto* dir = opendir("/proc/self/fd");
  if (dir == nullptr) {
    return -1;
  }
  std::int64_t count = 0;
  while (auto* entry = readdir(dir)) {
    if (entry->d_name[0] != '.') {
      ++count;
    }
  }
  closedir(dir);
  // The directory stream itself holds one descriptor while it is counted.
  return count > 0 ? count - 1 : 0;
}

}  // namespace tos::validator
