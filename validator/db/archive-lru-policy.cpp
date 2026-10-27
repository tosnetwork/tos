/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <atomic>
#include <dirent.h>
#include <mutex>

#include "td/utils/logging.h"

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
  if (!info.is_permanent) {
    lru_.emplace(info.opened_idx, key);
  }
  return enforce(open_fds, 0);
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
  return enforce(open_fds, 0);
}

std::vector<ArchiveLruPolicy::Key> ArchiveLruPolicy::rebalance(std::int64_t open_fds, std::size_t demand) {
  return enforce(open_fds, demand);
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

std::vector<ArchiveLruPolicy::Key> ArchiveLruPolicy::enforce(std::int64_t open_fds, std::size_t demand) {
  std::vector<Key> closed;
  const bool budgeted = options_.descriptor_budget > 0 && open_fds >= 0;
  auto estimate = budgeted ? static_cast<std::size_t>(open_fds) : 0;
  const auto room = std::max(options_.descriptor_reserve, demand);
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

std::size_t count_directory_files(const std::string& directory) {
  auto* dir = opendir(directory.c_str());
  if (dir == nullptr) {
    return 0;
  }
  std::size_t count = 0;
  while (auto* entry = readdir(dir)) {
    if (entry->d_name[0] != '.') {
      ++count;
    }
  }
  closedir(dir);
  return count;
}

DescriptorVerdict decide_descriptors(std::size_t budget, std::size_t held, std::size_t demand, std::size_t releasable) {
  if (held <= budget && demand <= budget - held) {
    return DescriptorVerdict::Admit;
  }
  auto floor = held - std::min(held, releasable);
  if (floor <= budget && demand <= budget - floor) {
    return DescriptorVerdict::Wait;
  }
  return DescriptorVerdict::Shortage;
}

namespace {
std::atomic<std::size_t> g_descriptor_budget{0};
std::atomic<std::size_t> g_releasable_descriptors{0};
std::mutex g_refusals_mutex;
DescriptorRefusals g_refusals;  // guarded by g_refusals_mutex
}  // namespace

void set_archive_descriptor_budget(std::size_t budget) {
  g_descriptor_budget.store(budget, std::memory_order_relaxed);
}

std::size_t archive_descriptor_budget() {
  return g_descriptor_budget.load(std::memory_order_relaxed);
}

void publish_archive_releasable_descriptors(std::size_t files) {
  g_releasable_descriptors.store(files, std::memory_order_relaxed);
}

std::size_t archive_releasable_descriptors() {
  return g_releasable_descriptors.load(std::memory_order_relaxed);
}

td::Status admit_archive_descriptors(std::size_t demand, td::Slice what) {
  auto budget = archive_descriptor_budget();
  if (budget == 0) {
    return td::Status::OK();
  }
  auto counted = count_process_open_fds();
  if (counted < 0) {
    return td::Status::Error(PSLICE() << what << " refused: the process's open descriptors cannot be counted");
  }
  auto held = static_cast<std::size_t>(counted);
  auto releasable = archive_releasable_descriptors();
  auto verdict = decide_descriptors(budget, held, demand, releasable);
  if (verdict == DescriptorVerdict::Admit) {
    return td::Status::OK();
  }
  bool shortage = verdict == DescriptorVerdict::Shortage;
  std::string message;
  if (shortage) {
    message = PSTRING() << what << " needs " << demand << " descriptors; " << held << " are held, of which "
                        << releasable << " could be released by closing archive slices, and the budget is " << budget
                        << ": raise the descriptor limit (LimitNOFILE) by at least "
                        << (held - std::min(held, releasable) + demand - budget);
  } else {
    message = PSTRING() << what << " needs " << demand << " descriptors; " << held << " are held and the budget is "
                        << budget << ": waiting for archive slices to close";
  }
  {
    std::lock_guard<std::mutex> guard(g_refusals_mutex);
    if (shortage) {
      ++g_refusals.shortages;
    } else {
      ++g_refusals.waits;
    }
    g_refusals.last_was_shortage = shortage;
    g_refusals.last_message = message;
  }
  return td::Status::Error(message);
}

DescriptorRefusals archive_descriptor_refusals() {
  std::lock_guard<std::mutex> guard(g_refusals_mutex);
  return g_refusals;
}

}  // namespace tos::validator
