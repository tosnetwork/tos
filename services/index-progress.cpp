/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <dirent.h>

#include "td/utils/logging.h"
#include "validator-engine/wallet-index.h"

#include "index-progress.h"

namespace tos::services {
namespace {
std::string ms(uint64_t us) {
  return std::to_string(us / 1000);
}
uint64_t delta(uint64_t now, uint64_t before) {
  return now >= before ? now - before : 0;
}
}  // namespace

ReplayStats::Snapshot ReplayStats::snapshot(double uptime_s, uint64_t archive_slice_opens,
                                            uint64_t archive_slice_closes) const {
  Snapshot s;
  s.uptime_s = uptime_s;
  s.mc_blocks = mc_blocks.load(std::memory_order_relaxed);
  s.shard_blocks = shard_blocks.load(std::memory_order_relaxed);
  s.source_requests = source_requests.load(std::memory_order_relaxed);
  s.source_wait_us = source_wait_us.load(std::memory_order_relaxed);
  s.catch_ups = catch_ups.load(std::memory_order_relaxed);
  s.catch_up_us = catch_up_us.load(std::memory_order_relaxed);
  s.walk_us = walk_us.load(std::memory_order_relaxed);
  s.commits = commits.load(std::memory_order_relaxed);
  s.commit_us = commit_us.load(std::memory_order_relaxed);
  s.drains = drains.load(std::memory_order_relaxed);
  s.drain_us = drain_us.load(std::memory_order_relaxed);
  s.archive_slice_opens = archive_slice_opens;
  s.archive_slice_closes = archive_slice_closes;
  s.open_fds = open_fds.load(std::memory_order_relaxed);
  return s;
}

std::string replay_stats_json(const ReplayStats::Snapshot& s) {
  return "{\"uptime_s\":" + std::to_string(static_cast<uint64_t>(s.uptime_s)) +
         ",\"mc_blocks\":" + std::to_string(s.mc_blocks) + ",\"shard_blocks\":" + std::to_string(s.shard_blocks) +
         ",\"source_requests\":" + std::to_string(s.source_requests) + ",\"source_wait_ms\":" + ms(s.source_wait_us) +
         ",\"catch_ups\":" + std::to_string(s.catch_ups) + ",\"catch_up_ms\":" + ms(s.catch_up_us) +
         ",\"walk_ms\":" + ms(s.walk_us) + ",\"commits\":" + std::to_string(s.commits) +
         ",\"commit_ms\":" + ms(s.commit_us) + ",\"drains\":" + std::to_string(s.drains) +
         ",\"drain_ms\":" + ms(s.drain_us) + ",\"archive_slice_opens\":" + std::to_string(s.archive_slice_opens) +
         ",\"archive_slice_closes\":" + std::to_string(s.archive_slice_closes) +
         ",\"open_fds\":" + (s.open_fds < 0 ? std::string("null") : std::to_string(s.open_fds)) + "}";
}

std::string replay_stats_log_line(const ReplayStats::Snapshot& now, const ReplayStats::Snapshot& previous) {
  double seconds = now.uptime_s - previous.uptime_s;
  auto blocks = delta(now.mc_blocks, previous.mc_blocks);
  char rate[32];
  snprintf(rate, sizeof(rate), "%.2f", seconds > 0 ? static_cast<double>(blocks) / seconds : 0.0);
  return "replay stats over " + std::to_string(static_cast<uint64_t>(seconds)) +
         "s: mc_blocks=" + std::to_string(blocks) + " (" + rate +
         "/s) shard_blocks=" + std::to_string(delta(now.shard_blocks, previous.shard_blocks)) +
         " source_requests=" + std::to_string(delta(now.source_requests, previous.source_requests)) +
         " source_wait_ms=" + ms(delta(now.source_wait_us, previous.source_wait_us)) +
         " catch_up_ms=" + ms(delta(now.catch_up_us, previous.catch_up_us)) +
         " walk_ms=" + ms(delta(now.walk_us, previous.walk_us)) +
         " commit_ms=" + ms(delta(now.commit_us, previous.commit_us)) +
         " drain_ms=" + ms(delta(now.drain_us, previous.drain_us)) +
         " archive_slice_opens=" + std::to_string(delta(now.archive_slice_opens, previous.archive_slice_opens)) +
         " archive_slice_closes=" + std::to_string(delta(now.archive_slice_closes, previous.archive_slice_closes)) +
         " open_fds=" + std::to_string(now.open_fds);
}

std::string Progress::json(double now) const {
  auto known = [](bool is_known, uint32_t value) { return is_known ? std::to_string(value) : std::string("null"); };
  return "{\"masterchain_seqno\":" + known(cursor_known.load(), cursor.load()) +
         ",\"source_seqno\":" + known(tip_known.load(), tip.load()) +
         ",\"caught_up\":" + (is_ready(now) ? "true" : "false") +
         ",\"initialized\":" + (cursor_known.load() ? "true" : "false") + "}";
}

std::string Progress::readyz_json(double now, const ReplayStats::Snapshot& stats) const {
  auto body = json(now);
  body.pop_back();
  return body + ",\"replay_stats\":" + replay_stats_json(stats) + "}";
}

td::Status load_checkpoint_progress(tos_wallet_index::WalletIndexDb& db, Progress& progress) {
  TRY_RESULT(stored, db.replay_checkpoint());
  if (!stored) {
    progress.cursor_known = false;
    return td::Status::OK();
  }
  progress.cursor = stored.value().committed.seqno();
  progress.cursor_known = true;
  return td::Status::OK();
}

int64_t count_open_fds() {
  auto* dir = opendir("/proc/self/fd");
  if (dir == nullptr) {
    return -1;
  }
  int64_t count = 0;
  while (auto* entry = readdir(dir)) {
    if (entry->d_name[0] != '.') {
      ++count;
    }
  }
  closedir(dir);
  // The directory stream itself holds one descriptor while it is counted.
  return count > 0 ? count - 1 : 0;
}

}  // namespace tos::services
