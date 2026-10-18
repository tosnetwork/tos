/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cmath>
#include <limits>

#include "downloaders/download-state.hpp"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_utils.h"
#include "vm/boc.h"

#include "bootstrap-state.h"

namespace tos::validator {
namespace {

constexpr std::size_t kMaxStateFiles = 4096;
constexpr td::uint64 kMaxSplitHeaderBytes = 4ULL << 20;

td::actor::Task<td::uint64> probe_file(const BootstrapStateReader &reader, BlockIdExt block, BlockIdExt mc,
                                       PersistentStateType type, td::Timestamp deadline) {
  if (deadline.is_in_past()) {
    co_return td::Status::Error("readiness deadline exceeded");
  }
  auto size = co_await reader.state_size(block, mc, type);
  if (deadline.is_in_past()) {
    co_return td::Status::Error(ErrorCode::timeout, "readiness deadline exceeded");
  }
  if (size == 0 || size > static_cast<td::uint64>(std::numeric_limits<td::int64>::max())) {
    co_return td::Status::Error("invalid persistent state file size");
  }
  // The registry's size is cached. Reading both ends through the same serving
  // path also detects a removed, unreadable or truncated registered file.
  auto first = co_await reader.state_slice(block, mc, type, 0, 1);
  if (deadline.is_in_past()) {
    co_return td::Status::Error(ErrorCode::timeout, "readiness deadline exceeded");
  }
  auto last = co_await reader.state_slice(block, mc, type, static_cast<td::int64>(size - 1), 1);
  if (first.size() != 1 || last.size() != 1) {
    co_return td::Status::Error("persistent state file is not readable at its registered size");
  }
  co_return size;
}

td::actor::Task<BootstrapStateStatus> scan_bootstrap_state(td::Ref<PersistentStateDescription> description,
                                                           double archive_ttl, UnixTime now,
                                                           BootstrapStateReader reader, td::Timestamp deadline) {
  const double started_at = td::Time::now();
  BootstrapStateStatus status{description->masterchain_id, false,      "snapshot_expired", description->start_time,
                              description->end_time,       archive_ttl};
  if (description->end_time <= now) {
    co_return status;
  }
  status.reason = "resource_limit";
  if (description->shard_blocks.size() >= kMaxStateFiles) {
    co_return status;
  }

  auto shards = description->shard_blocks;
  shards.insert(shards.begin(), {description->masterchain_id, 0});
  std::size_t file_count = 0;
  // A shard block older than the anchor is filed under its own, earlier
  // masterchain reference, so its proof can sit in an older package that
  // archive retention deletes first. Keep the earliest package start.
  auto oldest_package = std::numeric_limits<UnixTime>::max();
  for (const auto &entry : shards) {
    if (!entry.block.is_valid_full()) {
      status.reason = "invalid_state";
      co_return status;
    }
    if (file_count >= kMaxStateFiles) {
      status.reason = "resource_limit";
      co_return status;
    }
    if (deadline.is_in_past()) {
      status.reason = "timeout";
      co_return status;
    }
    if (entry.block.seqno() == 0) {
      auto zero = co_await reader.zero_state(entry.block).wrap();
      if (zero.is_error()) {
        status.reason = "state_unavailable";
        co_return status;
      }
      ++file_count;
      continue;
    }
    auto root = co_await reader.archived_proof(entry.block).wrap();
    if (root.is_error()) {
      status.reason = deadline.is_in_past() ? "timeout" : "proof_unavailable";
      co_return status;
    }
    oldest_package = std::min(oldest_package, root.ok().package_start);
    const bool split = entry.split_depth > static_cast<td::uint32>(shard_pfx_len(entry.block.id.shard));
    PersistentStateType type =
        split ? PersistentStateType{SplitPersistentStateType{}} : PersistentStateType{UnsplitStateType{}};
    auto size = co_await probe_file(reader, entry.block, description->masterchain_id, type, deadline).wrap();
    if (size.is_error()) {
      status.reason = deadline.is_in_past() ? "timeout" : "state_unavailable";
      co_return status;
    }
    ++file_count;
    if (!split) {
      continue;
    }
    if (size.ok() > kMaxSplitHeaderBytes) {
      status.reason = "resource_limit";
      co_return status;
    }
    auto header = co_await reader
                      .state_slice(entry.block, description->masterchain_id, type, 0, static_cast<td::int64>(size.ok()))
                      .wrap();
    if (header.is_error() || header.ok().size() != size.ok()) {
      status.reason = "state_unavailable";
      co_return status;
    }
    auto cell = vm::std_boc_deserialize(header.ok().as_slice());
    if (cell.is_error()) {
      status.reason = "invalid_state";
      co_return status;
    }
    auto parts =
        read_split_state_parts(entry.block.id.shard, root.ok().state_root, cell.move_as_ok(), entry.split_depth);
    if (parts.is_error()) {
      status.reason = "invalid_state";
      co_return status;
    }
    if (parts.ok().size() > kMaxStateFiles - file_count) {
      status.reason = "resource_limit";
      co_return status;
    }
    for (const auto &part : parts.ok()) {
      auto part_size = co_await probe_file(reader, entry.block, description->masterchain_id,
                                           SplitAccountStateType{part.effective_shard}, deadline)
                           .wrap();
      if (part_size.is_error()) {
        status.reason = deadline.is_in_past() ? "timeout" : "state_unavailable";
        co_return status;
      }
      ++file_count;
    }
  }
  if (deadline.is_in_past()) {
    status.reason = "timeout";
    co_return status;
  }
  if (static_cast<double>(now) + td::Time::now() - started_at >= description->end_time) {
    status.reason = "snapshot_expired";
    co_return status;
  }
  // The anchor itself always has a proof, so oldest_package is set here.
  const double horizon = static_cast<double>(oldest_package) + archive_ttl;
  if (!std::isfinite(horizon)) {
    status.reason = "invalid_state";
    co_return status;
  }
  constexpr auto kMaxTime = static_cast<double>(std::numeric_limits<UnixTime>::max());
  status.archive_expires_at = horizon >= kMaxTime ? std::numeric_limits<UnixTime>::max()
                                                  : static_cast<UnixTime>(std::floor(std::max(horizon, 0.0)));
  status.ready = true;
  status.reason = "ready";
  co_return status;
}

}  // namespace

td::actor::Task<BootstrapStateStatus> check_bootstrap_state(td::Ref<PersistentStateDescription> description,
                                                            double archive_ttl, UnixTime now,
                                                            BootstrapStateReader reader, td::Timestamp deadline) {
  if (description.is_null()) {
    co_return BootstrapStateStatus{};
  }
  BootstrapStateStatus timed_out{description->masterchain_id, false,      "timeout", description->start_time,
                                 description->end_time,       archive_ttl};
  if (deadline.is_in_past()) {
    co_return timed_out;
  }
  auto result =
      co_await td::actor::await_with_timeout(
          scan_bootstrap_state(std::move(description), archive_ttl, now, std::move(reader), deadline), deadline)
          .wrap();
  if (result.is_error() && result.error().code() == td::actor::AWAIT_TIMEOUT_CODE) {
    co_return timed_out;
  }
  co_return std::move(result);
}

}  // namespace tos::validator
