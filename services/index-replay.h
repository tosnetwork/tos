/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <algorithm>
#include <set>

#include "validator/interfaces/block-handle.h"

namespace tos::services {
// Follow full identities across splits and merges, stop at the preceding
// masterchain interval, and return parents before children. A missing source
// record fails the entire interval; no cursor may advance on a partial walk.
template <class Lookup>
td::Result<std::vector<validator::BlockHandle>> replay_interval(std::vector<BlockIdExt> todo, uint32_t next,
                                                                Lookup lookup) {
  std::set<BlockIdExt> visited;
  std::vector<validator::BlockHandle> blocks;
  while (!todo.empty()) {
    auto id = todo.back();
    todo.pop_back();
    if (!id.seqno() || !visited.insert(id).second)
      continue;
    if (visited.size() > 4096)
      return td::Status::Error("masterchain interval exceeds 4096 shard blocks");
    TRY_RESULT(handle, lookup(id));
    if (handle->id() != id || id.id.workchain != 0)
      return td::Status::Error("invalid replay block identity");
    if (!handle->is_applied() || !handle->inited_masterchain_ref_block()) {
      return td::Status::Error("shard block has not been applied");
    }
    if (handle->masterchain_ref_block() < next)
      continue;
    if (handle->masterchain_ref_block() > next || !handle->inited_prev()) {
      return td::Status::Error("invalid shard ancestry for masterchain interval");
    }
    for (auto parent : handle->prev()) {
      if (parent.seqno() >= id.seqno())
        return td::Status::Error("nondecreasing shard ancestry");
      todo.push_back(parent);
    }
    blocks.push_back(std::move(handle));
  }
  std::sort(blocks.begin(), blocks.end(),
            [](const auto& a, const auto& b) { return a->id().seqno() < b->id().seqno(); });
  return blocks;
}
}  // namespace tos::services
