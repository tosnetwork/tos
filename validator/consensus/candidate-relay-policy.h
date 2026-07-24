/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include "td/utils/LRUCache.h"
#include "tos/tos-types.h"

namespace tos::validator::consensus {

class CandidateRelayDeduplicator {
 public:
  explicit CandidateRelayDeduplicator(size_t capacity = 256) : sent_candidates_(capacity) {
  }

  bool should_relay(const BlockIdExt &block_id) {
    if (sent_candidates_.contains(block_id)) {
      return false;
    }
    sent_candidates_.put(block_id, td::Unit{});
    return true;
  }

 private:
  td::LRUCache<BlockIdExt, td::Unit> sent_candidates_;
};

}  // namespace tos::validator::consensus
