/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <set>

#include "auto/tl/lite_api.h"

#include "rate-limiter.h"

namespace tos::validator {

using namespace lite_api;

class LiteServerAdmission {
 public:
  static constexpr size_t MAX_INFLIGHT = 512;

  bool try_acquire(td::int32 request_id, size_t request_bytes, td::Timestamp now = td::Timestamp::now()) {
    if (inflight_ >= MAX_INFLIGHT || !known_requests_.contains(request_id)) {
      return false;
    }
    size_t cost = 1 + request_bytes / (16 * 1024);
    if (!rate_limiter_.check_in(request_id, cost, now)) {
      return false;
    }
    ++inflight_;
    return true;
  }

  void release() {
    if (inflight_ != 0) {
      --inflight_;
    }
  }

  size_t inflight() const {
    return inflight_;
  }

 private:
  const std::set<td::int32> heavy_requests_{
      liteServer_getState::ID,
      liteServer_getBlockProof::ID,
      liteServer_getConfigAll::ID,
      liteServer_getTransactions::ID,
      liteServer_getValidatorStats::ID,
      liteServer_getShardBlockProof::ID,
      liteServer_getLibrariesWithProof::ID,
      liteServer_lookupBlockWithProof::ID,
  };
  const std::set<td::int32> medium_requests_{
      liteServer_getAccountState::ID,
      liteServer_getAccountStatePrunned::ID,
      liteServer_getAllShardsInfo::ID,
      liteServer_getBlock::ID,
      liteServer_getBlockHeader::ID,
      liteServer_getBlockOutMsgQueueSize::ID,
      liteServer_getConfigParams::ID,
      liteServer_getDispatchQueueInfo::ID,
      liteServer_getDispatchQueueMessages::ID,
      liteServer_getLibraries::ID,
      liteServer_getOneTransaction::ID,
      liteServer_getOutMsgQueueSizes::ID,
      liteServer_getShardInfo::ID,
      liteServer_listBlockTransactions::ID,
      liteServer_listBlockTransactionsExt::ID,
      liteServer_lookupBlock::ID,
      liteServer_nonfinal_getCandidate::ID,
      liteServer_nonfinal_getPendingShardBlocks::ID,
      liteServer_nonfinal_getValidatorGroups::ID,
      liteServer_runSmcMethod::ID,
      liteServer_sendMessage::ID,
  };
  const std::set<td::int32> small_requests_{
      liteServer_getMasterchainInfo::ID,
      liteServer_getMasterchainInfoExt::ID,
      liteServer_getTime::ID,
      liteServer_getVersion::ID,
  };
  const std::set<td::int32> known_requests_ = [] {
    std::set<td::int32> result{
        liteServer_getState::ID,
        liteServer_getBlockProof::ID,
        liteServer_getConfigAll::ID,
        liteServer_getTransactions::ID,
        liteServer_getValidatorStats::ID,
        liteServer_getShardBlockProof::ID,
        liteServer_getLibrariesWithProof::ID,
        liteServer_lookupBlockWithProof::ID,
        liteServer_getAccountState::ID,
        liteServer_getAccountStatePrunned::ID,
        liteServer_getAllShardsInfo::ID,
        liteServer_getBlock::ID,
        liteServer_getBlockHeader::ID,
        liteServer_getBlockOutMsgQueueSize::ID,
        liteServer_getConfigParams::ID,
        liteServer_getDispatchQueueInfo::ID,
        liteServer_getDispatchQueueMessages::ID,
        liteServer_getLibraries::ID,
        liteServer_getOneTransaction::ID,
        liteServer_getOutMsgQueueSizes::ID,
        liteServer_getShardInfo::ID,
        liteServer_listBlockTransactions::ID,
        liteServer_listBlockTransactionsExt::ID,
        liteServer_lookupBlock::ID,
        liteServer_nonfinal_getCandidate::ID,
        liteServer_nonfinal_getPendingShardBlocks::ID,
        liteServer_nonfinal_getValidatorGroups::ID,
        liteServer_runSmcMethod::ID,
        liteServer_sendMessage::ID,
        liteServer_getMasterchainInfo::ID,
        liteServer_getMasterchainInfoExt::ID,
        liteServer_getTime::ID,
        liteServer_getVersion::ID,
    };
    return result;
  }();
  fullnode::RateLimiter<td::int32> rate_limiter_{
      fullnode::RateLimit{1.0, 2048},
      fullnode::RateLimit{1.0, 128},
      heavy_requests_,
      fullnode::RateLimit{1.0, 512},
      medium_requests_,
      fullnode::RateLimit{1.0, 1024},
      small_requests_,
  };
  size_t inflight_{0};
};

}  // namespace tos::validator
