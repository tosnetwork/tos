/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "adnl/utils.hpp"
#include "auto/tl/lite_api.h"
#include "common/delay.h"
#include "td/utils/SharedSlice.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/tos-shard.h"
#include "tos/tos-tl.hpp"

#include "full-node-master.hpp"
#include "full-node-shard-queries.hpp"

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>

namespace tos {

namespace validator {

namespace fullnode {

namespace {

// Codex audit (round 4, finding #3): the shard endpoint runs every query
// through a `RateLimiter<>` (see full-node-shard.cpp:743-750), but the
// master endpoint had no per-method rate limit. An ADNL peer could
// repeatedly issue heavy `getArchiveSlice` / `downloadPersistentStateSliceV2`
// queries (each up to 16 MiB after R3.2's max_size cap) and drive disk I/O
// + bandwidth on the master.
//
// Mirroring shard's full RateLimiter would require plumbing a shared_ptr
// through `FullNodeMaster::create` to all callers — out of scope for this
// audit pass. Instead install a simple process-wide bucket here:
//
// Codex audit (round 5, finding #2): the round-4 fix used ONE process-wide
// bucket. A single misbehaving / aggressive peer could burn the entire
// 16-burst / 4-per-sec budget and starve every other peer. Add a
// per-source bucket (keyed by `adnl::AdnlNodeIdShort`) with the global
// bucket as a backstop. A query is admitted only when BOTH buckets allow
// it, so the global cap still bounds total master CPU/IO and the
// per-source cap stops one peer from monopolising it. Per-source map
// grows by adnl id; in practice the slave set is small (validator-set
// scale), but cap entries with a soft eviction every 1000 unique sources
// to bound worst-case memory under spray attacks.
struct MasterIngressLimiter {
    std::mutex mutex;
    uint64_t   tokens;
    uint64_t   max_tokens;
    uint64_t   refill_rate;
    uint64_t   last_refill;

    MasterIngressLimiter(uint64_t max_tok, uint64_t rate)
        : tokens(max_tok), max_tokens(max_tok), refill_rate(rate),
          last_refill(now_sec()) {}

    static uint64_t now_sec() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // Refill + try-consume; takes the mutex internally. Returns true on
    // success.
    bool try_consume() {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t now = now_sec();
        if (now > last_refill) {
            tokens = std::min(tokens + (now - last_refill) * refill_rate, max_tokens);
            last_refill = now;
        }
        if (tokens == 0) return false;
        --tokens;
        return true;
    }
};

constexpr uint64_t kMasterIngressBurst  = 16;
constexpr uint64_t kMasterIngressPerSec = 4;
constexpr uint64_t kPerSourcePerSec     = 1;
constexpr uint64_t kPerSourceFreshBurst = 1;   // codex r7 #4: new bucket only gets 1 token, not full burst
constexpr size_t   kMaxTrackedSources   = 1000;
constexpr uint64_t kPerSourceIdleSec    = 300; // 5 min idle → eligible for eviction

MasterIngressLimiter g_master_ingress_limiter{kMasterIngressBurst, kMasterIngressPerSec};

struct PerSourceLimiterMap {
    std::mutex mutex;
    struct Entry {
        std::unique_ptr<MasterIngressLimiter> limiter;
        uint64_t last_use_sec;
    };
    // Codex audit (round 7, finding #4): the round-5 implementation evicted
    // `buckets.begin()` (lowest adnl-id bytes) when the cap was hit and gave
    // every fresh bucket a full `kPerSourceBurst` token allowance. An attacker
    // churning through fresh adnl ids could (a) evict legitimate peers'
    // accumulated history and (b) effectively run at the global cap by
    // burning the fresh-bucket burst on every new identity.
    //
    // New design: track last-use time per source. On cap-pressure, evict the
    // longest-idle entry (real LRU). New buckets are seeded with only
    // `kPerSourceFreshBurst` (1) tokens — they refill at the normal rate, but
    // a churn attacker no longer gets a free 4-burst per identity.
    std::map<adnl::AdnlNodeIdShort, Entry> buckets;

    bool try_consume(adnl::AdnlNodeIdShort src) {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t now = MasterIngressLimiter::now_sec();
        auto it = buckets.find(src);
        if (it == buckets.end()) {
            if (buckets.size() >= kMaxTrackedSources) {
                // LRU eviction: scan for the longest-idle entry. Map is small
                // bounded (1000 entries); linear scan is cheap.
                auto victim = buckets.end();
                uint64_t oldest = now;
                for (auto cur = buckets.begin(); cur != buckets.end(); ++cur) {
                    if (cur->second.last_use_sec < oldest) {
                        oldest = cur->second.last_use_sec;
                        victim = cur;
                    }
                }
                // Only evict if the victim is truly idle. If even the oldest
                // entry is fresh (cap reached under sustained load from many
                // active peers), fall through and reject this new source —
                // the global limiter still bounds aggregate load.
                if (victim != buckets.end() && now - oldest >= kPerSourceIdleSec) {
                    buckets.erase(victim);
                } else {
                    return false;
                }
            }
            it = buckets.emplace(src,
                Entry{std::make_unique<MasterIngressLimiter>(
                          kPerSourceFreshBurst, kPerSourcePerSec),
                      now}).first;
        }
        it->second.last_use_sec = now;
        return it->second.limiter->try_consume();
    }
};

PerSourceLimiterMap g_per_source_master_limiter;

}  // namespace

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getNextBlockDescription &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda([promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
    if (R.is_error()) {
      auto x = create_serialize_tl_object<tos_api::tosNode_blockDescriptionEmpty>();
      promise.set_value(std::move(x));
    } else {
      auto B = R.move_as_ok();
      if (!B->received() || !B->inited_proof()) {
        auto x = create_serialize_tl_object<tos_api::tosNode_blockDescriptionEmpty>();
        promise.set_value(std::move(x));
      } else {
        auto x = create_serialize_tl_object<tos_api::tosNode_blockDescription>(create_tl_block_id(B->id()));
        promise.set_value(std::move(x));
      }
    }
  });
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_next_block,
                          create_block_id(query.prev_block_), std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareBlock &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda([promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
    if (R.is_error()) {
      auto x = create_serialize_tl_object<tos_api::tosNode_notFound>();
      promise.set_value(std::move(x));
    } else {
      auto B = R.move_as_ok();
      if (!B->received()) {
        auto x = create_serialize_tl_object<tos_api::tosNode_notFound>();
        promise.set_value(std::move(x));
      } else {
        auto x = create_serialize_tl_object<tos_api::tosNode_prepared>();
        promise.set_value(std::move(x));
      }
    }
  });
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle,
                          create_block_id(query.block_), false, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlock &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda([validator_manager = validator_manager_,
                                       promise = std::move(promise)](td::Result<BlockHandle> R) mutable {
    if (R.is_error()) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block"));
    } else {
      auto B = R.move_as_ok();
      if (!B->received()) {
        promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block"));
      } else {
        td::actor::send_closure(validator_manager, &ValidatorManagerInterface::get_block_data, B, std::move(promise));
      }
    }
  });
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle,
                          create_block_id(query.block_), false, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockFull &query,
                                       td::Promise<td::BufferSlice> promise) {
  td::actor::create_actor<BlockFullSender>("sender", tos::create_block_id(query.block_), false, validator_manager_,
                                           std::move(promise))
      .release();
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadNextBlockFull &query,
                                       td::Promise<td::BufferSlice> promise) {
  td::actor::create_actor<BlockFullSender>("sender", tos::create_block_id(query.prev_block_), true, validator_manager_,
                                           std::move(promise))
      .release();
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareBlockProof &query,
                                       td::Promise<td::BufferSlice> promise) {
  if (query.block_->seqno_ == 0) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot download proof for zero state"));
    return;
  }
  auto P = td::PromiseCreator::lambda([allow_partial = query.allow_partial_, promise = std::move(promise),
                                       validator_manager = validator_manager_](td::Result<BlockHandle> R) mutable {
    if (R.is_error()) {
      auto x = create_serialize_tl_object<tos_api::tosNode_preparedProofEmpty>();
      promise.set_value(std::move(x));
      return;
    } else {
      auto handle = R.move_as_ok();
      if (!handle || (!handle->inited_proof() && (!allow_partial || !handle->inited_proof_link()))) {
        auto x = create_serialize_tl_object<tos_api::tosNode_preparedProofEmpty>();
        promise.set_value(std::move(x));
        return;
      }
      if (handle->inited_proof() && handle->id().is_masterchain()) {
        auto x = create_serialize_tl_object<tos_api::tosNode_preparedProof>();
        promise.set_value(std::move(x));
      } else {
        auto x = create_serialize_tl_object<tos_api::tosNode_preparedProofLink>();
        promise.set_value(std::move(x));
      }
    }
  });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle,
                          create_block_id(query.block_), false, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareKeyBlockProof &query,
                                       td::Promise<td::BufferSlice> promise) {
  if (query.block_->seqno_ == 0) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot download proof for zero state"));
    return;
  }
  auto P = td::PromiseCreator::lambda(
      [allow_partial = query.allow_partial_, promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          auto x = create_serialize_tl_object<tos_api::tosNode_preparedProofEmpty>();
          promise.set_value(std::move(x));
        } else if (allow_partial) {
          auto x = create_serialize_tl_object<tos_api::tosNode_preparedProofLink>();
          promise.set_value(std::move(x));
        } else {
          auto x = create_serialize_tl_object<tos_api::tosNode_preparedProof>();
          promise.set_value(std::move(x));
        }
      });

  if (query.allow_partial_) {
    td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_key_block_proof_link,
                            create_block_id(query.block_), std::move(P));
  } else {
    td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_key_block_proof,
                            create_block_id(query.block_), std::move(P));
  }
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockProof &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [promise = std::move(promise), validator_manager = validator_manager_](td::Result<BlockHandle> R) mutable {
        if (R.is_error()) {
          promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
          return;
        } else {
          auto handle = R.move_as_ok();
          if (!handle || !handle->inited_proof()) {
            promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
            return;
          }

          td::actor::send_closure(validator_manager, &ValidatorManagerInterface::get_block_proof, handle,
                                  std::move(promise));
        }
      });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle,
                          create_block_id(query.block_), false, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockProofLink &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [promise = std::move(promise), validator_manager = validator_manager_](td::Result<BlockHandle> R) mutable {
        if (R.is_error()) {
          promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
          return;
        } else {
          auto handle = R.move_as_ok();
          if (!handle || !handle->inited_proof_link()) {
            promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
            return;
          }

          td::actor::send_closure(validator_manager, &ValidatorManagerInterface::get_block_proof_link, handle,
                                  std::move(promise));
        }
      });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle,
                          create_block_id(query.block_), false, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadKeyBlockProof &query,
                                       td::Promise<td::BufferSlice> promise) {
  if (query.block_->seqno_ == 0) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot download proof for zero state"));
    return;
  }
  auto P = td::PromiseCreator::lambda([promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
    } else {
      promise.set_value(R.move_as_ok());
    }
  });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_key_block_proof,
                          create_block_id(query.block_), std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadKeyBlockProofLink &query,
                                       td::Promise<td::BufferSlice> promise) {
  if (query.block_->seqno_ == 0) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot download proof for zero state"));
    return;
  }
  auto P = td::PromiseCreator::lambda([promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "unknown block proof"));
    } else {
      promise.set_value(R.move_as_ok());
    }
  });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_key_block_proof_link,
                          create_block_id(query.block_), std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareZeroState &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P =
      td::PromiseCreator::lambda([SelfId = actor_id(this), promise = std::move(promise)](td::Result<bool> R) mutable {
        if (R.is_error() || !R.move_as_ok()) {
          auto x = create_serialize_tl_object<tos_api::tosNode_notFoundState>();
          promise.set_value(std::move(x));
          return;
        }

        auto x = create_serialize_tl_object<tos_api::tosNode_preparedState>();
        promise.set_value(std::move(x));
      });
  auto block_id = create_block_id(query.block_);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::check_zero_state_exists, block_id,
                          std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_preparePersistentState &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::uint64> R) mutable {
        if (R.is_error()) {
          auto x = create_serialize_tl_object<tos_api::tosNode_notFoundState>();
          promise.set_value(std::move(x));
          return;
        }
        auto x = create_serialize_tl_object<tos_api::tosNode_preparedState>();
        promise.set_value(std::move(x));
      });
  auto block_id = create_block_id(query.block_);
  auto masterchain_block_id = create_block_id(query.masterchain_block_);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_persistent_state_size, block_id,
                          masterchain_block_id, UnsplitStateType{}, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getNextKeyBlockIds &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto cnt = static_cast<td::uint32>(query.max_size_);
  if (cnt > 8) {
    cnt = 8;
  }
  auto P =
      td::PromiseCreator::lambda([promise = std::move(promise), cnt](td::Result<std::vector<BlockIdExt>> R) mutable {
        if (R.is_error()) {
          LOG(WARNING) << "getnextkey: " << R.move_as_error();
          auto x = create_serialize_tl_object<tos_api::tosNode_keyBlocks>(
              std::vector<tl_object_ptr<tos_api::tosNode_blockIdExt>>{}, false, true);
          promise.set_value(std::move(x));
          return;
        }
        auto res = R.move_as_ok();
        std::vector<tl_object_ptr<tos_api::tosNode_blockIdExt>> v;
        for (auto &b : res) {
          v.emplace_back(create_tl_block_id(b));
        }
        auto x = create_serialize_tl_object<tos_api::tosNode_keyBlocks>(std::move(v), res.size() < cnt, false);
        promise.set_value(std::move(x));
      });
  auto block_id = create_block_id(query.block_);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_next_key_blocks, block_id, cnt,
                          std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadZeroState &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error_prefix("failed to get state from db: "));
          return;
        }

        promise.set_value(R.move_as_ok());
      });
  auto block_id = create_block_id(query.block_);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_zero_state, block_id, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getCapabilities &query,
                                       td::Promise<td::BufferSlice> promise) {
  promise.set_value(
      create_serialize_tl_object<tos_api::tosNode_capabilities>(proto_version_major(), proto_version_minor(), 0));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getArchiveInfo &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::uint64> R) mutable {
        if (R.is_error()) {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_archiveNotFound>());
        } else {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_archiveInfo>(R.move_as_ok()));
        }
      });
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_archive_id, query.masterchain_seqno_,
                          ShardIdFull{masterchainId}, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getShardArchiveInfo &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::uint64> R) mutable {
        if (R.is_error()) {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_archiveNotFound>());
        } else {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_archiveInfo>(R.move_as_ok()));
        }
      });
  ShardIdFull shard_prefix = create_shard_id(query.shard_prefix_);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_archive_id, query.masterchain_seqno_,
                          shard_prefix, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getArchiveSlice &query,
                                       td::Promise<td::BufferSlice> promise) {
  // Codex audit (round 3, finding #2): mirror the shard endpoint's
  // `max_size_` guard (validator/full-node-shard.cpp:637-640) — without it,
  // an ADNL peer can request arbitrarily large or negative slices, driving
  // disk I/O / bandwidth on the master. The shard endpoint also charges a
  // request-cost limiter; the master path lacks one (no `limiter_` member).
  // Validation is the minimum-viable fix; a per-method limiter is a
  // larger change and is left as a follow-up.
  if (query.max_size_ < 0 || query.max_size_ > (1 << 24)) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "invalid max_size"));
    return;
  }
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_archive_slice, query.archive_id_,
                          query.offset_, query.max_size_, std::move(promise));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_slave_sendExtMessage &query,
                                       td::Promise<td::BufferSlice> promise) {
  td::actor::send_closure(
      validator_manager_, &ValidatorManagerInterface::run_ext_query,
      create_serialize_tl_object<lite_api::liteServer_query>(
          create_serialize_tl_object<lite_api::liteServer_sendMessage>(std::move(query.message_->data_))),
      [&](td::Result<td::BufferSlice>) {});
  promise.set_value(create_serialize_tl_object<tos_api::tosNode_success>());
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src,
                                       tos_api::tosNode_downloadPersistentStateSliceV2 &query,
                                       td::Promise<td::BufferSlice> promise) {
  // Codex audit (round 3, finding #2): mirror shard validation (full-node-shard.cpp:700-703).
  if (query.max_size_ < 0 || query.max_size_ > (1 << 24)) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "invalid max_size"));
    return;
  }
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error_prefix("failed to get state from db: "));
          return;
        }

        promise.set_value(R.move_as_ok());
      });
  auto [block_id, mc_block_id, state_type] = persistent_state_from_v2_query(query);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_persistent_state_slice, block_id,
                          mc_block_id, state_type, query.offset_, query.max_size_, std::move(P));
}

void FullNodeMasterImpl::process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getPersistentStateSizeV2 &query,
                                       td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise)](td::Result<td::uint64> R) mutable {
        if (R.is_error()) {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_persistentStateSizeNotFound>());
        } else {
          promise.set_value(create_serialize_tl_object<tos_api::tosNode_persistentStateSize>(R.move_as_ok()));
        }
      });
  auto [block_id, mc_block_id, state_type] = persistent_state_from_v2_query(query);
  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_persistent_state_size, block_id,
                          mc_block_id, state_type, std::move(P));
}

void FullNodeMasterImpl::receive_query(adnl::AdnlNodeIdShort src, td::BufferSlice query,
                                       td::Promise<td::BufferSlice> promise) {
  // Codex audit (round 4 #3 + round 5 #2): per-source bucket gates one
  // peer's share; global bucket is the backstop on aggregate cost. Both
  // must allow. Per-source consumption first so a peer that hits its own
  // cap does not also deplete the global bucket on every reject.
  if (!g_per_source_master_limiter.try_consume(src)) {
    promise.set_error(td::Status::Error(ErrorCode::failure, "too many requests from this source"));
    return;
  }
  if (!g_master_ingress_limiter.try_consume()) {
    promise.set_error(td::Status::Error(ErrorCode::failure, "too many requests"));
    return;
  }
  auto BX = fetch_tl_prefix<tos_api::tosNode_query>(query, true);
  if (BX.is_error()) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot parse tosnode query"));
    return;
  }
  auto B = fetch_tl_object<tos_api::Function>(std::move(query), true);
  if (B.is_error()) {
    promise.set_error(td::Status::Error(ErrorCode::protoviolation, "cannot parse tosnode query"));
    return;
  }
  tos_api::downcast_call(*B.move_as_ok().get(), [&](auto &obj) { this->process_query(src, obj, std::move(promise)); });
}

void FullNodeMasterImpl::start_up() {
  class Cb : public adnl::Adnl::Callback {
   public:
    Cb(td::actor::ActorId<FullNodeMasterImpl> id) : id_(std::move(id)) {
    }
    void receive_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
    }
    void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      td::actor::send_closure(id_, &FullNodeMasterImpl::receive_query, src, std::move(data), std::move(promise));
    }

   private:
    td::actor::ActorId<FullNodeMasterImpl> id_;
  };

  td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, adnl_id_,
                          adnl::Adnl::int_to_bytestring(tos_api::tosNode_query::ID),
                          std::make_unique<Cb>(actor_id(this)));

  auto P =
      td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> R) {
        R.ensure();
        R.move_as_ok().release();
      });
  td::actor::send_closure(adnl_, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{adnl_id_},
                          std::vector<td::uint16>{port_}, std::move(P));
}

FullNodeMasterImpl::FullNodeMasterImpl(adnl::AdnlNodeIdShort adnl_id, td::uint16 port, FileHash zero_state_file_hash,
                                       td::actor::ActorId<keyring::Keyring> keyring,
                                       td::actor::ActorId<adnl::Adnl> adnl,
                                       td::actor::ActorId<ValidatorManagerInterface> validator_manager)
    : adnl_id_(adnl_id)
    , port_(port)
    , zero_state_file_hash_(zero_state_file_hash)
    , keyring_(keyring)
    , adnl_(adnl)
    , validator_manager_(validator_manager) {
}

td::actor::ActorOwn<FullNodeMaster> FullNodeMaster::create(
    adnl::AdnlNodeIdShort adnl_id, td::uint16 port, FileHash zero_state_file_hash,
    td::actor::ActorId<keyring::Keyring> keyring, td::actor::ActorId<adnl::Adnl> adnl,
    td::actor::ActorId<ValidatorManagerInterface> validator_manager) {
  return td::actor::create_actor<FullNodeMasterImpl>("tosnode", adnl_id, port, zero_state_file_hash, keyring, adnl,
                                                     validator_manager);
}

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
