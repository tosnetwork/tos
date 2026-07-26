/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "consensus/utils.h"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_utils.h"
#include "td/utils/memory-tracker.h"

#include "bus.h"
#include "completed-lru.h"

namespace tos::validator::consensus::simplex {

namespace tl {

using db_key_finalizedBlock = tos_api::consensus_simplex_db_key_finalizedBlock;
using db_key_finalizedBlockRef = tl_object_ptr<db_key_finalizedBlock>;

}  // namespace tl

namespace {

constexpr size_t DEFAULT_STATE_CACHE_MAX_ENTRIES = 1024;
constexpr size_t DEFAULT_FINALIZED_CACHE_MAX_ENTRIES = 4096;

size_t cache_limit_from_env(const char* name, size_t default_value) {
  const char* value = std::getenv(name);
  if (value == nullptr) {
    return default_value;
  }
  auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
  if (parsed.is_error() || parsed.ok() == 0) {
    LOG(WARNING) << "Simplex state-resolver: ignoring invalid " << name << "=" << value;
    return default_value;
  }
  return parsed.move_as_ok();
}

class StateResolverImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
  using ResolvedState = ResolveState::Result;

 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator() || bus.config.observers_in_private_overlay();
  }

  void start_up() override {
    auto [awaiter, promise] = td::actor::StartedTask<StartEvent>::make_bridge();
    genesis_promise_ = std::move(promise);
    genesis_ = std::move(awaiter);

    // Historical finalized IDs are now queried exactly through Db::get_latest
    // on demand. Bulk-loading every ID made restart memory proportional to the
    // entire chain lifetime.
    LOG(INFO) << "Simplex state-resolver cache limits: states=" << state_cache_lru_.capacity()
              << " finalized=" << finalized_blocks_lru_.capacity();
  }

  void tear_down() override {
    genesis_promise_.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
    for (auto& [_, s] : state_cache_) {
      for (auto& p : s.promises) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
    }
    for (auto& [_, s] : finalized_blocks_) {
      for (auto& p : s.waiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
    }
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const Start> event) {
    genesis_promise_.set_value(std::move(event));
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizationObserved> event) {
    if (!latest_finalized_slot_.has_value() || *latest_finalized_slot_ < event->id.slot) {
      latest_finalized_slot_ = event->id.slot;
    }
    finalize_blocks(event->id, event->certificate, std::nullopt).start().detach();
  }

  template <>
  td::actor::Task<ResolvedState> process(BusHandle, std::shared_ptr<ResolveState> request) {
    co_return co_await resolve_state(request->id);
  }

 private:
  // ===== State resolution =====
  struct CachedState {
    std::optional<ResolvedState> result;
    bool started = false;
    std::vector<td::Promise<ResolvedState>> promises;
  };

  td::Promise<StartEvent> genesis_promise_;
  td::actor::SharedFuture<StartEvent> genesis_;

  std::map<ParentId, CachedState> state_cache_;
  CompletedLru<ParentId> state_cache_lru_{
      cache_limit_from_env("TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES", DEFAULT_STATE_CACHE_MAX_ENTRIES)};
  size_t state_cache_evictions_ = 0;
  std::optional<td::uint32> latest_finalized_slot_;

  td::actor::Task<ResolvedState> resolve_state(ParentId id) {
    CachedState& entry = state_cache_[id];
    if (entry.result.has_value()) {
      touch_state_cache(id);
      co_return *entry.result;
    }
    auto [task, promise] = td::actor::StartedTask<ResolvedState>::make_bridge();
    entry.promises.push_back(std::move(promise));
    if (!entry.started) {
      entry.started = true;
      auto result = co_await resolve_state_inner(id).wrap();
      for (auto& p : entry.promises) {
        p.set_result(result.clone());
      }
      entry.promises.clear();
      if (result.is_ok()) {
        entry.result = result.move_as_ok();
        touch_state_cache(id);
      } else {
        state_cache_lru_.erase(id);
        state_cache_.erase(id);
      }
    }
    co_return co_await std::move(task);
  }

  void touch_state_cache(const ParentId& id) {
    auto evicted = state_cache_lru_.touch(id);
    if (!evicted.has_value()) {
      return;
    }
    auto it = state_cache_.find(*evicted);
    CHECK(it != state_cache_.end());
    CHECK(it->second.result.has_value());
    CHECK(it->second.promises.empty());
    state_cache_.erase(it);
    ++state_cache_evictions_;
    maybe_log_cache_stats();
  }

  td::actor::Task<bool> is_finalized(CandidateId id, bool skip_db_for_newer_slot = false) {
    auto it = finalized_blocks_.find(id);
    if (it != finalized_blocks_.end()) {
      if (it->second.done) {
        touch_finalized_cache(id);
        co_return true;
      }
      // finalize_blocks() holds a reference to this entry across co_await.
      // Even if its DB write has just become visible, promoting the entry to
      // the completed LRU here could let another completion evict it before
      // the owning coroutine resumes.
      co_return false;
    }

    // During steady-state processing, a candidate newer than the latest
    // finalization observed by this resolver cannot yet need the historical
    // finalized fast path. Avoid serializing its first resolution behind a
    // RocksDB point read. Startup/replay remains conservative until the first
    // FinalizationObserved event, and finalize_blocks() always checks the DB.
    if (skip_db_for_newer_slot && latest_finalized_slot_.has_value() && id.slot > *latest_finalized_slot_) {
      ++finalized_db_skips_;
      co_return false;
    }

    auto key = create_serialize_tl_object<tl::db_key_finalizedBlock>(id.to_tl());
    auto value = co_await owning_bus()->db->get_latest(std::move(key));
    if (!value.has_value()) {
      ++finalized_db_misses_;
      co_return false;
    }

    ++finalized_db_hits_;
    finalized_blocks_[id].done = true;
    touch_finalized_cache(id);
    co_return true;
  }

  td::actor::Task<ResolvedState> resolve_state_inner(ParentId id) {
    if (!id.has_value()) {
      auto genesis = co_await genesis_.get();
      auto state = co_await ChainState::from_manager(owning_bus()->manager, owning_bus()->shard,
                                                     genesis->state->block_ids(), genesis->state->min_mc_block_id());
      co_return ResolvedState{state, std::nullopt};
    }

    auto candidate = (co_await owning_bus().publish<ResolveCandidate>(*id)).candidate;
    if (candidate->is_empty()) {
      co_return co_await resolve_state(candidate->parent_id);
    }
    auto gen_utime_result = get_candidate_gen_utime_exact(std::get<BlockCandidate>(candidate->block));
    if (gen_utime_result.is_error()) {
      LOG(WARNING) << "Simplex state-resolver: candidate " << *id
                   << " has invalid generation time: " << gen_utime_result.error();
      co_return gen_utime_result.move_as_error();
    }
    auto gen_utime_exact = gen_utime_result.move_as_ok();

    if (co_await is_finalized(*id, true)) {
      auto genesis = co_await genesis_.get();
      auto state = co_await ChainState::from_manager(owning_bus()->manager, owning_bus()->shard,
                                                     {candidate->block_id()}, genesis->state->min_mc_block_id());
      co_return ResolvedState{state, gen_utime_exact};
    }

    auto prev_data_state = co_await resolve_state(candidate->parent_id);
    co_return ResolvedState{
        .state = prev_data_state.state->apply(std::get<BlockCandidate>(candidate->block)),
        .gen_utime_exact = gen_utime_exact,
    };
  }

  // ===== Block finalization =====
  struct FinalizedBlock {
    bool done = false;
    bool started = false;
    std::vector<td::Promise<td::Unit>> waiters;
  };

  std::map<CandidateId, FinalizedBlock> finalized_blocks_;
  CompletedLru<CandidateId> finalized_blocks_lru_{
      cache_limit_from_env("TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES", DEFAULT_FINALIZED_CACHE_MAX_ENTRIES)};
  size_t finalized_cache_evictions_ = 0;
  size_t finalized_db_hits_ = 0;
  size_t finalized_db_misses_ = 0;
  size_t finalized_db_skips_ = 0;

  void touch_finalized_cache(const CandidateId& id) {
    auto evicted = finalized_blocks_lru_.touch(id);
    if (!evicted.has_value()) {
      return;
    }
    auto it = finalized_blocks_.find(*evicted);
    CHECK(it != finalized_blocks_.end());
    CHECK(it->second.done);
    CHECK(it->second.waiters.empty());
    finalized_blocks_.erase(it);
    ++finalized_cache_evictions_;
    maybe_log_cache_stats();
  }

  void maybe_log_cache_stats() const {
    if (!td::memory_tracker_enabled()) {
      return;
    }
    const size_t total_evictions = state_cache_evictions_ + finalized_cache_evictions_;
    if (total_evictions == 1 || total_evictions % 1024 == 0) {
      LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-state-resolver"
                   << " state_cache=" << state_cache_.size() << "/" << state_cache_lru_.capacity()
                   << " state_evictions=" << state_cache_evictions_
                   << " finalized_cache=" << finalized_blocks_.size() << "/" << finalized_blocks_lru_.capacity()
                   << " finalized_evictions=" << finalized_cache_evictions_
                   << " finalized_db_hits=" << finalized_db_hits_ << " finalized_db_misses=" << finalized_db_misses_
                   << " finalized_db_skips=" << finalized_db_skips_;
    }
  }

  td::actor::Task<> finalize_blocks(CandidateId id, std::optional<FinalCertRef> final_cert,
                                    std::optional<CandidateRef> final_candidate) {
    if (co_await is_finalized(id)) {
      co_return td::Unit{};
    }
    FinalizedBlock& state = finalized_blocks_[id];
    if (state.done) {
      touch_finalized_cache(id);
      co_return td::Unit{};
    }
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    state.waiters.push_back(std::move(promise));
    if (!state.started) {
      state.started = true;
      auto result = co_await finalize_blocks_inner(id, final_cert, final_candidate).wrap();
      for (auto& p : state.waiters) {
        p.set_result(result.clone());
      }
      state.waiters.clear();
      if (result.is_ok()) {
        state.done = true;
        touch_finalized_cache(id);
      } else {
        finalized_blocks_lru_.erase(id);
        finalized_blocks_.erase(id);
      }
    }
    co_return co_await std::move(task);
  }

  td::actor::Task<> finalize_blocks_inner(CandidateId id, std::optional<FinalCertRef> final_cert,
                                          std::optional<CandidateRef> final_candidate) {
    auto& bus = *owning_bus();

    if (!final_cert && bus.shard.is_masterchain()) {
      co_return td::Unit{};
    }

    auto [candidate, notar_cert] = co_await owning_bus().publish<ResolveCandidate>(id);
    if (final_cert && !final_candidate) {
      CHECK((*final_cert)->vote.id == id);
      final_candidate = candidate;
    }

    if (!candidate->is_empty()) {
      if (auto parent = candidate->parent_id) {
        co_await finalize_blocks(*parent, std::nullopt, std::nullopt);
      }

      td::Ref<block::BlockSignatureSet> sig_set;
      if (final_cert) {
        sig_set = (*final_cert)->to_signature_set(*final_candidate, bus);
      } else {
        sig_set = notar_cert->to_signature_set(candidate, bus);
      }
      co_await owning_bus().publish<FinalizeBlock>(candidate, sig_set);
    } else {
      if (auto parent = candidate->parent_id) {
        co_await finalize_blocks(*parent, final_cert, final_candidate);
      }
    }

    auto key = create_serialize_tl_object<tl::db_key_finalizedBlock>(id.to_tl());
    co_await bus.db->set(std::move(key), td::BufferSlice());
    co_return td::Unit{};
  }
};

}  // namespace

void StateResolver::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<StateResolverImpl>("StateResolver");
}

}  // namespace tos::validator::consensus::simplex
