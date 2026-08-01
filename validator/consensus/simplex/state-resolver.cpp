/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "consensus/utils.h"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_utils.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/memory-tracker.h"

#include <unordered_set>

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
// Bounds the number of concurrently in-flight (started, unresolved)
// resolve_state()/finalize_blocks() operations, independent of the
// completed-entry LRU caps above. Without this, a single permanently-stuck
// ancestor (e.g. local state that never becomes available) lets every new
// candidate that recurses back through it accumulate its own unbounded
// pending map entry until the stuck ancestor finally times out and the whole
// backlog cascades free -- only to start piling up again on the very next
// candidate. See MEMORY_DIAGNOSTICS simplex-state-resolver "state_inflight".
constexpr size_t DEFAULT_STATE_INFLIGHT_MAX = 4096;
constexpr size_t DEFAULT_FINALIZED_INFLIGHT_MAX = 4096;

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
    if (td::memory_tracker_enabled()) {
      alarm_timestamp() = td::Timestamp::in(60.0);
    }
  }

  void alarm() override {
    maybe_log_cache_stats(true);
    alarm_timestamp() = td::Timestamp::in(60.0);
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
  InflightAdmission state_inflight_{
      cache_limit_from_env("TOS_SIMPLEX_STATE_INFLIGHT_MAX", DEFAULT_STATE_INFLIGHT_MAX)};
  size_t state_admission_rejections_ = 0;
  std::optional<td::uint32> latest_finalized_slot_;

  td::actor::Task<ResolvedState> resolve_state(ParentId id) {
    if (!state_cache_.contains(id) && !state_inflight_.try_admit()) {
      ++state_admission_rejections_;
      co_return td::Status::Error(
          ErrorCode::notready, PSTRING() << "Simplex state-resolver: too many concurrent state resolutions ("
                                         << state_inflight_.count() << "/" << state_inflight_.capacity() << ")");
    }
    CachedState& entry = state_cache_[id];
    if (entry.result.has_value()) {
      touch_state_cache(id);
      co_return *entry.result;
    }
    auto [task, promise] = td::actor::StartedTask<ResolvedState>::make_bridge();
    entry.promises.push_back(std::move(promise));
    if (!entry.started) {
      entry.started = true;
      SCOPE_EXIT {
        state_inflight_.release();
      };
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
    maybe_log_cache_stats(false);
  }

  td::actor::Task<bool> is_finalized(CandidateId id, bool skip_db_for_newer_slot = false) {
    auto it = finalized_blocks_.find(id);
    if (it != finalized_blocks_.end()) {
      if (it->second.done) {
        touch_finalized_cache(id);
        co_return true;
      }
      // A concurrent finalization is already materializing this candidate in
      // ManagerFacade and persisting its finalized marker. Replaying the same
      // ancestor chain in parallel can combine a pre-finalization manager
      // anchor with newer candidates. Wait for the authoritative finalization
      // instead; this is especially important during cold-start catch-up.
      CHECK(it->second.started);
      auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
      it->second.waiters.push_back(std::move(promise));
      co_await std::move(task);
      auto completed = finalized_blocks_.find(id);
      CHECK(completed != finalized_blocks_.end() && completed->second.done);
      touch_finalized_cache(id);
      co_return true;
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
    std::vector<CandidateRef> candidates_to_apply;
    std::optional<double> gen_utime_exact;
    std::optional<ChainStateRef> state;
    bool reconstruct_from_candidate_data = false;

    // Resolve the whole ancestor walk inside one admitted operation. Empty
    // candidates do not change ChainState, and full candidates can be applied
    // oldest-to-newest after an available finalized anchor (or genesis) is
    // found. The old recursive implementation created one independently
    // admitted state-cache entry per candidate; a quiet shard with more than
    // 4096 empty candidates therefore failed deterministically after a cold
    // restart.
    //
    // CandidateId parents are strictly older (enforced on candidate ingress),
    // so this loop is finite. Only full candidates that must be replayed are
    // retained; an arbitrarily long empty run remains constant-memory.
    while (id.has_value()) {
      // A previous resolution may already have cached an ancestor reached
      // through a newer empty candidate. Reuse it directly; otherwise every
      // newly finalized empty candidate would rescan the same historical run.
      auto cached = state_cache_.find(id);
      if (cached != state_cache_.end() && cached->second.result.has_value()) {
        if (!gen_utime_exact.has_value()) {
          gen_utime_exact = cached->second.result->gen_utime_exact;
        }
        state = cached->second.result->state;
        touch_state_cache(id);
        break;
      }

      // A skip-only slot never had a Candidate object. Pool's available_base
      // jumps directly past the skip run. Query the exact CandidateId so Pool
      // can reject the shortcut when the slot also has a NotarCert.
      if (auto skip_base = co_await owning_bus().publish<QuerySlotSkipped>(*id)) {
        id = *skip_base;
        continue;
      }

      auto candidate = (co_await owning_bus().publish<ResolveCandidate>(*id)).candidate;
      if (candidate->is_empty()) {
        id = candidate->parent_id;
        continue;
      }

      const auto& block_candidate = std::get<BlockCandidate>(candidate->block);
      auto candidate_gen_utime = get_candidate_gen_utime_exact(block_candidate);
      if (candidate_gen_utime.is_error()) {
        LOG(WARNING) << "Simplex state-resolver: candidate " << *id
                     << " has invalid generation time: " << candidate_gen_utime.error();
        co_return candidate_gen_utime.move_as_error();
      }
      if (!gen_utime_exact.has_value()) {
        gen_utime_exact = candidate_gen_utime.move_as_ok();
      }

      if (!reconstruct_from_candidate_data && co_await is_finalized(*id, true)) {
        auto genesis = co_await genesis_.get();
        auto manager_state =
            co_await ChainState::from_manager(owning_bus()->manager, owning_bus()->shard,
                                              {candidate->block_id()}, genesis->state->min_mc_block_id())
                .wrap();
        if (manager_state.is_ok()) {
          state = manager_state.move_as_ok();
          break;
        }
        if (manager_state.error().code() != ErrorCode::timeout &&
            manager_state.error().code() != ErrorCode::notready) {
          co_return manager_state.move_as_error();
        }

        // A finalized consensus candidate can temporarily be absent from the
        // manager's block/state indexes during cold-start replay. Restarting
        // the entire ancestor walk on that transient timeout is both
        // needlessly expensive and, for a long empty chain, a liveness bug.
        // Reconstruct it from its already validated candidate data instead.
        LOG(WARNING) << "Simplex state-resolver: finalized anchor " << *id
                     << " is not available from manager (" << manager_state.error()
                     << "); reconstructing it from candidate data";
        reconstruct_from_candidate_data = true;
      }

      candidates_to_apply.push_back(std::move(candidate));
      id = candidates_to_apply.back()->parent_id;
    }

    if (!state.has_value()) {
      auto genesis = co_await genesis_.get();
      state = co_await ChainState::from_manager(owning_bus()->manager, owning_bus()->shard,
                                               genesis->state->block_ids(), genesis->state->min_mc_block_id());
    }
    for (auto it = candidates_to_apply.rbegin(); it != candidates_to_apply.rend(); ++it) {
      state = (*state)->apply(std::get<BlockCandidate>((*it)->block));
    }
    co_return ResolvedState{*state, gen_utime_exact};
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
  InflightAdmission finalized_inflight_{
      cache_limit_from_env("TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX", DEFAULT_FINALIZED_INFLIGHT_MAX)};
  size_t finalized_admission_rejections_ = 0;
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
    maybe_log_cache_stats(false);
  }

  void maybe_log_cache_stats(bool force) const {
    if (!td::memory_tracker_enabled()) {
      return;
    }
    const size_t total_evictions = state_cache_evictions_ + finalized_cache_evictions_;
    if (force || total_evictions == 1 || total_evictions % 1024 == 0) {
      std::unordered_set<const BlockData*> unique_blocks;
      size_t state_block_bytes = 0;
      size_t state_inflight = 0;
      size_t state_waiters = 0;
      for (const auto& [_, entry] : state_cache_) {
        state_inflight += entry.started && !entry.result.has_value();
        state_waiters += entry.promises.size();
        if (!entry.result.has_value()) {
          continue;
        }
        for (const auto& block : entry.result->state->block_data()) {
          if (unique_blocks.insert(block.get()).second) {
            state_block_bytes += block->data().size();
          }
        }
      }
      size_t finalized_inflight = 0;
      size_t finalized_waiters = 0;
      for (const auto& [_, entry] : finalized_blocks_) {
        finalized_inflight += entry.started && !entry.done;
        finalized_waiters += entry.waiters.size();
      }
      LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-state-resolver"
                   << " state_cache=" << state_cache_.size() << "/" << state_cache_lru_.capacity()
                   << " state_evictions=" << state_cache_evictions_
                   << " state_inflight=" << state_inflight << " state_waiters=" << state_waiters
                   << " state_inflight_admission=" << state_inflight_.count() << "/" << state_inflight_.capacity()
                   << " state_admission_rejections=" << state_admission_rejections_
                   << " unique_state_blocks=" << unique_blocks.size() << " state_block_bytes=" << state_block_bytes
                   << " finalized_cache=" << finalized_blocks_.size() << "/" << finalized_blocks_lru_.capacity()
                   << " finalized_evictions=" << finalized_cache_evictions_
                   << " finalized_inflight=" << finalized_inflight << " finalized_waiters=" << finalized_waiters
                   << " finalized_inflight_admission=" << finalized_inflight_.count() << "/"
                   << finalized_inflight_.capacity()
                   << " finalized_admission_rejections=" << finalized_admission_rejections_
                   << " finalized_db_hits=" << finalized_db_hits_ << " finalized_db_misses=" << finalized_db_misses_
                   << " finalized_db_skips=" << finalized_db_skips_;
    }
  }

  td::actor::Task<> finalize_blocks(CandidateId id, std::optional<FinalCertRef> final_cert,
                                    std::optional<CandidateRef> final_candidate) {
    if (co_await is_finalized(id)) {
      co_return td::Unit{};
    }
    if (!finalized_blocks_.contains(id) && !finalized_inflight_.try_admit()) {
      ++finalized_admission_rejections_;
      co_return td::Status::Error(ErrorCode::notready,
                                  PSTRING() << "Simplex state-resolver: too many concurrent finalizations ("
                                            << finalized_inflight_.count() << "/" << finalized_inflight_.capacity()
                                            << ")");
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
      SCOPE_EXIT {
        finalized_inflight_.release();
      };
      auto result = co_await finalize_blocks_inner(id, final_cert, final_candidate).wrap();
      auto waiters = std::move(state.waiters);
      if (result.is_ok()) {
        state.done = true;
        touch_finalized_cache(id);
      } else {
        finalized_blocks_lru_.erase(id);
        finalized_blocks_.erase(id);
      }
      for (auto& p : waiters) {
        p.set_result(result.clone());
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
