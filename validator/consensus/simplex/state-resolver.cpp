/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "consensus/utils.h"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_utils.h"

#include "bus.h"

namespace tos::validator::consensus::simplex {

namespace tl {

using db_key_finalizedBlock = tos_api::consensus_simplex_db_key_finalizedBlock;
using db_key_finalizedBlockRef = tl_object_ptr<db_key_finalizedBlock>;

}  // namespace tl

namespace {

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

    auto data = owning_bus()->db->get_by_prefix(tos_api::consensus_simplex_db_key_finalizedBlock::ID);
    size_t skipped = 0;
    for (auto& [key_str, _] : data) {
      // Round 168 (claude review) LOW fix: log-and-skip on a
      // malformed TL key instead of aborting via .ensure().move_as_ok().
      // The DB iterator returns every record whose key starts with
      // the finalizedBlock prefix, but a truncated / corrupted write
      // could leave a record whose key bytes do not parse as the
      // expected TL type — the pre-fix path turned that single bad
      // record into a silent SIGABRT during start_up with no
      // operator-readable context.  Same operator-visibility class
      // as rounds 142 / 166 (simplex init_votes / catchain-receiver
      // DB lambdas).  Skip the record and surface a count in the
      // load log so the operator can correlate.
      auto key_r = fetch_tl_object<tos_api::consensus_simplex_db_key_finalizedBlock>(
          key_str, true);
      if (key_r.is_error()) {
        LOG(WARNING) << "Simplex state-resolver: skipping malformed "
                        "finalizedBlock key in DB ("
                     << key_str.size() << " bytes): "
                     << key_r.error().message();
        ++skipped;
        continue;
      }
      auto key = key_r.move_as_ok();
      finalized_blocks_[CandidateId::from_tl(key->candidateId_)].done = true;
    }
    if (skipped > 0) {
      LOG(WARNING) << "Simplex state-resolver: skipped " << skipped
                   << " malformed finalizedBlock keys during DB load";
    }
    LOG(INFO) << "Loaded " << (data.size() - skipped) << " finalized blocks from DB";
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

  td::actor::Task<ResolvedState> resolve_state(ParentId id) {
    CachedState& entry = state_cache_[id];
    if (entry.result.has_value()) {
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
      } else {
        state_cache_.erase(id);
      }
    }
    co_return co_await std::move(task);
  }

  bool is_finalized(CandidateId id) {
    auto it = finalized_blocks_.find(id);
    return it != finalized_blocks_.end() && it->second.done;
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

    if (is_finalized(*id)) {
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

  td::actor::Task<> finalize_blocks(CandidateId id, std::optional<FinalCertRef> final_cert,
                                    std::optional<CandidateRef> final_candidate) {
    FinalizedBlock& state = finalized_blocks_[id];
    if (state.done) {
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
      } else {
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
