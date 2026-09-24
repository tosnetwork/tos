/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "consensus/utils.h"
#include "crypto/block/block.h"
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
// How many certificates this resolver will hold un-converted before the group is told to
// stop producing more.
//
// Nothing drops a certificate to stay under it. The limit is on how far consensus may run
// ahead of the finality it has agreed, and the way it is enforced is that the round pauses,
// not that evidence is discarded. Small on purpose: a healthy group converts each
// certificate long before the next few slots are agreed, so reaching this at all means
// something below is not working, and the useful response is to stop rather than to
// accumulate.
constexpr size_t DEFAULT_PENDING_FINALIZATIONS_MAX = 16;
// How a finalization that failed for a reason that may not recur is tried again. The wait
// grows with the attempt and is capped, and there is deliberately no attempt limit.
//
// A limit was the first shape of this, and it only moved the loss: the event that carried
// this certificate is long consumed, so the resolver is the only thing left that knows the
// certificate needs converting, and giving up after a few short waits loses it just as
// completely as giving up on the first failure did. Any condition that outlasts a second of
// backoff -- a database still catching up, a dependency a few seconds away, a node still
// coming up -- would end with an agreed, verified certificate that nothing will ever ask
// for again. So the entry is kept and retried for as long as the group lives.
//
// The count is still tracked, for the one thing a count is good for here: saying so, once,
// when a finalization has been failing long enough that somebody should look.
constexpr double finalization_retry_delay = 0.2;
constexpr double max_finalization_retry_delay = 5.0;
constexpr size_t finalization_attempts_before_reporting = 4;
// Fault injection for the retry path, read once. The transient failures that produce it in
// production -- admission pressure, a dependency not ready yet -- cannot be turned on and
// off on demand, so the one property that matters cannot otherwise be shown: that a failure
// outlasting several retries still ends with the same certificate being finalized. Unset outside tests; a
// value of N fails the first N conversion attempts with exactly that class of error.
size_t injected_transient_finalization_failures() {
  const char* value = std::getenv("TOS_SIMPLEX_INJECT_TRANSIENT_FINALIZATION_FAILURES");
  if (value == nullptr) {
    return 0;
  }
  auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
  return parsed.is_error() ? 0 : parsed.move_as_ok();
}

// The same, for the class of failure retrying cannot mend. The candidate resolver normally
// gives up with `notready` and its limiter answers `failure`, so without this the Permanent
// branch would not have a deterministic test input.
size_t injected_permanent_finalization_failures() {
  const char* value = std::getenv("TOS_SIMPLEX_INJECT_PERMANENT_FINALIZATION_FAILURE");
  if (value == nullptr) {
    return 0;
  }
  auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
  return parsed.is_error() ? 0 : parsed.move_as_ok();
}

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

  // What has happened to one candidate's finalization. This was three booleans, and the
  // combination that mattered could not be read: a caller that asked only "is it done" met
  // an entry which had already refused permanently, and waited on a promise nobody was left
  // to keep. Naming the states forces every reader to say which one it means, and makes the
  // terminal one impossible to mistake for one that is still coming.
  enum class Finalization {
    // Nothing is running. Either no attempt has been made, or one failed for a reason that
    // may not recur, and the next caller starts another. Keeping the entry rather than
    // erasing it is what stops a certificate being forgotten because the event that would
    // have retried it was consumed long ago.
    Idle,
    // An attempt is running. A waiter added here will be resolved when it finishes.
    InFlight,
    // The block is finalized.
    Finalized,
    // Terminal for a different reason: the conversion failed in a way retrying cannot mend.
    // The entry and its certificate are kept, and it is reported, because the certificate is
    // still evidence a quorum agreed on -- what stops is the spinning, not the remembering.
    StalledPermanently,
  };

  // What to do about a finalization that did not succeed.
  //
  // Treating every failure as transient commits a node to retrying a
  // protocol violation or a mismatched candidate for as long as it lives. The codes below
  // are the ones this path can actually produce, read out of the code that produces them --
  // the candidate resolver gives up with `notready`, its rate limiter answers `failure`,
  // shutdown answers `cancelled` -- rather than guessed at.
  enum class FailureKind {
    // The group is stopping. Nothing to retry and nothing to report.
    Cancelled,
    // A dependency that was not ready, a request that timed out, a limiter that said no.
    // These are the failures a later attempt can find gone.
    Retryable,
    // Anything else: a protocol violation, a candidate whose id does not match the one
    // asked for, an error carrying no code at all. Retrying does not make a mismatched
    // candidate match, and a node that spins on one says nothing to anybody.
    Permanent,
  };

  static FailureKind classify_failure(const td::Status& error) {
    switch (error.code()) {
      case ErrorCode::cancelled:
        return FailureKind::Cancelled;
      case ErrorCode::notready:
      case ErrorCode::timeout:
      case ErrorCode::failure:
        return FailureKind::Retryable;
      default:
        return FailureKind::Permanent;
    }
  }

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

  template <>
  td::actor::Task<QueryFinalizationState::Result> process(BusHandle, std::shared_ptr<QueryFinalizationState> query) {
    QueryFinalizationState::Result result{.finalizations_started = finalizations_started_,
                                          .finalizations_settled = finalizations_settled_,
                                          .finalization_retries = finalization_retries_,
                                          .finalization_retries_at_admission = finalization_retries_at_admission_,
                                          .finalizations_stalled = finalizations_stalled_,
                                          .pending_finalizations = pending_finalizations_,
                                          .backlog_over_limit = backlog_over_limit_,
                                          .finalizations_stalled_permanently = finalizations_stalled_permanently_,
                                          .slot_attempts = 0};
    for (const auto& [id, state] : finalized_blocks_) {
      if (id.slot != query->slot) {
        continue;
      }
      result.slot_attempts = std::max(result.slot_attempts, state.attempts);
    }
    co_return result;
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

  // What state this candidate's finalization is in, waiting only on an attempt that can
  // still change it. Answering "not finalized yet" for a terminal refusal, or waiting on
  // one, is how a latch meant to suppress retries became a permanent hang.
  td::actor::Task<Finalization> finalization_of(CandidateId id, bool skip_db_for_newer_slot = false) {
    auto it = finalized_blocks_.find(id);
    if (it != finalized_blocks_.end()) {
      switch (it->second.state) {
        case Finalization::Finalized:
          touch_finalized_cache(id);
          co_return Finalization::Finalized;
        case Finalization::Idle:
          co_return Finalization::Idle;
        case Finalization::StalledPermanently:
          co_return Finalization::StalledPermanently;
        case Finalization::InFlight:
          break;
      }
      // A concurrent finalization is already materializing this candidate in
      // ManagerFacade and persisting its finalized marker. Replaying the same
      // ancestor chain in parallel can combine a pre-finalization manager
      // anchor with newer candidates. Wait for the authoritative finalization
      // instead; this is especially important during cold-start catch-up.
      auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
      it->second.waiters.push_back(std::move(promise));
      // Wrapped: the attempt may have refused, and a refusal is something to report from
      // the state below rather than to throw out of a question about state.
      auto ignored = co_await std::move(task).wrap();
      auto completed = finalized_blocks_.find(id);
      if (completed == finalized_blocks_.end()) {
        co_return Finalization::Idle;
      }
      if (completed->second.state == Finalization::Finalized) {
        touch_finalized_cache(id);
      }
      co_return completed->second.state;
    }

    // During steady-state processing, a candidate newer than the latest
    // finalization observed by this resolver cannot yet need the historical
    // finalized fast path. Avoid serializing its first resolution behind a
    // RocksDB point read. Startup/replay remains conservative until the first
    // FinalizationObserved event, and finalize_blocks() always checks the DB.
    if (skip_db_for_newer_slot && latest_finalized_slot_.has_value() && id.slot > *latest_finalized_slot_) {
      ++finalized_db_skips_;
      co_return Finalization::Idle;
    }

    auto key = create_serialize_tl_object<tl::db_key_finalizedBlock>(id.to_tl());
    auto value = co_await owning_bus()->db->get_latest(std::move(key));
    if (!value.has_value()) {
      ++finalized_db_misses_;
      co_return Finalization::Idle;
    }

    ++finalized_db_hits_;
    finalized_blocks_[id].state = Finalization::Finalized;
    touch_finalized_cache(id);
    co_return Finalization::Finalized;
  }

  td::actor::Task<ResolvedState> resolve_state_inner(ParentId id) {
    std::vector<CandidateRef> candidates_to_apply;
    std::optional<double> gen_utime_exact;
    std::optional<ChainStateRef> state;
    std::optional<BlockIdExt> empty_reference;
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

      // An already-signed candidate names this exact parent CandidateId.
      // Local skip-certificate visibility cannot replace that ancestry.
      // Resolve the exact candidate or fail closed; a missing ancestor must
      // never silently omit a full state transition.
      auto resolved_candidate = co_await owning_bus().publish<ResolveCandidate>(*id).wrap();
      if (resolved_candidate.is_error()) {
        co_return td::Status::Error(resolved_candidate.error().code(),
                                    PSTRING() << "Simplex state-resolver: cannot resolve exact ancestor " << *id
                                              << ": " << resolved_candidate.error().message());
      }
      auto candidate = resolved_candidate.move_as_ok().candidate;
      if (candidate->id != *id) {
        co_return td::Status::Error(ErrorCode::protoviolation,
                                    PSTRING() << "Simplex state-resolver: resolver returned candidate " << candidate->id
                                              << " for exact ancestor " << *id);
      }
      if (candidate->is_empty()) {
        // If this walk contains no full candidate, the exact empty candidate
        // still names the block whose state it preserves. A restarted Start
        // may point at a later local tip and is not this session's origin.
        if (!empty_reference.has_value()) {
          empty_reference = candidate->block_id();
        }
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

      if (!reconstruct_from_candidate_data && (co_await finalization_of(*id, true)) == Finalization::Finalized) {
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
      std::vector<BlockIdExt> base_blocks;
      if (!candidates_to_apply.empty()) {
        // The oldest full candidate carries the exact predecessor block IDs
        // its Merkle update was built from. On restart, Start can be a newer
        // local tip; using that tip as the replay base applies old updates to
        // the wrong state and aborts. Derive the base from the candidate's
        // validated block header instead, including split/merge predecessors.
        const auto& oldest = std::get<BlockCandidate>(candidates_to_apply.back()->block);
        auto block_result = create_block(oldest.id, oldest.data.clone());
        if (block_result.is_error()) {
          co_return block_result.move_as_error_prefix("Simplex state-resolver: cannot read oldest candidate block: ");
        }
        BlockIdExt mc_block_id;
        bool after_split = false;
        auto unpack_status = block::unpack_block_prev_blk_try(block_result.move_as_ok()->root_cell(), oldest.id,
                                                               base_blocks, mc_block_id, after_split);
        if (unpack_status.is_error() || base_blocks.empty() || base_blocks.size() > 2) {
          co_return td::Status::Error(ErrorCode::protoviolation,
                                      PSTRING() << "Simplex state-resolver: oldest candidate " << oldest.id.to_str()
                                                << " has unusable predecessor IDs: " << unpack_status);
        }
      } else if (empty_reference.has_value()) {
        base_blocks.push_back(*empty_reference);
      } else {
        // Resolving the null parent for fresh production still starts from
        // Start. No historical candidate is being replayed in this case.
        base_blocks = genesis->state->block_ids();
      }
      // The exact predecessor can still be coming online after restart. Retry
      // only its read-only manager lookup, for a bounded number of attempts;
      // never substitute the newer Start tip when it remains unavailable.
      for (unsigned attempt = 0; attempt < 3; ++attempt) {
        auto manager_state =
            co_await ChainState::from_manager(owning_bus()->manager, owning_bus()->shard,
                                              base_blocks, genesis->state->min_mc_block_id())
                .wrap();
        if (manager_state.is_ok()) {
          state = manager_state.move_as_ok();
          break;
        }
        auto error = manager_state.move_as_error();
        if (error.code() != ErrorCode::notready && error.code() != ErrorCode::timeout) {
          co_return error;
        }
        if (attempt == 2) {
          co_return td::Status::Error(ErrorCode::notready,
                                      PSTRING() << "Simplex state-resolver: exact predecessor state unavailable after 3 attempts: "
                                                << error.message());
        }
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
    }
    for (auto it = candidates_to_apply.rbegin(); it != candidates_to_apply.rend(); ++it) {
      state = (*state)->apply(std::get<BlockCandidate>((*it)->block));
    }
    co_return ResolvedState{*state, gen_utime_exact};
  }

  // ===== Block finalization =====
  struct FinalizedBlock {
    Finalization state = Finalization::Idle;
    size_t attempts = 0;
    std::vector<td::Promise<td::Unit>> waiters;
  };

  std::map<CandidateId, FinalizedBlock> finalized_blocks_;
  CompletedLru<CandidateId> finalized_blocks_lru_{
      cache_limit_from_env("TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES", DEFAULT_FINALIZED_CACHE_MAX_ENTRIES)};
  size_t finalized_cache_evictions_ = 0;
  InflightAdmission finalized_inflight_{
      cache_limit_from_env("TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX", DEFAULT_FINALIZED_INFLIGHT_MAX)};
  size_t finalized_admission_rejections_ = 0;
  // Finalizations entered and finished. Kept as two counters rather than one gauge so a
  // finalization that never returns is visible as a gap that stops closing.
  size_t finalizations_started_ = 0;
  size_t finalizations_settled_ = 0;
  size_t finalization_retries_ = 0;
  size_t finalization_retries_at_admission_ = 0;
  // Finalizations that have been failing long enough to have been reported once. They are
  // still being retried; this is what an operator watches, not a count of what was lost.
  size_t finalizations_stalled_ = 0;
  size_t finalizations_stalled_permanently_ = 0;
  // Certificates held un-converted right now, and whether the group has been told to stop.
  size_t pending_finalizations_ = 0;
  bool backlog_over_limit_ = false;
  const size_t pending_finalizations_max_ =
      cache_limit_from_env("TOS_SIMPLEX_PENDING_FINALIZATIONS_MAX", DEFAULT_PENDING_FINALIZATIONS_MAX);
  size_t finalized_db_hits_ = 0;
  size_t finalized_db_misses_ = 0;
  size_t finalized_db_skips_ = 0;
  size_t injected_transient_failures_remaining_ = injected_transient_finalization_failures();
  size_t injected_permanent_failures_remaining_ = injected_permanent_finalization_failures();

  void touch_finalized_cache(const CandidateId& id) {
    auto evicted = finalized_blocks_lru_.touch(id);
    if (!evicted.has_value()) {
      return;
    }
    auto it = finalized_blocks_.find(*evicted);
    CHECK(it != finalized_blocks_.end());
    CHECK(it->second.state == Finalization::Finalized);
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
        finalized_inflight += entry.state == Finalization::InFlight;
        finalized_waiters += entry.waiters.size();
      }
      LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-state-resolver"
                   << " state_cache=" << state_cache_.size() << "/" << state_cache_lru_.capacity()
                   << " state_evictions=" << state_cache_evictions_ << " state_inflight=" << state_inflight
                   << " state_waiters=" << state_waiters << " state_inflight_admission=" << state_inflight_.count()
                   << "/" << state_inflight_.capacity() << " state_admission_rejections=" << state_admission_rejections_
                   << " unique_state_blocks=" << unique_blocks.size() << " state_block_bytes=" << state_block_bytes
                   << " finalized_cache=" << finalized_blocks_.size() << "/" << finalized_blocks_lru_.capacity()
                   << " finalized_evictions=" << finalized_cache_evictions_
                   << " finalized_inflight=" << finalized_inflight << " finalized_waiters=" << finalized_waiters
                   << " finalized_inflight_admission=" << finalized_inflight_.count() << "/"
                   << finalized_inflight_.capacity()
                   << " finalized_admission_rejections=" << finalized_admission_rejections_
                   << " finalization_retries=" << finalization_retries_
                   << " finalization_retries_at_admission=" << finalization_retries_at_admission_
                   << " finalizations_stalled=" << finalizations_stalled_
                   << " pending_finalizations=" << pending_finalizations_ << "/" << pending_finalizations_max_
                   << " finalizations_stalled_permanently=" << finalizations_stalled_permanently_
                   << " finalizations_outstanding=" << (finalizations_started_ - finalizations_settled_)
                   << " finalized_db_hits=" << finalized_db_hits_ << " finalized_db_misses=" << finalized_db_misses_
                   << " finalized_db_skips=" << finalized_db_skips_;
    }
  }

  td::actor::Task<> finalize_blocks(CandidateId id, std::optional<FinalCertRef> final_cert,
                                    std::optional<CandidateRef> final_candidate) {
    ++finalizations_started_;
    SCOPE_EXIT {
      ++finalizations_settled_;
    };
    switch (co_await finalization_of(id)) {
      case Finalization::Finalized:
        co_return td::Unit{};
      case Finalization::StalledPermanently:
        co_return td::Status::Error(ErrorCode::protoviolation, PSTRING() << "Simplex state-resolver: slot " << id.slot
                                                                         << " is permanently stalled");
      case Finalization::InFlight:
        // The attempt this waited on finished and another has already started. Fall through
        // to the re-read below, which attaches to whichever attempt is now running.
      case Finalization::Idle:
        break;
    }
    // finalization_of() may have suspended on a database read, so the entry can have been
    // decided by another attempt while this one was waiting. Read it again before committing
    // to anything: adding a waiter to an entry that has already resolved its waiters is a
    // promise nobody is left to keep.
    if (auto it = finalized_blocks_.find(id); it != finalized_blocks_.end()) {
      switch (it->second.state) {
        case Finalization::Finalized:
          touch_finalized_cache(id);
          co_return td::Unit{};
        case Finalization::InFlight: {
          // Someone else owns the attempt; wait for its verdict rather than starting a
          // second conversion of the same certificate.
          auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
          it->second.waiters.push_back(std::move(promise));
          co_return co_await std::move(task);
        }
        case Finalization::Idle:
          break;
        case Finalization::StalledPermanently:
          co_return td::Status::Error(ErrorCode::protoviolation, PSTRING() << "Simplex state-resolver: slot " << id.slot
                                                                           << " is permanently stalled");
      }
    }
    // Every attempt is admitted, including a retry of one that failed transiently: an entry
    // left behind by a failed attempt no longer holds an admission slot, and retries that
    // skipped admission would be exactly the concurrency the limit exists to bound.
    //
    // A rejection here is the transient failure that costs the most, because it happens
    // before anything has been recorded. The event that carried this certificate is already
    // consumed, so returning the rejection alone drops the certificate with nothing left to
    // ask for it again. The attempt is counted against an entry and retried, exactly as a
    // failure inside the attempt is.
    FinalizedBlock& state = finalized_blocks_[id];
    if (!finalized_inflight_.try_admit()) {
      ++finalized_admission_rejections_;
      ++state.attempts;
      auto rejection =
          td::Status::Error(ErrorCode::notready,
                            PSTRING() << "Simplex state-resolver: too many concurrent finalizations ("
                                      << finalized_inflight_.count() << "/" << finalized_inflight_.capacity() << ")");
      ++finalization_retries_;
      ++finalization_retries_at_admission_;
      report_if_stalled(id, state, rejection.message());
      retry_finalization(id, final_cert, final_candidate, state.attempts).start().detach();
      co_return std::move(rejection);
    }
    state.state = Finalization::InFlight;
    ++state.attempts;
    {
      SCOPE_EXIT {
        finalized_inflight_.release();
      };
      auto result = co_await finalize_blocks_inner(id, final_cert, final_candidate).wrap();
      auto waiters = std::move(state.waiters);
      if (result.is_ok()) {
        state.state = Finalization::Finalized;
        touch_finalized_cache(id);
      } else {
        switch (classify_failure(result.error())) {
          case FailureKind::Cancelled:
            // The group is going away. Leave the entry as it is; nothing outlives this.
            state.state = Finalization::Idle;
            break;
          case FailureKind::Retryable:
            // The entry goes back to Idle rather than being erased, because erasing it
            // loses the fact that this candidate still needs finalizing -- and the
            // FinalizationObserved that would have said so again was consumed when this
            // attempt started. A retry is scheduled while the certificate is still in hand,
            // and there is no count at which that stops: see the constants above.
            state.state = Finalization::Idle;
            ++finalization_retries_;
            report_if_stalled(id, state, result.error().message());
            retry_finalization(id, final_cert, final_candidate, state.attempts).start().detach();
            break;
          case FailureKind::Permanent:
            // Kept, reported, and not retried. The certificate is still evidence a quorum
            // agreed on, so it is not thrown away, and it still counts against the backlog
            // below -- a chain must not run ahead of a finality that is not coming.
            state.state = Finalization::StalledPermanently;
            ++finalizations_stalled_permanently_;
            LOG(ERROR) << "Simplex state-resolver: the certificate for slot " << id.slot
                       << " cannot be finalized and retrying will not change that: " << result.error().message()
                       << ". It is kept rather than dropped, and this group stops producing.";
            break;
        }
      }
      update_finalization_backlog();
      for (auto& p : waiters) {
        p.set_result(result.clone());
      }
      co_return std::move(result);
    }
  }

  // Count what is being held, and tell the group when that crosses the limit or clears.
  //
  // A pending finalization is a certificate this resolver is holding because converting it
  // has not succeeded: still being retried, or stopped for a reason retrying cannot mend.
  // Neither is dropped, so the only lever left is to stop adding to the pile.
  void update_finalization_backlog() {
    size_t pending = 0;
    size_t beyond_retrying = 0;
    for (const auto& [_, entry] : finalized_blocks_) {
      const bool unresolved =
          entry.state == Finalization::StalledPermanently ||
          ((entry.state == Finalization::Idle || entry.state == Finalization::InFlight) && entry.attempts > 0);
      pending += unresolved ? 1 : 0;
      beyond_retrying += entry.state == Finalization::StalledPermanently ? 1 : 0;
    }
    pending_finalizations_ = pending;
    // One certificate that can never be converted is enough on its own, whatever the limit
    // says. The limit exists to bound a queue that is still moving; a finalization beyond
    // retrying is not a queue, it is a chain that cannot pass this slot, and producing more
    // for it is pointless rather than merely expensive.
    const bool over = pending > pending_finalizations_max_ || beyond_retrying > 0;
    if (over == backlog_over_limit_) {
      return;
    }
    backlog_over_limit_ = over;
    if (over) {
      LOG(ERROR) << "Simplex state-resolver: " << pending
                 << " agreed certificates are waiting to be finalized, over the limit of " << pending_finalizations_max_
                 << "; this group stops producing until they clear. Nothing is discarded.";
    } else {
      LOG(WARNING) << "Simplex state-resolver: the finalization backlog has cleared; this group produces again.";
    }
    owning_bus().publish<FinalizationBacklog>(over, pending);
  }

  // Say once that a finalization has been failing long enough to be worth looking at, and
  // keep the entry either way. This replaces giving up: the operator is told at the same
  // point the old code abandoned the certificate, and the certificate stays.
  void report_if_stalled(const CandidateId& id, FinalizedBlock& state, td::Slice last_error) {
    if (state.attempts != finalization_attempts_before_reporting) {
      return;
    }
    ++finalizations_stalled_;
    LOG(ERROR) << "Simplex state-resolver: the certificate for slot " << id.slot << " has failed to finalize "
               << state.attempts << " times and is still being retried; the last failure was " << last_error;
  }

  // Try a transiently failed finalization again, after a backoff that grows with the attempt
  // up to a cap. Detached on purpose: the caller that met the failure has already been told,
  // and this exists so the certificate is not forgotten, not so anyone waits for it.
  td::actor::Task<> retry_finalization(CandidateId id, std::optional<FinalCertRef> final_cert,
                                       std::optional<CandidateRef> final_candidate, size_t attempts) {
    const double delay =
        std::min(finalization_retry_delay * static_cast<double>(attempts), max_finalization_retry_delay);
    co_await td::actor::coro_sleep(td::Timestamp::in(delay));
    auto result = co_await finalize_blocks(id, std::move(final_cert), std::move(final_candidate)).wrap();
    if (result.is_error() && result.error().code() != ErrorCode::cancelled) {
      LOG(DEBUG) << "Simplex state-resolver: retry of slot " << id.slot
                 << " did not finalize it yet: " << result.error().message();
    }
    co_return td::Unit{};
  }

  td::actor::Task<> finalize_blocks_inner(CandidateId id, std::optional<FinalCertRef> final_cert,
                                          std::optional<CandidateRef> final_candidate) {
    auto& bus = *owning_bus();

    if (injected_transient_failures_remaining_ > 0) {
      --injected_transient_failures_remaining_;
      co_return td::Status::Error(ErrorCode::notready,
                                  "Simplex state-resolver: injected transient finalization failure");
    }
    if (injected_permanent_failures_remaining_ > 0) {
      --injected_permanent_failures_remaining_;
      co_return td::Status::Error(ErrorCode::protoviolation,
                                  "Simplex state-resolver: injected permanent finalization failure");
    }

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

      // Conversion preserves the already verified certificate bytes in the post-quantum
      // block-finality carrier. Any structural disagreement is returned as a status before
      // FinalizeBlock is published.
      auto sig_set = final_cert ? (*final_cert)->to_signature_set(*final_candidate, bus)
                                : notar_cert->to_signature_set(candidate, bus);
      if (sig_set.is_error()) {
        co_return sig_set.move_as_error();
      }
      co_await owning_bus().publish<FinalizeBlock>(candidate, sig_set.move_as_ok());
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
