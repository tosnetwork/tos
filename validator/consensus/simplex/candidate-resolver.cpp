/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <unordered_set>

#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/memory-tracker.h"
#include "validator/rate-limiter.h"

#include "bus.h"
#include "candidate-payload-budget.h"
#include "candidate-retention.h"

namespace tos::validator::consensus::simplex {

namespace tl {

using candidateAndCert = tos_api::consensus_simplex_candidateAndCert;
using CandidateAndCertRef = tl_object_ptr<candidateAndCert>;

using requestCandidate = tos_api::consensus_simplex_requestCandidate;
using RequestCandidateRef = tl_object_ptr<requestCandidate>;

using db_key_candidateResolver_candidateInfo = tos_api::consensus_simplex_db_key_candidateResolver_candidateInfo;
using db_key_candidateResolver_candidateInfoRef = tl_object_ptr<db_key_candidateResolver_candidateInfo>;

using db_candidateResolver_candidateInfo = tos_api::consensus_simplex_db_candidateResolver_candidateInfo;
using db_candidateResolver_candidateInfoRef = tl_object_ptr<db_candidateResolver_candidateInfo>;

using db_key_candidateResolver_notarCert = tos_api::consensus_simplex_db_key_candidateResolver_notarCert;
using db_key_candidateResolver_notarCertRef = tl_object_ptr<db_key_candidateResolver_notarCert>;

using db_candidateResolver_notarCert = tos_api::consensus_simplex_db_candidateResolver_notarCert;
using db_candidateResolver_notarCertRef = tl_object_ptr<db_candidateResolver_notarCert>;

using db_key_candidate = tos_api::consensus_simplex_db_key_candidate;
using db_key_candidateRef = tl_object_ptr<db_key_candidate>;

}  // namespace tl

namespace {
using BlockSignatureSetRef = td::Ref<block::BlockSignatureSet>;

// Bounds peer-query retries for an exact CandidateId. StateResolver never
// replaces a signed parent with local skip evidence, so an unavailable exact
// ancestor must fail cleanly instead of leaving resolution in flight forever.
// New proposals choose their base in Pool before signing; this retry bound
// also covers withholding, partitions, and malformed skip-only references.
constexpr int DEFAULT_CANDIDATE_RESOLVE_MAX_ATTEMPTS = 16;

int candidate_resolve_max_attempts_from_env() {
  const char* value = std::getenv("TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS");
  if (value == nullptr) {
    return DEFAULT_CANDIDATE_RESOLVE_MAX_ATTEMPTS;
  }
  auto parsed = td::to_integer_safe<int>(td::Slice(value));
  if (parsed.is_error() || parsed.ok() <= 0) {
    LOG(WARNING) << "Simplex candidate-resolver: ignoring invalid "
                    "TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS="
                 << value;
    return DEFAULT_CANDIDATE_RESOLVE_MAX_ATTEMPTS;
  }
  return parsed.move_as_ok();
}

// Database reads of candidate payloads one resolver runs at once. Each holds the stored record
// and the candidate decoded from it until the reader is done, so this bounds the cold-read
// buffers of a resolver to this many candidates. Readers beyond it wait in arrival order.
constexpr size_t COLD_READ_CONCURRENCY = 4;
// Peer requests that may wait for a read slot. A peer request that would wait beyond this is
// refused as busy, and the peer asks again or asks another validator; local readers always wait,
// and there is at most one local resolve per candidate.
constexpr size_t COLD_READ_MAX_REMOTE_WAITERS = 32;

td::uint64 candidate_data_bytes(const Candidate& candidate) {
  if (const auto* block = std::get_if<BlockCandidate>(&candidate.block)) {
    return saturating_add(block->data.size(), block->collated_data.size());
  }
  return 0;
}

struct CandidateAndCert {
  static td::Result<CandidateAndCert> from_tl(tl::candidateAndCert &&entry, const tl::requestCandidate &request,
                                              const Bus &bus) {
    if (!entry.candidate_.empty() && !request.want_candidate_) {
      return td::Status::Error("Candidate was not requested but was provided");
    }
    if (!entry.notar_.empty() && !request.want_notar_) {
      return td::Status::Error("Notar cert was not requested but was provided");
    }

    auto id = CandidateId::from_tl(request.id_);
    CandidateAndCert result;

    if (!entry.candidate_.empty()) {
      TRY_RESULT(candidate, Candidate::deserialize(entry.candidate_, bus));
      if (candidate->id != id) {
        return td::Status::Error("Candidate id mismatch");
      }
      result.candidate = candidate;
    }
    if (!entry.notar_.empty()) {
      auto vote = NotarizeVote{id};
      TRY_RESULT(signatures, fetch_tl_object<tl::voteSignatureSet>(entry.notar_, true));
      TRY_RESULT_ASSIGN(result.notar_cert, NotarCert::from_tl(std::move(*signatures), vote, bus));
    }
    return result;
  }

  tl::CandidateAndCertRef to_tl(const tl::requestCandidate &request) {
    auto id = CandidateId::from_tl(request.id_);

    td::BufferSlice serialized_candidate;
    if (request.want_candidate_ && candidate.has_value()) {
      CHECK((*candidate)->id == id);
      serialized_candidate = (*candidate)->serialize();
    }

    td::BufferSlice serialized_notar;
    if (request.want_notar_ && notar_cert.has_value()) {
      serialized_notar = serialize_tl_object((*notar_cert)->to_tl_vote_signature_set(), true);
    }

    return create_tl_object<tl::candidateAndCert>(std::move(serialized_candidate), std::move(serialized_notar));
  }

  bool is_complete() const {
    return candidate.has_value() && notar_cert.has_value();
  }

  ResolveCandidate::Result as_resolution_result() const {
    CHECK(is_complete());
    return {*candidate, *notar_cert};
  }

  tl::RequestCandidateRef make_request(CandidateId id) const {
    return create_tl_object<tl::requestCandidate>(id.to_tl(), !candidate.has_value(), !notar_cert.has_value());
  }

  void merge(const CandidateAndCert &other) {
    if (!candidate.has_value() && other.candidate.has_value()) {
      candidate = other.candidate;
    }
    if (!notar_cert.has_value() && other.notar_cert.has_value()) {
      notar_cert = other.notar_cert;
    }
  }

  std::optional<CandidateRef> candidate = std::nullopt;
  std::optional<NotarCertRef> notar_cert = std::nullopt;
};

class CandidateResolverImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator() || bus.config.observers_in_private_overlay();
  }

  void start_up() override {
    params_ = owning_bus()->config.noncritical_params;
    load_from_db();
    LOG(INFO) << "Simplex candidate-resolver retention window: " << retention_policy_.retained_slots()
              << " finalized slots; node-wide finalized payload cache: " << payload_budget_.limit() << " bytes";
    if (td::memory_tracker_enabled()) {
      alarm_timestamp() = td::Timestamp::in(60.0);
    }
  }

  void alarm() override {
    for (auto& [id, state] : state_) {
      schedule_store_notar_cert(id, state);
    }
    prune_finalized();
    payload_budget_.sweep();
    log_memory_diagnostics();
    alarm_timestamp() = td::Timestamp::in(60.0);
  }

  void tear_down() override {
    // Nothing is cached after this point: an operation that still ends later must not charge
    // the node-wide allowance for an entry nobody will release.
    stopped_ = true;
    for (auto& [id, s] : state_) {
      for (auto &p : s.resolve_awaiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
      for (auto &p : s.store_awaiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
      for (auto& p : s.load_awaiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
      s.load_awaiters.clear();
      // Cached payloads go to the node-wide allowance, which keeps any that something still
      // holds charged after this session is gone.
      if (s.payload_cached) {
        drop_cached_payload(id, s);
      }
    }
    while (!cold_read_waiters_.empty()) {
      auto promise = std::move(cold_read_waiters_.front());
      cold_read_waiters_.pop_front();
      promise.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
    }
    payload_budget_.sweep();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const NoncriticalParamsUpdated> event) {
    if (params_.candidate_resolve_rate_limit != event->params.candidate_resolve_rate_limit) {
      rate_limiter_.clear();
    }
    params_ = event->params;
  }

  template <>
  td::actor::Task<ProtocolMessage> process(BusHandle, std::shared_ptr<IncomingOverlayRequest> event) {
    auto request = co_await fetch_tl_object<tl::requestCandidate>(event->request.data, true);
    auto id = CandidateId::from_tl(request->id_);

    co_await check_rate_limit(event->source);

    if (auto it = state_.find(id); it != state_.end()) {
      auto& state = it->second;
      begin_operation(state);
      SCOPE_EXIT {
        end_operation(id, state);
      };
      if (request->want_candidate_) {
        co_await try_load_candidate_data_from_db(id, state, /*tracked=*/true, /*remote=*/true);
      }
      if (request->want_notar_) {
        co_await try_load_notar_cert_from_db_or_bootstrap(id, state);
      }
      co_return ProtocolMessage{state.candidate_and_cert.to_tl(*request)};
    }
    // An id this node is not tracking is served through a transient state
    // that never enters the map: the requested id is remote-chosen (any
    // slot, including far beyond the retention window), so inserting it
    // would let peers grow the map for the life of the session. Anything
    // durable is still served from the database and bootstrap set.
    CandidateState state;
    if (request->want_candidate_) {
      co_await try_load_candidate_data_from_db(id, state, /*tracked=*/false, /*remote=*/true);
    }
    if (request->want_notar_) {
      co_await try_load_notar_cert_from_db_or_bootstrap(id, state);
    }
    co_return ProtocolMessage{state.candidate_and_cert.to_tl(*request)};
  }

  template <>
  td::actor::Task<ResolveCandidate::Result> process(BusHandle bus, std::shared_ptr<ResolveCandidate> request) {
    CandidateState &state = state_[request->id];
    begin_operation(state);
    SCOPE_EXIT {
      end_operation(request->id, state);
    };

    if (state.candidate_and_cert.is_complete()) {
      if (!state.candidate_in_db && !state.candidate_stored) {
        co_await store_candidate(request->id, state);
      }
      schedule_store_notar_cert(request->id, state);
      co_return state.candidate_and_cert.as_resolution_result();
    }

    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    state.resolve_awaiters.push_back(std::move(promise));

    if (state.resolve_awaiters.size() == 1) {
      // The task holds its own pin on the entry: once a store or a notarization completes
      // the entry and resumes the awaiters, this coroutine returns and drops its pin while
      // the task can still be suspended on a request or a cooldown. Taken here, before the
      // task is started, so no scheduling order leaves it unpinned.
      begin_operation(state);
      resolve_candidate_task(request->id, state).start().detach();
    }

    co_await std::move(task);
    co_return state.candidate_and_cert.as_resolution_result();
  }

  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<StoreCandidate> request) {
    auto &state = state_[request->candidate->id];
    begin_operation(state);
    SCOPE_EXIT {
      end_operation(request->candidate->id, state);
    };

    // The id commits to the contents, so a payload already held is the same one; keeping it
    // keeps a cached copy and the allocations it is charged for paired.
    if (!state.candidate_and_cert.candidate.has_value()) {
      state.candidate_and_cert.candidate = request->candidate;
    }
    maybe_resume_resolve_awaiters(state);

    if (state.candidate_stored) {
      co_return td::Unit{};
    }

    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    state.store_awaiters.push_back(std::move(promise));

    if (state.store_awaiters.size() == 1) {
      auto result = co_await store_candidate(request->candidate->id, state).wrap();

      for (auto &p : state.store_awaiters) {
        p.set_result(result.clone());
      }
      state.store_awaiters.clear();
    }

    co_await std::move(task);
    co_return td::Unit{};
  }

  template <>
  td::actor::Task<size_t> process(BusHandle, std::shared_ptr<QueryResolverTrackedStateCount> query) {
    size_t count = 0;
    for (const auto& [id, _] : state_) {
      if (id.slot >= query->min_slot) {
        ++count;
      }
    }
    co_return count;
  }

  template <>
  td::actor::Task<QueryCandidatePayloadCache::Result> process(BusHandle,
                                                              std::shared_ptr<QueryCandidatePayloadCache> query) {
    auto result = payload_cache_state();
    if (query->id.has_value()) {
      if (auto it = state_.find(*query->id); it != state_.end()) {
        result.id_tracked = true;
        result.id_payload_resident = it->second.candidate_and_cert.candidate.has_value();
        result.id_payload_cached = it->second.payload_cached;
        result.id_durable = is_durable(it->second);
      }
    }
    co_return result;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const NotarizationObserved> event) {
    auto &state = state_[event->id];
    state.candidate_and_cert.notar_cert = event->certificate;
    maybe_resume_resolve_awaiters(state);
    schedule_store_notar_cert(event->id, state);
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizationObserved> event) {
    auto previous = retention_policy_.latest_finalized_slot();
    retention_policy_.observe_finalized(event->id.slot);
    prune_finalized();
    // Payloads of the slots finalized just now may be cached from here on, oldest slot first,
    // so that under pressure the newest ones are the ones kept.
    auto latest = retention_policy_.latest_finalized_slot();
    if (latest.has_value() && (!previous.has_value() || *previous < *latest)) {
      td::uint32 first = previous.has_value() ? *previous + 1 : 0;
      for (auto it = state_.lower_bound(CandidateId{first, {}}); it != state_.end() && it->first.slot <= *latest;
           ++it) {
        admit_payload(it->first, it->second);
      }
    }
    payload_budget_.sweep();
  }

 private:
  struct CandidateState {
    bool candidate_in_db = false;
    bool candidate_stored = false;
    bool notar_stored = false;
    bool notar_store_in_flight = false;
    // The payload is the cache's compact copy and is charged to the node-wide allowance.
    bool payload_cached = false;
    // A database read of the payload is running; later readers wait for it instead of
    // starting their own.
    bool payload_load_in_flight = false;
    // Counts completed candidate stores, so a database read that started before one can tell
    // that its result no longer describes the record.
    td::uint64 store_generation = 0;
    size_t active_operations = 0;
    CandidateAndCert candidate_and_cert;

    std::vector<td::Promise<td::Unit>> resolve_awaiters;
    std::vector<td::Promise<td::Unit>> store_awaiters;
    std::vector<td::Promise<td::Unit>> load_awaiters;
  };

  NewConsensusConfig::NoncriticalParams params_;
  std::map<CandidateId, CandidateState> state_;
  std::map<adnl::AdnlNodeIdShort, td::RateLimiterWindow> rate_limiter_;
  CandidateRetentionPolicy retention_policy_{candidate_retention_slots_from_env()};
  size_t state_evictions_ = 0;

  // The cached finalized payloads of this resolver, oldest slot first, and the allocations
  // each is charged for in the node-wide allowance.
  CandidatePayloadBudget& payload_budget_ = node_candidate_payload_budget();
  std::map<CandidateId, CachedPayloadAllocations> cached_payloads_;
  td::uint64 cached_bytes_ = 0;
  td::uint64 admitted_payloads_ = 0;
  td::uint64 admitted_bytes_ = 0;
  td::uint64 dropped_payloads_ = 0;
  td::uint64 not_cached_payloads_ = 0;
  bool stopped_ = false;

  td::uint64 db_payload_reads_ = 0;
  td::uint64 db_payload_read_misses_ = 0;
  td::uint64 db_payload_read_invalid_ = 0;
  td::uint64 coalesced_reads_ = 0;
  td::uint64 durability_revocations_ = 0;

  size_t cold_reads_in_flight_ = 0;
  size_t cold_reads_in_flight_peak_ = 0;
  std::deque<td::Promise<td::Unit>> cold_read_waiters_;
  size_t cold_read_waiters_peak_ = 0;
  td::uint64 cold_read_bytes_in_flight_ = 0;
  td::uint64 cold_read_bytes_peak_ = 0;
  td::uint64 cold_reads_refused_ = 0;

  static bool can_evict(const CandidateState& state) {
    const CandidateEvictionState eviction_state{
        .active_operations = state.active_operations,
        .resolve_waiters = state.resolve_awaiters.size(),
        .store_waiters = state.store_awaiters.size(),
        .notar_store_in_flight = state.notar_store_in_flight,
        .candidate_durable = !state.candidate_and_cert.candidate.has_value() || state.candidate_in_db ||
                             state.candidate_stored,
        .notar_durable = !state.candidate_and_cert.notar_cert.has_value() || state.notar_stored,
    };
    return eviction_state.can_evict();
  }

  void begin_operation(CandidateState& state) {
    ++state.active_operations;
  }

  // The last pin of an entry is where an operation may have added a payload (a store, a
  // database read, a network response) or ended its use of one, so it is where the payload
  // is cached or let go, whatever path the operation took to get here.
  void end_operation(const CandidateId& id, CandidateState& state) {
    CHECK(state.active_operations > 0);
    --state.active_operations;
    if (state.active_operations != 0) {
      return;
    }
    if (retention_policy_.is_before_retained_window(id) && can_evict(state)) {
      auto it = state_.find(id);
      CHECK(it != state_.end());
      CHECK(&it->second == &state);
      release_entry_payload(id, state);
      state_.erase(it);
      ++state_evictions_;
    } else {
      admit_payload(id, state);
    }
    payload_budget_.sweep();
  }

  void prune_finalized() {
    state_evictions_ += prune_candidate_states(
        state_, retention_policy_.first_retained_slot(), [](const CandidateState& state) { return can_evict(state); },
        [this](const CandidateId& id, CandidateState& state) { release_entry_payload(id, state); });
  }

  bool slot_is_finalized(td::uint32 slot) const {
    auto latest = retention_policy_.latest_finalized_slot();
    return latest.has_value() && slot <= *latest;
  }

  static bool is_durable(const CandidateState& state) {
    return state.candidate_in_db || state.candidate_stored;
  }

  // Nothing is using the entry's payload: no operation holds the entry and nobody waits on it.
  static bool payload_unused(const CandidateState& state) {
    return state.active_operations == 0 && state.resolve_awaiters.empty() && state.store_awaiters.empty() &&
           state.load_awaiters.empty() && !state.payload_load_in_flight;
  }

  // Whether a payload the entry holds outside the cache may now go to the cache. Unlike
  // can_evict(), the notarization certificate does not matter: it stays in the entry.
  bool payload_cacheable(const CandidateId& id, const CandidateState& state) const {
    return !stopped_ && state.candidate_and_cert.candidate.has_value() && !state.payload_cached &&
           slot_is_finalized(id.slot) && is_durable(state) && payload_unused(state);
  }

  // Whether a cached payload may be dropped to make room.
  static bool payload_droppable(const CandidateState& state) {
    return state.payload_cached && payload_unused(state);
  }

  // Moves a finalized, durable payload nobody uses into the cache, as a compact copy charged
  // to the node-wide allowance. Room is made by dropping this resolver's own cached payloads
  // of older slots, oldest first; when that is not enough, because the rest of the allowance
  // is held by newer payloads, by other sessions or by retired allocations, the payload is
  // not cached. Either way the resolver lets go of the original, and a later reader loads the
  // durable record again.
  void admit_payload(const CandidateId& id, CandidateState& state) {
    if (!payload_cacheable(id, state)) {
      return;
    }
    const auto& original = **state.candidate_and_cert.candidate;
    auto charge = compact_candidate_charge(original);
    // Retired payloads whose last holder is gone give their room back first.
    payload_budget_.sweep();
    while (!payload_budget_.try_reserve(charge)) {
      auto victim = cached_payloads_.end();
      for (auto it = cached_payloads_.begin(); it != cached_payloads_.end() && it->first < id; ++it) {
        auto victim_state = state_.find(it->first);
        if (victim_state != state_.end() && payload_droppable(victim_state->second)) {
          victim = it;
          break;
        }
      }
      if (victim == cached_payloads_.end()) {
        state.candidate_and_cert.candidate.reset();
        ++not_cached_payloads_;
        return;
      }
      auto victim_id = victim->first;
      drop_cached_payload(victim_id, state_.find(victim_id)->second);
    }
    CachedPayloadAllocations allocations;
    auto compact = make_compact_candidate(original, allocations);
    if (allocations.charge != charge) {
      LOG(ERROR) << "Simplex candidate-resolver: compact copy of " << id << " is charged " << allocations.charge
                 << " bytes, reserved " << charge;
    }
    state.candidate_and_cert.candidate = std::move(compact);
    state.payload_cached = true;
    cached_payloads_.emplace(id, allocations);
    cached_bytes_ = saturating_add(cached_bytes_, charge);
    ++admitted_payloads_;
    admitted_bytes_ = saturating_add(admitted_bytes_, charge);
  }

  // Stops caching the entry's payload. The node-wide allowance keeps it charged while
  // anything else still holds it.
  void drop_cached_payload(const CandidateId& id, CandidateState& state) {
    state.payload_cached = false;
    auto it = cached_payloads_.find(id);
    if (it == cached_payloads_.end()) {
      LOG(ERROR) << "Simplex candidate-resolver: cached payload of " << id << " has no charge";
      state.candidate_and_cert.candidate.reset();
      return;
    }
    auto allocations = it->second;
    cached_payloads_.erase(it);
    cached_bytes_ = saturating_sub(cached_bytes_, allocations.charge);
    ++dropped_payloads_;
    CandidateRef payload;
    if (state.candidate_and_cert.candidate.has_value()) {
      payload = std::move(*state.candidate_and_cert.candidate);
      state.candidate_and_cert.candidate.reset();
    }
    payload_budget_.retire(std::move(payload), allocations);
  }

  void release_entry_payload(const CandidateId& id, CandidateState& state) {
    if (state.payload_cached) {
      drop_cached_payload(id, state);
    }
  }

  QueryCandidatePayloadCache::Result payload_cache_state() const {
    QueryCandidatePayloadCache::Result result;
    auto node = payload_budget_.snapshot();
    result.node_limit = node.limit;
    result.node_charged_bytes = node.charged_bytes;
    result.node_charged_peak = node.charged_peak;
    result.node_retired_bytes = node.retired_bytes;
    result.node_retired_payloads = node.retired_payloads;
    result.node_refused_reservations = node.refused_reservations;
    result.node_accounting_errors = node.accounting_errors;
    result.entries = state_.size();
    result.cached_payloads = cached_payloads_.size();
    result.cached_bytes = cached_bytes_;
    result.admitted_payloads = admitted_payloads_;
    result.admitted_bytes = admitted_bytes_;
    result.dropped_payloads = dropped_payloads_;
    result.not_cached_payloads = not_cached_payloads_;
    for (const auto& [id, state] : state_) {
      if (!state.candidate_and_cert.candidate.has_value() || state.payload_cached) {
        continue;
      }
      auto bytes = candidate_data_bytes(**state.candidate_and_cert.candidate);
      if (!slot_is_finalized(id.slot)) {
        result.nonfinalized_bytes = saturating_add(result.nonfinalized_bytes, bytes);
      } else if (!is_durable(state)) {
        result.nondurable_bytes = saturating_add(result.nondurable_bytes, bytes);
      } else {
        result.pinned_bytes = saturating_add(result.pinned_bytes, bytes);
      }
    }
    result.db_payload_reads = db_payload_reads_;
    result.db_payload_read_misses = db_payload_read_misses_;
    result.db_payload_read_invalid = db_payload_read_invalid_;
    result.coalesced_reads = coalesced_reads_;
    result.durability_revocations = durability_revocations_;
    result.cold_read_concurrency = COLD_READ_CONCURRENCY;
    result.cold_read_max_remote_waiters = COLD_READ_MAX_REMOTE_WAITERS;
    result.cold_reads_in_flight = cold_reads_in_flight_;
    result.cold_reads_in_flight_peak = cold_reads_in_flight_peak_;
    result.cold_read_waiters = cold_read_waiters_.size();
    result.cold_read_waiters_peak = cold_read_waiters_peak_;
    result.cold_read_bytes_in_flight = cold_read_bytes_in_flight_;
    result.cold_read_bytes_peak = cold_read_bytes_peak_;
    result.cold_reads_refused = cold_reads_refused_;
    return result;
  }

  // A peer request that would have to wait behind a full queue of readers is refused; a
  // local reader is never refused.
  bool cold_read_must_refuse(bool remote) const {
    return remote && cold_reads_in_flight_ >= COLD_READ_CONCURRENCY &&
           cold_read_waiters_.size() >= COLD_READ_MAX_REMOTE_WAITERS;
  }

  td::actor::Task<> acquire_cold_read() {
    if (cold_reads_in_flight_ < COLD_READ_CONCURRENCY) {
      ++cold_reads_in_flight_;
      cold_reads_in_flight_peak_ = std::max(cold_reads_in_flight_peak_, cold_reads_in_flight_);
      co_return td::Unit{};
    }
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    cold_read_waiters_.push_back(std::move(promise));
    cold_read_waiters_peak_ = std::max(cold_read_waiters_peak_, cold_read_waiters_.size());
    // The slot is handed over by release_cold_read(), so the count does not change here.
    co_await std::move(task);
    co_return td::Unit{};
  }

  void release_cold_read() {
    if (!cold_read_waiters_.empty()) {
      auto promise = std::move(cold_read_waiters_.front());
      cold_read_waiters_.pop_front();
      promise.set_value(td::Unit{});
      return;
    }
    if (cold_reads_in_flight_ == 0) {
      LOG(ERROR) << "Simplex candidate-resolver: released a cold-read slot nobody held";
      return;
    }
    --cold_reads_in_flight_;
  }

  // A read proved that the database does not hold this candidate's record as the entry
  // believed: it is missing, undecodable or for another candidate. Neither flag may claim
  // durability any more, so a payload fetched again is written again before it can be
  // cached and dropped.
  void revoke_durability(const CandidateId& id, CandidateState& state, td::Slice reason) {
    if (!is_durable(state)) {
      return;
    }
    LOG(WARNING) << "Simplex candidate-resolver: candidate data for " << id << " was believed durable but the record "
                 << reason << "; it will be written again when the candidate is obtained";
    state.candidate_in_db = false;
    state.candidate_stored = false;
    ++durability_revocations_;
  }

  void log_memory_diagnostics() const {
    std::unordered_set<const Candidate*> unique_candidates;
    size_t candidate_data_bytes = 0;
    size_t collated_data_bytes = 0;
    size_t signature_bytes = 0;
    size_t proof_bytes = 0;
    size_t notar_certs = 0;
    size_t notar_signatures = 0;
    size_t notar_signature_bytes = 0;
    size_t candidate_in_db = 0;
    size_t candidate_stored = 0;
    size_t resolve_waiters = 0;
    size_t store_waiters = 0;
    size_t active_operations = 0;
    size_t notar_store_in_flight = 0;

    for (const auto& [_, state] : state_) {
      candidate_in_db += state.candidate_in_db;
      candidate_stored += state.candidate_stored;
      if (state.candidate_and_cert.notar_cert.has_value()) {
        ++notar_certs;
        for (const auto& signature : (*state.candidate_and_cert.notar_cert)->signatures) {
          ++notar_signatures;
          notar_signature_bytes += signature.signature.size();
        }
      }
      resolve_waiters += state.resolve_awaiters.size();
      store_waiters += state.store_awaiters.size();
      active_operations += state.active_operations;
      notar_store_in_flight += state.notar_store_in_flight;
      if (!state.candidate_and_cert.candidate.has_value()) {
        continue;
      }
      const auto& candidate = *state.candidate_and_cert.candidate;
      if (!unique_candidates.insert(candidate.get()).second) {
        continue;
      }
      signature_bytes += candidate->signature.size();
      if (const auto* block = std::get_if<BlockCandidate>(&candidate->block)) {
        candidate_data_bytes += block->data.size();
        collated_data_bytes += block->collated_data.size();
        for (const auto& proof : block->out_msg_queue_proof_broadcasts) {
          proof_bytes += proof->queue_proofs.size();
          proof_bytes += proof->block_state_proofs.size();
        }
      }
    }

    LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-candidate-resolver"
                 << " state_entries=" << state_.size() << " unique_candidates=" << unique_candidates.size()
                 << " candidate_data_bytes=" << candidate_data_bytes
                 << " collated_data_bytes=" << collated_data_bytes << " signature_bytes=" << signature_bytes
                 << " proof_bytes=" << proof_bytes << " candidate_in_db=" << candidate_in_db
                 << " candidate_stored=" << candidate_stored << " notar_certs=" << notar_certs
                 << " notar_signatures=" << notar_signatures
                 << " notar_signature_bytes=" << notar_signature_bytes
                 << " resolve_waiters=" << resolve_waiters << " store_waiters=" << store_waiters
                 << " active_operations=" << active_operations
                 << " notar_store_in_flight=" << notar_store_in_flight
                 << " latest_finalized_slot="
                 << retention_policy_.latest_finalized_slot().value_or(0)
                 << " first_retained_slot=" << retention_policy_.first_retained_slot()
                 << " retention_slots=" << retention_policy_.retained_slots()
                 << " evictions=" << state_evictions_ << " rate_limit_peers=" << rate_limiter_.size();

    auto cache = payload_cache_state();
    LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-candidate-payloads"
                 << " node_limit=" << cache.node_limit << " node_charged_bytes=" << cache.node_charged_bytes
                 << " node_charged_peak=" << cache.node_charged_peak
                 << " node_retired_bytes=" << cache.node_retired_bytes
                 << " node_retired_payloads=" << cache.node_retired_payloads
                 << " node_refused_reservations=" << cache.node_refused_reservations
                 << " node_accounting_errors=" << cache.node_accounting_errors
                 << " cached_payloads=" << cache.cached_payloads << " cached_bytes=" << cache.cached_bytes
                 << " admitted_payloads=" << cache.admitted_payloads << " admitted_bytes=" << cache.admitted_bytes
                 << " dropped_payloads=" << cache.dropped_payloads
                 << " not_cached_payloads=" << cache.not_cached_payloads << " pinned_bytes=" << cache.pinned_bytes
                 << " nondurable_bytes=" << cache.nondurable_bytes << " nonfinalized_bytes=" << cache.nonfinalized_bytes
                 << " db_payload_reads=" << cache.db_payload_reads
                 << " db_payload_read_misses=" << cache.db_payload_read_misses
                 << " db_payload_read_invalid=" << cache.db_payload_read_invalid
                 << " coalesced_reads=" << cache.coalesced_reads
                 << " durability_revocations=" << cache.durability_revocations
                 << " cold_reads_in_flight=" << cache.cold_reads_in_flight
                 << " cold_reads_in_flight_peak=" << cache.cold_reads_in_flight_peak
                 << " cold_read_waiters=" << cache.cold_read_waiters
                 << " cold_read_waiters_peak=" << cache.cold_read_waiters_peak
                 << " cold_read_bytes_in_flight=" << cache.cold_read_bytes_in_flight
                 << " cold_read_bytes_peak=" << cache.cold_read_bytes_peak
                 << " cold_reads_refused=" << cache.cold_reads_refused;
  }

  td::Status check_rate_limit(adnl::AdnlNodeIdShort src) {
    if (!rate_limiter_.contains(src)) {
      rate_limiter_[src] = td::RateLimiterWindow{1.0, params_.candidate_resolve_rate_limit};
    }
    auto &window = rate_limiter_[src];
    auto now = td::Timestamp::now();
    if (!window.check(now)) {
      return td::Status::Error(ErrorCode::failure, "too many requests");
    }
    window.insert(now);

    return td::Status::OK();
  }

  void load_from_db() {
    auto &bus = *owning_bus();

    for (const auto& cert : bus.bootstrap_certificates) {
      if (const auto* final_vote = std::get_if<FinalizeVote>(&cert->vote.vote)) {
        retention_policy_.observe_finalized(final_vote->id.slot);
      }
    }

    size_t notar_certs_count = 0;

    // Load only the recent recovery window. Older certificates remain durable
    // in the generic certificate database and can be found in the bootstrap
    // vector on demand without duplicating them in CandidateResolver::state_.
    for (auto cert : bus.bootstrap_certificates) {
      if (std::holds_alternative<NotarizeVote>(cert->vote.vote)) {
        std::move(cert.write()).consume_and_downcast([&]<typename T>(CertificateRef<T> cert) {
          if constexpr (std::same_as<T, NotarizeVote>) {
            if (!retention_policy_.is_before_retained_window(cert->vote.id)) {
              auto& state = state_[cert->vote.id];
              state.candidate_and_cert.notar_cert = cert;
              state.notar_stored = true;
              ++notar_certs_count;
            }
          }
        });
      }
    }

    // Candidate contents are now probed by their exact CandidateId key on
    // demand. Avoid materializing the all-history candidateInfo prefix.
    LOG(INFO) << "Loaded " << notar_certs_count << " recent notarization certificates; "
              << "candidate metadata will be loaded on demand";
  }

  // `tracked` is false for the transient state of an id the map does not hold: such a read is
  // neither coalesced nor recorded, so a remote-chosen id never enters the map. `remote` marks
  // a peer's request, which is refused as busy instead of queueing without bound.
  td::actor::Task<bool> try_load_candidate_data_from_db(CandidateId id, CandidateState& state, bool tracked,
                                                        bool remote) {
    auto &bus = *owning_bus();

    if (state.candidate_and_cert.candidate.has_value()) {
      co_return true;
    }
    if (tracked && state.payload_load_in_flight) {
      // One read per candidate at a time: wait for the running one and use what it found.
      ++coalesced_reads_;
      auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
      state.load_awaiters.push_back(std::move(promise));
      co_await std::move(task);
      co_return state.candidate_and_cert.candidate.has_value();
    }
    if (cold_read_must_refuse(remote)) {
      ++cold_reads_refused_;
      co_return td::Status::Error(ErrorCode::notready, "candidate database reads are busy");
    }
    if (tracked) {
      state.payload_load_in_flight = true;
    }
    SCOPE_EXIT {
      if (tracked) {
        state.payload_load_in_flight = false;
        auto awaiters = std::move(state.load_awaiters);
        state.load_awaiters.clear();
        for (auto& p : awaiters) {
          p.set_value(td::Unit{});
        }
      }
    };
    co_await acquire_cold_read();
    SCOPE_EXIT {
      release_cold_read();
    };

    // A store that completes while this read runs is newer than whatever the read returns.
    const td::uint64 store_generation = state.store_generation;
    auto contents_key = create_serialize_tl_object<tl::db_key_candidate>(id.to_tl());
    ++db_payload_reads_;
    auto data_r = co_await bus.db->get_latest(std::move(contents_key));
    const bool superseded =
        state.store_generation != store_generation || state.candidate_and_cert.candidate.has_value();
    if (!data_r.has_value()) {
      ++db_payload_read_misses_;
      if (!superseded) {
        revoke_durability(id, state, "is missing");
      }
      co_return state.candidate_and_cert.candidate.has_value();
    }
    auto data = std::move(*data_r);
    const td::uint64 read_bytes = data.size();
    cold_read_bytes_in_flight_ = saturating_add(cold_read_bytes_in_flight_, read_bytes);
    cold_read_bytes_peak_ = std::max(cold_read_bytes_peak_, cold_read_bytes_in_flight_);
    SCOPE_EXIT {
      cold_read_bytes_in_flight_ = saturating_sub(cold_read_bytes_in_flight_, read_bytes);
    };
    // Round 140 MEDIUM fix: validate that the deserialized
    // candidate's id matches the requested id, mirroring the
    // network-path gate at CandidateAndCert::from_tl above.
    // Pre-fix this DB resume path used .move_as_ok() and
    // accepted whatever was decoded; a corrupted /
    // mis-indexed db_key_candidate(idA) → bytes-for-idB
    // record let to_tl() at line 69 trip a CHECK on the
    // mismatch, turning a single bad DB record into a
    // remote-triggerable validator abort.  Now we deserialize
    // into a temporary, log-and-skip on either deserialize
    // failure or id mismatch.  Such a record also revokes the
    // entry's durability, so the candidate is written again
    // once a network or local store supplies it.
    auto candidate_res = Candidate::deserialize(data, bus);
    if (candidate_res.is_error()) {
      LOG(WARNING) << "Simplex candidate-resolver: db record for " << id
                   << " failed to deserialize: " << candidate_res.error().message();
      ++db_payload_read_invalid_;
      if (!superseded) {
        revoke_durability(id, state, "does not decode");
      }
      co_return state.candidate_and_cert.candidate.has_value();
    }
    auto candidate = candidate_res.move_as_ok();
    if (candidate->id != id) {
      LOG(WARNING) << "Simplex candidate-resolver: db record for " << id
                   << " contains a candidate for a different id " << candidate->id
                   << " (refusing to surface mismatched bytes)";
      ++db_payload_read_invalid_;
      if (!superseded) {
        revoke_durability(id, state, "holds another candidate");
      }
      co_return state.candidate_and_cert.candidate.has_value();
    }
    if (state.candidate_and_cert.candidate.has_value()) {
      co_return true;
    }
    state.candidate_and_cert.candidate = std::move(candidate);
    state.candidate_in_db = true;

    co_return true;
  }

  td::actor::Task<bool> try_load_notar_cert_from_db_or_bootstrap(CandidateId id, CandidateState& state) {
    if (state.candidate_and_cert.notar_cert.has_value()) {
      co_return true;
    }

    auto key = create_serialize_tl_object<tl::db_key_candidateResolver_notarCert>(id.to_tl());
    auto value = co_await owning_bus()->db->get_latest(std::move(key));
    if (value.has_value()) {
      auto entry_r = fetch_tl_object<tl::db_candidateResolver_notarCert>(*value, true);
      if (entry_r.is_error()) {
        LOG(WARNING) << "Simplex candidate-resolver: stored notarization certificate for " << id
                     << " is malformed: " << entry_r.error();
      } else {
        auto entry = entry_r.move_as_ok();
        auto cert_r = NotarCert::from_tl(std::move(*entry->notar_), NotarizeVote{id}, *owning_bus());
        if (cert_r.is_error()) {
          LOG(WARNING) << "Simplex candidate-resolver: stored notarization certificate for " << id
                       << " is invalid: " << cert_r.error();
        } else {
          state.candidate_and_cert.notar_cert = cert_r.move_as_ok();
          state.notar_stored = true;
          co_return true;
        }
      }
    }

    for (auto cert : owning_bus()->bootstrap_certificates) {
      const auto* vote = std::get_if<NotarizeVote>(&cert->vote.vote);
      if (vote == nullptr || vote->id != id) {
        continue;
      }
      std::move(cert.write()).consume_and_downcast([&]<typename T>(CertificateRef<T> typed_cert) {
        if constexpr (std::same_as<T, NotarizeVote>) {
          state.candidate_and_cert.notar_cert = std::move(typed_cert);
          state.notar_stored = true;
        }
      });
      co_return state.candidate_and_cert.notar_cert.has_value();
    }
    co_return false;
  }

  void schedule_store_notar_cert(CandidateId id, CandidateState& state) {
    if (!state.candidate_and_cert.notar_cert.has_value() || state.notar_stored || state.notar_store_in_flight) {
      return;
    }
    state.notar_store_in_flight = true;
    store_notar_cert(id, *state.candidate_and_cert.notar_cert).start().detach();
  }

  td::actor::Task<> store_notar_cert(CandidateId id, NotarCertRef cert) {
    auto key = create_serialize_tl_object<tl::db_key_candidateResolver_notarCert>(id.to_tl());
    auto value =
        create_serialize_tl_object<tl::db_candidateResolver_notarCert>(cert->to_tl_vote_signature_set());
    auto result = co_await owning_bus()->db->set(std::move(key), std::move(value)).wrap();

    auto it = state_.find(id);
    if (it != state_.end()) {
      it->second.notar_store_in_flight = false;
      if (result.is_ok()) {
        it->second.notar_stored = true;
      }
    }
    if (result.is_error()) {
      LOG(ERROR) << "Simplex candidate-resolver: failed to persist notarization certificate for " << id << ": "
                 << result.error();
    }
    prune_finalized();
    co_return td::Unit{};
  }

  void maybe_resume_resolve_awaiters(CandidateState &state) {
    if (state.candidate_and_cert.is_complete()) {
      for (auto &p : state.resolve_awaiters) {
        p.set_value({});
      }
      state.resolve_awaiters.clear();
    }
  }

  // Requires the caller to have taken one operation pin on `state` for this task; the task
  // releases it when it ends, which also evicts the entry if it has left the window.
  td::actor::Task<> resolve_candidate_task(CandidateId id, CandidateState &state) {
    SCOPE_EXIT {
      end_operation(id, state);
    };
    auto result = co_await resolve_candidate_inner(id, state).wrap();
    if (result.is_ok()) {
      CHECK(state.candidate_and_cert.is_complete());
      maybe_resume_resolve_awaiters(state);
    } else {
      for (auto &p : state.resolve_awaiters) {
        p.set_result(result.clone());
      }
      state.resolve_awaiters.clear();
    }
    co_return td::Unit{};
  }

  td::actor::Task<> resolve_candidate_inner(CandidateId id, CandidateState &state) {
    auto &bus = *owning_bus();

    co_await try_load_candidate_data_from_db(id, state, /*tracked=*/true, /*remote=*/false);
    co_await try_load_notar_cert_from_db_or_bootstrap(id, state);

    const size_t overlay_member_count =
        bus.all_validators.empty() ? bus.validator_set.size() : bus.all_validators.size();
    if (overlay_member_count <= 1) {
      // Round 141 LOW fix: round-140 made try_load_candidate_data_
      // from_db skip mismatched DB candidates instead of feeding
      // them into to_tl, but the singleton path still assumed the
      // load was authoritative.  In a one-validator group there is
      // no peer to resolve from, so a corrupted db_key_candidate
      // record now genuinely cannot be recovered — LOG(FATAL) with
      // a clear reason is the right exit, replacing the bare
      // CHECK(state.candidate_and_cert.is_complete()) that would
      // otherwise abort with no context.
      if (!state.candidate_and_cert.is_complete()) {
        LOG(FATAL) << "Simplex candidate-resolver: singleton group "
                      "cannot resolve candidate "
                   << id
                   << " — DB record is missing or corrupted and there "
                      "is no peer to fall back to";
      }
      co_return td::Unit{};
    }

    std::chrono::duration<double> timeout = params_.candidate_resolve_timeout;
    int attempts_remaining = candidate_resolve_max_attempts_from_env();

    while (!state.candidate_and_cert.is_complete()) {
      if (attempts_remaining-- <= 0) {
        co_return td::Status::Error(
            ErrorCode::notready, PSTRING() << "Simplex candidate-resolver: giving up resolving " << id
                                           << " after repeated attempts; no peer supplied it");
      }

      auto cooldown_wait = td::Timestamp::in(params_.candidate_resolve_cooldown);

      auto request_tl = state.candidate_and_cert.make_request(id);
      ProtocolMessage request{serialize_tl_object(request_tl, true)};

      auto timeout_ts = td::Timestamp::in(std::chrono::round<std::chrono::nanoseconds>(timeout));
      auto maybe_response =
          co_await owning_bus()
              .publish<OutgoingOverlayRequest>(std::nullopt, timeout_ts, std::move(request))
              .wrap();

      if (maybe_response.is_ok()) {
        auto response = maybe_response.move_as_ok();
        auto response_tl_r = fetch_tl_object<tl::candidateAndCert>(response.data, true);
        if (response_tl_r.is_ok()) {
          auto data_r = CandidateAndCert::from_tl(std::move(*response_tl_r.move_as_ok()), *request_tl, bus);
          if (data_r.is_ok()) {
            state.candidate_and_cert.merge(data_r.move_as_ok());
            schedule_store_notar_cert(id, state);
            // Observers do not run SimplexConsensus::try_notarize(), so a
            // candidate obtained through resolution would otherwise remain
            // memory-only forever and correctly block finalized-window
            // eviction. Persist remote candidates here as well. Validators
            // normally reach this point with candidate_stored already set by
            // StoreCandidate, making this a no-op for their common path.
            if (state.candidate_and_cert.candidate.has_value() && !state.candidate_in_db &&
                !state.candidate_stored) {
              co_await store_candidate(id, state);
            }
          }
        }
      }

      timeout = std::min<std::chrono::duration<double>>(timeout * params_.candidate_resolve_timeout_multiplier,
                                                        params_.candidate_resolve_timeout_cap);
      // Prevent spamming requests in case of synchronous errors.
      if (!state.candidate_and_cert.is_complete()) {
        co_await td::actor::coro_sleep(cooldown_wait);
      }
    }

    co_return td::Unit{};
  }

  td::actor::Task<> store_candidate(CandidateId id, CandidateState &state) {
    auto &bus = *owning_bus();

    auto candidate = state.candidate_and_cert.candidate;
    CHECK(candidate.has_value());

    if (state.candidate_stored) {
      co_return td::Unit{};
    }

    auto contents_key = create_serialize_tl_object<tl::db_key_candidate>(id.to_tl());
    auto contents = co_await bus.db->set(std::move(contents_key), (*candidate)->serialize()).wrap();
    if (contents.is_ok()) {
      auto index_key = create_serialize_tl_object<tl::db_key_candidateResolver_candidateInfo>(id.to_tl());
      contents = co_await bus.db->set(std::move(index_key), td::BufferSlice()).wrap();
    }
    if (contents.is_error()) {
      // The payload is not durable, so it stays in memory outside the cache and is reported
      // as non-durable.
      LOG(WARNING) << "Simplex candidate-resolver: failed to persist candidate " << id
                   << "; its payload stays in memory: " << contents.error();
      co_return contents.move_as_error();
    }

    state.candidate_stored = true;
    ++state.store_generation;
    co_return td::Unit{};
  }
};

}  // namespace

void CandidateResolver::register_in(td::actor::Runtime &runtime) {
  runtime.register_actor<CandidateResolverImpl>("CandidateResolver");
}

}  // namespace tos::validator::consensus::simplex
