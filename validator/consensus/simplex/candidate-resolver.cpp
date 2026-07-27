/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/memory-tracker.h"
#include "validator/rate-limiter.h"

#include <cstdlib>
#include <unordered_set>

#include "bus.h"
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

constexpr td::uint32 DEFAULT_CANDIDATE_RETENTION_SLOTS = 4096;

td::uint32 candidate_retention_slots_from_env() {
  const char* value = std::getenv("TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS");
  if (value == nullptr) {
    return DEFAULT_CANDIDATE_RETENTION_SLOTS;
  }
  auto parsed = td::to_integer_safe<td::uint32>(td::Slice(value));
  if (parsed.is_error() || parsed.ok() == 0) {
    LOG(WARNING) << "Simplex candidate-resolver: ignoring invalid "
                    "TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS="
                 << value;
    return DEFAULT_CANDIDATE_RETENTION_SLOTS;
  }
  return parsed.move_as_ok();
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
              << " finalized slots";
    if (td::memory_tracker_enabled()) {
      alarm_timestamp() = td::Timestamp::in(60.0);
    }
  }

  void alarm() override {
    for (auto& [id, state] : state_) {
      schedule_store_notar_cert(id, state);
    }
    prune_finalized();
    log_memory_diagnostics();
    alarm_timestamp() = td::Timestamp::in(60.0);
  }

  void tear_down() override {
    for (auto &[_, s] : state_) {
      for (auto &p : s.resolve_awaiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
      for (auto &p : s.store_awaiters) {
        p.set_error(td::Status::Error(ErrorCode::cancelled, "cancelled"));
      }
    }
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

    auto& state = state_[id];
    begin_operation(state);
    SCOPE_EXIT {
      end_operation(id, state);
    };
    if (request->want_candidate_) {
      co_await try_load_candidate_data_from_db(id, state);
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

    state.candidate_and_cert.candidate = request->candidate;
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
  void handle(BusHandle, std::shared_ptr<const NotarizationObserved> event) {
    auto &state = state_[event->id];
    state.candidate_and_cert.notar_cert = event->certificate;
    maybe_resume_resolve_awaiters(state);
    schedule_store_notar_cert(event->id, state);
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizationObserved> event) {
    retention_policy_.observe_finalized(event->id.slot);
    prune_finalized();
  }

 private:
  struct CandidateState {
    bool candidate_in_db = false;
    bool candidate_stored = false;
    bool notar_stored = false;
    bool notar_store_in_flight = false;
    size_t active_operations = 0;
    CandidateAndCert candidate_and_cert;

    std::vector<td::Promise<td::Unit>> resolve_awaiters;
    std::vector<td::Promise<td::Unit>> store_awaiters;
  };

  NewConsensusConfig::NoncriticalParams params_;
  std::map<CandidateId, CandidateState> state_;
  std::map<adnl::AdnlNodeIdShort, td::RateLimiterWindow> rate_limiter_;
  CandidateRetentionPolicy retention_policy_{candidate_retention_slots_from_env()};
  size_t state_evictions_ = 0;

  static bool can_evict(const CandidateState& state) {
    const bool candidate_durable = !state.candidate_and_cert.candidate.has_value() || state.candidate_in_db ||
                                   state.candidate_stored;
    const bool notar_durable = !state.candidate_and_cert.notar_cert.has_value() || state.notar_stored;
    return state.active_operations == 0 && state.resolve_awaiters.empty() && state.store_awaiters.empty() &&
           !state.notar_store_in_flight && candidate_durable && notar_durable;
  }

  void begin_operation(CandidateState& state) {
    ++state.active_operations;
  }

  void end_operation(const CandidateId& id, CandidateState& state) {
    CHECK(state.active_operations > 0);
    --state.active_operations;
    if (state.active_operations != 0 || !retention_policy_.is_before_retained_window(id) || !can_evict(state)) {
      return;
    }
    auto it = state_.find(id);
    CHECK(it != state_.end());
    CHECK(&it->second == &state);
    state_.erase(it);
    ++state_evictions_;
  }

  void prune_finalized() {
    state_evictions_ += prune_candidate_states(state_, retention_policy_.first_retained_slot(),
                                               [](const CandidateState& state) { return can_evict(state); });
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

  td::actor::Task<bool> try_load_candidate_data_from_db(CandidateId id, CandidateState &state) {
    auto &bus = *owning_bus();

    if (state.candidate_and_cert.candidate.has_value()) {
      co_return true;
    }

    auto contents_key = create_serialize_tl_object<tl::db_key_candidate>(id.to_tl());
    auto data_r = co_await bus.db->get_latest(std::move(contents_key));
    if (!data_r.has_value()) {
      if (state.candidate_in_db) {
        LOG(WARNING) << "Simplex candidate-resolver: candidate data for " << id
                     << " is indexed in DB but the content record is missing";
        state.candidate_in_db = false;
      }
      co_return false;
    }
    auto data = std::move(*data_r);
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
    // failure or id mismatch.  The candidate stays in
    // candidate_in_db state but is not surfaced to to_tl
    // until a fresh network/local store overwrites it.
    auto candidate_res = Candidate::deserialize(data, bus);
    if (candidate_res.is_error()) {
      LOG(WARNING) << "Simplex candidate-resolver: db record for " << id
                   << " failed to deserialize: " << candidate_res.error().message();
      co_return false;
    }
    auto candidate = candidate_res.move_as_ok();
    if (candidate->id != id) {
      LOG(WARNING) << "Simplex candidate-resolver: db record for " << id
                   << " contains a candidate for a different id " << candidate->id
                   << " (refusing to surface mismatched bytes)";
      co_return false;
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

  td::actor::Task<> resolve_candidate_task(CandidateId id, CandidateState &state) {
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

    co_await try_load_candidate_data_from_db(id, state);
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

    while (!state.candidate_and_cert.is_complete()) {
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
    co_await bus.db->set(std::move(contents_key), (*candidate)->serialize());

    auto index_key = create_serialize_tl_object<tl::db_key_candidateResolver_candidateInfo>(id.to_tl());
    co_await bus.db->set(std::move(index_key), td::BufferSlice());

    state.candidate_stored = true;
    co_return td::Unit{};
  }
};

}  // namespace

void CandidateResolver::register_in(td::actor::Runtime &runtime) {
  runtime.register_actor<CandidateResolverImpl>("CandidateResolver");
}

}  // namespace tos::validator::consensus::simplex
