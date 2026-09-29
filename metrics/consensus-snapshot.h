#pragma once

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "consensus-work.h"

namespace tos::health {
inline std::array<std::array<ConsensusStats::Counter, phase_count>, action_count> replay_metric_phases{};
inline std::array<ConsensusStats::Counter, action_count> action_age_ns{}, action_complete_value{};
inline std::array<std::atomic<bool>, action_count> action_age_available{};
inline std::array<ConsensusStats::Counter, work_count> work_age_ns{};
inline std::array<std::atomic<bool>, work_count> work_age_available{};
inline std::array<ConsensusStats::Counter, 2> masterchain_slots{};
inline std::array<std::atomic<bool>, 2> masterchain_slot_available{};
// Ownership release is measured separately. Actor drain is deliberately not
// claimed by the publisher until its production boundary has been established.
inline std::atomic<bool> lifecycle_verified{false};

#include "consensus-metric-bindings.inc"

using JsonFields = std::vector<std::pair<std::string, std::string>>;
inline std::string c04_object(JsonFields fields) {
  std::sort(fields.begin(), fields.end());
  std::string result = "{";
  for (const auto &[key, value] : fields) {
    if (result.size() != 1) result += ',';
    result += '"' + key + "\":" + value;
  }
  return result + '}';
}
inline std::string c04_u64(std::uint64_t value) { return '"' + std::to_string(value) + '"'; }
inline std::string c04_bool(bool value) { return value ? "true" : "false"; }
inline std::string c04_text(const char *value) { return '"' + std::string(value) + '"'; }
inline std::string c04_array(const std::vector<std::string> &values) {
  std::string result = "[";
  for (const auto &value : values) { if (result.size() != 1) result += ','; result += value; }
  return result + ']';
}
inline std::string c04_reasons(std::uint32_t bits) {
  constexpr std::array names = {"context_capacity", "ledger_capacity", "pending_capacity", "counter_saturation",
      "cas_exhaustion", "observation_gap", "session_lifecycle_unverified", "scope_unapproved", "snapshot_contention"};
  std::vector<std::string> reasons;
  for (std::size_t i = 0; i < names.size(); ++i) if (bits & (std::uint32_t{1} << i)) reasons.push_back(c04_text(names[i]));
  std::sort(reasons.begin(), reasons.end());
  return c04_array(reasons);
}
inline std::uint64_t c04_sum(std::uint64_t a, std::uint64_t b, Action action) {
  if (a > UINT64_MAX - b) {
    consensus_stats.incomplete(action, IncompleteReason::CounterSaturation);
    return UINT64_MAX;
  }
  return a + b;
}
inline std::string c04_age(Action action, Origin origin, std::uint64_t now) {
  const auto started = consensus_stats.oldest_started_ns(action, origin);
  const auto index = static_cast<unsigned>(action);
  const bool available = started != 0 && now >= started && consensus_stats.action_complete[index].load();
  if (origin == Origin::Live) {
    action_age_available[index].store(available);
    action_age_ns[index].store(available ? now - started : 0);
  }
  return available ? c04_u64(now - started) : "null";
}
inline std::string c04_phases(Action action, Origin origin, std::initializer_list<std::pair<const char *, Phase>> phases) {
  JsonFields fields;
  for (const auto &[name, phase] : phases) fields.push_back({name, c04_u64(consensus_stats.phase(action, origin, phase).load())});
  return c04_object(std::move(fields));
}
inline std::string c04_replay(Action action, Origin origin, std::uint64_t now) {
  const auto a = static_cast<unsigned>(action), o = static_cast<unsigned>(origin) - 1;
  const auto phases = origin == Origin::ReplaySigned
      ? c04_phases(action, origin, {{"requested", Phase::Requested}, {"restored_signed", Phase::RestoredSigned}, {"local_applied", Phase::LocalApplied}})
      : c04_phases(action, origin, {{"requested", Phase::Requested}, {"signed", Phase::Signed}, {"signed_committed", Phase::SignedCommitted}, {"local_applied", Phase::LocalApplied}});
  JsonFields terminals;
  constexpr std::array names = {"applied", "failed", "cancelled", "suppressed", "unknown"};
  for (std::size_t t = 0; t < names.size(); ++t) terminals.push_back({names[t], c04_u64(consensus_stats.replay_terminals[a][o][t].load())});
  return c04_object({{"oldest_age_ns", c04_age(action, origin, now)}, {"pending", c04_u64(consensus_stats.pending[a][o + 1].load())},
      {"phases", phases}, {"terminals", c04_object(std::move(terminals))}});
}
inline std::string c04_action(Action action, std::uint64_t now) {
  constexpr std::array names = {"proposal", "notarize_vote", "finalize_vote", "skip_vote"};
  const auto a = static_cast<unsigned>(action);
  const auto phases = action == Action::Proposal
      ? c04_phases(action, Origin::Live, {{"requested", Phase::Requested}, {"signed", Phase::Signed}, {"candidate_published", Phase::CandidatePublished}})
      : c04_phases(action, Origin::Live, {{"requested", Phase::Requested}, {"intent_committed", Phase::IntentCommitted}, {"signed", Phase::Signed},
          {"signed_committed", Phase::SignedCommitted}, {"local_applied", Phase::LocalApplied}, {"broadcast_enqueued", Phase::BroadcastEnqueued}});
  constexpr std::array outcome_names = {"enqueued", "failed", "cancelled", "suppressed", "unknown"};
  JsonFields outcomes, failures;
  for (std::size_t o = 0; o < outcome_names.size(); ++o) outcomes.push_back({outcome_names[o], c04_u64(consensus_stats.outcomes[a][o].load())});
  for (auto [name, reason] : {std::pair{"missing_signer", FailureReason::MissingSigner}, {"sign_backend", FailureReason::SignBackend},
      {"finality_behind", FailureReason::FinalityBehind}, {"superseded", FailureReason::Superseded}, {"cancelled", FailureReason::Cancelled}})
    failures.push_back({name, c04_u64(consensus_stats.failures[a][static_cast<unsigned>(reason)].load())});
  if (action != Action::Proposal) {
    for (auto [name, reason] : {std::pair{"intent_storage", FailureReason::IntentStorage}, {"signed_storage", FailureReason::SignedStorage},
        {"journal_unusable", FailureReason::JournalUnusable}, {"duplicate_or_stale", FailureReason::DuplicateOrStale}})
      failures.push_back({name, c04_u64(consensus_stats.failures[a][static_cast<unsigned>(reason)].load())});
  }
  const auto live = c04_object({{"phases", phases}, {"outcomes", c04_object(std::move(outcomes))}, {"failures", c04_object(std::move(failures))},
      {"pending", c04_u64(consensus_stats.pending[a][0].load())}, {"oldest_age_ns", c04_age(action, Origin::Live, now)}});
  const auto replay = action == Action::Proposal ? "null" : c04_object({{"signed_record", c04_replay(action, Origin::ReplaySigned, now)},
      {"intent_only", c04_replay(action, Origin::ReplayIntent, now)}});
  // One bitmap sample keeps the flag and reasons coherent during concurrent updates.
  const auto reasons = consensus_stats.action_reasons[a].load();
  const bool complete = reasons == 0;
  action_complete_value[a].store(complete ? 1 : 0);
  return c04_object({{"action", c04_text(names[a])}, {"accounting_complete", c04_bool(complete)},
      {"incomplete_reasons", c04_reasons(reasons)}, {"live", live}, {"replay", replay}});
}

inline std::size_t remaining_core_publication_bytes(std::initializer_list<std::size_t> allocations) {
  std::size_t remaining = 4 * 1024 * 1024;
  for (const auto allocation : allocations) {
    if (allocation >= remaining) return 0;
    remaining -= allocation;
  }
  return remaining;
}

// At most eight bounded diagnostic HTTP responses may coexist with publication.
inline constexpr std::size_t diagnostic_status_response_bytes = 8 * 4096;
inline std::size_t consensus_core_resident_bytes() {
  std::size_t result = sizeof(ConsensusStats) + sizeof(WorkStats) + sizeof(CoreRegistry) + sizeof(OperationStats) * 2 +
      sizeof(ActionLedger::Bank) * ActionLedger::max_banks + sizeof(SessionObservation::context_rows) +
      sizeof(consensus_metric_catalog) + sizeof(replay_metric_phases) + sizeof(action_age_ns) + sizeof(action_complete_value) +
      sizeof(action_age_available) + sizeof(work_age_ns) + sizeof(work_age_available) + sizeof(masterchain_slots) +
      sizeof(masterchain_slot_available) + sizeof(DiagnosticProducer::Stats) + 4096;
  for (const auto &descriptor : consensus_metric_catalog) {
    result += std::strlen(descriptor.name) + std::strlen(descriptor.type) + std::strlen(descriptor.suffix) + 3;
    for (const auto &label : descriptor.labels) result += std::strlen(label[0]) + std::strlen(label[1]) + 2;
  }
  return result;
}

struct ConsensusPublication {
  std::string json;
  bool complete = false;
};
inline std::optional<ConsensusPublication> capture_consensus(const std::string &network) {
  if (network.size() != 64) return std::nullopt;
  if (!enabled.load(std::memory_order_relaxed) || !consensus_enabled.load(std::memory_order_relaxed)) return std::nullopt;
  const auto now = ConsensusStats::now_ns();
  if (!lifecycle_verified.load()) consensus_stats.global_incomplete(IncompleteReason::SessionLifecycleUnverified);
  for (std::size_t a = 0; a < action_count; ++a) {
    for (std::size_t phase = 0; phase < phase_count; ++phase)
      replay_metric_phases[a][phase].store(c04_sum(consensus_stats.phases[a][1][phase].load(), consensus_stats.phases[a][2][phase].load(), static_cast<Action>(a)));
  }
  for (std::size_t w = 0; w < work_count; ++w) {
    const auto started = work_stats.oldest_started_ns(static_cast<Work>(w));
    const bool available = started != 0 && now >= started && work_stats.complete[w].load();
    work_age_available[w].store(available);
    work_age_ns[w].store(available ? now - started : 0);
  }
  std::vector<std::pair<std::uint64_t, std::string>> ordered_contexts;
  std::vector<std::string> context_identities;
  unsigned masterchain_active = 0;
  std::uint64_t current = UINT64_MAX, finalized = UINT64_MAX;
  bool typed_observed = false, scope_valid = true;
  for (const auto &row : SessionObservation::context_rows) {
    if (!row.leased.load(std::memory_order_acquire)) continue;
    const auto sequence = row.sequence.load(std::memory_order_acquire);
    if (sequence == 0) { consensus_stats.global_incomplete(IncompleteReason::SnapshotContention); continue; }
    std::string session;
    constexpr char hex[] = "0123456789abcdef";
    for (const auto &byte : row.session) { auto value = byte.load(); session += hex[value >> 4]; session += hex[value & 15]; }
    const auto wc = row.workchain.load();
    const auto shard = row.shard.load(), slot = row.current_slot.load(), final_slot = row.finalized_slot.load(), stop = row.stop_started.load();
    if (!row.leased.load(std::memory_order_acquire) || sequence != row.sequence.load(std::memory_order_acquire)) {
      consensus_stats.global_incomplete(IncompleteReason::SnapshotContention); continue;
    }
    const bool approved = wc == -1 && shard == (std::uint64_t{1} << 63);
    const auto identity = std::to_string(wc) + ":" + std::to_string(shard) + ":" + session;
    if (std::find(context_identities.begin(), context_identities.end(), identity) != context_identities.end()) {
      consensus_stats.global_incomplete(IncompleteReason::SnapshotContention);
      continue;
    }
    context_identities.push_back(identity);
    scope_valid &= approved;
    typed_observed |= approved && (slot != UINT64_MAX || final_slot != UINT64_MAX);
    if (approved && stop == 0) { ++masterchain_active; current = slot; finalized = final_slot; }
    const auto context = c04_object({{"network_id", '"' + network + '"'}, {"session_id", '"' + session + '"'},
        {"scope", c04_object({{"scope_id", approved ? "\"masterchain\"" : "null"}, {"workchain", std::to_string(wc)}, {"shard", c04_u64(shard)}})},
        {"current_slot", slot == UINT64_MAX ? "null" : std::to_string(slot)}, {"last_finalized_slot", final_slot == UINT64_MAX ? "null" : std::to_string(final_slot)},
        {"lifecycle", stop == 0 ? "\"active\"" : "\"stopping\""}, {"stop_started_monotonic_ns", stop == 0 ? "null" : c04_u64(stop)}});
    ordered_contexts.push_back({sequence, context});
  }
  std::sort(ordered_contexts.begin(), ordered_contexts.end());
  std::vector<std::string> contexts;
  for (const auto &[_, context] : ordered_contexts) contexts.push_back(context);
  for (std::size_t i = 0; i < 2; ++i) {
    const auto value = i == 0 ? current : finalized;
    const bool available = masterchain_active == 1 && value != UINT64_MAX;
    masterchain_slot_available[i].store(available);
    masterchain_slots[i].store(available ? value : 0);
  }
  JsonFields capabilities;
  auto capability = [&](const char *name, bool supported, const char *reason) {
    capabilities.push_back({name, c04_object({{"supported", c04_bool(supported)}, {"enabled", c04_bool(supported)},
        {"contract_valid", "false"}, {"performance_gate", "false"}, {"reason", supported ? "null" : c04_text(reason)}})});
  };
  capability("cohort_success_rate", false, "closed_cohort_not_implemented");
  capability("durable_finality", false, "hardware_power_loss_not_proven");
  capability("network_result", false, "local_enqueue_is_not_network_observation");
  capability("pq_queue", false, "synchronous_signer_no_queue");
  capability("vote_assigned", false, "no_independent_assigned_denominator");
  capability("vote_deadline", false, "no_frozen_protocol_deadline");
  std::uint64_t requested = 0;
  for (std::size_t a = 0; a < action_count; ++a) requested |= consensus_stats.phases[a][0][0].load();
  capability("local_actions", requested != 0, "observation_incomplete");
  capability("leader_progress", consensus_stats.leader_windows_observed.load() != 0, "observation_incomplete");
  capability("storage_commit_ack", work_stats.results[0][0].load() != 0 && work_stats.results[1][0].load() != 0, "observation_incomplete");
  capability("typed_consensus_progress", typed_observed && scope_valid, scope_valid ? "observation_incomplete" : "scope_unapproved");
  capability("session_lifecycle", lifecycle_verified.load(), "lifecycle_unverified");
  std::vector<std::string> actions;
  for (std::size_t a = 0; a < action_count; ++a) actions.push_back(c04_action(static_cast<Action>(a), now));
  if (!core_registry.complete()) consensus_stats.global_incomplete(IncompleteReason::ObservationGap);
  const auto reasons = consensus_stats.incomplete_reasons.load();
  const bool complete = reasons == 0;
  const auto sessions = c04_object({{"active", c04_u64(consensus_stats.sessions_active.load())}, {"started", c04_u64(consensus_stats.sessions_started.load())},
      {"stop_started", c04_u64(consensus_stats.sessions_stop_started.load())}, {"stopping", c04_u64(consensus_stats.sessions_stopping.load())},
      {"stopped", lifecycle_verified.load() ? c04_u64(consensus_stats.sessions_drained.load()) : "null"}});
  auto json = c04_object({{"actions", c04_array(actions)}, {"capabilities", c04_object(std::move(capabilities))}, {"contexts", c04_array(contexts)},
      {"instrumentation_complete", c04_bool(complete)}, {"incomplete_reasons", c04_reasons(reasons)},
      {"repeated_requests", c04_u64(consensus_stats.repeated_requests.load())}, {"retired_requests", c04_u64(consensus_stats.retired_requests.load())},
      {"post_terminal_progress", c04_u64(consensus_stats.post_terminal_progress.load())}, {"sessions", sessions}});
  if (json.size() > 32 * 1024) return std::nullopt;
  return ConsensusPublication{std::move(json), complete};
}
}  // namespace tos::health
