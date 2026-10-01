#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>

#include "core-health.h"
#include "core-registry.h"
#include "diagnostic-producer.h"

namespace tos::health {
// Process lifetime observations. Labels are frozen enums; no session, candidate,
// block, actor or signer reference is retained here. Reading is approximate.
enum class Action : std::uint8_t { Proposal, Notarize, Finalize, Skip, Count };
enum class Origin : std::uint8_t { Live, ReplaySigned, ReplayIntent, Count };
enum class Phase : std::uint8_t {
  Requested,
  IntentCommitted,
  Signed,
  SignedCommitted,
  RestoredSigned,
  LocalApplied,
  BroadcastEnqueued,
  CandidatePublished,
  Retry,
  Empty,
  IntentFailure,
  SignFailure,
  SignedCommitFailure,
  ApplyFalse,
  MissingSigner,
  IntentCancelled,
  SignedCommitCancelled,
  FinalitySuppressed,
  JournalSuppressed,
  Superseded,
  Cancelled,
  Completed,
  Count
};
enum class Outcome : std::uint8_t { Enqueued, Failed, Cancelled, Suppressed, Unknown, Count };
enum class FailureReason : std::uint8_t {
  IntentStorage,
  MissingSigner,
  SignBackend,
  SignedStorage,
  DuplicateOrStale,
  FinalityBehind,
  JournalUnusable,
  Superseded,
  Cancelled,
  Count
};
enum class IncompleteReason : std::uint8_t {
  ContextCapacity,
  LedgerCapacity,
  PendingCapacity,
  CounterSaturation,
  CasExhaustion,
  ObservationGap,
  SessionLifecycleUnverified,
  ScopeUnapproved,
  SnapshotContention
};
constexpr auto action_count = static_cast<std::size_t>(Action::Count);
constexpr auto origin_count = static_cast<std::size_t>(Origin::Count);
constexpr auto phase_count = static_cast<std::size_t>(Phase::Count);

struct ConsensusStats {
  using Counter = std::atomic<std::uint64_t>;
  std::array<std::array<std::array<Counter, phase_count>, origin_count>, action_count> phases{};
  std::array<std::array<Counter, origin_count>, action_count> pending{};
  std::array<std::array<Counter, static_cast<std::size_t>(Outcome::Count)>, action_count> outcomes{};
  std::array<std::array<Counter, static_cast<std::size_t>(FailureReason::Count)>, action_count> failures{};
  std::array<std::array<std::array<Counter, 5>, 2>, action_count> replay_terminals{};
  std::atomic<std::uint32_t> incomplete_reasons{0};
  std::array<std::atomic<std::uint32_t>, action_count> action_reasons{};
  Counter sessions_started{0}, sessions_stopped{0}, sessions_active{0}, sessions_drained{0};
  Counter leader_windows_observed{0}, leader_windows_started{0};
  Counter resolver_stopped{0};
  Counter sessions_stop_started{0}, sessions_stopping{0};
  Counter repeated_requests{0}, retired_requests{0}, post_terminal_progress{0};
  static constexpr std::size_t max_pending = 1024;
  struct Pending {
    std::atomic<std::uint64_t> started_ns{0};
    std::atomic<Action> action{Action::Proposal};
    std::atomic<Origin> origin{Origin::Live};
  };
  std::array<Pending, max_pending> pending_rows{};

  static std::uint64_t now_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
  std::size_t track_pending(Action action, Origin origin) noexcept {
    for (std::size_t i = 0; i < max_pending; ++i) {
      std::uint64_t empty = 0;
      if (pending_rows[i].started_ns.compare_exchange_strong(empty, UINT64_MAX, std::memory_order_acquire)) {
        pending_rows[i].action.store(action, std::memory_order_relaxed);
        pending_rows[i].origin.store(origin, std::memory_order_relaxed);
        pending_rows[i].started_ns.store(now_ns(), std::memory_order_release);
        return i;
      }
    }
    incomplete(action, IncompleteReason::PendingCapacity);
    return max_pending;
  }
  std::uint64_t oldest_started_ns(Action action, Origin origin) const noexcept {
    std::uint64_t oldest = UINT64_MAX;
    for (const auto &row : pending_rows) {
      auto started = row.started_ns.load(std::memory_order_acquire);
      if (started == 0 || started == UINT64_MAX)
        continue;
      const auto row_action = row.action.load(std::memory_order_relaxed);
      const auto row_origin = row.origin.load(std::memory_order_relaxed);
      std::atomic_thread_fence(std::memory_order_acquire);
      if (row_action == action && row_origin == origin && started == row.started_ns.load(std::memory_order_relaxed) &&
          started < oldest)
        oldest = started;
    }
    return oldest == UINT64_MAX ? 0 : oldest;
  }
  std::atomic<bool> instrumentation_complete{true};
  std::array<std::atomic<bool>, action_count> action_complete{true, true, true, true};
  void global_incomplete(IncompleteReason reason) noexcept {
    incomplete_reasons.fetch_or(std::uint32_t{1} << static_cast<unsigned>(reason), std::memory_order_relaxed);
    instrumentation_complete.store(false, std::memory_order_relaxed);
  }
  void incomplete(Action action, IncompleteReason reason = IncompleteReason::ObservationGap) noexcept {
    action_reasons[static_cast<std::size_t>(action)].fetch_or(std::uint32_t{1} << static_cast<unsigned>(reason),
                                                              std::memory_order_relaxed);
    global_incomplete(reason);
    action_complete[static_cast<std::size_t>(action)].store(false, std::memory_order_relaxed);
    instrumentation_complete.store(false, std::memory_order_relaxed);
  }

  bool add(Counter &counter, std::uint64_t amount = 1) noexcept {
    const auto result = CoreRegistry::bounded_add(counter, amount);
    if (result == CoreRegistry::UpdateResult::Updated)
      return true;
    core_registry.note_update_failure();
    global_incomplete(result == CoreRegistry::UpdateResult::Saturated ? IncompleteReason::CounterSaturation
                                                                      : IncompleteReason::CasExhaustion);
    return false;
  }
  void subtract(Counter &counter) noexcept {
    auto old = counter.load(std::memory_order_relaxed);
    for (unsigned attempt = 0; attempt < 8 && old != 0; ++attempt)
      if (counter.compare_exchange_weak(old, old - 1, std::memory_order_relaxed))
        return;
    core_registry.note_update_failure();
    global_incomplete(IncompleteReason::ObservationGap);
  }
  Counter &phase(Action action, Origin origin, Phase phase) noexcept {
    return phases[static_cast<std::size_t>(action)][static_cast<std::size_t>(origin)][static_cast<std::size_t>(phase)];
  }
  Counter &inflight(Action action, Origin origin) noexcept {
    return pending[static_cast<std::size_t>(action)][static_cast<std::size_t>(origin)];
  }
};
inline ConsensusStats consensus_stats;
inline std::atomic<bool> consensus_enabled{false};

// Each lease is confined to one existing actor. Entries carry only scalar keys;
// retired actors release the bank. No eviction can silently forget a logical key.
class ActionLedger {
 public:
  struct Key {
    Action action{};
    Origin origin{};
    std::uint32_t slot{};
    std::array<std::uint8_t, 32> candidate{};
    bool operator==(const Key &) const = default;
  };
  static constexpr std::size_t max_banks = 16, max_rows = 512;
  struct Entry {
    Key key{};
    std::uint32_t seen = 0, holders = 0;
    bool occupied = false, terminal = false, closed = false, tracking_declined = false;
  };
  struct Bank {
    std::atomic<bool> leased{false};
    std::array<Entry, max_rows> entries{};
    std::uint64_t retired_floor = 0;
  };
  struct Admission {
    Entry *entry = nullptr;
    bool fresh = false;
  };
  Admission begin(const Key &key, ConsensusStats &stats) noexcept {
    if (auto *bank = bank_.load(std::memory_order_acquire); bank != nullptr) {
      if (key.slot < bank->retired_floor) {
        stats.add(stats.retired_requests);
        return {};
      }
      Entry *free = nullptr;
      for (auto &entry : bank->entries) {
        if (entry.occupied && entry.closed && entry.holders == 0 && entry.key.slot < bank->retired_floor)
          entry.occupied = false;
        if (!entry.occupied) {
          if (free == nullptr)
            free = &entry;
          continue;
        }
        if (entry.key == key) {
          stats.add(stats.repeated_requests);
          if (entry.holders == UINT32_MAX) {
            stats.incomplete(key.action);
            return {};
          }
          ++entry.holders;
          return {&entry, false};
        }
      }
      if (free != nullptr) {
        *free = Entry{key, 0, 1, true, false};
        return {free, true};
      }
    }
    stats.incomplete(key.action, IncompleteReason::LedgerCapacity);
    return {};
  }
  // The caller supplies the actual finalization rejection boundary, never a
  // scrape time or guessed deadline. Pending entries are never evicted.
  void retire_before(std::uint64_t floor) noexcept {
    auto *bank = bank_.load(std::memory_order_acquire);
    if (bank == nullptr)
      return;
    if (floor > bank->retired_floor)
      bank->retired_floor = floor;
    for (auto &entry : bank->entries)
      if (entry.occupied && entry.closed && entry.holders == 0 && entry.key.slot < bank->retired_floor)
        entry.occupied = false;
  }
  bool reserve(std::size_t index) noexcept {
    if (bank_.load(std::memory_order_acquire) != nullptr)
      return true;
    if (index >= max_banks)
      return false;
    auto &bank = banks_[index];
    bool free = false;
    if (!bank.leased.compare_exchange_strong(free, true, std::memory_order_acquire))
      return false;
    for (auto &entry : bank.entries)
      entry = {};
    bank.retired_floor = 0;
    bank_.store(&bank, std::memory_order_release);
    return true;
  }
  void reset() noexcept {
    if (auto *bank = bank_.exchange(nullptr, std::memory_order_acq_rel); bank != nullptr) {
      bank->leased.store(false, std::memory_order_release);
    }
  }
  ~ActionLedger() {
    reset();
  }
  ActionLedger() = default;
  ActionLedger(const ActionLedger &) = delete;
  ActionLedger &operator=(const ActionLedger &) = delete;

 private:
  static std::array<Bank, max_banks> banks_;
  std::atomic<Bank *> bank_{nullptr};
};
inline std::array<ActionLedger::Bank, ActionLedger::max_banks> ActionLedger::banks_{};
static_assert(sizeof(ActionLedger::Bank) * ActionLedger::max_banks < 512 * 1024);

// This token lives in the existing coroutine frame. Its destruction reports a
// cancelled unfinished request, including teardown; it owns no business object.
class ActionObservation {
 public:
  ActionObservation(Action action, Origin origin = Origin::Live, ConsensusStats &stats = consensus_stats,
                    ActionLedger *ledger = nullptr, const ActionLedger::Key *key = nullptr) noexcept
      : stats_(stats)
      , action_(action)
      , origin_(origin)
      , active_(enabled.load(std::memory_order_relaxed) && consensus_enabled.load(std::memory_order_relaxed)) {
    if (active_ && ledger != nullptr && key != nullptr) {
      const auto admission = ledger->begin(*key, stats_);
      entry_ = admission.entry;
      active_ = entry_ != nullptr;
      duplicate_ = active_ && !admission.fresh;
      if (entry_ != nullptr && entry_->tracking_declined)
        active_ = false;
    }
    if (active_ && !duplicate_) {
      pending_slot_ = stats_.track_pending(action_, origin_);
      if (pending_slot_ == ConsensusStats::max_pending) {
        active_ = false;
        if (entry_ != nullptr)
          entry_->tracking_declined = true;
        return;
      }
      observe(Phase::Requested);
      pending_recorded_ = stats_.add(stats_.inflight(action_, origin_));
      if (!pending_recorded_)
        stats_.incomplete(action_);
    }
  }
  void observe(Phase phase) noexcept {
    if (active_) {
      const auto bit = std::uint32_t{1} << static_cast<unsigned>(phase);
      auto &seen = entry_ != nullptr ? entry_->seen : seen_;
      if ((seen & bit) == 0) {
        if (duplicate_ && entry_->terminal && phase != Phase::Completed && phase != Phase::IntentCancelled &&
            phase != Phase::SignedCommitCancelled && phase != Phase::ApplyFalse) {
          stats_.add(stats_.post_terminal_progress);
          stats_.incomplete(action_);
        }
        if (!stats_.add(stats_.phase(action_, origin_, phase)))
          stats_.incomplete(action_);
        seen |= bit;
        diagnostic_phase(static_cast<std::uint8_t>(action_), static_cast<std::uint8_t>(origin_),
                         static_cast<std::uint8_t>(phase));
      }
      enqueued_ |= phase == Phase::BroadcastEnqueued || phase == Phase::CandidatePublished;
    }
  }
  void finish(Phase terminal = Phase::Completed) noexcept {
    if (!active_ && entry_ != nullptr && entry_->tracking_declined) {
      entry_->closed = true;
      release_entry();
    }
    if (active_) {
      if (duplicate_) {
        release_entry();
        active_ = false;
        return;
      }
      observe(terminal);
      if (entry_ != nullptr) {
        entry_->terminal = true;
        entry_->closed = true;
      }
      Outcome outcome = Outcome::Unknown;
      FailureReason reason = FailureReason::Cancelled;
      bool failure = true;
      switch (terminal) {
        case Phase::Completed:
          outcome = enqueued_ ? Outcome::Enqueued : Outcome::Unknown;
          failure = false;
          break;
        case Phase::IntentFailure:
          outcome = Outcome::Failed;
          reason = FailureReason::IntentStorage;
          break;
        case Phase::MissingSigner:
          outcome = Outcome::Failed;
          reason = FailureReason::MissingSigner;
          break;
        case Phase::SignFailure:
          outcome = Outcome::Failed;
          reason = FailureReason::SignBackend;
          break;
        case Phase::SignedCommitFailure:
          outcome = Outcome::Failed;
          reason = FailureReason::SignedStorage;
          break;
        case Phase::ApplyFalse:
          outcome = Outcome::Suppressed;
          reason = FailureReason::DuplicateOrStale;
          break;
        case Phase::FinalitySuppressed:
          outcome = Outcome::Suppressed;
          reason = FailureReason::FinalityBehind;
          break;
        case Phase::JournalSuppressed:
          outcome = Outcome::Suppressed;
          reason = FailureReason::JournalUnusable;
          break;
        case Phase::Superseded:
          outcome = Outcome::Cancelled;
          reason = FailureReason::Superseded;
          break;
        case Phase::Cancelled:
        case Phase::IntentCancelled:
        case Phase::SignedCommitCancelled:
          outcome = Outcome::Cancelled;
          break;
        default:
          failure = false;
          break;
      }
      if (origin_ != Origin::Live) {
        auto replay_outcome = outcome;
        if (terminal == Phase::Completed && ((entry_ != nullptr ? entry_->seen : seen_) &
                                             (std::uint32_t{1} << static_cast<unsigned>(Phase::LocalApplied))))
          replay_outcome = Outcome::Enqueued;
        if (!stats_.add(stats_.replay_terminals[static_cast<std::size_t>(
                action_)][static_cast<std::size_t>(origin_) - 1][static_cast<std::size_t>(replay_outcome)]))
          stats_.incomplete(action_);
      }
      if (origin_ == Origin::Live) {
        if (!stats_.add(stats_.outcomes[static_cast<std::size_t>(action_)][static_cast<std::size_t>(outcome)]))
          stats_.incomplete(action_);
        if (failure &&
            !stats_.add(stats_.failures[static_cast<std::size_t>(action_)][static_cast<std::size_t>(reason)]))
          stats_.incomplete(action_);
      }
      if (pending_recorded_)
        stats_.subtract(stats_.inflight(action_, origin_));
      if (pending_slot_ < ConsensusStats::max_pending)
        stats_.pending_rows[pending_slot_].started_ns.store(0, std::memory_order_release);
      release_entry();
      active_ = false;
    }
  }
  ~ActionObservation() {
    finish(Phase::Cancelled);
  }
  ActionObservation(const ActionObservation &) = delete;
  ActionObservation &operator=(const ActionObservation &) = delete;

 private:
  void release_entry() noexcept {
    if (entry_ != nullptr) {
      if (entry_->holders != 0)
        --entry_->holders;
      else
        stats_.incomplete(action_);
      entry_ = nullptr;
    }
  }
  ConsensusStats &stats_;
  Action action_;
  Origin origin_;
  ActionLedger::Entry *entry_ = nullptr;
  bool active_, pending_recorded_ = false, enqueued_ = false, duplicate_ = false;
  std::uint32_t seen_ = 0;
  std::size_t pending_slot_ = ConsensusStats::max_pending;
};

// True once at least one validator session has been observed through the
// whole drain boundary since process start: stop requested, consensus database
// closed, bus released, observation closed. Until then the session counters
// are published but the lifecycle is reported unverified. A node whose
// sessions never rotate keeps it false truthfully.
inline std::atomic<bool> lifecycle_verified{false};

// Attached to the existing bus lifetime, never used as a reason to retain it.
class SessionObservation {
 public:
  struct Context {
    std::atomic<bool> leased{false};
    std::atomic<std::uint64_t> sequence{0};
    std::array<std::atomic<std::uint8_t>, 32> session{};
    std::atomic<std::int32_t> workchain{0};
    std::atomic<std::uint64_t> shard{0}, current_slot{UINT64_MAX}, finalized_slot{UINT64_MAX}, stop_started{0};
  };
  static std::array<Context, 8> context_rows;
  static inline std::atomic<std::uint64_t> registration_sequence{0};
  void start(const void *session_id = nullptr, std::int32_t workchain = 0, std::uint64_t shard = 0) noexcept {
    if (!active_ && enabled.load(std::memory_order_relaxed) && consensus_enabled.load(std::memory_order_relaxed)) {
      for (std::size_t i = 0; i < context_rows.size(); ++i) {
        bool free = false;
        if (context_rows[i].leased.compare_exchange_strong(free, true, std::memory_order_acquire)) {
          context_.store(i, std::memory_order_release);
          auto &row = context_rows[i];
          row.sequence.store(0, std::memory_order_release);
          for (std::size_t byte = 0; byte < 32; ++byte)
            row.session[byte].store(session_id == nullptr ? 0 : static_cast<const std::uint8_t *>(session_id)[byte],
                                    std::memory_order_relaxed);
          row.workchain.store(workchain, std::memory_order_relaxed);
          row.shard.store(shard, std::memory_order_relaxed);
          row.current_slot.store(UINT64_MAX, std::memory_order_relaxed);
          row.finalized_slot.store(UINT64_MAX, std::memory_order_relaxed);
          row.stop_started.store(0, std::memory_order_relaxed);
          row.sequence.store(registration_sequence.fetch_add(1, std::memory_order_relaxed) + 1,
                             std::memory_order_release);
          vote_ledger.reserve(i * 2);
          proposal_ledger.reserve(i * 2 + 1);
          break;
        }
      }
      if (context_.load(std::memory_order_acquire) == context_rows.size()) {
        for (std::size_t a = 0; a < action_count; ++a)
          consensus_stats.incomplete(static_cast<Action>(a), IncompleteReason::ContextCapacity);
      }
      consensus_stats.add(consensus_stats.sessions_started);
      recorded_ = consensus_stats.add(consensus_stats.sessions_active);
      active_.store(true, std::memory_order_release);
      if (stop_requested_.load(std::memory_order_acquire))
        begin_stop();
    }
  }
  void begin_stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    if (active_.load(std::memory_order_acquire) && !stopping_.exchange(true, std::memory_order_acq_rel)) {
      const auto context = context_.load(std::memory_order_acquire);
      if (context < context_rows.size())
        context_rows[context].stop_started.store(ConsensusStats::now_ns(), std::memory_order_release);
      consensus_stats.add(consensus_stats.sessions_stop_started);
      stopping_recorded_ = consensus_stats.add(consensus_stats.sessions_stopping);
    }
  }
  void stop() noexcept {
    if (active_) {
      consensus_stats.add(consensus_stats.sessions_stopped);
      if (recorded_)
        consensus_stats.subtract(consensus_stats.sessions_active);
      if (stopping_recorded_)
        consensus_stats.subtract(consensus_stats.sessions_stopping);
      active_ = false;
    }
  }
  void close() noexcept {
    if (closed_)
      return;
    closed_ = true;
    const bool was_active = active_.load(std::memory_order_acquire);
    stop();
    vote_ledger.reset();
    proposal_ledger.reset();
    const auto context = context_.exchange(context_rows.size(), std::memory_order_acq_rel);
    if (context < context_rows.size()) {
      context_rows[context].sequence.store(0, std::memory_order_release);
      context_rows[context].leased.store(false, std::memory_order_release);
    }
    if (was_active && !consensus_stats.add(consensus_stats.sessions_drained))
      consensus_stats.global_incomplete(IncompleteReason::CounterSaturation);
    // The drain boundary was observed end to end: stop requested, then closed.
    if (was_active && stopping_.load(std::memory_order_acquire))
      lifecycle_verified.store(true, std::memory_order_release);
  }
  ~SessionObservation() {
    close();
  }
  void current_slot(std::uint32_t slot) noexcept {
    const auto context = context_.load(std::memory_order_acquire);
    if (context < context_rows.size())
      context_rows[context].current_slot.store(slot, std::memory_order_relaxed);
  }
  void finalized_slot(std::uint32_t slot) noexcept {
    const auto context = context_.load(std::memory_order_acquire);
    if (context < context_rows.size())
      context_rows[context].finalized_slot.store(slot, std::memory_order_relaxed);
  }
  ActionLedger vote_ledger, proposal_ledger;
  SessionObservation() = default;
  SessionObservation(const SessionObservation &) = delete;
  SessionObservation &operator=(const SessionObservation &) = delete;

 private:
  std::atomic<std::size_t> context_{context_rows.size()};
  std::atomic<bool> active_{false}, stopping_{false}, stop_requested_{false};
  bool recorded_ = false, stopping_recorded_ = false;
  bool closed_ = false;
};
inline std::array<SessionObservation::Context, 8> SessionObservation::context_rows{};
static_assert(sizeof(ConsensusStats) < 40 * 1024);
}  // namespace tos::health
