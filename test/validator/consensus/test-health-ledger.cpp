#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "metrics/consensus-health.h"

using namespace tos::health;
static void require(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "C04_LEDGER_ASSERTION: %s\n", message);
    std::exit(1);
  }
}

namespace {
// A reusable barrier on a mutex and a condition variable, which the thread
// sanitizer models exactly. It orders what precedes an arrival before what
// follows the release, and nothing among the released threads.
class Barrier {
 public:
  explicit Barrier(std::size_t parties) : parties_(parties) {
  }
  void arrive_and_wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    const auto generation = generation_;
    if (++arrived_ == parties_) {
      arrived_ = 0;
      ++generation_;
      changed_.notify_all();
      return;
    }
    changed_.wait(lock, [&] { return generation_ != generation; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable changed_;
  std::size_t parties_, arrived_ = 0, generation_ = 0;
};

// Bounds a mode's wall time: a hang is reported as such, never as a pass.
class Watchdog {
 public:
  explicit Watchdog(std::chrono::seconds limit)
      : thread_([this, limit] {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!changed_.wait_for(lock, limit, [&] { return done_; })) {
          std::fprintf(stderr, "C04_LEDGER_WATCHDOG: mode did not finish in time\n");
          std::_Exit(3);
        }
      }) {
  }
  ~Watchdog() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      done_ = true;
    }
    changed_.notify_all();
    thread_.join();
  }
  Watchdog(const Watchdog &) = delete;
  Watchdog &operator=(const Watchdog &) = delete;

 private:
  std::mutex mutex_;
  std::condition_variable changed_;
  bool done_ = false;
  std::thread thread_;
};

constexpr auto notarize = static_cast<std::size_t>(Action::Notarize);
std::uint32_t reason_bit(IncompleteReason reason) {
  return std::uint32_t{1} << static_cast<unsigned>(reason);
}
bool pending_rows_clear(const ConsensusStats &stats) {
  for (const auto &row : stats.pending_rows)
    if (row.started_ns.load() != 0)
      return false;
  return true;
}
std::uint64_t outcome(const ConsensusStats &stats, Action action, Outcome value) {
  return stats.outcomes[static_cast<std::size_t>(action)][static_cast<std::size_t>(value)].load();
}

// Proves that all max_rows rows of the leased bank can be held at once and that
// no further row exists: a stranded holder would leave room for fewer.
void require_full_refill(SessionObservation &session, ConsensusStats &stats, std::uint32_t first_slot) {
  const auto requested = stats.phase(Action::Notarize, Origin::Live, Phase::Requested).load();
  std::vector<std::unique_ptr<ActionObservation>> held;
  std::array<bool, ActionLedger::max_rows> rows{};
  for (std::uint32_t i = 0; i < ActionLedger::max_rows; ++i) {
    auto key = ActionLedger::Key{Action::Notarize, Origin::Live, first_slot + i, {}};
    held.push_back(std::make_unique<ActionObservation>(key.action, key.origin, stats, &session.vote_ledger, &key));
    const auto &handle = held.back()->ledger_handle();
    require(static_cast<bool>(handle) && !rows[handle.row()], "every refill observation is admitted to its own row");
    rows[handle.row()] = true;
  }
  require(stats.phase(Action::Notarize, Origin::Live, Phase::Requested).load() == requested + ActionLedger::max_rows,
          "the refill admitted all max_rows observations");
  require((stats.action_reasons[notarize].load() & reason_bit(IncompleteReason::LedgerCapacity)) == 0,
          "the refill met no capacity refusal");
  constexpr auto rows_total = static_cast<std::uint32_t>(ActionLedger::max_rows);
  auto overflow = ActionLedger::Key{Action::Notarize, Origin::Live, first_slot + rows_total, {}};
  ActionObservation refused(overflow.action, overflow.origin, stats, &session.vote_ledger, &overflow);
  require(!refused.ledger_handle() &&
              (stats.action_reasons[notarize].load() & reason_bit(IncompleteReason::LedgerCapacity)) != 0,
          "exactly max_rows rows exist");
}

// Concurrent cleanup of one key's holders. Admission stays serialized on one
// thread, as the production constructor contract requires; the holders' phase
// marks and releases then run on separate threads at once.
int concurrent() {
  constexpr std::uint32_t rounds = 2000;
  constexpr std::size_t holders = 8;
  const Watchdog watchdog(std::chrono::seconds(240));
  ConsensusStats stats;  // outlives every observation and worker
  SessionObservation session;
  session.start();
  require(session.vote_ledger.leased_bank() != nullptr, "the session leases a vote bank");
  std::array<std::unique_ptr<ActionObservation>, holders> handed{};
  Barrier start(holders + 1), done(holders + 1);
  std::atomic<bool> stop{false};
  std::vector<std::thread> workers;
  for (std::size_t w = 0; w < holders; ++w)
    workers.emplace_back([&, w] {
      for (;;) {
        start.arrive_and_wait();
        if (stop.load())
          return;
        auto observation = std::move(handed[w]);
        observation->observe(Phase::LocalApplied);
        observation.reset();
        done.arrive_and_wait();
      }
    });
  for (std::uint32_t round = 0; round < rounds; ++round) {
    auto key = ActionLedger::Key{Action::Notarize, Origin::Live, round, {}};
    for (auto &slot : handed)
      slot = std::make_unique<ActionObservation>(key.action, key.origin, stats, &session.vote_ledger, &key);
    start.arrive_and_wait();
    done.arrive_and_wait();
    session.vote_ledger.retire_before(static_cast<std::uint64_t>(round) + 1);
  }
  stop.store(true);
  start.arrive_and_wait();
  for (auto &worker : workers)
    worker.join();
  const auto value = [&](Phase phase) { return stats.phase(Action::Notarize, Origin::Live, phase).load(); };
  require(stats.inflight(Action::Notarize, Origin::Live).load() == 0 && pending_rows_clear(stats),
          "no request remains pending after concurrent cleanup");
  require(value(Phase::Cancelled) == rounds && outcome(stats, Action::Notarize, Outcome::Cancelled) == rounds,
          "every owner records exactly one cancellation");
  require(value(Phase::Requested) == rounds, "one logical request per round");
  require(value(Phase::LocalApplied) == rounds, "shared phase deduplication counts one LocalApplied per round");
  require(stats.repeated_requests.load() == rounds * (holders - 1), "every duplicate admission is counted");
  require(stats.action_reasons[notarize].load() == 0 && stats.post_terminal_progress.load() == 0,
          "concurrent cleanup loses no holder and reports no gap");
  session.vote_ledger.retire_before(rounds);
  require_full_refill(session, stats, rounds);
  std::printf("C04_LEDGER_PASS concurrent: %u rounds of %zu holders released on separate threads\n", rounds, holders);
  return 0;
}

int single_thread() {
  ConsensusStats stats;
  SessionObservation session;
  session.start();
  auto &ledger = session.vote_ledger;
  auto key = ActionLedger::Key{Action::Notarize, Origin::Live, 0, {}};
  {
    ActionObservation pending(key.action, key.origin, stats, &ledger, &key);
    require(stats.inflight(key.action, key.origin) == 1, "real unfinished operation pending");
    require(stats.oldest_started_ns(key.action, key.origin) != 0, "unfinished operation has oldest start");
    ledger.retire_before(1);
    // This pending key must survive retirement. Fill every other row.
    for (unsigned slot = 1; slot < ActionLedger::max_rows; ++slot) {
      auto next = key;
      next.slot = slot;
      ActionObservation completed(next.action, next.origin, stats, &ledger, &next);
      completed.observe(Phase::BroadcastEnqueued);
      completed.finish();
    }
    auto overflow = key;
    overflow.slot = ActionLedger::max_rows;
    ActionObservation refused(overflow.action, overflow.origin, stats, &ledger, &overflow);
    require(!stats.instrumentation_complete, "full ledger is explicitly incomplete");
    require(stats.inflight(key.action, key.origin) == 1, "capacity does not evict pending");
    pending.finish(Phase::Cancelled);
  }
  require(stats.inflight(key.action, key.origin) == 0 && stats.oldest_started_ns(key.action, key.origin) == 0,
          "cancellation removes pending and age");
  ledger.retire_before(ActionLedger::max_rows);
  const auto requested = stats.phase(key.action, key.origin, Phase::Requested).load();
  {
    ActionObservation retired(key.action, key.origin, stats, &ledger, &key);
    auto conflict = key;
    conflict.candidate[0] = 1;
    ActionObservation retired_conflict(conflict.action, conflict.origin, stats, &ledger, &conflict);
  }
  require(stats.phase(key.action, key.origin, Phase::Requested) == requested && stats.retired_requests == 2,
          "retired same and conflicting candidates never reopen logical population");
  auto next = key;
  next.slot = ActionLedger::max_rows;
  {
    ActionObservation after_retirement(next.action, next.origin, stats, &ledger, &next);
    after_retirement.observe(Phase::Signed);
    after_retirement.observe(Phase::Signed);
    after_retirement.finish(Phase::SignFailure);
  }
  {
    ActionObservation repeat(next.action, next.origin, stats, &ledger, &next);
    repeat.observe(Phase::Signed);
    repeat.observe(Phase::SignedCommitted);
    repeat.observe(Phase::SignedCommitted);
    repeat.observe(Phase::BroadcastEnqueued);
    repeat.finish();
  }
  require(stats.phase(key.action, key.origin, Phase::Requested) == requested + 1,
          "retirement makes room without resetting cumulative counters");
  require(stats.phase(key.action, key.origin, Phase::Signed) == 1 &&
              stats.phase(key.action, key.origin, Phase::SignedCommitted) == 1 && stats.post_terminal_progress == 2,
          "post-terminal new phases remain visible exactly once");
  require(stats.outcomes[1][static_cast<unsigned>(Outcome::Failed)] == 1,
          "post-terminal progress cannot add a second outcome");
  std::atomic<std::uint64_t> saturation{std::numeric_limits<std::uint64_t>::max() - 1};
  require(!stats.add(saturation, 2) && saturation == std::numeric_limits<std::uint64_t>::max(),
          "overflow saturates without wrapping");

  ConsensusStats ages;
  std::vector<std::unique_ptr<ActionObservation>> waiters;
  for (unsigned i = 0; i < ConsensusStats::max_pending; ++i)
    waiters.push_back(std::make_unique<ActionObservation>(Action::Skip, Origin::Live, ages));
  {
    ActionObservation refused(Action::Skip, Origin::Live, ages);
    require(!ages.instrumentation_complete && ages.inflight(Action::Skip, Origin::Live) == ConsensusStats::max_pending,
            "pending capacity declines new observations while preserving existing waits");
  }
  auto declined_key = ActionLedger::Key{Action::Finalize, Origin::Live, 10000, {}};
  const auto before_declined = ages.phase(Action::Finalize, Origin::Live, Phase::Requested).load();
  {
    ActionObservation declined(declined_key.action, declined_key.origin, ages, &session.vote_ledger, &declined_key);
    require(ages.phase(Action::Finalize, Origin::Live, Phase::Requested) == before_declined,
            "pending-full fresh key contributes no fabricated requested or terminal");
    session.vote_ledger.retire_before(10001);
    // It is still held by the declined frame until its actual observation ends.
    auto same = session.vote_ledger.begin(declined_key, ages);
    require(!same.handle, "retired declined key never reopens during frame lifetime");
  }
  waiters.clear();
  require(ages.inflight(Action::Skip, Origin::Live) == 0, "teardown accounts for all admitted cancellations");
  // Fill the entire bank after the declined frame ended and retirement passed.
  // A stranded nonterminal key would leave room for only 511 new observations.
  for (unsigned i = 0; i < ActionLedger::max_rows; ++i) {
    auto fresh = declined_key;
    fresh.slot = 10001 + i;
    ActionObservation observed(fresh.action, fresh.origin, ages, &session.vote_ledger, &fresh);
    observed.finish(Phase::Cancelled);
  }
  require(ages.phase(Action::Finalize, Origin::Live, Phase::Requested) == before_declined + ActionLedger::max_rows,
          "declined frame termination frees its retired key without a business terminal");
  session.begin_stop();
  session.close();
  require(consensus_stats.sessions_drained.load() == 1 && consensus_stats.sessions_active.load() == 0,
          "explicit observation close drains one active session");
  for (const auto &row : SessionObservation::context_rows)
    require(!row.leased.load(), "observation close releases context lease");
  session.close();
  require(consensus_stats.sessions_drained.load() == 1 && consensus_stats.sessions_stopped.load() == 1,
          "observation close is idempotent before destructor");
  require(lifecycle_verified.load(), "a session observed through stop and close verifies the lifecycle");
  // A session that closes without a requested stop (teardown without drain)
  // does not count as a verified boundary.
  lifecycle_verified.store(false);
  {
    SessionObservation torn;
    torn.start();
    torn.close();
  }
  require(!lifecycle_verified.load(), "close without begin_stop does not verify the lifecycle");
  std::printf("C04_LEDGER_PASS capacity, pending age, cancellation, retirement, repeated phases, saturation\n");
  return 0;
}
}  // namespace

int main(int argc, char **argv) {
  enabled.store(true);
  consensus_enabled.store(true);
  const std::string mode = argc > 1 ? argv[1] : "";
  if (mode.empty())
    return single_thread();
  if (mode == "concurrent")
    return concurrent();
  std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
  return 2;
}
