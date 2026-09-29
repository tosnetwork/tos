#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <vector>

#include "metrics/consensus-health.h"

using namespace tos::health;
static void require(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "C04_LEDGER_ASSERTION: %s\n", message);
    std::exit(1);
  }
}

int main() {
  enabled.store(true);
    consensus_enabled.store(true);
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
    require(same.entry == nullptr, "retired declined key never reopens during frame lifetime");
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
  std::printf("C04_LEDGER_PASS capacity, pending age, cancellation, retirement, repeated phases, saturation\n");
}
