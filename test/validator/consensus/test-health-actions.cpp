#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "consensus/bus.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/votes.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "metrics/consensus-health.h"
#include "metrics/native-core-snapshot.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/SharedFuture.h"
#include "td/actor/coro_utils.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;
using namespace tos::health;

namespace {
std::string mode, output_directory;
std::atomic<unsigned> writes{0}, broadcasts{0};
td::Bits256 fill(unsigned byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}
std::uint64_t cancelled(Action action) {
  return consensus_stats.outcomes[static_cast<std::size_t>(action)][static_cast<std::size_t>(Outcome::Cancelled)]
      .load();
}

// The stopped-duplicate mode races several entries, each held by an owner and a
// duplicate. The thread sanitizer keeps a few shadow cells per eight bytes and
// can evict one access of a racing pair, so independent pairs make a missed race
// on every entry at once negligible.
constexpr std::size_t stopped_pairs = 4, stopped_requests = 2 * stopped_pairs;
// Vote requests parked by the stopped-duplicate mode at the Pool's test vote
// gate, after admission and before the intent. The gates live outside every bus
// and actor, so releasing them needs neither.
struct ParkedRequests {
  std::mutex mutex;
  std::vector<td::actor::StartedTask<>::ExternalPromise> gates;
  unsigned parked = 0;
} parked_requests;

// Holds every stopped request cleanup at one point until all have arrived.
// Each arrives while its Pool frame is being destroyed: the parked gate task is
// that frame's await temporary, destroyed immediately before its observation,
// with no shared synchronization in between. So the observation releases that
// follow run at the same time on separate threads, unordered by anything but
// the ledger itself. No lock of this rendezvous is held across them.
struct CleanupRendezvous {
  std::mutex mutex;
  std::condition_variable changed;
  unsigned arrived = 0;
  bool met = false, timed_out = false;
  std::array<std::thread::id, stopped_requests> threads{};
  std::array<std::uint64_t, stopped_requests> cancelled_at_arrival{};
  void arrive() {
    std::unique_lock<std::mutex> lock(mutex);
    if (arrived < threads.size()) {
      threads[arrived] = std::this_thread::get_id();
      cancelled_at_arrival[arrived] = cancelled(Action::Notarize);
    }
    if (++arrived == threads.size()) {
      met = true;
      changed.notify_all();
      return;
    }
    if (!changed.wait_for(lock, std::chrono::seconds(20), [&] { return met; }))
      timed_out = true;
  }
} rendezvous;
// Carried as a coroutine parameter, so it is destroyed with the gate task's
// frame rather than when the task's body ends.
struct CleanupGuard {
  bool armed = true;
  CleanupGuard() = default;
  CleanupGuard(CleanupGuard &&other) noexcept : armed(std::exchange(other.armed, false)) {
  }
  CleanupGuard(const CleanupGuard &) = delete;
  CleanupGuard &operator=(const CleanupGuard &) = delete;
  CleanupGuard &operator=(CleanupGuard &&) = delete;
  ~CleanupGuard() {
    if (armed)
      rendezvous.arrive();
  }
};
td::actor::Task<> parked_gate(td::actor::StartedTask<> gate, CleanupGuard guard) {
  co_await std::move(gate);
  co_return td::Unit{};
}
// Parks the first stopped_requests votes that reach the gate; any later vote passes.
td::actor::StartedTask<> park_requests(const simplex::Vote &, simplex::VoteGatePoint point) {
  auto [gate, promise] = td::actor::StartedTask<>::make_bridge();
  {
    std::lock_guard<std::mutex> lock(parked_requests.mutex);
    if (point == simplex::VoteGatePoint::BeforeFinalityGate && parked_requests.parked < stopped_requests) {
      ++parked_requests.parked;
      parked_requests.gates.push_back(std::move(promise));
      // The gate task runs on the scheduler, so its frame holds no actor reference.
      auto task = parked_gate(std::move(gate), CleanupGuard{});
      task.set_executor(td::actor::Executor::on_scheduler());
      return std::move(task).start();
    }
  }
  promise.set_value(td::Unit{});
  return std::move(gate);
}

// What the producer-stop-ordering mode sees at its session's close and at its
// proposal bank's release. Installed as a plain function pointer: it holds no
// reference to an actor or a bus, records at most a fixed number of events and
// only for the one bank it tracks.
struct LifecycleRecord {
  LedgerLifecycle event{};
  double at = 0;
  std::uint64_t cancelled = 0, inflight = 0;
  std::size_t pending = 0;
  bool row_released = false;
};
struct LifecycleLog {
  std::atomic<const void *> tracked{nullptr};
  std::mutex mutex;
  std::array<LifecycleRecord, 8> records{};
  std::size_t size = 0;
  bool overflow = false;
} lifecycle_log;
std::size_t pending_rows(Action action);
void record_lifecycle(LedgerLifecycle event, const void *bank) noexcept {
  if (bank == nullptr || bank != lifecycle_log.tracked.load())
    return;
  LifecycleRecord record{.event = event,
                         .at = td::Timestamp::now().at(),
                         .cancelled = cancelled(Action::Proposal),
                         .inflight = consensus_stats.inflight(Action::Proposal, Origin::Live).load(),
                         .pending = pending_rows(Action::Proposal)};
  ActionLedger::Entry entry;
  record.row_released = ActionLedger::inspect(static_cast<const ActionLedger::Bank *>(bank), 0, entry) &&
                        entry.holders == 0 && entry.closed;
  std::lock_guard<std::mutex> lock(lifecycle_log.mutex);
  if (lifecycle_log.size == lifecycle_log.records.size()) {
    lifecycle_log.overflow = true;
    return;
  }
  lifecycle_log.records[lifecycle_log.size++] = record;
}
void require(bool condition, const char *assertion);
// Every recorded close or bank release found the stopped frame's observation
// already complete: its row released, its outcome recorded, nothing pending.
void require_lifecycle_order() {
  std::lock_guard<std::mutex> lock(lifecycle_log.mutex);
  for (std::size_t i = 0; i < lifecycle_log.size; ++i) {
    const auto &record = lifecycle_log.records[i];
    require(record.row_released && record.cancelled == 1 && record.inflight == 0 && record.pending == 0,
            "the observation is released before its session closes and its bank is released");
  }
}

// Only the journal API and overlay are controlled. Pool, vote state, signer,
// serialization and all observation branches are production implementations.
class Fixture : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const OutgoingProtocolMessage>) {
    ++broadcasts;
  }
  template <>
  td::actor::Task<td::int64> process(simplex::BusHandle, std::shared_ptr<simplex::PersistOwnVoteIntent>) {
    ++writes;
    if (mode == "intent-failure")
      co_return td::Status::Error("fixture intent failure");
    co_return td::int64{1};
  }
  template <>
  td::actor::Task<> process(simplex::BusHandle, std::shared_ptr<simplex::PersistOwnSignedVote>) {
    ++writes;
    if ((mode == "signed-failure" || mode == "replay-intent-signed-failure"))
      co_return td::Status::Error("fixture signed failure");
    co_return td::Unit{};
  }
};

class FailingCloseDb : public consensus::Db {
 public:
  std::optional<td::BufferSlice> get(td::Slice) const override {
    return std::nullopt;
  }
  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32) const override {
    return {};
  }
  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice) const override {
    co_return std::nullopt;
  }
  td::actor::Task<> set(td::BufferSlice, td::BufferSlice) override {
    co_return td::Unit{};
  }
  td::actor::Task<> close() override {
    co_return td::Status::Error("fixture close failure");
  }
};

std::uint64_t count(Action action, Origin origin, Phase phase) {
  return consensus_stats.phase(action, origin, phase).load();
}
// Ends the process without running static destructors: scheduler workers are
// still running, and destroying statics under them is a race of its own.
[[noreturn]] void end_process(int code) {
  std::fflush(nullptr);
  std::_Exit(code);
}
void require(bool condition, const char *assertion) {
  if (!condition) {
    std::fprintf(stderr, "C04_ACTION_ASSERTION: %s\n", assertion);
    end_process(1);
  }
}
std::size_t pending_rows(Action action) {
  std::size_t rows = 0;
  for (const auto &row : consensus_stats.pending_rows)
    if (row.started_ns.load() != 0 && row.action.load() == action)
      ++rows;
  return rows;
}
bool has_reason(Action action, IncompleteReason reason) {
  return (consensus_stats.action_reasons[static_cast<std::size_t>(action)].load() &
          (std::uint32_t{1} << static_cast<unsigned>(reason))) != 0;
}
// Polls a condition from the driver actor with a bounded deadline.
template <class Condition>
td::actor::Task<bool> wait_until(Condition condition, double seconds) {
  const auto deadline = td::Timestamp::in(seconds);
  while (!condition()) {
    if (deadline.is_in_past())
      co_return false;
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
  }
  co_return true;
}

// A four-validator masterchain bus whose local validator is the first one.
std::shared_ptr<simplex::Bus> make_validator_bus(unsigned session_byte) {
  auto bus = std::make_shared<simplex::Bus>();
  bus->session_id = fill(session_byte);
  bus->shard = ShardIdFull{masterchainId, shardIdAll};
  for (unsigned i = 0; i < 4; ++i) {
    // Public, isolated fixture seeds; never node custody or business seed input.
    auto key = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, char(0x60 + i)));
    CHECK(key.has_value());
    auto signer = std::make_shared<tos::pq::ValidatorPQKeyStore>(std::move(*key));
    auto adnl = adnl::AdnlNodeIdShort{fill(0x90 + i)};
    bus->validator_set.push_back(PeerValidator{.validator_id = ValidatorId{fill(0x70 + i)},
                                               .idx = PeerValidatorId{i},
                                               .consensus_key = signer->consensus_key(),
                                               .transport_key_id = adnl.pubkey_hash(),
                                               .adnl_id = adnl,
                                               .weight = 1});
    if (i == 0) {
      if ((mode == "sign-failure" || mode == "replay-intent-sign-failure")) {
        // A moved-from fixture store has no secret; exercise the actual leaf failure.
        auto removed_secret = std::move(*signer);
        bus->pq_signer = signer;
      } else if (mode != "no-signer")
        bus->pq_signer = signer;
    }
  }
  bus->local_id = bus->validator_set.front();
  bus->local_adnl_id = bus->local_id->adnl_id;
  bus->total_weight = 4;
  bus->config.slots_per_leader_window = 4;
  bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600000);
  return bus;
}

class Driver : public td::actor::Actor {
 public:
  td::actor::Task<> paused_duplicate(ActionLedger &ledger, const ActionLedger::Key &key, ConsensusStats &stats) {
    ActionObservation duplicate(key.action, key.origin, stats, &ledger, &key);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.08));
    duplicate.observe(Phase::SignedCommitted);
    duplicate.finish();
    co_return td::Unit{};
  }
  td::actor::Task<> lifetime_control() {
    SessionObservation session;
    session.start();
    ConsensusStats stats;
    auto key = ActionLedger::Key{Action::Notarize, Origin::Live, 0, {}};
    {
      ActionObservation original(key.action, key.origin, stats, &session.vote_ledger, &key);
      original.finish(Phase::SignFailure);
    }
    auto duplicate = paused_duplicate(session.vote_ledger, key, stats).start();
    co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
    session.vote_ledger.retire_before(1);
    for (unsigned slot = 1; slot < ActionLedger::max_rows; ++slot) {
      auto other = key;
      other.slot = slot;
      ActionObservation finished(other.action, other.origin, stats, &session.vote_ledger, &other);
      finished.finish(Phase::Cancelled);
    }
    auto next = key;
    next.slot = ActionLedger::max_rows;
    {
      ActionObservation blocked(next.action, next.origin, stats, &session.vote_ledger, &next);
    }
    require(stats.phase(key.action, key.origin, Phase::Requested) == ActionLedger::max_rows,
            "paused duplicate lease prevents retirement and new-key reuse");
    co_await std::move(duplicate);
    {
      ActionObservation replacement(next.action, next.origin, stats, &session.vote_ledger, &next);
      replacement.observe(Phase::SignedCommitted);
      replacement.finish(Phase::Cancelled);
    }
    require(stats.phase(key.action, key.origin, Phase::Requested) == ActionLedger::max_rows + 1 &&
                stats.phase(key.action, key.origin, Phase::SignedCommitted) == 2,
            "resumed duplicate cannot poison replacement key phase bitset");
    require(stats.post_terminal_progress == 1, "old-key progress stays attached to original terminal");
    co_return td::Unit{};
  }

  // Stopped duplicate cleanup on the production Pool. Several votes are each
  // requested twice, so each ledger entry has an owner and a duplicate, and
  // every request parks at the Pool's test vote gate, after admission and
  // before the intent. The Pool stops, every outside bus reference is dropped,
  // and only then are the gates released: no frame can resume, so all are
  // destroyed off the actor, concurrently, while their requests still pin the
  // bus. This is duplicate cleanup within one lease.
  td::actor::Task<> stopped_duplicate() {
    auto bus = make_validator_bus(0x44);
    bus->vote_gate_hook_for_test = park_requests;
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus->stop_promise = std::move(stop_promise);
    td::actor::Runtime runtime;
    runtime.register_actor<Fixture>("Fixture");
    simplex::Pool::register_in(runtime);
    simplex::DefaultCollatorSchedule::provide_for(runtime);
    auto handle = runtime.start(bus, "c04-stopped-duplicate");
    for (unsigned pair = 0; pair < stopped_pairs; ++pair)
      for (unsigned request = 0; request < 2; ++request) {
        const simplex::Vote vote{simplex::NotarizeVote{CandidateId{pair, fill(0x22 + pair)}}};
        // The outer request runs on the scheduler, not on this actor, so no
        // cleanup is serialized behind another on the driver.
        auto task = handle.publish<simplex::BroadcastVote>(vote);
        task.set_executor(td::actor::Executor::on_scheduler());
        std::move(task).start().detach();
      }
    require(co_await wait_until(
                [] {
                  std::lock_guard<std::mutex> lock(parked_requests.mutex);
                  return parked_requests.parked == stopped_requests;
                },
                10),
            "every request is parked after admission");
    require(count(Action::Notarize, Origin::Live, Phase::Requested) == stopped_pairs &&
                consensus_stats.repeated_requests.load() == stopped_pairs &&
                consensus_stats.inflight(Action::Notarize, Origin::Live).load() == stopped_pairs,
            "each entry is held by one owner and one duplicate");
    // A probe that still reached a running Pool would be refused before its intent.
    handle.publish<FinalizationBacklog>(true);
    bus->health_session.begin_stop();
    handle.publish<StopRequested>();
    bool pool_closed = false;
    for (unsigned attempt = 0; attempt < 1000 && !pool_closed; ++attempt) {
      auto probe = co_await handle.publish<simplex::BroadcastVote>(simplex::Vote{simplex::SkipVote{1}}).wrap();
      pool_closed = probe.is_error();
      if (!pool_closed)
        co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    require(pool_closed, "the stopped Pool accepts no further request");
    handle = {};
    bus.reset();
    {
      std::lock_guard<std::mutex> lock(parked_requests.mutex);
      require(parked_requests.gates.size() == stopped_requests, "every parked request is held outside the bus");
      for (auto &gate : parked_requests.gates)
        gate.set_value(td::Unit{});
      parked_requests.gates.clear();
    }
    auto drained = co_await td::actor::await_with_timeout(std::move(stopped), td::Timestamp::in(30)).wrap();
    require(drained.is_ok(), "the bus is released once every stopped request is destroyed");
    {
      std::lock_guard<std::mutex> lock(rendezvous.mutex);
      bool distinct = true;
      for (std::size_t i = 0; i < stopped_requests; ++i)
        for (std::size_t j = i + 1; j < stopped_requests; ++j)
          distinct = distinct && rendezvous.threads[i] != rendezvous.threads[j];
      require(rendezvous.met && !rendezvous.timed_out && rendezvous.arrived == stopped_requests && distinct,
              "every stopped cleanup reached the rendezvous together on its own thread");
      bool early = true;
      for (const auto value : rendezvous.cancelled_at_arrival)
        early = early && value == 0;
      require(early, "every cleanup arrived before any observation was released");
    }
    require(consensus_stats.inflight(Action::Notarize, Origin::Live).load() == 0 && pending_rows(Action::Notarize) == 0,
            "stopped duplicate cleanup clears the pending request and row");
    require(count(Action::Notarize, Origin::Live, Phase::IntentCommitted) == 0 &&
                count(Action::Notarize, Origin::Live, Phase::IntentCancelled) == 0 &&
                count(Action::Notarize, Origin::Live, Phase::Cancelled) == stopped_pairs,
            "no frame resumed after stop; each owner's destruction is its one cancellation");
    require(cancelled(Action::Notarize) == stopped_pairs && consensus_stats.repeated_requests.load() == stopped_pairs,
            "exactly one cancelled outcome and one repeated request per entry");
    require(!has_reason(Action::Notarize, IncompleteReason::ObservationGap),
            "stopped duplicate cleanup within one lease reports no gap");
    require(consensus_stats.sessions_drained.load() == 1, "the session drains after every request ends");
    for (const auto &row : SessionObservation::context_rows)
      require(!row.leased.load(), "the session releases its context row");
    std::printf(
        "C04_ACTION_PASS pool-stopped-duplicate: duplicate pairs destroyed concurrently off the actor, one "
        "cancellation per entry, no gap\n");
    end_process(0);
    co_return td::Unit{};
  }

  // The production block producer's frame sleeps before its first slot while its
  // session stops and every fixture reference to the bus is dropped. The frame
  // keeps its actor, and through the actor's owning handle the bus, alive until
  // it is destroyed, so its observation must be released before the session's
  // close begins and before its proposal bank is released. The order is
  // recorded at those two points; the bank stays unavailable while the frame is
  // outstanding, the bus still drains, and the same bank is leased again after.
  td::actor::Task<> producer_stop_ordering() {
    constexpr double sleep_seconds = 2.0;
    constexpr td::uint32 start_slot = 4;
    auto bus = make_validator_bus(0x45);
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus->stop_promise = std::move(stop_promise);
    // No Pool runs here, so the session observation is started directly.
    bus->health_session.start(bus->session_id.data(), bus->shard.workchain, bus->shard.shard);
    const auto *bank = bus->health_session.proposal_ledger.leased_bank();
    require(bank != nullptr, "the session leases a proposal bank");
    lifecycle_log.tracked.store(bank);
    ledger_lifecycle_hook_for_test.store(&record_lifecycle);
    td::actor::Runtime runtime;
    BlockProducer::register_in(runtime);
    auto handle = runtime.start(bus, "c04-producer-stop-ordering");
    const auto wake = td::Timestamp::in(sleep_seconds);
    handle.publish<OurLeaderWindowStarted>(std::make_shared<OurLeaderWindowStarted>(OurLeaderWindowStarted{
        .base = std::nullopt, .state = {}, .start_slot = start_slot, .end_slot = 8, .start_time = wake}));
    require(co_await wait_until(
                [] {
                  return count(Action::Proposal, Origin::Live, Phase::Requested) == 1 &&
                         consensus_stats.inflight(Action::Proposal, Origin::Live).load() == 1;
                },
                10),
            "the producer frame admitted its proposal");
    ActionLedger::Entry entry;
    require(ActionLedger::inspect(bank, 0, entry) && entry.occupied && entry.holders == 1 &&
                entry.key.action == Action::Proposal && entry.key.slot == start_slot && !entry.closed,
            "the producer frame holds row 0 of the proposal bank");
    // Admission runs inside the frame's first run on the producer actor, which
    // continues without suspending to the frame's first sleep unless it records
    // a terminal. The stop below is handled by the same actor after that run.
    require(cancelled(Action::Proposal) == 0 && count(Action::Proposal, Origin::Live, Phase::FinalitySuppressed) == 0,
            "the admitted frame reached its first sleep without a terminal");
    bus->health_session.begin_stop();
    handle.publish<StopRequested>();
    handle = {};
    bus.reset();
    // Every fixture-owned strong reference to the bus is gone. The frame is
    // still outstanding: its bank must stay leased and unavailable.
    require(cancelled(Action::Proposal) == 0 && consensus_stats.inflight(Action::Proposal, Origin::Live).load() == 1,
            "the stopped producer frame is still outstanding after the bus references are dropped");
    require_lifecycle_order();
    {
      SessionObservation probe;
      probe.start();
      require(
          bank->leased.load() && probe.proposal_ledger.leased_bank() != bank && probe.vote_ledger.leased_bank() != bank,
          "the lease stays unavailable while the observation is outstanding");
      probe.close();
    }
    auto drained =
        co_await td::actor::await_with_timeout(std::move(stopped), td::Timestamp::in(sleep_seconds + 20)).wrap();
    require(drained.is_ok(), "the bus drains once the stopped producer frame is destroyed");
    require(consensus_stats.inflight(Action::Proposal, Origin::Live).load() == 0 && pending_rows(Action::Proposal) == 0,
            "the stopped producer frame records its cancellation and clears its pending request and row");
    require(cancelled(Action::Proposal) == 1 && count(Action::Proposal, Origin::Live, Phase::Cancelled) == 1 &&
                count(Action::Proposal, Origin::Live, Phase::Superseded) == 0,
            "the stopped producer frame is cancelled without resuming its body");
    require_lifecycle_order();
    {
      std::lock_guard<std::mutex> lock(lifecycle_log.mutex);
      require(!lifecycle_log.overflow && lifecycle_log.size == 2 &&
                  lifecycle_log.records[0].event == LedgerLifecycle::SessionCloseEntered &&
                  lifecycle_log.records[1].event == LedgerLifecycle::BankReleased,
              "the session close and then the bank release were each recorded once");
      require(lifecycle_log.records[0].at >= wake.at(),
              "the session closes only after the frame's sleep completes, so the frame was suspended in it");
    }
    ledger_lifecycle_hook_for_test.store(nullptr);
    lifecycle_log.tracked.store(nullptr);
    require(!bank->leased.load() && !has_reason(Action::Proposal, IncompleteReason::ObservationGap),
            "the drained session released its bank without an observation gap");
    SessionObservation next;
    next.start();
    require(next.proposal_ledger.leased_bank() == bank, "the drained bank is leased again by the next session");
    const ActionLedger::Key key{Action::Proposal, Origin::Live, start_slot, {}};
    {
      ActionObservation reused(key.action, key.origin, consensus_stats, &next.proposal_ledger, &key);
      require(reused.ledger_handle().bank() == bank && reused.ledger_handle().row() == 0 &&
                  ActionLedger::inspect(bank, 0, entry) && entry.holders == 1 && !entry.closed &&
                  entry.seen == (std::uint32_t{1} << static_cast<unsigned>(Phase::Requested)),
              "the reused bank admits a fresh owner to a clean row");
      reused.finish(Phase::Cancelled);
    }
    require(consensus_stats.inflight(Action::Proposal, Origin::Live).load() == 0 && pending_rows(Action::Proposal) == 0,
            "the reused bank's owner clears its own pending request");
    next.close();
    std::printf(
        "C04_ACTION_PASS producer-stop-ordering: stopped frame released before session close and bank release; "
        "bank unavailable while outstanding, drained and reused\n");
    end_process(0);
    co_return td::Unit{};
  }

  td::actor::Task<> run() {
    enabled.store(true);
    consensus_enabled.store(true);
    if (mode == "pool-stopped-duplicate") {
      co_await stopped_duplicate();
      end_process(1);
    }
    if (mode == "producer-stop-ordering") {
      co_await producer_stop_ordering();
      end_process(1);
    }
    if (mode == "lease") {
      co_await lifetime_control();
      std::printf(
          "C04_ACTION_PASS lease: actual suspended coroutine, terminal, retirement, blocked reuse, resume, safe "
          "reuse\n");
      std::exit(0);
    }
    if (mode == "close-error") {
      auto bus = std::make_shared<simplex::Bus>();
      bus->db = std::make_unique<FailingCloseDb>();
      const auto session_id = fill(0x55);
      bus->health_session.start(session_id.data(), -1, std::uint64_t{1} << 63);
      auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
      bus->stop_promise = std::move(stop_promise);
      td::actor::Runtime runtime;
      auto handle = runtime.start(bus, "c04-close-error");
      bus->health_session.begin_stop();
      handle.publish<StopRequested>();
      bus.reset();
      auto closed = co_await simplex::close_and_release_bus(handle).wrap();
      require(closed.is_error() && !handle, "failed DB close still releases bridge bus handle");
      co_await std::move(stopped);
      require(consensus_stats.sessions_drained.load() == 1 && consensus_stats.sessions_active.load() == 0,
              "failed DB close still drains observation before bus stop promise");
      for (const auto &row : SessionObservation::context_rows)
        require(!row.leased.load(), "failed DB close releases context before bus stop promise");
      std::printf("C04_ACTION_PASS close-error: failed DB close released bus and observation before stop promise\n");
      std::exit(0);
    }
    NativeCorePublisher publisher;
    require(publisher.set_node("v1") && publisher.set_network(std::string(64, 'a')), "isolated publisher identity");
    for (unsigned rotation = 0; rotation < 3; ++rotation) {
      auto bus = make_validator_bus(0x42 + rotation);
      if (mode == "journal-suppressed")
        bus->vote_journal_failure = "fixture journal unusable";
      const CandidateId id{0, fill(0x22)};
      simplex::Vote vote{simplex::NotarizeVote{id}};
      const auto action = mode == "finalize" ? Action::Finalize : Action::Notarize;
      if (mode == "finalize")
        vote = simplex::FinalizeVote{id};
      const bool replay = mode.starts_with("replay-");
      if (replay || mode == "apply-false") {
        td::BufferSlice signature;
        if (mode == "replay-signed" || mode == "apply-false") {
          auto data = create_serialize_tl_object<tos_api::consensus_dataToSign>(
              bus->session_id, serialize_tl_object(vote.to_tl(), true));
          const auto bytes = data.as_slice();
          auto signed_vote = bus->pq_signer->sign_consensus(std::string_view(bytes.data(), bytes.size()));
          CHECK(signed_vote.has_value());
          signature = td::BufferSlice(signed_vote->signature);
        }
        bus->bootstrap_votes.push_back(simplex::BootstrapVote{vote, 1, std::move(signature)});
      }
      auto before = bus->pq_signer ? bus->pq_signer->consensus_signatures_produced() : 0;
      const auto crypto_before = pq_sign.completed.load();
      auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
      bus->stop_promise = std::move(stop_promise);
      td::actor::Runtime runtime;
      runtime.register_actor<Fixture>("Fixture");
      simplex::Pool::register_in(runtime);
      simplex::DefaultCollatorSchedule::provide_for(runtime);
      auto handle = runtime.start(bus, "c04-isolated");
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
      if (mode == "finality-suppressed" || mode == "post-terminal") {
        handle.publish<FinalizationBacklog>(true);
        co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
      }
      if (!replay) {
        // Only a refusal before the intent may be reported as one; everything from the
        // intent on, including a failure, is Submitted.
        using simplex::VoteCastOutcome;
        const auto expected = mode == "finality-suppressed" || mode == "post-terminal"
                                  ? VoteCastOutcome::SuppressedBeforeIntentFinalityBehind
                              : mode == "journal-suppressed" ? VoteCastOutcome::SuppressedBeforeIntentJournalUnusable
                                                             : VoteCastOutcome::Submitted;
        auto outcome = co_await handle.publish<simplex::BroadcastVote>(vote);
        require(outcome == expected, "BroadcastVote reports exactly whether the vote was refused before its intent");
        if (mode == "duplicate")
          require(co_await handle.publish<simplex::BroadcastVote>(vote) == VoteCastOutcome::Submitted,
                  "a duplicate request reaches the journal and is Submitted");
        if (mode == "post-terminal") {
          handle.publish<FinalizationBacklog>(false);
          co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
          require(co_await handle.publish<simplex::BroadcastVote>(vote) == VoteCastOutcome::Submitted,
                  "the same vote requested again after the backlog cleared is Submitted");
        }
        if (mode == "skip")
          require(co_await handle.publish<simplex::BroadcastVote>(simplex::SkipVote{1}) == VoteCastOutcome::Submitted,
                  "a skip is Submitted");
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
      const auto signatures = bus->pq_signer ? bus->pq_signer->consensus_signatures_produced() - before : 0;
      const Origin origin = mode == "replay-signed" ? Origin::ReplaySigned
                            : replay                ? Origin::ReplayIntent
                                                    : Origin::Live;
      const auto n = rotation + 1;
      auto value = [&](Phase phase) { return count(action, origin, phase); };
      require(value(Phase::Requested) == n, "exact request count across rotation");
      if (mode == "post-terminal") {
        require(value(Phase::FinalitySuppressed) == n && value(Phase::Signed) == n &&
                    value(Phase::BroadcastEnqueued) == n && broadcasts == n,
                "later real progress remains observed");
        require(!consensus_stats.action_complete[static_cast<std::size_t>(action)].load(),
                "post terminal progress invalidates logical completeness");
        require(consensus_stats.post_terminal_progress.load() == n * 5, "new stages counted once after terminal");
        require(
            consensus_stats.outcomes[static_cast<std::size_t>(action)][static_cast<std::size_t>(Outcome::Suppressed)]
                    .load() == n,
            "first terminal remains the only terminal");
      } else if (mode == "apply-false") {
        require(value(Phase::SignedCommitted) == n, "false apply follows actual signed commit");
        require(value(Phase::ApplyFalse) == n && value(Phase::LocalApplied) == 0 && broadcasts == 0,
                "false apply does not report applied or enqueue");
      } else if (mode == "intent-failure") {
        require(value(Phase::IntentFailure) == n, "intent failure observed");
        require(value(Phase::Signed) == 0 && signatures == 0 && broadcasts == 0,
                "intent failure forbids signing/publish");
      } else if (mode == "no-signer" || (mode == "sign-failure" || mode == "replay-intent-sign-failure")) {
        require(value(Phase::IntentCommitted) == (replay ? 0 : n) &&
                    value(mode == "no-signer" ? Phase::MissingSigner : Phase::SignFailure) == n,
                "committed intent then sign failure");
        require(value(Phase::SignedCommitted) == 0 && value(Phase::LocalApplied) == 0 && broadcasts == 0,
                "sign failure forbids commit/apply/publish");
        if ((mode == "sign-failure" || mode == "replay-intent-sign-failure"))
          require(pq_sign.failed.load() == n, "actual leaf sign failure separate from no signer");
        else
          require(pq_sign.failed.load() == 0, "missing signer is not a crypto operation");
      } else if ((mode == "signed-failure" || mode == "replay-intent-signed-failure")) {
        require(value(Phase::Signed) == n && value(Phase::SignedCommitFailure) == n, "signed commit failure observed");
        require(value(Phase::LocalApplied) == 0 && broadcasts == 0, "signed commit failure forbids apply/publish");
      } else if (mode == "journal-suppressed" || mode == "finality-suppressed") {
        require(value(mode == "journal-suppressed" ? Phase::JournalSuppressed : Phase::FinalitySuppressed) == n,
                "specific suppression observed");
        require(writes == 0 && signatures == 0 && broadcasts == 0, "suppression preserves zero journal/sign/publish");
      } else {
        require(value(Phase::LocalApplied) == n, "apply success observed once");
        require(value(Phase::BroadcastEnqueued) == (replay ? 0 : n), "only actual live publish enqueued");
        if (mode == "duplicate") {
          require(value(Phase::ApplyFalse) == 0, "duplicate cannot add a second logical terminal");
          require(consensus_stats.repeated_requests.load() == n, "duplicate request observed separately");
        }
        if (mode == "replay-signed") {
          require(signatures == 0 && pq_sign.completed.load() == crypto_before, "signed replay does not invoke crypto");
          require(value(Phase::Signed) == 0 && value(Phase::RestoredSigned) == n,
                  "restored bytes separate from signing");
        } else if (mode == "replay-intent") {
          require(signatures == 1 && pq_sign.completed.load() == crypto_before + 1, "intent replay signs exactly once");
          require(value(Phase::SignedCommitted) == n && broadcasts == 0, "intent replay commits without live publish");
        }
        if (mode == "skip") {
          require(count(Action::Skip, Origin::Live, Phase::IntentCommitted) == n &&
                      count(Action::Skip, Origin::Live, Phase::SignedCommitted) == n &&
                      count(Action::Skip, Origin::Live, Phase::BroadcastEnqueued) == n,
                  "skip obeys journal pipeline");
        }
      }
      if (replay) {
        std::uint64_t terminals = 0;
        for (const auto &counter :
             consensus_stats.replay_terminals[static_cast<std::size_t>(action)][static_cast<std::size_t>(origin) - 1])
          terminals += counter.load();
        require(terminals == n, "failed or successful replay has exactly one separate terminal");
      }
      for (std::size_t a = 0; a < action_count; ++a) {
        std::uint64_t terminals = 0;
        for (const auto &counter : consensus_stats.outcomes[a])
          terminals += counter.load();
        require(terminals + consensus_stats.pending[a][0].load() ==
                    consensus_stats.phases[a][0][static_cast<std::size_t>(Phase::Requested)].load(),
                "all live logical operations conserve exactly one terminal");
      }
      require(consensus_stats.inflight(action, origin).load() == 0, "no pending request after terminal");
      if (!output_directory.empty()) {
        require(register_consensus_metrics(core_registry), "frozen C01 registry bindings succeed");
        auto observed = capture_consensus(std::string(64, 'a'));
        require(observed.has_value(), "bounded native consensus publication exists");
        auto metrics = core_registry.collect();
        metrics.families.push_back(metrics::MetricFamily::make_scalar("tos_exporter_snapshot_generation", "gauge", n));
        auto operations = metrics::MetricFamily{.name = "tos_pq_operations_total",
                                                .type = "counter",
                                                .help = "Actual isolated production PQ operations.",
                                                .metrics = {}};
        for (auto [operation, stats] : {std::pair{"sign", &pq_sign}, std::pair{"verify", &pq_verify}}) {
          for (auto [result, counter] : {std::pair{"success", &stats->completed}, std::pair{"failure", &stats->failed}})
            operations.metrics.push_back(
                {.suffix = "",
                 .label_set = {{{"operation", operation}, {"suite", "mldsa44"}, {"result", result}}},
                 .samples = {{.label_set = {}, .value = static_cast<double>(counter->load())}}});
        }
        metrics.families.push_back(std::move(operations));
        auto rendered = std::move(metrics).render_bounded(1048576);
        require(rendered.has_value(), "registered native complete OpenMetrics body");
        const OperationSnapshot sign{pq_sign.completed.load(), pq_sign.failed.load(), pq_sign.complete.load()};
        const OperationSnapshot verify{pq_verify.completed.load(), pq_verify.failed.load(), pq_verify.complete.load()};
        const auto pair = publisher.prepare(n, 10, 1700000000, *rendered, true, sign, verify, true, &*observed);
        require(pair.has_value(), "actual native-core-v2 pair prepared");
        const auto body = pair->read(10);
        require(body.has_value(), "actual native-core-v2 immutable body readable");
        std::filesystem::create_directories(output_directory);
        const auto prefix = output_directory + "/" + mode + "-" + std::to_string(n);
        std::ofstream(prefix + ".json") << *body << '\n';
        std::ofstream(prefix + ".prom") << *rendered;
      }
      bus->health_session.begin_stop();
      require(consensus_stats.sessions_stopping.load() == 1, "stop request is pending before drain");
      handle.publish<StopRequested>();
      handle = {};
      bus.reset();
      co_await std::move(stopped);
      require(consensus_stats.sessions_stopping.load() == 0, "stopping cleared only at release boundary");
      require(consensus_stats.sessions_active.load() == 0, "bus lifetime released after stop");
      require(consensus_stats.sessions_drained.load() == n, "observation drain precedes bus stop promise");
      for (const auto &row : SessionObservation::context_rows)
        require(!row.leased.load(), "context lease released before bus stop promise");
      require(consensus_stats.sessions_started.load() == n && consensus_stats.sessions_stopped.load() == n,
              "session rotation counters monotonic and exact");
    }
    std::printf("C04_ACTION_PASS %s: production branches, trace without consumer, three rotations\n", mode.c_str());
    std::exit(0);
    co_return td::Unit{};
  }
};
}  // namespace

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3)
    return 2;
  mode = argv[1];
  if (argc == 3)
    output_directory = argv[2];
  // The stopped-cleanup modes need a worker for each concurrent cleanup, and spare.
  const bool stopped_cleanup = mode == "pool-stopped-duplicate" || mode == "producer-stop-ordering";
  td::actor::Scheduler scheduler({stopped_cleanup ? 12 : 2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("c04-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 1;
}
