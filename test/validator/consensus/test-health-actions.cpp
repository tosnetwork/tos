#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <filesystem>
#include <fstream>
#include "metrics/native-core-snapshot.h"

#include "consensus/simplex/bus.h"
#include "consensus/simplex/votes.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "metrics/consensus-health.h"
#include "td/actor/BusRuntime.h"
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

// Only the journal API and overlay are controlled. Pool, vote state, signer,
// serialization and all observation branches are production implementations.
class Fixture : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();
  template <> void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) { stop(); }
  template <> void handle(simplex::BusHandle, std::shared_ptr<const OutgoingProtocolMessage>) { ++broadcasts; }
  template <> td::actor::Task<td::int64> process(simplex::BusHandle,
                                                std::shared_ptr<simplex::PersistOwnVoteIntent>) {
    ++writes;
    if (mode == "intent-failure") co_return td::Status::Error("fixture intent failure");
    co_return td::int64{1};
  }
  template <> td::actor::Task<> process(simplex::BusHandle,
                                      std::shared_ptr<simplex::PersistOwnSignedVote>) {
    ++writes;
    if ((mode == "signed-failure" || mode == "replay-intent-signed-failure")) co_return td::Status::Error("fixture signed failure");
    co_return td::Unit{};
  }
};

std::uint64_t count(Action action, Origin origin, Phase phase) {
  return consensus_stats.phase(action, origin, phase).load();
}
void require(bool condition, const char *assertion) {
  if (!condition) {
    std::fprintf(stderr, "C04_ACTION_ASSERTION: %s\n", assertion);
    std::exit(1);
  }
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
  td::actor::Task<> run() {
    enabled.store(true);
    consensus_enabled.store(true);
    if (mode == "lease") {
      co_await lifetime_control();
      std::printf("C04_ACTION_PASS lease: actual suspended coroutine, terminal, retirement, blocked reuse, resume, safe reuse\n");
      std::exit(0);
    }
    NativeCorePublisher publisher;
    require(publisher.set_node("v1") && publisher.set_network(std::string(64, 'a')), "isolated publisher identity");
    for (unsigned rotation = 0; rotation < 3; ++rotation) {
      auto bus = std::make_shared<simplex::Bus>();
      bus->session_id = fill(0x42 + rotation);
      bus->shard = ShardIdFull{masterchainId, shardIdAll};
      for (unsigned i = 0; i < 4; ++i) {
        // Public, isolated fixture seeds; never node custody or business seed input.
        auto key = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, char(0x60 + i)));
        CHECK(key.has_value());
        auto signer = std::make_shared<tos::pq::ValidatorPQKeyStore>(std::move(*key));
        auto adnl = adnl::AdnlNodeIdShort{fill(0x90 + i)};
        bus->validator_set.push_back(PeerValidator{.validator_id = ValidatorId{fill(0x70 + i)},
          .idx = PeerValidatorId{i}, .consensus_key = signer->consensus_key(),
          .transport_key_id = adnl.pubkey_hash(), .adnl_id = adnl, .weight = 1});
        if (i == 0) {
          if ((mode == "sign-failure" || mode == "replay-intent-sign-failure")) {
            // A moved-from fixture store has no secret; exercise the actual leaf failure.
            auto removed_secret = std::move(*signer);
            bus->pq_signer = signer;
          } else if (mode != "no-signer") bus->pq_signer = signer;
        }
      }
      bus->local_id = bus->validator_set.front();
      bus->local_adnl_id = bus->local_id->adnl_id;
      bus->total_weight = 4;
      bus->config.slots_per_leader_window = 4;
      bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600000);
      if (mode == "journal-suppressed") bus->vote_journal_failure = "fixture journal unusable";
      const CandidateId id{0, fill(0x22)};
      simplex::Vote vote{simplex::NotarizeVote{id}};
      const auto action = mode == "finalize" ? Action::Finalize : Action::Notarize;
      if (mode == "finalize") vote = simplex::FinalizeVote{id};
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
        co_await handle.publish<simplex::BroadcastVote>(vote);
        if (mode == "duplicate") co_await handle.publish<simplex::BroadcastVote>(vote);
        if (mode == "post-terminal") {
          handle.publish<FinalizationBacklog>(false);
          co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
          co_await handle.publish<simplex::BroadcastVote>(vote);
        }
        if (mode == "skip") co_await handle.publish<simplex::BroadcastVote>(simplex::SkipVote{1});
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
      const auto signatures = bus->pq_signer ? bus->pq_signer->consensus_signatures_produced() - before : 0;
      const Origin origin = mode == "replay-signed" ? Origin::ReplaySigned :
                            replay ? Origin::ReplayIntent : Origin::Live;
      const auto n = rotation + 1;
      auto value = [&](Phase phase) { return count(action, origin, phase); };
      require(value(Phase::Requested) == n, "exact request count across rotation");
      if (mode == "post-terminal") {
        require(value(Phase::FinalitySuppressed) == n && value(Phase::Signed) == n &&
                value(Phase::BroadcastEnqueued) == n && broadcasts == n, "later real progress remains observed");
        require(!consensus_stats.action_complete[static_cast<std::size_t>(action)].load(),
                "post terminal progress invalidates logical completeness");
        require(consensus_stats.post_terminal_progress.load() == n * 5, "new stages counted once after terminal");
        require(consensus_stats.outcomes[static_cast<std::size_t>(action)][static_cast<std::size_t>(Outcome::Suppressed)].load() == n,
                "first terminal remains the only terminal");
      } else if (mode == "apply-false") {
        require(value(Phase::SignedCommitted) == n, "false apply follows actual signed commit");
        require(value(Phase::ApplyFalse) == n && value(Phase::LocalApplied) == 0 && broadcasts == 0,
                "false apply does not report applied or enqueue");
      } else if (mode == "intent-failure") {
        require(value(Phase::IntentFailure) == n, "intent failure observed");
        require(value(Phase::Signed) == 0 && signatures == 0 && broadcasts == 0, "intent failure forbids signing/publish");
      } else if (mode == "no-signer" || (mode == "sign-failure" || mode == "replay-intent-sign-failure")) {
        require(value(Phase::IntentCommitted) == (replay ? 0 : n) && value(mode == "no-signer" ? Phase::MissingSigner : Phase::SignFailure) == n, "committed intent then sign failure");
        require(value(Phase::SignedCommitted) == 0 && value(Phase::LocalApplied) == 0 && broadcasts == 0,
                "sign failure forbids commit/apply/publish");
        if ((mode == "sign-failure" || mode == "replay-intent-sign-failure")) require(pq_sign.failed.load() == n, "actual leaf sign failure separate from no signer");
        else require(pq_sign.failed.load() == 0, "missing signer is not a crypto operation");
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
          require(value(Phase::Signed) == 0 && value(Phase::RestoredSigned) == n, "restored bytes separate from signing");
        } else if (mode == "replay-intent") {
          require(signatures == 1 && pq_sign.completed.load() == crypto_before + 1, "intent replay signs exactly once");
          require(value(Phase::SignedCommitted) == n && broadcasts == 0, "intent replay commits without live publish");
        }
        if (mode == "skip") {
          require(count(Action::Skip, Origin::Live, Phase::IntentCommitted) == n &&
                  count(Action::Skip, Origin::Live, Phase::SignedCommitted) == n &&
                  count(Action::Skip, Origin::Live, Phase::BroadcastEnqueued) == n, "skip obeys journal pipeline");
        }
      }
      if (replay) {
        std::uint64_t terminals = 0;
        for (const auto &counter : consensus_stats.replay_terminals[static_cast<std::size_t>(action)][static_cast<std::size_t>(origin) - 1])
          terminals += counter.load();
        require(terminals == n, "failed or successful replay has exactly one separate terminal");
      }
      for (std::size_t a = 0; a < action_count; ++a) {
        std::uint64_t terminals = 0;
        for (const auto &counter : consensus_stats.outcomes[a]) terminals += counter.load();
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
        auto operations = metrics::MetricFamily{.name = "tos_pq_operations_total", .type = "counter",
            .help = "Actual isolated production PQ operations.", .metrics = {}};
        for (auto [operation, stats] : {std::pair{"sign", &pq_sign}, std::pair{"verify", &pq_verify}}) {
          for (auto [result, counter] : {std::pair{"success", &stats->completed}, std::pair{"failure", &stats->failed}})
            operations.metrics.push_back({.suffix = "",
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
  if (argc != 2 && argc != 3) return 2;
  mode = argv[1];
  if (argc == 3) output_directory = argv[2];
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("c04-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {}
  return 1;
}
