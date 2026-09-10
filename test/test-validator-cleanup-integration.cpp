/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
// Manager-level integration acceptance for the validator consensus-DB cleanup.
//
// The real ValidatorManagerImpl is not constructible in a unit test (it needs live
// keyring/adnl/overlay actors and a DB seeded with an applied masterchain state). So
// this harness drives the SAME dispatch/continuation glue the manager uses -- the
// template free functions in validator-cleanup-dispatch.h -- over the REAL pieces: the
// real ValidatorCleanupManager adapter, the real ValidatorConsensusCleanupWorker actor
// doing real filesystem deletes, and a real RootDb/StateDb on a real td::actor
// Scheduler. The only thing the harness substitutes for the manager is the
// environment-specific head of try_validator_consensus_db_cleanup: the enable flag
// (true here; compile-time false in production) and the GC-snapshot oracles (injected
// here; built from a MasterchainState in production). Everything the integration test
// actually asserts about -- async completion, token threading, durable erase, and the
// retry-pacing / no-hot-loop property -- is the shared code, not a hand-rolled copy.
//
// Each scenario is falsifiable; the mutations that turn each red are named above it.
#include "validator/consensus/validator-cleanup-dispatch.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/consensus/validator-cleanup-worker.h"
#include "validator/consensus/db-path.h"
#include "validator/db/rootdb.hpp"
#include "validator/interfaces/db.h"
#include "validator/validator.h"

#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

const tos::ShardId kMasterShard = static_cast<tos::ShardId>(0x8000000000000000ULL);
const tos::ShardIdFull kShard{0, kMasterShard};
constexpr tos::CatchainSeqno kRecordCc = 7;  // dir-name catchain seqno baked into every fixture

tos::ValidatorSessionId make_session_id(unsigned char seed) {
  tos::ValidatorSessionId id;
  for (size_t i = 0; i < id.as_slice().size(); i++) {
    id.as_slice()[i] = static_cast<char>(seed + i * 7);
  }
  return id;
}

tos::Bits256 make_hash(unsigned char seed) {
  tos::Bits256 h;
  for (size_t i = 0; i < h.as_slice().size(); i++) {
    h.as_slice()[i] = static_cast<char>(seed + i * 3 + 1);
  }
  return h;
}

tos::BlockIdExt make_checkpoint(tos::BlockSeqno seqno) {
  return tos::BlockIdExt{tos::masterchainId, kMasterShard, seqno, make_hash(static_cast<unsigned char>(seqno)),
                         make_hash(static_cast<unsigned char>(seqno + 128))};
}

PendingValidatorConsensusDbCleanup make_record(unsigned char sid_seed, tos::BlockSeqno retire_seqno) {
  auto sid = make_session_id(sid_seed);
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  r.retirement_checkpoint = make_checkpoint(retire_seqno);
  r.dir_name = consensus_db_dir_name(kShard, kRecordCc, sid, td::Slice(""));
  return r;
}

void create_consensus_dir(const std::string& root, const std::string& dir_name) {
  auto db_dir = consensus_db_root(td::Slice{root}) + dir_name + "/db/";
  td::mkpath(db_dir).ensure();
  td::write_file(db_dir + "CURRENT", td::Slice{"x"}).ensure();
}

bool consensus_dir_exists(const std::string& root, const std::string& dir_name) {
  return td::stat(consensus_db_root(td::Slice{root}) + dir_name).is_ok();
}

#if !defined(_WIN32)
// Block removal of exactly ONE consensus dir by dropping write permission on it, so
// rmrf cannot unlink its contents while sibling dirs (and the consensus root) stay
// writable and delete normally. Returns the path so the caller can restore perms.
std::string block_dir_removal(const std::string& root, const std::string& dir_name) {
  auto dir = consensus_db_root(td::Slice{root}) + dir_name;
  ::chmod(dir.c_str(), 0555);
  return dir;
}
#endif

td::Ref<ValidatorManagerOptions> make_options() {
  auto opts = ValidatorManagerOptions::create(tos::BlockIdExt{}, tos::BlockIdExt{},
                                              /*allow_blockchain_init=*/false,
                                              /*sync_blocks_before=*/0.0,
                                              /*block_ttl=*/0.0,
                                              /*state_ttl=*/0.0,
                                              /*archive_ttl=*/0.0,
                                              /*key_proof_ttl=*/0.0,
                                              /*max_mempool_num=*/0,
                                              /*initial_sync_disabled=*/true);
  auto& w = opts.write();
  w.set_disable_rocksdb_stats(true);
  w.set_celldb_compress_depth(0);
  w.set_celldb_in_memory(false);
  w.set_celldb_v2(false);
  w.set_celldb_disable_bloom_filter(true);
  w.set_permanent_celldb(false);
  w.set_catchain_broadcast_speed_multiplier(1.0);
  return opts;
}

// The harness actor. It owns the real adapter + worker + a real Db id, and exposes the
// exact `Self` surface validator-cleanup-dispatch.h drives, so the shared glue runs
// here identically to the manager. The GC oracles and the enable flag are injected.
class CleanupHarness : public td::actor::Actor {
 public:
  CleanupHarness(td::actor::ActorId<Db> db, std::string db_root, tos::BlockIdExt gc_checkpoint,
                 tos::CatchainSeqno gc_shard_cc, std::set<tos::ValidatorSessionId> live, size_t dispatch_budget,
                 size_t scan_budget, size_t max_outstanding)
      : db_(db)
      , db_root_(std::move(db_root))
      , gc_checkpoint_(gc_checkpoint)
      , gc_shard_cc_(gc_shard_cc)
      , live_(std::move(live))
      , dispatch_budget_(dispatch_budget)
      , scan_budget_(scan_budget)
      , max_outstanding_(max_outstanding) {
  }

  // --- the Self surface consumed by the shared dispatch glue -------------------
  void try_validator_consensus_db_cleanup() {
    if (!enabled_) {
      return;
    }
    ++pass_count_;
    auto ancestor = [](const tos::BlockIdExt&) { return true; };
    auto cc = [this](tos::ShardIdFull) -> std::optional<tos::CatchainSeqno> { return gc_shard_cc_; };
    auto is_live = [this](const tos::ValidatorSessionId& s) { return live_.count(s) > 0; };
    auto reserved = adapter_.begin_eligible_deletes(gc_checkpoint_, ancestor, cc, is_live, dispatch_budget_,
                                                    scan_budget_, max_outstanding_);
    for (const auto& item : reserved) {
      ++attempt_count_[item.record.session_id];
    }
    dispatch_reserved_validator_deletes(actor_id(this), worker_, db_root_, reserved);
  }
  void validator_cleanup_delete_done(tos::ValidatorSessionId session, td::uint64 generation, td::uint64 attempt_id,
                                     bool confirmed_gone) {
    ++completed_delete_count_;  // a worker delete attempt actually finished (gone or not)
    complete_validator_delete(actor_id(this), adapter_, db_, session, generation, attempt_id, confirmed_gone);
  }
  void validator_cleanup_erase_acked(tos::ValidatorSessionId session, td::uint64 generation, td::uint64 attempt_id) {
    ++erase_ack_count_;
    acknowledge_validator_erase(this, adapter_, session, generation, attempt_id);
  }

  // --- control surface (driven from the test thread via ask/send) --------------
  void set_enabled(bool e) {
    enabled_ = e;
  }
  void load_startup_record(PendingValidatorConsensusDbCleanup record) {
    adapter_.on_loaded_at_startup(std::move(record));
  }
  void group_created(tos::ValidatorSessionId session) {
    adapter_.on_group_created(session);
  }
  void group_retired(PendingValidatorConsensusDbCleanup record, td::Promise<td::uint64> promise) {
    promise.set_value(adapter_.on_group_retired(std::move(record)));
  }
  void close_confirmed(tos::ValidatorSessionId session, td::uint64 generation) {
    adapter_.on_close_confirmed(session, generation);
  }
  // Inject a completion directly, as a stale/duplicate worker callback would arrive.
  // Synchronous: the promise resolves only AFTER validator_cleanup_delete_done has run,
  // so any (wrongly-dispatched) erase has already been enqueued to the Db by the time
  // the caller proceeds -- a subsequent Db read is then ordered after it (FIFO on the
  // Db mailbox), making the stale-rejection assertion race-free.
  void inject_delete_done(tos::ValidatorSessionId session, td::uint64 generation, td::uint64 attempt_id, bool gone,
                          td::Promise<td::Unit> promise) {
    validator_cleanup_delete_done(session, generation, attempt_id, gone);
    promise.set_value(td::Unit{});
  }
  void is_delete_in_flight(tos::ValidatorSessionId session, td::Promise<bool> promise) {
    promise.set_value(adapter_.is_delete_in_flight(session));
  }
  void attempt_count(tos::ValidatorSessionId session, td::Promise<td::uint64> promise) {
    auto it = attempt_count_.find(session);
    promise.set_value(it == attempt_count_.end() ? td::uint64{0} : it->second);
  }
  void pass_count(td::Promise<td::uint64> promise) {
    promise.set_value(td::uint64{pass_count_});
  }
  void erase_ack_count(td::Promise<td::uint64> promise) {
    promise.set_value(td::uint64{erase_ack_count_});
  }
  void completed_delete_count(td::Promise<td::uint64> promise) {
    promise.set_value(td::uint64{completed_delete_count_});
  }

 private:
  ValidatorCleanupManager adapter_;
  td::actor::ActorOwn<ValidatorConsensusCleanupWorker> worker_;
  td::actor::ActorId<Db> db_;
  std::string db_root_;
  tos::BlockIdExt gc_checkpoint_;
  tos::CatchainSeqno gc_shard_cc_;
  std::set<tos::ValidatorSessionId> live_;
  size_t dispatch_budget_;
  size_t scan_budget_;
  size_t max_outstanding_;
  bool enabled_ = true;
  td::uint64 pass_count_ = 0;
  td::uint64 erase_ack_count_ = 0;
  td::uint64 completed_delete_count_ = 0;
  std::map<tos::ValidatorSessionId, td::uint64> attempt_count_;
};

// Owns the scheduler, a real RootDb (as Db), and the harness actor. Mirrors the drive
// pattern of test-celldb-actor-restart.cpp (Scheduler, run_in_context, ask, run_until).
class HarnessSession {
 public:
  HarnessSession(std::string db_root, tos::BlockIdExt gc_checkpoint, tos::CatchainSeqno gc_shard_cc,
                 std::set<tos::ValidatorSessionId> live, size_t dispatch_budget, size_t scan_budget,
                 size_t max_outstanding)
      : db_root_(std::move(db_root)), scheduler_({1}) {
    auto opts = make_options();
    scheduler_.run_in_context([&] {
      // Construct RootDb directly (as its Db base) rather than via create_db_actor, so
      // the test links only validator-db, not the full manager impl. The pending-
      // cleanup DB ops forward to StateDb and never call back into the (empty) manager.
      db_ = td::actor::create_actor<RootDb>("db", td::actor::ActorId<ValidatorManager>{}, db_root_, opts);
      harness_ = td::actor::create_actor<CleanupHarness>("cleanup-harness", db_.get(), db_root_, gc_checkpoint,
                                                         gc_shard_cc, std::move(live), dispatch_budget, scan_budget,
                                                         max_outstanding);
    });
  }
  HarnessSession(const HarnessSession&) = delete;
  HarnessSession& operator=(const HarnessSession&) = delete;
  ~HarnessSession() {
    stop();
  }

  void persist_retirement(const std::vector<PendingValidatorConsensusDbCleanup>& records) {
    ask<td::Unit>([&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(db_.get(), &Db::persist_validator_retirement, std::vector<tos::ValidatorSessionId>{},
                              records, promise.wrap([](td::Unit) { return td::Unit{}; }));
    });
  }
  std::vector<PendingValidatorConsensusDbCleanup> load_pending() {
    return ask<std::vector<PendingValidatorConsensusDbCleanup>>([&](auto promise) {
      td::actor::send_closure(db_.get(), &Db::get_pending_validator_consensus_db_cleanup, std::move(promise));
    });
  }
  void load_startup_record(PendingValidatorConsensusDbCleanup record) {
    run_in_ctx([&] { td::actor::send_closure(harness_.get(), &CleanupHarness::load_startup_record, record); });
  }
  td::uint64 group_retired(PendingValidatorConsensusDbCleanup record) {
    return ask<td::uint64>([&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::group_retired, record, std::move(promise));
    });
  }
  void group_created(tos::ValidatorSessionId session) {
    run_in_ctx([&] { td::actor::send_closure(harness_.get(), &CleanupHarness::group_created, session); });
  }
  void close_confirmed(tos::ValidatorSessionId session, td::uint64 generation) {
    run_in_ctx([&] { td::actor::send_closure(harness_.get(), &CleanupHarness::close_confirmed, session, generation); });
  }
  void inject_delete_done(tos::ValidatorSessionId session, td::uint64 generation, td::uint64 attempt_id, bool gone) {
    ask<td::Unit>([&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::inject_delete_done, session, generation, attempt_id,
                              gone, std::move(promise));
    });
  }
  bool is_delete_in_flight(tos::ValidatorSessionId session) {
    return ask<bool>([&](td::Promise<bool> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::is_delete_in_flight, session, std::move(promise));
    });
  }
  td::uint64 attempt_count(tos::ValidatorSessionId session) {
    return ask<td::uint64>([&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::attempt_count, session, std::move(promise));
    });
  }
  td::uint64 pass_count() {
    return ask<td::uint64>(
        [&](td::Promise<td::uint64> promise) { td::actor::send_closure(harness_.get(), &CleanupHarness::pass_count, std::move(promise)); });
  }
  td::uint64 erase_ack_count() {
    return ask<td::uint64>([&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::erase_ack_count, std::move(promise));
    });
  }
  td::uint64 completed_delete_count() {
    return ask<td::uint64>([&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(harness_.get(), &CleanupHarness::completed_delete_count, std::move(promise));
    });
  }

  // Send a single cleanup pass. Subsequent passes re-trigger themselves via erase-ack.
  void fire_cleanup_pass() {
    run_in_ctx([&] { td::actor::send_closure(harness_.get(), &CleanupHarness::try_validator_consensus_db_cleanup); });
  }

  // Run the scheduler for approximately `seconds` of wall-clock time regardless of
  // whether it reports idle. (The real RootDb keeps background actors alive, so "idle"
  // never occurs; progress is asserted via scenario state, and a hot loop shows up as
  // an unbounded attempt_count after a fixed drive window, not as non-idleness.)
  void run_for(double seconds) {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past()) {
      scheduler_.run(0.01);
    }
  }

  // Run until `cond()` holds (polled between scheduler bursts) or `timeout` elapses.
  // Returns whether the condition was met.
  bool wait_until(const std::function<bool()>& cond, double timeout) {
    auto deadline = td::Timestamp::in(timeout);
    while (!deadline.is_in_past()) {
      if (cond()) {
        return true;
      }
      scheduler_.run(0.02);
    }
    return cond();
  }

  void stop() {
    if (stopped_) {
      return;
    }
    stopped_ = true;
    scheduler_.run_in_context([&] {
      harness_.reset();
      db_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
  }

 private:
  // Enqueue an actor message. The harness actor's mailbox is FIFO and single-threaded,
  // so ordering is preserved; the message is processed by the next scheduler drive
  // (an ask(), wait_until(), or run_for()). We deliberately do NOT spin the scheduler
  // here: the real RootDb keeps background actors runnable, so a "drive until idle"
  // loop would never terminate.
  void run_in_ctx(const std::function<void()>& f) {
    scheduler_.run_in_context([&] { f(); });
  }
  template <class T, class Send>
  T ask(Send send) {
    // The promise may resolve on a scheduler CPU worker thread (Scheduler({1}) spawns
    // one), while this method polls on the test thread -- so the result handoff is
    // synchronized with a mutex rather than a bare optional.
    std::mutex mu;
    std::optional<td::Result<T>> result;
    auto ready = [&] {
      std::lock_guard<std::mutex> lk(mu);
      return result.has_value();
    };
    scheduler_.run_in_context([&] {
      auto promise = td::PromiseCreator::lambda([&](td::Result<T> r) mutable {
        std::lock_guard<std::mutex> lk(mu);
        result.emplace(std::move(r));
      });
      send(std::move(promise));
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!ready()) {
      LOG_CHECK(!deadline.is_in_past()) << "timed out waiting for harness promise";
      if (!scheduler_.run(0.05) && !ready()) {
        LOG(FATAL) << "scheduler stopped before harness promise resolved";
      }
    }
    std::lock_guard<std::mutex> lk(mu);
    return result->move_as_ok();
  }

  std::string db_root_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<Db> db_;  // holds a RootDb, upcast to its Db base
  td::actor::ActorOwn<CleanupHarness> harness_;
  bool stopped_ = false;
};

std::string temp_root(const char* suffix) {
  auto p = PSTRING() << "tmp-test-validator-cleanup-integration-" << suffix << "-" << td::Random::fast_uint32();
  td::rmrf(p).ignore();
  td::mkpath(p + "/").ensure();
  return p;
}

// ---------------------------------------------------------------------------------
// Scenario 1: happy drain end-to-end. Records persisted to a REAL RootDb are loaded
// back, all eligible dirs are deleted by the real worker, and every record is erased
// from the DB; the scheduler reaches idle.
// Falsifying mutations: break dispatch_reserved_validator_deletes (dirs survive);
// break the erase dispatch in complete_validator_delete (records survive in DB).
void scenario_happy_drain() {
  LOG(INFO) << "=== scenario_happy_drain ===";
  auto root = temp_root("happy");
  const size_t N = 5;
  std::vector<PendingValidatorConsensusDbCleanup> records;
  for (size_t i = 0; i < N; i++) {
    auto r = make_record(static_cast<unsigned char>(10 + i), 100);
    create_consensus_dir(root, r.dir_name);
    records.push_back(r);
  }

  HarnessSession s(root, make_checkpoint(200), kRecordCc + 1, /*live=*/{}, /*dispatch=*/16, /*scan=*/256,
                   /*outstanding=*/64);
  s.persist_retirement(records);
  // Load the durable records back through the real DB path and feed the adapter.
  auto loaded = s.load_pending();
  LOG_CHECK(loaded.size() == N) << "expected " << N << " persisted records, got " << loaded.size();
  for (auto& r : loaded) {
    s.load_startup_record(r);
  }

  s.fire_cleanup_pass();
  bool done = s.wait_until([&] { return s.erase_ack_count() >= N; }, 30.0);
  LOG_CHECK(done) << "happy drain did not erase all " << N << " records (acked " << s.erase_ack_count() << ")";

  for (const auto& r : records) {
    if (consensus_dir_exists(root, r.dir_name)) {
      LOG(FATAL) << "dir not deleted in happy drain: " << r.dir_name;
    }
  }
  auto remaining = s.load_pending();
  LOG_CHECK(remaining.empty()) << "records not erased from DB after drain: " << remaining.size();
  s.stop();
  td::rmrf(root).ignore();
}

// ---------------------------------------------------------------------------------
// Scenario 2: a stale/duplicate delete completion, injected as a worker callback would
// arrive when the entry is NOT in flight, must not erase the record or delete the dir;
// a correctly-tokened drive then cleans it up.
//
// What this PROVES: the glue routes every completion through the adapter's rejection
// (complete_validator_delete -> on_delete_completed) instead of erasing directly. The
// falsifying mutation is the glue bypass (erase without consulting the adapter): the
// stale completion then erases the record and the assert below fires.
//
// What this does NOT prove: that the generation check specifically is live. The
// injected completion here also mismatches on STATE (the entry is Pending, not
// Deleting), so the adapter's compound guard rejects it even with the generation check
// removed. A precise, single-dimension test of each token (generation, attempt_id)
// needs the entry held in Deleting -- that belongs to the controllable/slow-worker
// acceptance and to the pure adapter tests (test-validator-cleanup), not here.
void scenario_stale_completion_rejected() {
  LOG(INFO) << "=== scenario_stale_completion_rejected ===";
  auto root = temp_root("stale");
  auto r = make_record(42, 100);
  create_consensus_dir(root, r.dir_name);

  HarnessSession s(root, make_checkpoint(200), kRecordCc + 1, /*live=*/{}, 16, 256, 64);
  s.persist_retirement({r});

  // Drive through a real incarnation so there is a genuine generation to be stale to.
  s.group_created(r.session_id);
  auto gen = s.group_retired(r);
  s.close_confirmed(r.session_id, gen);

  // A stale completion for a DIFFERENT (older) generation: must be ignored. The entry
  // is still Pending (no delete dispatched yet), so any generation mismatch is
  // rejected inside on_delete_completed; assert nothing was erased or deleted.
  // inject_delete_done is synchronous: it returns only after the harness processed the
  // completion, so any wrongly-dispatched erase is already enqueued on the Db mailbox.
  // load_pending's read, enqueued afterwards, is therefore ordered strictly after it.
  s.inject_delete_done(r.session_id, gen + 999, /*attempt_id=*/1, /*gone=*/true);
  auto after_stale = s.load_pending();
  LOG_CHECK(after_stale.size() == 1) << "stale completion erased the durable record";
  LOG_CHECK(consensus_dir_exists(root, r.dir_name)) << "stale completion deleted the dir";

  // A correctly-tokened drive cleans it up for real.
  s.fire_cleanup_pass();
  bool done = s.wait_until([&] { return s.erase_ack_count() >= 1; }, 30.0);
  LOG_CHECK(done) << "valid drive did not erase the record after stale rejection";
  LOG_CHECK(!consensus_dir_exists(root, r.dir_name)) << "dir not deleted by the valid drive";
  LOG_CHECK(s.load_pending().empty()) << "record not erased by the valid drive";
  s.stop();
  td::rmrf(root).ignore();
}

#if !defined(_WIN32)
// ---------------------------------------------------------------------------------
// Scenario 3a: a single PERMANENTLY failing delete must NOT spin. With no successes
// and no external trigger, the completion path must not re-dispatch itself: the
// scheduler reaches idle and the directory was attempted exactly once.
// Falsifying mutation: make complete_validator_delete re-trigger unconditionally ->
// the failing dir is re-dispatched forever, the scheduler never idles, drive times out.
void scenario_persistent_failure_no_hot_loop() {
  LOG(INFO) << "=== scenario_persistent_failure_no_hot_loop ===";
  if (::geteuid() == 0) {
    LOG(WARNING) << "skipping: running as root bypasses directory permissions";
    return;
  }
  auto root = temp_root("failloop");
  auto r = make_record(77, 100);
  create_consensus_dir(root, r.dir_name);
  auto blocked = block_dir_removal(root, r.dir_name);

  {
    HarnessSession s(root, make_checkpoint(200), kRecordCc + 1, /*live=*/{}, 16, 256, 64);
    s.persist_retirement({r});
    s.load_startup_record(r);

    // Fire one pass and wait for the worker to actually FINISH the (failed) delete --
    // not just reserve it. With perms still blocked, drive an extra window so an
    // unconditional-retrigger regression has time to rack up further attempts, then
    // confirm the entry settled (not in flight) before touching perms.
    s.fire_cleanup_pass();
    bool completed = s.wait_until([&] { return s.completed_delete_count() >= 1; }, 30.0);
    LOG_CHECK(completed) << "the failing delete never completed";
    s.run_for(1.5);
    bool settled = s.wait_until([&] { return !s.is_delete_in_flight(r.session_id); }, 10.0);
    auto attempts = s.attempt_count(r.session_id);
    auto completions = s.completed_delete_count();
    auto acks = s.erase_ack_count();
    ::chmod(blocked.c_str(), 0755);  // restore for teardown AFTER all observations are taken
    LOG_CHECK(settled) << "the failing entry was still in flight after settling (re-dispatch loop)";
    LOG_CHECK(consensus_dir_exists(root, r.dir_name)) << "the blocked dir was unexpectedly deleted";
    LOG_CHECK(attempts == 1) << "a failing delete was retried without an external trigger: " << attempts;
    LOG_CHECK(completions == 1) << "a failing delete completed more than once (re-dispatched): " << completions;
    LOG_CHECK(acks == 0) << "a failing delete erased a record";
    s.stop();
  }
  td::rmrf(root).ignore();
}

// ---------------------------------------------------------------------------------
// Scenario 3b: one permanently-failing dir mixed with a healthy backlog LARGER than
// the dispatch budget. The healthy ones must all drain (each success re-triggers a
// pass), the failing one must survive, its attempts must be FINITE (bounded by the
// number of successes, since the backlog strictly shrinks), and the scheduler must
// reach idle -- not spin.
// Falsifying mutations: remove the erase-ack re-trigger in acknowledge_validator_erase
// -> the backlog beyond the dispatch budget never drains (healthy dirs survive);
// make complete_validator_delete re-trigger unconditionally -> the failing dir spins,
// drive times out.
void scenario_mixed_failure_bounded_retries() {
  LOG(INFO) << "=== scenario_mixed_failure_bounded_retries ===";
  if (::geteuid() == 0) {
    LOG(WARNING) << "skipping: running as root bypasses directory permissions";
    return;
  }
  auto root = temp_root("mixed");
  const size_t kHealthy = 20;  // > dispatch budget below, so draining needs re-triggers
  std::vector<PendingValidatorConsensusDbCleanup> healthy;
  for (size_t i = 0; i < kHealthy; i++) {
    auto r = make_record(static_cast<unsigned char>(100 + i), 100);
    create_consensus_dir(root, r.dir_name);
    healthy.push_back(r);
  }
  auto fail = make_record(250, 100);
  create_consensus_dir(root, fail.dir_name);
  auto blocked = block_dir_removal(root, fail.dir_name);

  {
    HarnessSession s(root, make_checkpoint(200), kRecordCc + 1, /*live=*/{}, /*dispatch=*/8, /*scan=*/256,
                     /*outstanding=*/64);
    std::vector<PendingValidatorConsensusDbCleanup> all = healthy;
    all.push_back(fail);
    s.persist_retirement(all);
    for (auto& r : all) {
      s.load_startup_record(r);
    }

    // Drain the healthy backlog (each success re-triggers a pass), then drive a short
    // extra window so an unconditional-retrigger regression on the failing dir has
    // time to rack up unbounded attempts before we check the bound. Require the failing
    // entry to SETTLE (not in flight) before touching perms, so a delayed worker can
    // never succeed against a restored directory and corrupt the assertions.
    s.fire_cleanup_pass();
    bool drained = s.wait_until([&] { return s.erase_ack_count() >= kHealthy; }, 30.0);
    s.run_for(1.5);
    bool settled = s.wait_until([&] { return !s.is_delete_in_flight(fail.session_id); }, 10.0);
    auto attempts = s.attempt_count(fail.session_id);
    ::chmod(blocked.c_str(), 0755);
    LOG_CHECK(drained) << "healthy backlog did not fully drain (acked " << s.erase_ack_count() << " of " << kHealthy
                       << ")";
    LOG_CHECK(settled) << "the failing entry was still in flight after settling (re-dispatch loop)";

    for (const auto& r : healthy) {
      if (consensus_dir_exists(root, r.dir_name)) {
        LOG(FATAL) << "healthy dir not drained in mixed scenario: " << r.dir_name;
      }
    }
    LOG_CHECK(consensus_dir_exists(root, fail.dir_name)) << "the blocked dir was unexpectedly deleted";
    // Bounded by successes + the initial pass; never unbounded. (<= healthy + 2 is a
    // generous ceiling; an unconditional-retrigger regression would blow far past it
    // AND fail the quiescence check above.)
    LOG_CHECK(attempts <= kHealthy + 2) << "failing dir retried too many times: " << attempts;
    LOG_CHECK(attempts >= 1) << "failing dir was never attempted";
    LOG(INFO) << "mixed scenario: failing dir attempted " << attempts << " times over " << s.pass_count() << " passes";
    s.stop();
  }
  td::rmrf(root).ignore();
}
#endif  // !_WIN32

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);
  scenario_happy_drain();
  scenario_stale_completion_rejected();

  // The two permission-based failure scenarios need an unprivileged POSIX user: they
  // are SKIPPED as root (directory permissions are bypassed) and not compiled on
  // Windows. Report run identity and per-scenario executed/skipped explicitly, so a
  // green exit on root/Windows is never mistaken for full four-scenario coverage when
  // this log is kept as enablement evidence.
  bool ran_failure_scenarios = false;
#if !defined(_WIN32)
  if (::geteuid() == 0) {
    LOG(WARNING) << "running as root (euid 0): SKIPPED persistent-failure and mixed-failure scenarios";
  } else {
    scenario_persistent_failure_no_hot_loop();
    scenario_mixed_failure_bounded_retries();
    ran_failure_scenarios = true;
  }
#else
  LOG(WARNING) << "Windows build: persistent-failure and mixed-failure scenarios are not compiled";
#endif

  LOG(INFO) << "test-validator-cleanup-integration: executed happy_drain + stale_completion_rejected; "
            << (ran_failure_scenarios ? "AND persistent-failure + mixed-failure (4/4 scenarios)"
                                      : "persistent-failure + mixed-failure SKIPPED (2/4 scenarios)");
  return 0;
}
