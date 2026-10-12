/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The startup inventory of orphaned validator session directories, run through the
// production glue (validator/consensus/startup-orphan-reconcile.h) against real
// directories, a real RootDb/StateDb and the real cleanup manager. The harness actor
// supplies only the owner's state: which sessions are live, the destroyed-session set,
// and the current catchain seqno per shard.

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#include "common/checksum.h"
#include "td/actor/actor.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator/consensus/db-path.h"
#include "validator/consensus/startup-orphan-reconcile.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/db/rootdb.hpp"
#include "validator/interfaces/db.h"
#include "validator/validator.h"

namespace tos::validator {
namespace {

using consensus::PendingValidatorConsensusDbCleanup;
using consensus::StartupOrphanSummary;

td::Ref<ValidatorManagerOptions> make_options() {
  auto opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}, false, 0.0, 0.0, 0.0, 0.0, 0.0, 0, true);
  auto& w = opts.write();
  w.set_disable_rocksdb_stats(true);
  w.set_celldb_compress_depth(0);
  w.set_celldb_in_memory(false);
  w.set_celldb_v2(false);
  w.set_celldb_disable_bloom_filter(true);
  w.set_permanent_celldb(false);
  return opts;
}

ValidatorSessionId session(int n) {
  return td::sha256_bits256(PSLICE() << "startup-orphan-session-" << n);
}

const ShardIdFull kMaster{masterchainId, shardIdAll};
const ShardIdFull kBase{basechainId, shardIdAll};
const ShardIdFull kLeft{basechainId, shard_child(shardIdAll, true)};

BlockIdExt checkpoint(BlockSeqno seqno) {
  return BlockIdExt{masterchainId, shardIdAll, seqno, td::sha256_bits256(PSLICE() << "root" << seqno),
                    td::sha256_bits256(PSLICE() << "file" << seqno)};
}

std::string dir_name(int n, ShardIdFull shard, CatchainSeqno cc) {
  return consensus::consensus_db_dir_name(shard, cc, session(n), td::Slice(""));
}

class Harness;

// The test-controlled side of the owner.
struct Owner {
  std::set<ValidatorSessionId> live;
  std::set<ValidatorSessionId> destroyed;
  std::map<ShardIdFull, CatchainSeqno> current_cc;
  std::set<ValidatorSessionId> failing_reads;
  // Runs inside the harness actor during the point read of one session.
  std::map<ValidatorSessionId, std::function<void(Harness&)>> during_read;
  // Runs inside the harness actor right after the inventory's write was issued.
  std::function<void(Harness&)> after_inventory_write;
  BlockIdExt retirement = checkpoint(100);
};

class Harness : public td::actor::Actor {
 public:
  Harness(td::actor::ActorId<Db> db, std::string root, Owner owner)
      : db_(db), root_(std::move(root)), owner_(std::move(owner)) {
  }

  // --- the owner surface the glue drives ---
  consensus::StartupOrphanReconcile& startup_orphan_reconcile() {
    return reconcile_;
  }
  bool startup_orphan_session_live(const ValidatorSessionId& s) {
    return owner_.live.count(s) > 0;
  }
  std::set<ValidatorSessionId>& startup_orphan_destroyed_sessions() {
    return owner_.destroyed;
  }
  consensus::ValidatorCleanupManager& startup_orphan_cleanup_manager() {
    return cleanup_;
  }
  std::optional<CatchainSeqno> startup_orphan_current_catchain_seqno(ShardIdFull shard) {
    auto it = owner_.current_cc.find(shard);
    if (it == owner_.current_cc.end()) {
      return std::nullopt;
    }
    return it->second;
  }
  BlockIdExt startup_orphan_retirement_checkpoint() {
    return owner_.retirement;
  }
  void startup_orphan_read_record(ValidatorSessionId s,
                                  td::Promise<std::optional<PendingValidatorConsensusDbCleanup>> promise) {
    if (auto it = owner_.during_read.find(s); it != owner_.during_read.end()) {
      it->second(*this);
    }
    if (owner_.failing_reads.count(s) > 0) {
      promise.set_error(td::Status::Error("injected point read failure"));
      return;
    }
    td::actor::send_closure(db_, &Db::get_pending_validator_consensus_db_cleanup_record, s, std::move(promise));
  }
  void startup_orphan_persist(std::vector<ValidatorSessionId> destroyed,
                              std::vector<PendingValidatorConsensusDbCleanup> records, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::persist_validator_retirement, std::move(destroyed), std::move(records),
                            std::move(promise));
    if (owner_.after_inventory_write) {
      auto f = std::move(owner_.after_inventory_write);
      owner_.after_inventory_write = {};
      f(*this);
    }
  }
  void startup_orphan_point_read(td::uint64 token, consensus::StartupOrphanCandidate candidate,
                                 td::Result<std::optional<PendingValidatorConsensusDbCleanup>> record) {
    consensus::handle_startup_orphan_point_read(this, actor_id(this), token, std::move(candidate),
                                                std::move(record));
  }
  void startup_orphan_persisted(td::uint64 token, std::vector<std::pair<ValidatorSessionId, td::uint64>> retired,
                                td::Result<td::Unit> result) {
    consensus::handle_startup_orphans_persisted(this, token, std::move(retired), std::move(result));
  }
  void startup_orphan_reconcile_finished(StartupOrphanSummary summary) {
    if (done_) {
      done_.set_value(std::move(summary));
    }
  }

  // --- test controls ---
  void run(td::Promise<StartupOrphanSummary> done) {
    done_ = std::move(done);
    consensus::begin_startup_orphan_reconcile(this, actor_id(this), root_);
  }
  void destroyed_now(td::Promise<std::set<ValidatorSessionId>> promise) {
    promise.set_value(std::set<ValidatorSessionId>(owner_.destroyed));
  }
  void open_retirements(td::Promise<size_t> promise) {
    promise.set_value(cleanup_.open_retirement_count());
  }
  // The retirement persistence of the group update, issued the way the manager issues
  // it: the retiring session enters the in-memory set first, then the complete set is
  // written together with its record.
  void retire_group(int n, ShardIdFull shard, CatchainSeqno cc) {
    auto record = consensus::make_validator_cleanup_record(session(n), shard, cc, owner_.retirement);
    cleanup_.on_group_retired(record);
    owner_.destroyed.insert(session(n));
    td::actor::send_closure(db_, &Db::persist_validator_retirement,
                            std::vector<ValidatorSessionId>(owner_.destroyed.begin(), owner_.destroyed.end()),
                            std::vector<PendingValidatorConsensusDbCleanup>{record}, [](td::Result<td::Unit> R) {
                              R.ensure();
                            });
  }
  // An init-block rotation the way the manager handles it: the snapshot of the set is
  // taken at the rotation, and only when the init-block write is acknowledged are the
  // snapshot's sessions pruned and the complete set written again.
  void take_rotation_snapshot() {
    rotation_snapshot_ = owner_.destroyed;
  }
  void acknowledge_rotation(td::Promise<td::Unit> promise) {
    for (auto& s : rotation_snapshot_) {
      owner_.destroyed.erase(s);
    }
    td::actor::send_closure(db_, &Db::update_destroyed_validator_sessions,
                            std::vector<ValidatorSessionId>(owner_.destroyed.begin(), owner_.destroyed.end()),
                            std::move(promise));
  }
  // One pass of the real cleanup manager at the anchor `gc`, with the deletion oracles
  // bound to it; reports the sessions it reserved for deletion.
  void cleanup_pass(BlockIdExt gc, CatchainSeqno gc_cc, td::Promise<std::vector<ValidatorSessionId>> promise) {
    auto request = cleanup_.begin_tick(gc);
    if (!request) {
      promise.set_error(td::Status::Error("cleanup pass did not start"));
      return;
    }
    pass_promise_ = std::move(promise);
    pass_gc_ = gc;
    pass_gc_cc_ = gc_cc;
    reserved_.clear();
    td::actor::send_closure(db_, &Db::get_pending_validator_consensus_db_cleanup_page, request->after_key,
                            request->max_keys,
                            [self = actor_id(this), request = *request](td::Result<consensus::ValidatorCleanupPage> R) {
                              td::actor::send_closure(self, &Harness::cleanup_page, request, std::move(R));
                            });
  }
  void cleanup_page(consensus::ValidatorCleanupPageRequest request, td::Result<consensus::ValidatorCleanupPage> R) {
    if (R.is_error()) {
      pass_promise_.set_error(R.move_as_error());
      return;
    }
    auto candidates = cleanup_.on_page(request, R.ok(), oracles());
    pending_points_ = candidates.size();
    if (pending_points_ == 0) {
      finish_pass();
      return;
    }
    for (auto& c : candidates) {
      td::actor::send_closure(
          db_, &Db::get_pending_validator_consensus_db_cleanup_record, c.session_id,
          [self = actor_id(this), token = request.token,
           c](td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current) {
            td::actor::send_closure(self, &Harness::cleanup_point, token, c, std::move(current));
          });
    }
  }
  void cleanup_point(td::uint64 token, PendingValidatorConsensusDbCleanup candidate,
                     td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current) {
    auto reserved = cleanup_.on_point_read_result(token, candidate, current, [this](const ValidatorSessionId& s) {
      return owner_.live.count(s) > 0;
    });
    if (reserved) {
      reserved_.push_back(reserved->record.session_id);
    }
    if (--pending_points_ == 0) {
      finish_pass();
    }
  }
  // Reserve `n` for deletion through the real cleanup manager, as a concurrent tick
  // would: retire it, confirm its close, and let a pass with permissive oracles take it.
  void reserve_now(int n, ShardIdFull shard, CatchainSeqno cc) {
    auto record = consensus::make_validator_cleanup_record(session(n), shard, cc, owner_.retirement);
    auto generation = cleanup_.on_group_retired(record);
    cleanup_.on_close_confirmed(session(n), generation);
    auto request = cleanup_.begin_tick(owner_.retirement);
    CHECK(request);
    consensus::ValidatorCleanupPage page;
    page.records.push_back(record);
    page.reached_end = true;
    consensus::ValidatorCleanupOracles o;
    o.gc = owner_.retirement;
    o.ancestor_or_equal_of_gc = [](const BlockIdExt&) { return true; };
    o.gc_shard_catchain_seqno = [](ShardIdFull) -> std::optional<CatchainSeqno> { return 1u << 30; };
    o.is_live = [](const ValidatorSessionId&) { return false; };
    auto candidates = cleanup_.on_page(*request, page, o);
    CHECK(candidates.size() == 1);
    auto reserved = cleanup_.on_point_read_result(
        request->token, record, td::Result<std::optional<PendingValidatorConsensusDbCleanup>>(record),
        [](const ValidatorSessionId&) { return false; });
    CHECK(reserved.has_value());
    cleanup_.end_pass();
    CHECK(cleanup_.is_delete_in_flight(session(n)));
  }

 private:
  consensus::ValidatorCleanupOracles oracles() {
    consensus::ValidatorCleanupOracles o;
    o.gc = pass_gc_;
    o.ancestor_or_equal_of_gc = [gc = pass_gc_](const BlockIdExt& retirement) {
      return retirement.seqno() <= gc.seqno();
    };
    o.gc_shard_catchain_seqno = [cc = pass_gc_cc_](ShardIdFull) -> std::optional<CatchainSeqno> { return cc; };
    o.is_live = [this](const ValidatorSessionId& s) { return owner_.live.count(s) > 0; };
    return o;
  }
  void finish_pass() {
    cleanup_.end_pass();
    pass_promise_.set_value(std::vector<ValidatorSessionId>(reserved_));
  }

  td::actor::ActorId<Db> db_;
  std::string root_;
  Owner owner_;
  consensus::StartupOrphanReconcile reconcile_;
  consensus::ValidatorCleanupManager cleanup_;
  td::Promise<StartupOrphanSummary> done_;
  std::set<ValidatorSessionId> rotation_snapshot_;
  td::Promise<std::vector<ValidatorSessionId>> pass_promise_;
  BlockIdExt pass_gc_;
  CatchainSeqno pass_gc_cc_ = 0;
  size_t pending_points_ = 0;
  std::vector<ValidatorSessionId> reserved_;
};

class Session {
 public:
  explicit Session(std::string root) : root_(std::move(root)), scheduler_({1}) {
    scheduler_.run_in_context([&] {
      db_ = td::actor::create_actor<RootDb>("db", td::actor::ActorId<ValidatorManager>{}, root_, make_options());
    });
  }
  ~Session() {
    scheduler_.run_in_context([&] {
      harness_.reset();
      db_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
  }
  // A fresh owner, as after a restart; the durable state stays.
  void start(Owner owner) {
    scheduler_.run_in_context([&] {
      harness_.reset();
      harness_ = td::actor::create_actor<Harness>("orphan-harness", db_.get(), root_, std::move(owner));
    });
  }
  template <class T, class Send>
  T ask(Send send) {
    std::mutex mu;
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context([&] {
      send(td::PromiseCreator::lambda([&](td::Result<T> r) {
        std::lock_guard<std::mutex> lk(mu);
        result.emplace(std::move(r));
      }));
    });
    auto deadline = td::Timestamp::in(300.0);
    while (true) {
      {
        std::lock_guard<std::mutex> lk(mu);
        if (result) {
          break;
        }
      }
      LOG_CHECK(!deadline.is_in_past()) << "timed out waiting for the harness";
      scheduler_.run(0.01);
    }
    return result->move_as_ok();
  }
  StartupOrphanSummary reconcile() {
    return ask<StartupOrphanSummary>(
        [&](td::Promise<StartupOrphanSummary> p) { td::actor::send_closure(harness_, &Harness::run, std::move(p)); });
  }
  std::optional<PendingValidatorConsensusDbCleanup> record(int n) {
    return ask<std::optional<PendingValidatorConsensusDbCleanup>>(
        [&](td::Promise<std::optional<PendingValidatorConsensusDbCleanup>> p) {
          td::actor::send_closure(db_, &Db::get_pending_validator_consensus_db_cleanup_record, session(n),
                                  std::move(p));
        });
  }
  std::set<ValidatorSessionId> durable_destroyed() {
    auto v = ask<std::vector<ValidatorSessionId>>([&](td::Promise<std::vector<ValidatorSessionId>> p) {
      td::actor::send_closure(db_, &Db::get_destroyed_validator_sessions, std::move(p));
    });
    return std::set<ValidatorSessionId>(v.begin(), v.end());
  }
  std::set<ValidatorSessionId> memory_destroyed() {
    return ask<std::set<ValidatorSessionId>>([&](td::Promise<std::set<ValidatorSessionId>> p) {
      td::actor::send_closure(harness_, &Harness::destroyed_now, std::move(p));
    });
  }
  size_t open_retirements() {
    return ask<size_t>(
        [&](td::Promise<size_t> p) { td::actor::send_closure(harness_, &Harness::open_retirements, std::move(p)); });
  }
  void persist(std::vector<ValidatorSessionId> destroyed, std::vector<PendingValidatorConsensusDbCleanup> records) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(db_, &Db::persist_validator_retirement, std::move(destroyed), std::move(records),
                              std::move(p));
    });
  }
  std::vector<ValidatorSessionId> cleanup_pass(BlockIdExt gc, CatchainSeqno cc) {
    return ask<std::vector<ValidatorSessionId>>([&](td::Promise<std::vector<ValidatorSessionId>> p) {
      td::actor::send_closure(harness_, &Harness::cleanup_pass, gc, cc, std::move(p));
    });
  }
  void acknowledge_rotation() {
    ask<td::Unit>(
        [&](td::Promise<td::Unit> p) { td::actor::send_closure(harness_, &Harness::acknowledge_rotation, std::move(p)); });
  }

 private:
  std::string root_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<Db> db_;
  td::actor::ActorOwn<Harness> harness_;
};

class Root {
 public:
  Root() {
    path = td::mkdtemp("/tmp", "startup-orphan").move_as_ok();
    td::mkdir(consensus::consensus_db_root(path)).ensure();
  }
  ~Root() {
    td::rmrf(path).ignore();
  }
  void make(int n, ShardIdFull shard, CatchainSeqno cc) {
    td::mkdir(consensus::consensus_db_root(path) + dir_name(n, shard, cc)).ensure();
  }
  std::string path;
};

}  // namespace
}  // namespace tos::validator

using namespace tos;
using namespace tos::validator;

// T21. The persisted init block is older than the previous process's sessions: their
// directories are found on disk. Every directory whose catchain seqno is below the
// current one gets exactly one record; the current and tentative sessions get none,
// and a second startup adds nothing.
TEST(StartupOrphanReconcile, T21_OlderInitBlockSessionsRecordedOnce) {
  Root root;
  root.make(1, kMaster, 3);  // the previous process's current session
  root.make(2, kMaster, 4);  // its tentative session
  root.make(3, kMaster, 6);  // the current session of the final state
  root.make(4, kMaster, 7);  // its tentative session
  root.make(5, kBase, 5);    // a basechain session below the current one
  Owner owner;
  owner.live = {session(3), session(4)};
  owner.current_cc = {{kMaster, 6}, {kBase, 6}};
  Session s(root.path);
  s.start(owner);
  auto summary = s.reconcile();
  ASSERT_EQ(3u, summary.recorded);
  for (int n : {1, 2, 5}) {
    auto r = s.record(n);
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(r->session_id == session(n));
    ASSERT_TRUE(r->retirement_checkpoint == owner.retirement);
  }
  for (int n : {3, 4}) {
    ASSERT_TRUE(!s.record(n).has_value());
  }
  // A restart: the recorded sessions are now fenced, nothing new is written.
  owner.destroyed = s.durable_destroyed();
  s.start(owner);
  auto again = s.reconcile();
  ASSERT_EQ(0u, again.recorded);
  ASSERT_EQ(0u, again.candidates);
}

// T22 + T23. A crash after the init block advanced but before reconciliation leaves an
// orphan; the next startup, which does not enter the mode, records it, and a cleanup
// pass of the same process reserves it for deletion once the anchor allows -- no
// further restart. That needs the actorless close to be confirmed.
TEST(StartupOrphanReconcile, T22_T23_OrphanBecomesEligibleInTheSameProcess) {
  Root root;
  root.make(7, kMaster, 2);
  Owner owner;
  owner.current_cc = {{kMaster, 5}};
  owner.retirement = checkpoint(100);
  Session s(root.path);
  s.start(owner);
  auto summary = s.reconcile();
  ASSERT_EQ(1u, summary.recorded);
  ASSERT_EQ(0u, s.open_retirements());
  // The anchor has not reached the retirement block yet: not eligible.
  ASSERT_TRUE(s.cleanup_pass(checkpoint(99), 5).empty());
  // It has: eligible and reserved, in this process.
  auto reserved = s.cleanup_pass(checkpoint(120), 5);
  ASSERT_EQ(1u, reserved.size());
  ASSERT_TRUE(reserved[0] == session(7));
}

// T30. Edge cases: an unknown catchain seqno and a seqno not below the current one are
// skipped; a split child is judged by the oracle's answer for its own shard; a cleanup
// reservation taken while the reads run and a directory removed before the commit are
// dropped by the recheck; files, observer directories and foreign names are ignored.
TEST(StartupOrphanReconcile, T30_EdgeCases) {
  Root root;
  root.make(10, kMaster, 1);  // unknown catchain seqno for its shard
  root.make(11, kBase, 4);    // not below the current seqno
  root.make(12, kLeft, 2);    // a split child, below its own current seqno
  root.make(13, kBase, 1);    // reserved for deletion during the reads
  root.make(14, kBase, 1);    // removed before the commit
  root.make(15, kBase, 1);    // an ordinary orphan
  td::mkdir(consensus::consensus_db_root(root.path) + dir_name(16, kBase, 1) + ".observer.x").ensure();
  td::mkdir(consensus::consensus_db_root(root.path) + "not-a-consensus-dir").ensure();
  td::write_file(consensus::consensus_db_root(root.path) + dir_name(17, kBase, 1), "a file").ensure();
  Owner owner;
  owner.current_cc = {{kBase, 4}, {kLeft, 3}};
  auto root_path = root.path;
  owner.during_read[session(13)] = [](Harness& h) { h.reserve_now(13, kBase, 1); };
  owner.during_read[session(14)] = [root_path](Harness&) {
    td::rmrf(consensus::consensus_db_root(root_path) + dir_name(14, kBase, 1)).ensure();
  };
  Session s(root.path);
  s.start(owner);
  auto summary = s.reconcile();
  ASSERT_EQ(2u, summary.rechecked_out);
  ASSERT_EQ(2u, summary.recorded);
  ASSERT_TRUE(s.record(12).has_value());
  ASSERT_TRUE(s.record(15).has_value());
  for (int n : {10, 11, 13, 14, 16, 17}) {
    ASSERT_TRUE(!s.record(n).has_value());
  }
}

// T35. The inventory's fence write is a complete-set write: destroyed-session entries
// that existed before it survive it.
TEST(StartupOrphanReconcile, T35_PreexistingFencesSurvive) {
  Root root;
  root.make(20, kBase, 1);
  root.make(21, kBase, 2);
  Owner owner;
  owner.current_cc = {{kBase, 5}};
  owner.destroyed = {session(50), session(51)};
  Session s(root.path);
  s.persist({session(50), session(51)}, {});
  s.start(owner);
  auto summary = s.reconcile();
  ASSERT_EQ(2u, summary.recorded);
  auto durable = s.durable_destroyed();
  for (int n : {50, 51, 20, 21}) {
    ASSERT_TRUE(durable.count(session(n)) == 1);
  }
}

// T36. The inventory's write interleaved with a group retirement write and an init-block
// rotation, in both orders. Neither write loses the other's fences; a rotation prunes
// only the sessions of its own snapshot, and only once the init-block write is
// acknowledged; cleanup records survive the pruning.
TEST(StartupOrphanReconcile, T36_InterleavedFenceWrites) {
  // Order 1: the retirement and the rotation snapshot happen while the inventory reads.
  {
    Root root;
    root.make(30, kBase, 1);
    Owner owner;
    owner.current_cc = {{kBase, 5}};
    owner.destroyed = {session(50)};
    owner.during_read[session(30)] = [](Harness& h) {
      h.retire_group(40, kBase, 4);
      h.take_rotation_snapshot();
    };
    Session s(root.path);
    s.persist({session(50)}, {});
    s.start(owner);
    ASSERT_EQ(1u, s.reconcile().recorded);
    auto durable = s.durable_destroyed();
    for (int n : {50, 40, 30}) {
      ASSERT_TRUE(durable.count(session(n)) == 1);
    }
    s.acknowledge_rotation();
    durable = s.durable_destroyed();
    // The snapshot held 50 and 40; the inventory id was outside it and survives.
    ASSERT_TRUE(durable.count(session(30)) == 1);
    ASSERT_TRUE(durable.count(session(40)) == 0);
    ASSERT_TRUE(s.record(30).has_value());
    ASSERT_TRUE(s.record(40).has_value());
  }
  // Order 2: both happen after the inventory's write was issued, before its ack.
  {
    Root root;
    root.make(30, kBase, 1);
    Owner owner;
    owner.current_cc = {{kBase, 5}};
    owner.after_inventory_write = [](Harness& h) {
      h.retire_group(40, kBase, 4);
      h.take_rotation_snapshot();
    };
    Session s(root.path);
    s.start(owner);
    ASSERT_EQ(1u, s.reconcile().recorded);
    auto durable = s.durable_destroyed();
    ASSERT_TRUE(durable.count(session(30)) == 1);
    ASSERT_TRUE(durable.count(session(40)) == 1);
    // The snapshot was taken after the inventory id entered memory: the rotation may
    // prune it, but only on its acknowledgement, and its record stays.
    ASSERT_TRUE(s.memory_destroyed().count(session(30)) == 1);
    s.acknowledge_rotation();
    ASSERT_TRUE(s.memory_destroyed().count(session(30)) == 0);
    ASSERT_TRUE(s.record(30).has_value());
  }
}

// T37. A large backlog. 5,000 directories, 300 unrecorded orphans and 256 directories
// that already have records (their fences gone, not yet deletable). The record limit
// counts only confirmed-missing records, so the existing-record directories never take
// a slot: with that backlog unchanged every orphan is recorded within two startups
// (ceil(300 / 256)). Memory held at once stays within the limit plus one pending read.
// The variant fails every read of the existing-record directories: they are counted
// and reported, and the orphans behind them are still recorded.
TEST(StartupOrphanReconcile, T37_LargeBacklogProgress) {
  for (bool failing_reads : {false, true}) {
    Root root;
    std::vector<PendingValidatorConsensusDbCleanup> existing;
    for (int n = 2000; n < 2256; ++n) {
      root.make(n, kBase, 1);
      existing.push_back(consensus::make_validator_cleanup_record(session(n), kBase, 1, checkpoint(90)));
    }
    for (int n = 1000; n < 1300; ++n) {
      root.make(n, kBase, 1);
    }
    for (int n = 3000; n < 7444; ++n) {
      root.make(n, kBase, 9);
    }
    Owner owner;
    owner.current_cc = {{kBase, 9}};
    if (failing_reads) {
      for (int n = 2000; n < 2256; ++n) {
        owner.failing_reads.insert(session(n));
      }
    }
    Session s(root.path);
    s.persist({}, existing);
    size_t recorded = 0;
    for (int startup = 1; startup <= 2; ++startup) {
      owner.destroyed = s.durable_destroyed();
      s.start(owner);
      auto summary = s.reconcile();
      ASSERT_EQ(5000u, summary.directories);
      ASSERT_TRUE(summary.peak_held <= startup_catchup::kMaxStartupOrphanRecords + 1);
      if (failing_reads) {
        ASSERT_EQ(256u, summary.read_failures);
      } else {
        ASSERT_EQ(256u, summary.already_recorded);
      }
      if (startup == 1) {
        ASSERT_EQ(256u, summary.recorded);
        ASSERT_EQ(44u, summary.deferred);
      } else {
        ASSERT_EQ(44u, summary.recorded);
        ASSERT_EQ(0u, summary.deferred);
      }
      recorded += summary.recorded;
    }
    ASSERT_EQ(300u, recorded);
    for (int n = 1000; n < 1300; ++n) {
      ASSERT_TRUE(s.record(n).has_value());
    }
  }
}
