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
// The consensus cleanup checkpoint against a real RootDb on disk and real
// masterchain states, through the production code paths:
//  - the checkpoint is written by the production Db update and reloaded, with its
//    handle and state, by the production startup loader after a restart (also
//    after archive pruning); a damaged or unloadable checkpoint is refused, never
//    treated as absent;
//  - startup refuses (exit status 2) a damaged checkpoint, a truncation or
//    hardfork below it, an init block off its branch and a reinitialization below
//    it -- before any database mutation -- by running the production startup
//    (validator_manager_init) in a child process;
//  - RootDb::truncate refuses a target below or off the checkpoint before it
//    dispatches the archive or StateDb mutation;
//  - the manager's readiness and head admission against the loaded checkpoint.
//
// The masterchain states are derived from a real genesis state: each block's
// state carries its predecessors in prev_blocks, so ancestry is answered by the
// production MasterchainState::check_old_mc_block_id. Main chain B0..B6; a fork
// F4 <- F5 branches off B3.
//
// usage: test-consensus-cleanup-checkpoint-db GENESIS_BOC
#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <vector>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "quic/quic-sender.h"
#include "td/actor/actor.h"
#include "td/actor/coro_task.h"
#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "test/consensus-checkpoint-chain.h"
#include "validator/consensus/consensus-cleanup-checkpoint.h"
#include "validator/consensus/db-path.h"
#include "validator/consensus/validator-cleanup.h"
#include "validator/db/rootdb.hpp"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager-init.h"
#include "validator/manager.hpp"
#include "vm/boc.h"
#include "vm/dict.h"

extern char** environ;

namespace tos::validator {

// A checkpoint state whose per-shard catchain counters and ancestry are given
// directly. It checks which state the manager's cleanup oracles consult across a
// split or merge; it does not verify the production computation of the counters
// from shard topology.
class TopologyState final : public MasterchainStateQ {
 public:
  TopologyState(BlockIdExt id, std::map<ShardIdFull, CatchainSeqno> counters, std::set<BlockIdExt> ancestors)
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm())
      , counters_(std::move(counters))
      , ancestors_(std::move(ancestors)) {
  }
  CatchainSeqno get_shard_cc_seqno(ShardIdFull shard) const override {
    auto it = counters_.find(shard);
    return it == counters_.end() ? std::numeric_limits<CatchainSeqno>::max() : it->second;
  }
  bool check_old_mc_block_id(const BlockIdExt& id, bool strict) const override {
    return ancestors_.contains(id) || (!strict && id == get_block_id());
  }

 private:
  std::map<ShardIdFull, CatchainSeqno> counters_;
  std::set<BlockIdExt> ancestors_;
};

// The production manager with its RootDb, minus the network-heavy start-up.
class ConsensusCheckpointDbProbe : public ValidatorManagerImpl {
 public:
  ConsensusCheckpointDbProbe(td::Ref<ValidatorManagerOptions> opts, std::string root)
      : ValidatorManagerImpl(std::move(opts), std::move(root), {}, {}, {}, {}, {}) {
  }
  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("checkpoint-ext-messages", opts_, actor_id(this));
  }
  void get_db(td::Promise<td::actor::ActorId<Db>> promise) {
    promise.set_value(db_.get());
  }
  // The rest of start-up after the init handoff talks to the network; the
  // handoff itself (started -> install_init_result) is production code.
  void continue_start_up() override {
  }
  // The manager alarm also runs archive GC, whose package deletion cannot survive
  // a scenario's teardown; the scenarios drive checkpoint retries explicitly.
  void alarm() override {
  }
  // The production init handoff with what the loader returned.
  void handoff(BlockHandle head, td::Ref<MasterchainState> head_state, BlockHandle gc,
               td::Ref<MasterchainState> gc_state, BlockHandle checkpoint, td::Ref<MasterchainState> checkpoint_state,
               td::Promise<bool> promise) {
    ValidatorManagerInitResult R;
    R.handle = std::move(head);
    R.state = std::move(head_state);
    R.gc_handle = std::move(gc);
    R.gc_state = std::move(gc_state);
    R.last_key_block_handle_ = R.handle;
    R.consensus_cleanup_checkpoint_handle = std::move(checkpoint);
    R.consensus_cleanup_checkpoint_state = std::move(checkpoint_state);
    started(std::move(R));
    promise.set_value(bool{consensus_checkpoint_reached_});
  }

  // Fault injection at the checkpoint's durable store.
  enum class PersistMode { Pass, WriteThenFail, FailWithoutWrite, NotAttempted, Hold };
  void set_persist_mode(PersistMode mode, bool fail_reads, td::Promise<td::Unit> promise) {
    persist_mode_ = mode;
    fail_reads_ = fail_reads;
    promise.set_value(td::Unit());
  }
  void persist_consensus_cleanup_checkpoint(BlockIdExt id, td::Promise<td::Unit> promise) override {
    persist_calls_++;
    switch (persist_mode_) {
      case PersistMode::Pass:
        ValidatorManagerImpl::persist_consensus_cleanup_checkpoint(id, std::move(promise));
        return;
      case PersistMode::WriteThenFail:
        ValidatorManagerImpl::persist_consensus_cleanup_checkpoint(
            id, [promise = std::move(promise)](td::Result<td::Unit> R) mutable {
              promise.set_error(td::Status::Error("injected sync failure after the write"));
            });
        return;
      case PersistMode::FailWithoutWrite:
        promise.set_error(td::Status::Error("injected write failure"));
        return;
      case PersistMode::NotAttempted:
        promise.set_error(td::Status::Error(consensus::kConsensusCheckpointNotAttemptedCode, "injected refusal"));
        return;
      case PersistMode::Hold:
        held_writes_.push_back(std::move(promise));
        return;
    }
  }
  void read_consensus_cleanup_checkpoint(td::Promise<std::optional<BlockIdExt>> promise) override {
    reads_++;
    if (fail_reads_) {
      promise.set_error(td::Status::Error("injected read failure"));
      return;
    }
    ValidatorManagerImpl::read_consensus_cleanup_checkpoint(std::move(promise));
  }
  struct CheckpointStatus {
    std::optional<BlockIdExt> installed;
    std::optional<BlockIdExt> in_flight;
    bool uncertain = false;
    bool unexpected = false;
    bool gc_may_persist_next = false;
    int persist_calls = 0;
    int reads = 0;
    size_t held = 0;
    bool reached = false;
    bool initial_replay = false;
    BlockIdExt head;
  };
  void checkpoint_status(BlockSeqno gc_next, td::Promise<CheckpointStatus> promise) {
    CheckpointStatus s;
    s.installed = consensus_checkpoint_.installed();
    s.in_flight = consensus_checkpoint_.in_flight();
    s.uncertain = consensus_checkpoint_.uncertain();
    s.unexpected = consensus_checkpoint_unexpected_;
    s.gc_may_persist_next = consensus_checkpoint_.gc_may_persist(gc_next);
    s.persist_calls = persist_calls_;
    s.reads = reads_;
    s.held = held_writes_.size();
    s.reached = consensus_checkpoint_reached_;
    s.initial_replay = initial_replay_;
    s.head = last_masterchain_block_id_;
    promise.set_value(std::move(s));
  }
  // The shard client's durable advance and the alarm's retry, both production.
  void shard_client_advanced(BlockHandle handle, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    update_shard_client_block_handle(std::move(handle), std::move(state), std::move(promise));
  }
  void retry_checkpoint(td::Promise<td::Unit> promise) {
    try_advance_consensus_cleanup_checkpoint();
    promise.set_value(td::Unit());
  }
  // One production cleanup timer tick (it does nothing while cleanup is disabled).
  void cleanup_tick(td::Promise<td::Unit> promise) {
    validator_cleanup_timer();
    promise.set_value(td::Unit());
  }
  // The production replay interval around an injected replay operation that
  // applies `heads` through the production new_block path, in order. A head
  // given with `defer` is submitted without waiting for it (a pending head) and
  // awaited after the next one. The replay operation ignores each head's own
  // result, so a refusal can stop the process only through the replay interval
  // itself, not through the replay's result.
  struct ReplayStep {
    BlockHandle handle;
    td::Ref<MasterchainState> state;
    bool defer = false;
  };
  void replay(std::vector<ReplayStep> steps, bool fail_at_end, td::Promise<td::Unit> promise) {
    finish_with(run_initial_replay(apply_steps(std::move(steps), fail_at_end, true)), std::move(promise))
        .start()
        .detach_silent();
  }
  void apply_heads(std::vector<ReplayStep> steps, td::Promise<td::Unit> promise) {
    finish_with(apply_steps(std::move(steps), false, false), std::move(promise)).start().detach_silent();
  }

 private:
  td::actor::Task<> finish_with(td::actor::Task<> task, td::Promise<td::Unit> promise) {
    auto R = co_await std::move(task).wrap();
    promise.set_result(std::move(R));
    co_return td::Unit{};
  }
  td::actor::Task<> apply_steps(std::vector<ReplayStep> steps, bool fail_at_end, bool ignore_results) {
    std::optional<td::actor::StartedTask<td::Unit>> deferred;
    for (auto& step : steps) {
      auto task =
          td::actor::ask(actor_id(this), &ValidatorManager::new_block, step.handle, td::Ref<ShardState>{step.state});
      if (step.defer) {
        deferred.emplace(std::move(task));
        continue;
      }
      auto applied = co_await std::move(task).wrap();
      if (applied.is_error() && !ignore_results) {
        co_return applied.move_as_error();
      }
      if (deferred) {
        auto pending = std::move(*deferred);
        deferred.reset();
        auto pending_applied = co_await std::move(pending).wrap();
        if (pending_applied.is_error() && !ignore_results) {
          co_return pending_applied.move_as_error();
        }
      }
    }
    if (fail_at_end) {
      co_return td::Status::Error("injected ordinary replay error");
    }
    co_return td::Unit{};
  }
  PersistMode persist_mode_ = PersistMode::Pass;
  bool fail_reads_ = false;
  int persist_calls_ = 0;
  int reads_ = 0;
  std::vector<td::Promise<td::Unit>> held_writes_;

 public:
  void set_gc(BlockHandle handle, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    gc_masterchain_handle_ = std::move(handle);
    gc_masterchain_state_ = std::move(state);
    promise.set_value(td::Unit());
  }
  // Sets the head and installs a loaded checkpoint directly (component tests;
  // the production handoff is `handoff`).
  void set_head_and_checkpoint(BlockHandle head, td::Ref<MasterchainState> head_state, BlockHandle checkpoint,
                               td::Ref<MasterchainState> checkpoint_state, td::Promise<bool> promise) {
    last_masterchain_block_handle_ = head;
    last_masterchain_block_id_ = head->id();
    last_masterchain_seqno_ = head->id().seqno();
    last_masterchain_state_ = std::move(head_state);
    install_loaded_consensus_cleanup_checkpoint(std::move(checkpoint), std::move(checkpoint_state));
    promise.set_value(bool{consensus_checkpoint_reached_});
  }
  // Installs a checkpoint as an acknowledged write does, at runtime.
  void install_runtime_checkpoint(BlockHandle handle, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    install_consensus_cleanup_checkpoint(std::move(handle), std::move(state));
    promise.set_value(td::Unit());
  }
  // A replayed head, as new_masterchain_block sees it.
  void replay_head(BlockHandle head, td::Ref<MasterchainState> head_state, td::Promise<bool> promise) {
    last_masterchain_block_handle_ = head;
    last_masterchain_block_id_ = head->id();
    last_masterchain_seqno_ = head->id().seqno();
    last_masterchain_state_ = std::move(head_state);
    recompute_consensus_checkpoint_readiness();
    promise.set_value(bool{consensus_checkpoint_reached_});
  }
  // The production cleanup decision for one retired masterchain session: the
  // manager's oracles (anchored to the checkpoint, or to the GC block while the
  // key is absent) fed to the production eligibility predicate. The anchor is
  // nullopt when there are no oracles at all.
  void cleanup_decision(BlockIdExt retirement, CatchainSeqno retired_cc, bool live,
                        td::Promise<std::pair<std::optional<BlockIdExt>, bool>> promise) {
    cleanup_decision_in(ShardIdFull{masterchainId}, retirement, retired_cc, live, std::move(promise));
  }
  void cleanup_decision_in(ShardIdFull shard, BlockIdExt retirement, CatchainSeqno retired_cc, bool live,
                           td::Promise<std::pair<std::optional<BlockIdExt>, bool>> promise) {
    auto oracles = validator_cleanup_oracles();
    if (!oracles) {
      promise.set_value(std::make_pair(std::optional<BlockIdExt>{}, false));
      return;
    }
    consensus::PendingValidatorConsensusDbCleanup record;
    record.session_id =
        td::sha256_bits256(PSLICE() << "session-" << shard.to_str() << "-" << retirement.to_str() << "-" << retired_cc);
    record.retirement_checkpoint = retirement;
    record.dir_name = consensus::consensus_db_dir_name(shard, retired_cc, record.session_id, "");
    auto is_live = [live](const ValidatorSessionId&) { return live; };
    auto eligible = consensus::validator_cleanup_eligible(record, oracles->gc, oracles->ancestor_or_equal_of_gc,
                                                          oracles->gc_shard_catchain_seqno, is_live,
                                                          [](const ValidatorSessionId&) { return true; });
    promise.set_value(std::make_pair(std::optional<BlockIdExt>{oracles->gc}, eligible));
  }
  // One GC step that reached its write: the production continuation after the
  // next GC block's state was loaded. Reports the in-memory GC block afterwards.
  void gc_step(BlockHandle next, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    gc_advancing_ = true;
    got_next_gc_masterchain_state(std::move(next), std::move(state));
    promise.set_value(td::Unit());
  }
  void gc_block(td::Promise<std::pair<BlockIdExt, bool>> promise) {
    promise.set_value(std::make_pair(gc_masterchain_handle_->id(), bool{gc_advancing_}));
  }
  void admit(BlockIdExt head, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    promise.set_result(admit_consensus_checkpoint_head(head, state));
  }
};

}  // namespace tos::validator

using namespace tos;
using namespace tos::validator;

namespace {

int g_failures = 0;
#define EXPECT(cond, what)                                                                               \
  do {                                                                                                   \
    if (!(cond)) {                                                                                       \
      std::cerr << "CHECKPOINT_DB_FAILED: " << std::string(PSTRING() << what) << " (" #cond ")" << '\n'; \
      g_failures++;                                                                                      \
    } else {                                                                                             \
      std::cout << "CHECKPOINT_DB_OK: " << std::string(PSTRING() << what) << '\n';                       \
    }                                                                                                    \
  } while (0)

using namespace tos::validator::checkpoint_chain;

// ---- running the production actors ----------------------------------------

using Body =
    std::function<td::actor::Task<td::Unit>(td::actor::ActorId<ConsensusCheckpointDbProbe>, td::actor::ActorId<Db>)>;

class Driver : public td::actor::Actor {
 public:
  Driver(td::actor::ActorId<ConsensusCheckpointDbProbe> probe, Body body, std::optional<td::Status>* out)
      : probe_(probe), body_(std::move(body)), out_(out) {
  }
  void start_up() override {
    run().start().detach();
  }

 private:
  td::actor::Task<> run() {
    auto db = co_await td::actor::ask(probe_, &ConsensusCheckpointDbProbe::get_db);
    auto r = co_await body_(probe_, db).wrap();
    *out_ = r.is_ok() ? td::Status::OK() : r.move_as_error();
    co_return td::Unit{};
  }
  td::actor::ActorId<ConsensusCheckpointDbProbe> probe_;
  Body body_;
  std::optional<td::Status>* out_;
};

td::Ref<ValidatorManagerOptions> make_options(const Chain& chain) {
  auto zero = chain["B0"].id;
  auto opts = ValidatorManagerOptions::create(zero, zero);
  opts.write().set_initial_sync_disabled(true);
  return opts;
}

td::Status run_scenario(const std::string& root, td::Ref<ValidatorManagerOptions> opts, Body body,
                        double timeout = 60.0) {
  // A database actor may release a helper actor that outlives the manager (the
  // archive does). Destroying a scheduler with a live actor aborts, so each
  // scenario's scheduler is stopped and deliberately not destroyed.
  auto& scheduler = *new td::actor::Scheduler({1});
  td::actor::ActorOwn<ConsensusCheckpointDbProbe> probe;
  td::actor::ActorOwn<Driver> driver;
  std::optional<td::Status> result;
  scheduler.run_in_context([&] {
    probe = td::actor::create_actor<ConsensusCheckpointDbProbe>("checkpoint-probe", opts, root);
    driver = td::actor::create_actor<Driver>("checkpoint-driver", probe.get(), std::move(body), &result);
  });
  auto deadline = td::Timestamp::in(timeout);
  while (!result.has_value() && !deadline.is_in_past()) {
    scheduler.run(0.01);
  }
  scheduler.run_in_context([&] {
    driver.reset();
    probe.reset();
  });
  scheduler.run(0.1);
  scheduler.stop();
  if (!result.has_value()) {
    return td::Status::Error("scenario timed out");
  }
  return std::move(*result);
}

// Seeds the database: the genesis zerostate, every chain block's state and handle,
// the init, GC and shard-client blocks, and (when given) the checkpoint through
// the production Db update.
struct Seed {
  std::string init = "B6";
  std::string gc = "B0";
  std::string shard_client = "B6";
  std::optional<std::string> checkpoint = "B4";
  bool write_init = true;
  // A retired validator session with its durable cleanup record and consensus
  // directory: retired at this block, with this catchain seqno.
  std::optional<std::pair<std::string, CatchainSeqno>> retired;
};

consensus::PendingValidatorConsensusDbCleanup retired_record(const Chain& chain, const std::string& block,
                                                             CatchainSeqno cc) {
  consensus::PendingValidatorConsensusDbCleanup record;
  record.session_id = label_hash("checkpoint-retired-session");
  record.retirement_checkpoint = chain[block].id;
  record.dir_name = consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc, record.session_id, "");
  return record;
}

std::string retired_dir(const std::string& root, const Chain& chain) {
  return consensus::consensus_db_root(td::Slice{root}) + retired_record(chain, "B0", 1).dir_name;
}

bool retired_dir_exists(const std::string& root, const Chain& chain) {
  return td::stat(retired_dir(root, chain)).is_ok();
}

td::Status seed_db(const std::string& root, const Chain& chain, const Seed& seed) {
  std::filesystem::create_directories(root + "/static");
  {
    std::ofstream static_zero(root + "/static/" + chain["B0"].id.file_hash.to_hex(), std::ios::binary);
    static_zero.write(chain.genesis_boc.data(), static_cast<std::streamsize>(chain.genesis_boc.size()));
  }
  return run_scenario(root, make_options(chain), [&](auto, td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
    co_await td::actor::ask(db, &Db::store_zero_state_file, chain["B0"].id, chain.genesis_boc.clone());
    for (const auto& [name, b] : chain.blocks) {
      auto handle = create_empty_block_handle(b.id);
      handle->set_logical_time(b.state->get_logical_time());
      handle->set_unix_time(b.state->get_unix_time());
      handle->set_split(false);
      handle->set_merge(false);
      handle->set_is_key_block(b.id.seqno() == 0);
      if (b.prev) {
        handle->set_prev(*b.prev);
      }
      if (b.next) {
        handle->set_next(*b.next);
      }
      handle->set_applied();
      handle->set_applied_stored();
      handle->set_processed();
      co_await td::actor::ask(db, &Db::store_block_state, handle, td::Ref<ShardState>{b.state}, vm::StoreCellHint{});
      co_await td::actor::ask(db, &Db::store_block_handle, handle);
    }
    if (seed.write_init) {
      co_await td::actor::ask(db, &Db::update_init_masterchain_block, chain[seed.init].id);
    }
    co_await td::actor::ask(db, &Db::update_gc_masterchain_block, chain[seed.gc].id);
    co_await td::actor::ask(db, &Db::update_shard_client_state, chain[seed.shard_client].id);
    if (seed.retired) {
      auto record = retired_record(chain, seed.retired->first, seed.retired->second);
      co_await td::actor::ask(db, &Db::persist_validator_retirement, std::vector<ValidatorSessionId>{record.session_id},
                              std::vector<consensus::PendingValidatorConsensusDbCleanup>{record});
      auto dir = consensus::consensus_db_root(td::Slice{root}) + record.dir_name + "/db/";
      td::mkpath(dir).ensure();
      td::write_file(dir + "CURRENT", td::Slice{"x"}).ensure();
    }
    if (seed.checkpoint) {
      co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain[*seed.checkpoint].id);
    }
    co_return td::Unit{};
  });
}

void put_raw_checkpoint(const std::string& root, td::Slice value) {
  auto kv = td::RocksDb::open(root + "/state/").move_as_ok();
  kv.begin_write_batch().ensure();
  kv.set(consensus::consensus_cleanup_checkpoint_key(), value).ensure();
  kv.commit_write_batch().ensure();
}

struct Snapshot {
  std::optional<BlockIdExt> init;
  BlockIdExt gc, shard_client;
  std::optional<BlockIdExt> checkpoint;
  std::vector<BlockIdExt> hardforks;
  std::map<std::string, bool> handle_present;
};

// What a refused startup or truncation must leave untouched.
td::Result<Snapshot> snapshot_db(const std::string& root, const Chain& chain) {
  Snapshot snap;
  TRY_STATUS(run_scenario(root, make_options(chain), [&](auto, td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
    auto init = co_await td::actor::ask(db, &Db::get_init_masterchain_block).wrap();
    if (init.is_ok()) {
      snap.init = init.move_as_ok();
    }
    snap.gc = co_await td::actor::ask(db, &Db::get_gc_masterchain_block);
    snap.shard_client = co_await td::actor::ask(db, &Db::get_shard_client_state);
    snap.checkpoint = co_await td::actor::ask(db, &Db::get_consensus_cleanup_checkpoint);
    snap.hardforks = co_await td::actor::ask(db, &Db::get_hardforks);
    for (const auto& [name, b] : chain.blocks) {
      auto h = co_await td::actor::ask(db, &Db::get_block_handle, b.id).wrap();
      snap.handle_present[name] = h.is_ok() && h.ok()->received_state();
    }
    co_return td::Unit{};
  }));
  return snap;
}

std::string fresh_root(const std::string& base, const std::string& name) {
  auto root = base + "/" + name;
  td::rmrf(root).ignore();
  td::mkpath(root + "/").ensure();
  return root;
}

// ---- child: the production startup ----------------------------------------

// Waits, in a scenario body, until `ready` holds or `seconds` pass, letting the
// actors run in between.
td::actor::Task<bool> wait_until(td::actor::ActorId<Db> db, std::function<td::actor::Task<bool>()> ready,
                                 double seconds) {
  auto deadline = td::Timestamp::in(seconds);
  while (true) {
    if (co_await ready()) {
      co_return true;
    }
    if (deadline.is_in_past()) {
      co_return false;
    }
    co_await td::actor::ask(db, &Db::get_shard_client_state);
  }
}

td::actor::Task<ConsensusCheckpointDbProbe::CheckpointStatus> checkpoint_status(
    td::actor::ActorId<ConsensusCheckpointDbProbe> probe, BlockSeqno gc_next = 0) {
  co_return co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::checkpoint_status, gc_next);
}

td::actor::Task<std::pair<BlockHandle, td::Ref<MasterchainState>>> load_block(
    td::actor::ActorId<ConsensusCheckpointDbProbe> probe, const BlockIdExt& id) {
  auto handle = co_await td::actor::ask(probe, &ValidatorManager::get_block_handle, id, false);
  auto state = td::Ref<MasterchainState>{
      co_await td::actor::ask(probe, &ValidatorManager::get_shard_state_from_db, ConstBlockHandle{handle})};
  co_return std::make_pair(std::move(handle), std::move(state));
}

// The chain for archive packages: one block per package (packages hold 20000
// masterchain blocks), 100 s apart. R3 is the checkpoint.
Chain build_retention_chain(const std::string& boc) {
  auto chain = build_chain(boc).move_as_ok();
  std::string parent = "B0";
  for (const auto& [name, seqno] : std::vector<std::pair<std::string, BlockSeqno>>{
           {"R1", 1}, {"R2", 20001}, {"R3", 40001}, {"R4", 60001}, {"R5", 80001}}) {
    extend_chain(chain, parent, name, seqno, 100).ensure();
    parent = name;
  }
  return chain;
}

// Archives R1..R5 through the production Db::archive into five packages, sets
// the checkpoint R3 and GC (R3, or R5 when `gc_past_checkpoint`), runs the
// production archive pruning keyed on the GC block's time with a 1 s TTL, and
// waits until every package pruning deletes is gone (the archive no longer finds
// it, and its pack file is removed) while the kept ones remain. It then exits
// without tearing the actors down: a pruned package's index database stays open
// in this process (its removal retries until the process ends), which a
// scheduler teardown cannot survive.
int retention_child(const std::string& boc, const std::string& root, bool gc_past_checkpoint) {
  auto chain = build_retention_chain(boc);
  auto gc_name = gc_past_checkpoint ? std::string("R5") : std::string("R3");
  std::vector<std::string> deleted = {"00000"};
  std::vector<std::string> kept = {"60000", "80000"};
  if (gc_past_checkpoint) {
    deleted.push_back("20000");
    deleted.push_back("40000");
  } else {
    kept.push_back("20000");
    kept.push_back("40000");
  }
  auto pack = [&](const std::string& package) {
    return root + "/archive/packages/arch0000/archive." + package + ".pack";
  };
  auto status = run_scenario(
      root, make_options(chain),
      [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
          td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
        co_await td::actor::ask(db, &Db::store_zero_state_file, chain["B0"].id, chain.genesis_boc.clone());
        std::vector<BlockHandle> handles;
        for (const auto& name : {"B0", "R1", "R2", "R3", "R4", "R5"}) {
          const auto& b = chain[name];
          auto handle = create_empty_block_handle(b.id);
          handle->set_logical_time(b.state->get_logical_time());
          handle->set_unix_time(b.state->get_unix_time());
          handle->set_split(false);
          handle->set_merge(false);
          handle->set_is_key_block(b.id.seqno() == 0);
          handle->set_applied();
          handle->set_applied_stored();
          handle->set_processed();
          co_await td::actor::ask(db, &Db::store_block_state, handle, td::Ref<ShardState>{b.state},
                                  vm::StoreCellHint{});
          co_await td::actor::ask(db, &Db::store_block_handle, handle);
          handles.push_back(handle);
        }
        for (size_t i = 1; i < handles.size(); i++) {
          co_await td::actor::ask(db, &Db::archive, handles[i]);
        }
        bool packages_exist = true;
        for (const auto& package : {"00000", "20000", "40000", "60000", "80000"}) {
          packages_exist = packages_exist && td::stat(pack(package)).is_ok();
        }
        co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["R3"].id);
        co_await td::actor::ask(db, &Db::update_gc_masterchain_block, chain[gc_name].id);
        co_await td::actor::ask(db, &Db::update_init_masterchain_block, chain["R5"].id);
        co_await td::actor::ask(db, &Db::update_shard_client_state, chain["R5"].id);
        td::actor::send_closure(db, &Db::run_gc, td::Ref<MasterchainState>{chain["R5"].state},
                                chain[gc_name].state->get_unix_time(), 1.0);
        bool pruned = co_await wait_until(
            db,
            [&]() -> td::actor::Task<bool> {
              for (const auto& package : deleted) {
                if (td::stat(pack(package)).is_ok()) {
                  co_return false;
                }
              }
              auto id = co_await td::actor::ask(db, &Db::get_archive_id, 1, ShardIdFull{masterchainId}).wrap();
              co_return id.is_error();
            },
            30.0);
        for (const auto& package : kept) {
          pruned = pruned && td::stat(pack(package)).is_ok();
        }
        // Which blocks the archive still has a package for, and whether the
        // production loader can load the checkpoint's handle and state. (The
        // handles also have a copy in the temporary package written before
        // archiving, which archive TTL pruning does not touch, so the loader
        // itself does not observe a lost archive package here.)
        std::string present;
        for (const auto& name : {"R1", "R2", "R3"}) {
          auto id = co_await td::actor::ask(db, &Db::get_archive_id, chain[name].id.seqno(), ShardIdFull{masterchainId})
                        .wrap();
          present += PSTRING() << " " << name << "=" << (id.is_ok() ? 1 : 0);
        }
        auto loaded = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe).wrap();
        bool loaded_ok = loaded.is_ok() && loaded.ok().handle && loaded.ok().handle->id() == chain["R3"].id &&
                         loaded.ok().state->get_block_id() == chain["R3"].id;
        std::cout << "PACKAGES_CREATED=" << packages_exist << " PRUNED=" << (packages_exist && pruned) << present
                  << " LOADED=" << loaded_ok << std::endl;
        std::_Exit(packages_exist && pruned ? 0 : 1);
        co_return td::Unit{};
      },
      60.0);
  std::cerr << "retention child: " << status.to_string() << '\n';
  return 1;
}

// The production startup (validator_manager_init) into the production init
// handoff (started), then what `mode` asks for. Modes ending in "-disabled" run
// with validator consensus cleanup disabled.
int child_main(const std::string& mode, const std::string& boc, const std::string& root) {
  auto r_chain = build_chain(boc);
  if (r_chain.is_error()) {
    std::cerr << "child: " << r_chain.error().to_string() << '\n';
    return 1;
  }
  auto chain = r_chain.move_as_ok();
  if (mode == "retention" || mode == "retention-violated") {
    return retention_child(boc, root, mode == "retention-violated");
  }
  auto opts = make_options(chain);
  if (mode.find("-disabled") != std::string::npos) {
    opts.write().set_validator_consensus_cleanup_enabled(false);
  }
  if (mode.rfind("truncate-below", 0) == 0) {
    opts.write().truncate_db(2);
  } else if (mode == "truncate-descendant") {
    opts.write().truncate_db(5);
  } else if (mode == "hardfork-below") {
    opts.write().set_hardforks(
        {BlockIdExt{masterchainId, shardIdAll, 3, label_hash("hardfork-root"), label_hash("hardfork-file")}});
  } else if (mode == "reinit-hardfork") {
    opts.write().set_hardforks(
        {BlockIdExt{masterchainId, shardIdAll, 0, label_hash("hardfork-root"), label_hash("hardfork-file")}});
  }
  std::string outcome;
  auto status = run_scenario(
      root, opts,
      [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
          td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
        auto [task, promise] = td::actor::StartedTask<ValidatorManagerInitResult>::make_bridge();
        validator_manager_init(opts, probe, db, std::move(promise));
        auto result = co_await std::move(task);
        auto head_seqno = result.handle->id().seqno();
        auto checkpoint_id = result.consensus_cleanup_checkpoint_handle
                                 ? result.consensus_cleanup_checkpoint_handle->id().to_str()
                                 : std::string("none");
        auto gc_id = result.gc_handle->id();
        auto gc_state_id = result.gc_state->get_block_id();
        auto ready = co_await td::actor::ask(
            probe, &ConsensusCheckpointDbProbe::handoff, result.handle, result.state, result.gc_handle, result.gc_state,
            result.consensus_cleanup_checkpoint_handle, result.consensus_cleanup_checkpoint_state);
        outcome = PSTRING() << "head=" << head_seqno << " checkpoint=" << checkpoint_id << " gc=" << gc_id.seqno()
                            << " gc_state=" << gc_state_id.seqno() << " ready=" << ready;
        if (mode == "late-conflict") {
          // A checkpoint the running head does not descend from is persisted and
          // then installed through the production installation path, as an
          // acknowledged write would be. Production must stop the process here.
          co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["F5"].id);
          auto [handle, state] = co_await load_block(probe, chain["F5"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::install_runtime_checkpoint, handle, state);
          outcome += " late-conflict-survived";
        } else if (mode == "replay-conflict" || mode == "replay-conflict-pending") {
          std::vector<ConsensusCheckpointDbProbe::ReplayStep> steps;
          auto add = [&](const std::string& name, bool defer) -> td::actor::Task<td::Unit> {
            auto [handle, state] = co_await load_block(probe, chain[name].id);
            steps.push_back({handle, state, defer});
            co_return td::Unit{};
          };
          co_await add("B3", false);
          if (mode == "replay-conflict") {
            co_await add("F4", false);
          } else {
            co_await add("F5", true);
            co_await add("B4", false);
          }
          auto r = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::replay, std::move(steps), false).wrap();
          outcome += PSTRING() << " replay-survived=" << (r.is_ok() ? "ok" : r.error().to_string());
        } else if (mode == "pre-persist-crash") {
          // The next checkpoint's write is issued and held before it reaches the
          // database; a cleanup pass runs meanwhile; then the process crashes.
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_persist_mode,
                                  ConsensusCheckpointDbProbe::PersistMode::Hold, false);
          auto [handle, state] = co_await load_block(probe, chain["B5"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::shard_client_advanced, handle, state);
          auto s = co_await checkpoint_status(probe);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::cleanup_tick);
          co_await wait_until(db, [&]() -> td::actor::Task<bool> { co_return !retired_dir_exists(root, chain); }, 3.0);
          std::cout << "CHILD_PRE_PERSIST held=" << s.held << " installed=" << (s.installed ? s.installed->seqno() : 0)
                    << " dir_present=" << retired_dir_exists(root, chain) << std::endl;
          std::_Exit(137);
        } else if (mode == "persist-then-crash" || mode == "advance-disabled") {
          auto [handle, state] = co_await load_block(probe, chain["B5"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::shard_client_advanced, handle, state);
          bool installed = co_await wait_until(
              db,
              [&]() -> td::actor::Task<bool> {
                auto s = co_await checkpoint_status(probe);
                co_return s.installed&& s.installed->seqno() > 2;
              },
              10.0);
          std::cout << "CHILD_ADVANCED installed=" << installed << " dir_present=" << retired_dir_exists(root, chain)
                    << std::endl;
          if (mode == "persist-then-crash") {
            std::_Exit(137);
          }
        } else if (mode.rfind("cleanup-pass", 0) == 0) {
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::cleanup_tick);
          co_await wait_until(
              db,
              [&]() -> td::actor::Task<bool> {
                auto record = co_await td::actor::ask(db, &Db::get_pending_validator_consensus_db_cleanup_record,
                                                      label_hash("checkpoint-retired-session"));
                co_return !retired_dir_exists(root, chain) && !record.has_value();
              },
              5.0);
          auto record = co_await td::actor::ask(db, &Db::get_pending_validator_consensus_db_cleanup_record,
                                                label_hash("checkpoint-retired-session"));
          outcome += PSTRING() << " dir_present=" << retired_dir_exists(root, chain)
                               << " record_present=" << record.has_value();
        }
        co_return td::Unit{};
      },
      120.0);
  if (status.is_error()) {
    std::cerr << "child " << mode << ": " << status.to_string() << '\n';
    return 1;
  }
  std::cout << "CHILD_STARTED " << mode << " " << outcome << '\n';
  return 0;
}

// Runs the child and returns its exit status; its output goes to `log_path`.
int spawn_child(const char* program, const std::string& mode, const std::string& boc, const std::string& root,
                const std::string& log_path) {
  std::string m = mode, b = boc, r = root;
  std::string flag = "--child";
  char* args[] = {const_cast<char*>(program), flag.data(), m.data(), b.data(), r.data(), nullptr};
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, 2, log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  posix_spawn_file_actions_adddup2(&actions, 2, 1);
  pid_t pid = -1;
  int spawned = posix_spawn(&pid, program, &actions, nullptr, args, environ);
  posix_spawn_file_actions_destroy(&actions);
  if (spawned != 0) {
    return -1;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

std::string read_text(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream text;
  text << input.rdbuf();
  return text.str();
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 5 && std::string_view(argv[1]) == "--child") {
    return child_main(argv[2], argv[3], argv[4]);
  }
  if (argc != 2) {
    std::cerr << "usage: test-consensus-cleanup-checkpoint-db GENESIS_BOC\n";
    return 2;
  }
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  std::cout << std::unitbuf;
  const std::string boc = argv[1];
  auto r_chain = build_chain(boc);
  if (r_chain.is_error()) {
    std::cerr << "CHECKPOINT_DB_FAILED: chain fixture: " << r_chain.error().to_string() << '\n';
    return 1;
  }
  auto chain = r_chain.move_as_ok();
  auto base = td::mkdtemp(td::realpath(".").move_as_ok(), "consensus-checkpoint-db-").move_as_ok();

  // The fixture's states answer ancestry through the production code.
  EXPECT(chain["B6"].state->check_old_mc_block_id(chain["B4"].id, true), "B6 verifies B4 as an ancestor");
  EXPECT(!chain["F5"].state->check_old_mc_block_id(chain["B4"].id, true), "F5 does not verify B4");
  EXPECT(chain["F5"].state->check_old_mc_block_id(chain["B3"].id, true), "F5 verifies B3 (the fork point)");

  // 1. Persist, restart, reload through the production loader, also after
  //    archive pruning; GC at the checkpoint keeps its state.
  {
    auto root = fresh_root(base, "reload");
    auto s = seed_db(root, chain, {});
    EXPECT(s.is_ok(), "seed the reload database: " << s);
    for (int round = 0; round < 2; round++) {
      std::optional<LoadedConsensusCleanupCheckpoint> loaded;
      bool state_gc_keeps_checkpoint = false;
      bool state_gc_deletes_older = false;
      auto r = run_scenario(
          root, make_options(chain),
          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
            loaded = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
            // State GC with the GC block at the checkpoint.
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_gc, loaded->handle, loaded->state);
            state_gc_keeps_checkpoint =
                !co_await td::actor::ask(probe, &ValidatorManager::allow_block_state_gc, chain["B4"].id);
            state_gc_deletes_older =
                co_await td::actor::ask(probe, &ValidatorManager::allow_block_state_gc, chain["B3"].id);
            // Archive TTL pruning keyed on the GC block's time; the
            // next round reloads the checkpoint after it.
            td::actor::send_closure(db, &Db::run_gc, td::Ref<MasterchainState>{chain["B6"].state},
                                    loaded->handle->unix_time(), 1.0);
            co_return td::Unit{};
          });
      EXPECT(r.is_ok(), "reload round " << round << ": " << r);
      EXPECT(loaded && loaded->handle && loaded->handle->id() == chain["B4"].id,
             "reload round " << round << ": the checkpoint handle is reloaded from disk");
      EXPECT(loaded && loaded->state.not_null() && loaded->state->get_block_id() == chain["B4"].id &&
                 loaded->state->check_old_mc_block_id(chain["B2"].id, true),
             "reload round " << round << ": the checkpoint state is reloaded and answers ancestry");
      EXPECT(state_gc_keeps_checkpoint && state_gc_deletes_older,
             "reload round " << round << ": state GC at the checkpoint keeps it and only deletes older states");
    }
  }

  // 2. Only an absent key is absent; anything else is a refusal.
  {
    auto root = fresh_root(base, "absent");
    Seed seed;
    seed.checkpoint.reset();
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed without a checkpoint");
    std::optional<LoadedConsensusCleanupCheckpoint> loaded;
    auto r = run_scenario(root, make_options(chain), [&](auto probe, auto db) -> td::actor::Task<td::Unit> {
      loaded = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
      co_return td::Unit{};
    });
    EXPECT(r.is_ok() && loaded && !loaded->handle, "an absent key loads as no checkpoint");

    auto refusal = [&](const std::string& what, std::function<void(const std::string&)> damage) {
      auto root2 = fresh_root(base, "damaged-" + what);
      Seed seed2;
      seed2.checkpoint.reset();
      EXPECT(seed_db(root2, chain, seed2).is_ok(), "seed for " << what);
      damage(root2);
      auto r2 = run_scenario(root2, make_options(chain), [&](auto probe, auto db) -> td::actor::Task<td::Unit> {
        co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
        co_return td::Unit{};
      });
      EXPECT(r2.is_error() && consensus::is_consensus_checkpoint_refusal(r2),
             what << " is refused, not treated as absent: " << r2);
    };
    refusal("garbage", [](const std::string& root2) { put_raw_checkpoint(root2, td::Slice{"garbage"}); });
    refusal("future-version", [&](const std::string& root2) {
      auto value = consensus::encode_consensus_cleanup_checkpoint(chain["B4"].id);
      value[4] = 9;
      put_raw_checkpoint(root2, td::Slice{value});
    });
    refusal("missing-handle", [&](const std::string& root2) {
      BlockIdExt unknown{masterchainId, shardIdAll, 4, label_hash("unknown-root"), label_hash("unknown-file")};
      put_raw_checkpoint(root2, td::Slice{consensus::encode_consensus_cleanup_checkpoint(unknown)});
    });
  }

  // 3. The startup boundary with real states.
  {
    LoadedConsensusCleanupCheckpoint cp;
    cp.handle = create_empty_block_handle(chain["B4"].id);
    cp.state = chain["B4"].state;
    auto boundary = [&](const std::string& name, bool allow_behind) {
      return check_consensus_cleanup_checkpoint_boundary(cp, chain[name].id, chain[name].state, allow_behind, "test");
    };
    EXPECT(boundary("B2", true).is_ok(), "an older init block is allowed (replay)");
    EXPECT(consensus::is_consensus_checkpoint_refusal(boundary("B2", false)), "a rollback target below is refused");
    EXPECT(boundary("B4", false).is_ok(), "the checkpoint itself is allowed");
    EXPECT(boundary("B6", false).is_ok(), "a verified descendant is allowed");
    EXPECT(consensus::is_consensus_checkpoint_refusal(boundary("F4", true)), "a sibling at its height is refused");
    EXPECT(consensus::is_consensus_checkpoint_refusal(boundary("F5", true)),
           "a higher block off its branch is refused");
    EXPECT(consensus::is_consensus_checkpoint_refusal(
               check_consensus_cleanup_checkpoint_boundary(cp, chain["B6"].id, chain["B5"].state, true, "test")),
           "a head whose state is not its own is refused");
  }

  // 4. RootDb::truncate refuses before dispatching any mutation.
  {
    auto root = fresh_root(base, "truncate");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the truncation database");
    auto before = snapshot_db(root, chain);
    EXPECT(before.is_ok() && before.ok().handle_present.at("B6"), "B6 is readable before truncation");
    for (const auto& [seqno, name] : std::vector<std::pair<BlockSeqno, std::string>>{{2, "B2"}, {4, "F4"}, {5, "F5"}}) {
      auto r = run_scenario(root, make_options(chain), [&](auto, auto db) -> td::actor::Task<td::Unit> {
        auto handle = co_await td::actor::ask(db, &Db::get_block_handle, chain[name].id);
        co_await td::actor::ask(db, &Db::truncate, seqno, ConstBlockHandle{handle});
        co_return td::Unit{};
      });
      EXPECT(r.is_error() && consensus::is_consensus_checkpoint_refusal(r),
             "RootDb refuses truncation to " << name << ": " << r);
      auto after = snapshot_db(root, chain);
      EXPECT(after.is_ok() && after.ok().shard_client == chain["B6"].id &&
                 after.ok().init == std::optional<BlockIdExt>{chain["B6"].id} &&
                 after.ok().checkpoint == std::optional<BlockIdExt>{chain["B4"].id} &&
                 after.ok().handle_present.at("B6") && after.ok().handle_present.at("B5"),
             "a refused truncation to " << name << " mutated neither StateDb nor the archive");
    }
    // Control: an allowed truncation to a verified descendant does mutate both,
    // so the observations above can see a mutation.
    auto r = run_scenario(root, make_options(chain), [&](auto, auto db) -> td::actor::Task<td::Unit> {
      auto handle = co_await td::actor::ask(db, &Db::get_block_handle, chain["B5"].id);
      co_await td::actor::ask(db, &Db::truncate, 5, ConstBlockHandle{handle});
      co_return td::Unit{};
    });
    EXPECT(r.is_ok(), "RootDb truncates to the descendant B5: " << r);
    auto after = snapshot_db(root, chain);
    EXPECT(after.is_ok() && after.ok().shard_client == chain["B5"].id &&
               after.ok().checkpoint == std::optional<BlockIdExt>{chain["B4"].id},
           "the allowed truncation lowered the shard client and kept the checkpoint");
    EXPECT(after.is_ok() && !after.ok().handle_present.at("B6"), "the allowed truncation mutated the archive");
  }

  // 5. The production startup in a child process.
  struct StartupCase {
    std::string mode;
    Seed seed;
    std::function<void(const std::string&)> damage;
    int expected_exit;
    std::string what;
    // The refusal the startup path itself must report (not a later backstop).
    std::string refusal = {};
  };
  std::vector<StartupCase> cases;
  cases.push_back({"plain",
                   {},
                   [&](const std::string& root) { put_raw_checkpoint(root, td::Slice{"garbage"}); },
                   2,
                   "a damaged checkpoint stops startup with exit status 2",
                   "cannot load the consensus cleanup checkpoint"});
  cases.push_back({"truncate-below",
                   {},
                   nullptr,
                   2,
                   "--truncate-db below the checkpoint is refused",
                   "refusing to start from the truncation target"});
  cases.push_back({"hardfork-below",
                   {},
                   nullptr,
                   2,
                   "a hardfork below the checkpoint is refused",
                   "refusing to start from the truncation target"});
  {
    Seed conflicting;
    conflicting.init = "F5";
    cases.push_back({"plain", conflicting, nullptr, 2, "an init block off the checkpoint's branch is refused",
                     "refusing to start from the init block"});
  }
  {
    Seed missing_init;
    missing_init.write_init = false;
    cases.push_back({"plain", missing_init, nullptr, 2,
                     "reinitialization below the checkpoint is refused before the shard client writes",
                     "refusing to start from the reinitialization block"});
  }
  cases.push_back({"truncate-descendant", {}, nullptr, 0, "--truncate-db to a verified descendant starts"});
  {
    Seed older;
    older.init = "B2";
    cases.push_back({"plain", older, nullptr, 0, "an older init block starts (replay toward the checkpoint)"});
  }
  cases.push_back({"plain", {}, nullptr, 0, "an intact database at a descendant starts"});
  int index = 0;
  for (auto& c : cases) {
    auto root = fresh_root(base, PSTRING() << "startup-" << index++);
    EXPECT(seed_db(root, chain, c.seed).is_ok(), "seed for: " << c.what);
    if (c.damage) {
      c.damage(root);
    }
    auto before = c.expected_exit == 2 && !c.damage ? snapshot_db(root, chain) : td::Result<Snapshot>{};
    auto log_path = root + ".child.log";
    int code = spawn_child(argv[0], c.mode, boc, root, log_path);
    EXPECT(code == c.expected_exit, c.what << " (exit " << code << ")");
    if (!c.refusal.empty()) {
      EXPECT(read_text(log_path).find(c.refusal) != std::string::npos,
             c.what << ": refused by the startup check (\"" << c.refusal << "\")");
    }
    if (c.expected_exit == 2 && !c.damage) {
      auto after = snapshot_db(root, chain);
      bool same = before.is_ok() && after.is_ok() && before.ok().init == after.ok().init &&
                  before.ok().gc == after.ok().gc && before.ok().shard_client == after.ok().shard_client &&
                  before.ok().checkpoint == after.ok().checkpoint && before.ok().hardforks == after.ok().hardforks &&
                  before.ok().handle_present == after.ok().handle_present;
      EXPECT(same, c.what << ": nothing was mutated before the refusal");
    }
  }

  // 6. Readiness and head admission against the loaded checkpoint.
  {
    auto root = fresh_root(base, "readiness");
    Seed seed;
    seed.init = "B2";
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed the readiness database");
    std::vector<bool> ready;
    std::vector<bool> admitted;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
          auto handle = [&](const std::string& name) {
            auto h = create_empty_block_handle(chain[name].id);
            return h;
          };
          ready.push_back(co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint,
                                                  handle("B2"), td::Ref<MasterchainState>{chain["B2"].state}, cp.handle,
                                                  cp.state));
          for (const auto& name : {"B3", "B4", "B5"}) {
            ready.push_back(co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::replay_head, handle(name),
                                                    td::Ref<MasterchainState>{chain[name].state}));
          }
          for (const auto& name : {"F4", "F5", "B6", "B3"}) {
            auto a = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::admit, chain[name].id,
                                             td::Ref<MasterchainState>{chain[name].state})
                         .wrap();
            admitted.push_back(a.is_ok());
          }
          co_return td::Unit{};
        });
    EXPECT(r.is_ok(), "readiness scenario ran: " << r);
    EXPECT(ready == (std::vector<bool>{false, false, true, true}),
           "validation waits for the replay to reach the checkpoint and needs no rotation");
    EXPECT(admitted == (std::vector<bool>{false, false, true, true}),
           "heads off the checkpoint's branch are refused before installation; descendants and older blocks are not");
  }

  // 7. Cleanup authority: anchored to the checkpoint while GC is still at
  //    genesis; the GC block only while the key is absent; nothing when a present
  //    checkpoint's state does not match it.
  {
    auto root = fresh_root(base, "oracles");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the oracle database");
    using Decision = std::pair<std::optional<BlockIdExt>, bool>;
    std::vector<Decision> with_checkpoint, without_checkpoint, mismatched;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto handle = [&](const std::string& name) { return create_empty_block_handle(chain[name].id); };
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_gc, handle("B0"),
                                  td::Ref<MasterchainState>{chain["B0"].state});
          auto decide = [&](const std::string& name, CatchainSeqno cc, bool live) {
            return td::actor::ask(probe, &ConsensusCheckpointDbProbe::cleanup_decision, chain[name].id, cc, live);
          };
          // GC fallback while the key is absent.
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint, handle("B6"),
                                  td::Ref<MasterchainState>{chain["B6"].state}, BlockHandle{},
                                  td::Ref<MasterchainState>{});
          without_checkpoint.push_back(co_await decide("B0", 0, false));
          without_checkpoint.push_back(co_await decide("B2", 1, false));
          // The loaded checkpoint B4 (g = 4) with GC still at genesis.
          auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint, handle("B6"),
                                  td::Ref<MasterchainState>{chain["B6"].state}, cp.handle, cp.state);
          with_checkpoint.push_back(co_await decide("B2", 1, false));  // r < g, an ancestor
          with_checkpoint.push_back(co_await decide("B4", 3, false));  // equal to the anchor
          with_checkpoint.push_back(co_await decide("B2", 4, false));  // r == g: the current set
          with_checkpoint.push_back(co_await decide("B5", 1, false));  // above the anchor
          with_checkpoint.push_back(co_await decide("F4", 1, false));  // off its branch
          with_checkpoint.push_back(co_await decide("B2", 1, true));   // live
          // A present checkpoint whose state is not its own.
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint, handle("B6"),
                                  td::Ref<MasterchainState>{chain["B6"].state}, cp.handle,
                                  td::Ref<MasterchainState>{chain["B5"].state});
          mismatched.push_back(co_await decide("B2", 1, false));
          co_return td::Unit{};
        });
    EXPECT(r.is_ok(), "oracle scenario ran: " << r);
    auto gc0 = std::optional<BlockIdExt>{chain["B0"].id};
    auto cp4 = std::optional<BlockIdExt>{chain["B4"].id};
    EXPECT(without_checkpoint == (std::vector<Decision>{{gc0, false}, {gc0, false}}),
           "without a checkpoint, cleanup is anchored to the GC block at genesis and deletes nothing");
    EXPECT(with_checkpoint == (std::vector<Decision>{
                                  {cp4, true}, {cp4, true}, {cp4, false}, {cp4, false}, {cp4, false}, {cp4, false}}),
           "with the checkpoint, sessions retired at or below it on its branch with r < g are deletable while GC "
           "stays at genesis; r == g, above, off-branch and live sessions are not");
    EXPECT(mismatched == (std::vector<Decision>{{std::nullopt, false}}),
           "a checkpoint whose state does not match it gives no cleanup authority, not the GC fallback");
  }

  // 8. The GC write never passes the checkpoint: a GC step to B5 with the
  //    checkpoint at B4 is not persisted; a step to B4 (equal) is.
  {
    auto root = fresh_root(base, "gc-boundary");
    Seed seed;
    seed.gc = "B3";
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed the GC boundary database");
    std::vector<std::pair<BlockIdExt, bool>> memory;
    std::vector<BlockIdExt> durable;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto handle = [&](const std::string& name) { return create_empty_block_handle(chain[name].id); };
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_gc, handle("B3"),
                                  td::Ref<MasterchainState>{chain["B3"].state});
          auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint, handle("B6"),
                                  td::Ref<MasterchainState>{chain["B6"].state}, cp.handle, cp.state);
          for (const auto& name : {"B5", "B4"}) {
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::gc_step, handle(name),
                                    td::Ref<MasterchainState>{chain[name].state});
            // Let a dispatched GC write and its continuation finish.
            for (int i = 0; i < 20; i++) {
              co_await td::actor::ask(db, &Db::get_gc_masterchain_block);
            }
            memory.push_back(co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::gc_block));
            durable.push_back(co_await td::actor::ask(db, &Db::get_gc_masterchain_block));
          }
          co_return td::Unit{};
        });
    EXPECT(r.is_ok(), "GC boundary scenario ran: " << r);
    EXPECT(durable == (std::vector<BlockIdExt>{chain["B3"].id, chain["B4"].id}),
           "the GC write to B5 past the checkpoint B4 was refused; the write to B4 itself was persisted");
    EXPECT(memory == (std::vector<std::pair<BlockIdExt, bool>>{{chain["B3"].id, false}, {chain["B4"].id, false}}),
           "the refused GC step left the in-memory GC block and released the advance");
  }

  auto run_child = [&](const std::string& mode, const std::string& root) {
    static int sequence = 0;
    auto log_path = PSTRING() << root << ".child-" << ++sequence << "-" << mode << ".log";
    int code = spawn_child(argv[0], mode, boc, root, log_path);
    return std::make_pair(code, read_text(log_path));
  };
  auto contains = [](const std::string& text, const std::string& needle) {
    return text.find(needle) != std::string::npos;
  };
  auto wait_seconds = [](td::actor::ActorId<Db> db, double seconds) -> td::actor::Task<td::Unit> {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past()) {
      co_await td::actor::ask(db, &Db::get_shard_client_state);
    }
    co_return td::Unit{};
  };

  // 9. Reinitialization never persists GC above the checkpoint, and a restart
  //    right after it starts. Without a checkpoint, GC is the reinitialization
  //    block, as before.
  for (bool with_checkpoint : {true, false}) {
    auto root = fresh_root(base, with_checkpoint ? "reinit-gc" : "reinit-gc-no-checkpoint");
    Seed seed;
    seed.write_init = false;
    if (!with_checkpoint) {
      seed.checkpoint.reset();
    }
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed the reinitialization GC database");
    std::optional<BlockIdExt> returned_gc, returned_gc_state, durable_gc;
    auto r = run_scenario(root, make_options(chain),
                          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                            auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
                            auto [handle, state] = co_await load_block(probe, chain["B6"].id);
                            auto gc = co_await persist_reinit_gc_block(probe, cp, handle, state);
                            returned_gc = gc.handle->id();
                            returned_gc_state = gc.state->get_block_id();
                            durable_gc = co_await td::actor::ask(db, &Db::get_gc_masterchain_block);
                            // As the manager records the init block after a reinitialization.
                            co_await td::actor::ask(db, &Db::update_init_masterchain_block, chain["B6"].id);
                            co_return td::Unit{};
                          });
    auto expected = with_checkpoint ? chain["B4"].id : chain["B6"].id;
    EXPECT(r.is_ok(), "reinitialization GC scenario ran: " << r);
    EXPECT(returned_gc == expected && returned_gc_state == expected && durable_gc == expected,
           (with_checkpoint ? "reinitialization at B6 keeps GC (persisted and in the init result) at the checkpoint B4"
                            : "without a checkpoint, reinitialization at B6 persists GC = B6"));
    auto [code, log] = run_child("plain", root);
    EXPECT(code == 0 && contains(log, with_checkpoint ? "gc=4 gc_state=4" : "gc=6 gc_state=6"),
           "an immediate restart after the reinitialization starts (exit " << code << ")");
  }

  // 10. Reinitialization writes the hardfork list only after its target passed
  //     the checkpoint check; without a checkpoint it still succeeds and writes it.
  for (bool with_checkpoint : {true, false}) {
    auto root = fresh_root(base, with_checkpoint ? "reinit-hardfork" : "reinit-hardfork-no-checkpoint");
    Seed seed;
    seed.write_init = false;
    if (!with_checkpoint) {
      seed.checkpoint.reset();
    }
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed the reinitialization hardfork database");
    auto before = snapshot_db(root, chain);
    auto [code, log] = run_child("reinit-hardfork", root);
    auto after = snapshot_db(root, chain);
    if (with_checkpoint) {
      EXPECT(code == 2 && contains(log, "refusing to start from the reinitialization block"),
             "reinitialization below the checkpoint with a changed hardfork list is refused (exit " << code << ")");
      EXPECT(before.is_ok() && after.is_ok() && after.ok().hardforks.empty() &&
                 after.ok().shard_client == before.ok().shard_client && after.ok().gc == before.ok().gc,
             "the refused reinitialization wrote neither the hardfork list nor shard-client or GC metadata");
    } else {
      EXPECT(code == 0, "reinitialization without a checkpoint succeeds (exit " << code << ")");
      EXPECT(after.is_ok() && after.ok().hardforks.size() == 1, "and writes the hardfork list");
    }
  }

  // 11. RootDb serializes checkpoint updates against a truncation.
  {
    struct Gate {
      std::mutex mutex;
      std::optional<td::Promise<td::Unit>> held;
      std::atomic<bool> blocked{false};
      void release() {
        std::optional<td::Promise<td::Unit>> promise;
        {
          std::lock_guard<std::mutex> lock(mutex);
          promise.swap(held);
        }
        if (promise) {
          promise->set_value(td::Unit());
        }
      }
    };
    auto gate = std::make_shared<Gate>();
    // Released on every exit path, even if an assertion below fails.
    struct GateGuard {
      std::shared_ptr<Gate> gate;
      ~GateGuard() {
        set_truncation_state_load_gate_for_testing({});
        gate->release();
      }
    } guard{gate};
    set_truncation_state_load_gate_for_testing([gate](td::Promise<td::Unit> promise) {
      std::lock_guard<std::mutex> lock(gate->mutex);
      gate->held.emplace(std::move(promise));
      gate->blocked = true;
    });
    auto root = fresh_root(base, "serialize");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the serialization database");
    td::Result<td::Unit> concurrent_update, second_truncation, first_truncation, later_update;
    std::optional<BlockIdExt> durable;
    BlockIdExt shard_client;
    bool observed_blocked = false;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto [b5, b5_state] = co_await load_block(probe, chain["B5"].id);
          auto [b6, b6_state] = co_await load_block(probe, chain["B6"].id);
          auto truncation = td::actor::ask(db, &Db::truncate, 5, ConstBlockHandle{b5});
          observed_blocked =
              co_await wait_until(db, [&]() -> td::actor::Task<bool> { co_return gate->blocked.load(); }, 10.0);
          concurrent_update =
              co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["B6"].id).wrap();
          second_truncation = co_await td::actor::ask(db, &Db::truncate, 6, ConstBlockHandle{b6}).wrap();
          gate->release();
          first_truncation = co_await std::move(truncation).wrap();
          durable = co_await td::actor::ask(db, &Db::get_consensus_cleanup_checkpoint);
          shard_client = co_await td::actor::ask(db, &Db::get_shard_client_state);
          later_update = co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["B5"].id).wrap();
          co_return td::Unit{};
        });
    set_truncation_state_load_gate_for_testing({});
    EXPECT(r.is_ok() && observed_blocked, "the truncation was held inside its preflight: " << r);
    EXPECT(concurrent_update.is_error() && consensus::is_consensus_checkpoint_not_attempted(concurrent_update.error()),
           "a checkpoint update during the truncation is refused without being written");
    EXPECT(second_truncation.is_error(), "a second truncation while one runs is refused");
    EXPECT(first_truncation.is_ok() && shard_client == chain["B5"].id && durable == chain["B4"].id,
           "the truncation completed against the checkpoint it read, which did not move");
    EXPECT(later_update.is_ok(), "after the truncation, checkpoint updates are accepted again");

    // An update forwarded before the truncation starts is seen by its preflight.
    auto root2 = fresh_root(base, "serialize-before");
    EXPECT(seed_db(root2, chain, {}).is_ok(), "seed the second serialization database");
    td::Result<td::Unit> early_update, late_truncation;
    std::optional<Snapshot> snap;
    r = run_scenario(root2, make_options(chain),
                     [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                         td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                       auto [b5, b5_state] = co_await load_block(probe, chain["B5"].id);
                       auto update = td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["B6"].id);
                       auto truncation = td::actor::ask(db, &Db::truncate, 5, ConstBlockHandle{b5});
                       early_update = co_await std::move(update).wrap();
                       late_truncation = co_await std::move(truncation).wrap();
                       co_return td::Unit{};
                     });
    auto after = snapshot_db(root2, chain);
    EXPECT(r.is_ok() && early_update.is_ok() && late_truncation.is_error() &&
               consensus::is_consensus_checkpoint_refusal(late_truncation.error()),
           "the truncation's preflight saw the update forwarded before it and refused the target below it");
    EXPECT(after.is_ok() && after.ok().shard_client == chain["B6"].id && after.ok().checkpoint == chain["B6"].id &&
               after.ok().handle_present.at("B6"),
           "and nothing was truncated");

    // A preflight refusal ends the truncation: updates are accepted again.
    auto root3 = fresh_root(base, "serialize-refused");
    EXPECT(seed_db(root3, chain, {}).is_ok(), "seed the third serialization database");
    td::Result<td::Unit> refused, after_refusal;
    r = run_scenario(root3, make_options(chain),
                     [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                         td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                       auto [b2, b2_state] = co_await load_block(probe, chain["B2"].id);
                       refused = co_await td::actor::ask(db, &Db::truncate, 2, ConstBlockHandle{b2}).wrap();
                       after_refusal =
                           co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain["B5"].id).wrap();
                       co_return td::Unit{};
                     });
    EXPECT(r.is_ok() && refused.is_error() && after_refusal.is_ok(),
           "after a refused truncation the serialization is released");
  }

  // 12. A conflict found after the head was installed stops the process (exit
  //     status 2) through the production hook, and the persisted conflicting
  //     checkpoint makes the restart refuse too.
  {
    auto root = fresh_root(base, "late-conflict");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the late-conflict database");
    auto [code, log] = run_child("late-conflict", root);
    EXPECT(code == 2 && contains(log, "stopping: the applied masterchain block") &&
               !contains(log, "late-conflict-survived"),
           "a conflicting checkpoint installed at runtime stops the process with exit status 2 (exit " << code << ")");
    auto snap = snapshot_db(root, chain);
    EXPECT(snap.is_ok() && snap.ok().checkpoint == chain["F5"].id, "the conflicting checkpoint is durable");
    auto [restart_code, restart_log] = run_child("plain", root);
    EXPECT(restart_code == 2 && contains(restart_log, "refusing to start from the init block"),
           "the restart refuses the head that conflicts with it (exit " << restart_code << ")");
  }

  // 13. A conflicting head during the initial replay stops the process (direct
  //     and pending admission); at runtime it is rejected and the head kept.
  for (const auto& mode : {std::string("replay-conflict"), std::string("replay-conflict-pending")}) {
    auto root = fresh_root(base, mode);
    Seed seed;
    seed.init = "B2";
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed " << mode);
    auto [code, log] = run_child(mode, root);
    EXPECT(code == 2 && contains(log, "refusing masterchain block") && !contains(log, "replay-survived"),
           mode << ": the startup replay conflict stops the process with exit status 2 (exit " << code << ")");
  }
  {
    auto root = fresh_root(base, "runtime-conflict");
    Seed seed;
    seed.init = "B2";
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed the runtime conflict database");
    td::Result<td::Unit> b3, f4, b4, pending_f5;
    std::vector<ConsensusCheckpointDbProbe::CheckpointStatus> seen;
    bool flag_after_replay = true, flag_after_error = true;
    td::Result<td::Unit> ordinary_error;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
          auto [h2, s2] = co_await load_block(probe, chain["B2"].id);
          auto [h0, s0] = co_await load_block(probe, chain["B0"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::handoff, h2, s2, h0, s0, cp.handle, cp.state);
          auto step = [&](const std::string& name,
                          bool defer = false) -> td::actor::Task<ConsensusCheckpointDbProbe::ReplayStep> {
            auto [h, s] = co_await load_block(probe, chain[name].id);
            co_return ConsensusCheckpointDbProbe::ReplayStep{h, s, defer};
          };
          // The replay interval clears when the replay finishes, or ends with an ordinary error.
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::replay,
                                  std::vector<ConsensusCheckpointDbProbe::ReplayStep>{co_await step("B3")}, false);
          flag_after_replay = (co_await checkpoint_status(probe)).initial_replay;
          ordinary_error = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::replay,
                                                   std::vector<ConsensusCheckpointDbProbe::ReplayStep>{}, true)
                               .wrap();
          flag_after_error = (co_await checkpoint_status(probe)).initial_replay;
          // Runtime: a conflicting head is rejected and the valid head kept.
          f4 = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::apply_heads,
                                       std::vector<ConsensusCheckpointDbProbe::ReplayStep>{co_await step("F4")})
                   .wrap();
          seen.push_back(co_await checkpoint_status(probe));
          // Pending admission at runtime: F5 waits for B4, then is refused.
          pending_f5 = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::apply_heads,
                                               std::vector<ConsensusCheckpointDbProbe::ReplayStep>{
                                                   co_await step("F5", true), co_await step("B4")})
                           .wrap();
          seen.push_back(co_await checkpoint_status(probe));
          co_return td::Unit{};
        });
    EXPECT(r.is_ok(), "runtime conflict scenario ran: " << r);
    EXPECT(!flag_after_replay && ordinary_error.is_error() && !flag_after_error,
           "the initial-replay interval ends when the replay finishes or fails with an ordinary error");
    EXPECT(f4.is_error() && seen.size() == 2 && seen[0].head == chain["B3"].id,
           "at runtime the conflicting head F4 is rejected and B3 is kept");
    EXPECT(pending_f5.is_error() && seen.size() == 2 && seen[1].head == chain["B4"].id && seen[1].reached,
           "at runtime the pending conflicting head F5 is rejected after B4, which is kept");
  }

  // 14. An uncertain checkpoint write keeps GC excluded and is rewritten until a
  //     synced write succeeds; a read is only a diagnosis.
  {
    using Mode = ConsensusCheckpointDbProbe::PersistMode;
    struct Case {
      std::string name;
      Mode first;
      bool fail_reads;
      std::optional<std::string> written_meanwhile;  // a value that appears durable after the failure
      Mode then;
      bool expect_installed;
      bool expect_unexpected;
    };
    std::vector<Case> cases = {
        {"visible-then-sync-fails", Mode::WriteThenFail, false, std::nullopt, Mode::Pass, true, false},
        {"old-read-then-recovered", Mode::FailWithoutWrite, false, std::string("B5"), Mode::Pass, true, false},
        {"unexpected-value", Mode::FailWithoutWrite, false, std::string("B6"), Mode::Pass, false, true},
        {"repeated-failures", Mode::FailWithoutWrite, true, std::nullopt, Mode::FailWithoutWrite, false, false},
    };
    for (const auto& c : cases) {
      auto root = fresh_root(base, "uncertain-" + c.name);
      EXPECT(seed_db(root, chain, {}).is_ok(), "seed " << c.name);
      ConsensusCheckpointDbProbe::CheckpointStatus after_failure, after_meanwhile, final;
      std::optional<BlockIdExt> durable_after_failure;
      auto r = run_scenario(
          root, make_options(chain),
          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
            auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
            auto [h6, s6] = co_await load_block(probe, chain["B6"].id);
            auto [h0, s0] = co_await load_block(probe, chain["B0"].id);
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::handoff, h6, s6, h0, s0, cp.handle, cp.state);
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_persist_mode, c.first, c.fail_reads);
            auto [h5, s5] = co_await load_block(probe, chain["B5"].id);
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::shard_client_advanced, h5, s5);
            co_await wait_until(
                db,
                [&]() -> td::actor::Task<bool> {
                  auto s = co_await checkpoint_status(probe, 1);
                  co_return s.uncertain&& s.reads > 0;
                },
                5.0);
            after_failure = co_await checkpoint_status(probe, 1);
            durable_after_failure = co_await td::actor::ask(db, &Db::get_consensus_cleanup_checkpoint);
            if (c.written_meanwhile) {
              co_await td::actor::ask(db, &Db::update_consensus_cleanup_checkpoint, chain[*c.written_meanwhile].id);
            }
            // A second failed attempt reads again (the diagnosis of what is durable now).
            co_await wait_seconds(db, 1.1);
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::retry_checkpoint);
            co_await wait_seconds(db, 0.2);
            after_meanwhile = co_await checkpoint_status(probe, 1);
            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_persist_mode, c.then, c.fail_reads);
            for (int i = 0; i < 3; i++) {
              co_await wait_seconds(db, 1.1);
              co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::retry_checkpoint);
            }
            co_await wait_seconds(db, 0.2);
            final = co_await checkpoint_status(probe, 1);
            co_return td::Unit{};
          });
      EXPECT(r.is_ok(), c.name << ": scenario ran: " << r);
      EXPECT(after_failure.uncertain && after_failure.installed == chain["B4"].id &&
                 after_failure.in_flight == chain["B5"].id && !after_failure.gc_may_persist_next,
             c.name << ": after the failure the write stays in flight, uninstalled, with GC excluded");
      if (c.name == "visible-then-sync-fails") {
        EXPECT(durable_after_failure == chain["B5"].id, c.name << ": the new value was visible after the failure");
      }
      EXPECT(after_meanwhile.installed == chain["B4"].id && !after_meanwhile.gc_may_persist_next,
             c.name << ": neither a visible value nor a read installs it or releases GC");
      if (c.expect_installed) {
        EXPECT(final.installed == chain["B5"].id && !final.in_flight && final.gc_may_persist_next &&
                   final.persist_calls >= 3,
               c.name << ": installed, and GC released, only after a later synced rewrite of the same id");
      } else {
        EXPECT(final.installed == chain["B4"].id && final.in_flight == chain["B5"].id && !final.gc_may_persist_next,
               c.name << ": still not installed and GC still excluded");
      }
      EXPECT(final.unexpected == c.expect_unexpected,
             c.name << ": an unexpected durable value is " << (c.expect_unexpected ? "" : "not ") << "reported");
      if (c.name == "repeated-failures") {
        EXPECT(final.persist_calls >= 4 && final.reads >= 4, c.name << ": every retry was attempted and read");
      }
    }
    // A refusal before anything was written releases the write.
    auto root = fresh_root(base, "not-attempted");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed not-attempted");
    ConsensusCheckpointDbProbe::CheckpointStatus status;
    auto r = run_scenario(
        root, make_options(chain),
        [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
            td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
          auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
          auto [h6, s6] = co_await load_block(probe, chain["B6"].id);
          auto [h0, s0] = co_await load_block(probe, chain["B0"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::handoff, h6, s6, h0, s0, cp.handle, cp.state);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_persist_mode, Mode::NotAttempted, false);
          auto [h5, s5] = co_await load_block(probe, chain["B5"].id);
          co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::shard_client_advanced, h5, s5);
          co_await wait_seconds(db, 0.2);
          status = co_await checkpoint_status(probe, 4);
          co_return td::Unit{};
        });
    EXPECT(r.is_ok() && !status.in_flight && !status.uncertain && status.gc_may_persist_next &&
               status.installed == chain["B4"].id,
           "a write refused before anything was written releases GC and keeps the checkpoint");
  }

  // 15. Archive TTL pruning with the GC block at the checkpoint deletes older
  //     packages and keeps the checkpoint's; the restart reloads it. GC moved
  //     past the checkpoint loses it (the instrument can see the loss). Pruning
  //     runs in a child process (see retention_child), the checks after a restart.
  for (bool gc_past_checkpoint : {false, true}) {
    auto root = fresh_root(base, gc_past_checkpoint ? "retention-violated" : "retention");
    auto [code, log] = run_child(gc_past_checkpoint ? "retention-violated" : "retention", root);
    EXPECT(code == 0 && contains(log, "PRUNED=1"),
           "archive pruning ran and deleted the expected packages (exit " << code << ")");
    auto archive_chain = build_retention_chain(boc);
    std::map<std::string, bool> present;
    std::optional<td::Result<LoadedConsensusCleanupCheckpoint>> reloaded;
    auto r = run_scenario(root, make_options(archive_chain),
                          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                            for (const auto& name : {"R1", "R2", "R3"}) {
                              auto h =
                                  co_await td::actor::ask(db, &Db::get_block_handle, archive_chain[name].id).wrap();
                              present[name] = h.is_ok();
                            }
                            reloaded = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe).wrap();
                            co_return td::Unit{};
                          });
    if (!gc_past_checkpoint) {
      EXPECT(contains(log, "R1=0 R2=1 R3=1 LOADED=1"),
             "with GC at the checkpoint, pruning deleted the oldest package and kept the newest qualifying one and "
             "the checkpoint's; the checkpoint's handle and state load");
      EXPECT(r.is_ok() && present["R3"] && reloaded && reloaded->is_ok() && reloaded->ok().handle &&
                 reloaded->ok().handle->id() == archive_chain["R3"].id &&
                 reloaded->ok().state->get_block_id() == archive_chain["R3"].id,
             "after a restart the production loader reloads the checkpoint's handle and state");
    } else {
      EXPECT(contains(log, "R1=0 R2=0 R3=0"),
             "with GC past the checkpoint, pruning deletes the checkpoint's archive package too");
    }
  }

  // 16. Crash ordering and the cleanup flag, through the production startup,
  //     handoff and cleanup pass. The retired session (retired at B4, r = 1) is
  //     deletable only once the checkpoint is B5 or above (B4 is not an ancestor
  //     of B2).
  {
    Seed seed;
    seed.checkpoint = "B2";
    seed.retired = std::make_pair(std::string("B4"), CatchainSeqno{1});
    // (a) Before persistence: the write is held, a cleanup pass runs, the process crashes.
    auto root = fresh_root(base, "crash-before-persist");
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed crash-before-persist");
    auto [code_a, log_a] = run_child("pre-persist-crash", root);
    EXPECT(code_a == 137 && contains(log_a, "held=1 installed=2"),
           "the next checkpoint's write was issued and held, and not installed (exit " << code_a << ")");
    EXPECT(contains(log_a, "dir_present=1"), "a cleanup pass while that write is held deletes nothing");
    auto [code_a2, log_a2] = run_child("cleanup-pass", root);
    EXPECT(code_a2 == 0 && contains(log_a2, "checkpoint=" + chain["B2"].id.to_str()) &&
               contains(log_a2, "dir_present=true record_present=true"),
           "after the crash the checkpoint is still B2 and nothing is deleted (exit " << code_a2 << ")");
    // (b) After persistence: the checkpoint is synced and installed, the process
    //     crashes before any deletion; the restart deletes.
    root = fresh_root(base, "crash-after-persist");
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed crash-after-persist");
    auto [code_b, log_b] = run_child("persist-then-crash", root);
    EXPECT(code_b == 137 && contains(log_b, "installed=1 dir_present=1"),
           "the checkpoint advanced past B2 and the process crashed before deleting (exit " << code_b << ")");
    auto [code_b2, log_b2] = run_child("cleanup-pass", root);
    EXPECT(code_b2 == 0 && contains(log_b2, "dir_present=false record_present=false"),
           "after the restart the retired session's directory and record are deleted (exit " << code_b2 << ")");
    // (c) Cleanup disabled: the checkpoint still advances and still refuses
    //     rollback, nothing is deleted; re-enabled, the backlog is deleted.
    root = fresh_root(base, "cleanup-disabled");
    EXPECT(seed_db(root, chain, seed).is_ok(), "seed cleanup-disabled");
    auto [code_c, log_c] = run_child("advance-disabled", root);
    EXPECT(code_c == 0 && contains(log_c, "installed=1"),
           "with cleanup disabled the checkpoint advances (exit " << code_c << ")");
    auto [code_c2, log_c2] = run_child("cleanup-pass-disabled", root);
    EXPECT(code_c2 == 0 && contains(log_c2, "dir_present=true record_present=true"),
           "with cleanup disabled nothing is deleted (exit " << code_c2 << ")");
    auto [code_c3, log_c3] = run_child("truncate-below-disabled", root);
    EXPECT(code_c3 == 2 && contains(log_c3, "refusing to start from the truncation target"),
           "with cleanup disabled a truncation below the checkpoint is still refused (exit " << code_c3 << ")");
    auto [code_c4, log_c4] = run_child("cleanup-pass", root);
    EXPECT(code_c4 == 0 && contains(log_c4, "dir_present=false record_present=false"),
           "re-enabled, the backlog is deleted (exit " << code_c4 << ")");
  }

  // 17. Across a split and a merge, the cleanup oracles take each shard's
  //     catchain counter from the checkpoint's state. The counters are given by a
  //     fake state; this does not verify how production computes them.
  {
    auto root = fresh_root(base, "topology");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the topology database");
    const ShardIdFull parent{basechainId, static_cast<ShardId>(0x8000000000000000ULL)};
    const ShardIdFull left{basechainId, static_cast<ShardId>(0x4000000000000000ULL)};
    const ShardIdFull right{basechainId, static_cast<ShardId>(0xc000000000000000ULL)};
    const ShardIdFull merged{basechainId, static_cast<ShardId>(0x2000000000000000ULL)};
    // At the checkpoint: the parent split into left (7) and right (7), and the
    // shard `merged` has counter 9 after its children merged.
    std::map<ShardIdFull, CatchainSeqno> counters = {{parent, 6}, {left, 7}, {right, 7}, {merged, 9}};
    BlockIdExt cp_id{masterchainId, shardIdAll, 6, label_hash("topology-root"), label_hash("topology-file")};
    std::set<BlockIdExt> ancestors;
    for (const auto& name : {"B1", "B2", "B3", "B4", "B5"}) {
      ancestors.insert(chain[name].id);
    }
    auto topology = td::Ref<MasterchainState>{td::make_ref<TopologyState>(cp_id, counters, ancestors)};
    struct Row {
      ShardIdFull shard;
      CatchainSeqno r;
      bool expected;
    };
    std::vector<Row> rows = {{parent, 5, true}, {parent, 6, false}, {left, 6, true},   {left, 7, false},
                             {right, 6, true},  {right, 8, false},  {merged, 8, true}, {merged, 9, false}};
    std::vector<bool> with_checkpoint, with_gc;
    auto r = run_scenario(root, make_options(chain),
                          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_gc,
                                                    create_empty_block_handle(chain["B0"].id),
                                                    td::Ref<MasterchainState>{chain["B0"].state});
                            // A head that descends from the checkpoint.
                            BlockIdExt head_id{masterchainId, shardIdAll, 7, label_hash("topology-head-root"),
                                               label_hash("topology-head-file")};
                            auto head_ancestors = ancestors;
                            head_ancestors.insert(cp_id);
                            auto head_state = td::Ref<MasterchainState>{td::make_ref<TopologyState>(
                                head_id, std::map<ShardIdFull, CatchainSeqno>{}, head_ancestors)};
                            co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_head_and_checkpoint,
                                                    create_empty_block_handle(head_id), head_state,
                                                    create_empty_block_handle(cp_id), topology);
                            for (const auto& row : rows) {
                              auto d = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::cleanup_decision_in,
                                                               row.shard, chain["B4"].id, row.r, false);
                              with_checkpoint.push_back(d.second);
                            }
                            co_return td::Unit{};
                          });
    std::vector<bool> expected;
    for (const auto& row : rows) {
      expected.push_back(row.expected);
    }
    EXPECT(r.is_ok() && with_checkpoint == expected,
           "across split and merge, sessions with r below the checkpoint's counter for their shard are deletable "
           "and the others are not");
  }

  td::rmrf(base).ignore();
  if (g_failures > 0) {
    std::cerr << "CHECKPOINT_DB_FAILED: " << g_failures << " failure(s)\n";
    return 1;
  }
  std::cout << "CHECKPOINT_DB_ALL_OK\n";
  return 0;
}
