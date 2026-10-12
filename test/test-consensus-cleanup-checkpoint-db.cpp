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
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
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
#include "td/actor/actor.h"
#include "td/actor/coro_task.h"
#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "quic/quic-sender.h"
#include "validator/consensus/consensus-cleanup-checkpoint.h"
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
  void set_gc(BlockHandle handle, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    gc_masterchain_handle_ = std::move(handle);
    gc_masterchain_state_ = std::move(state);
    promise.set_value(td::Unit());
  }
  // What started() does with the init result for the head and the checkpoint.
  void install_init_result(BlockHandle head, td::Ref<MasterchainState> head_state, BlockHandle checkpoint,
                           td::Ref<MasterchainState> checkpoint_state, td::Promise<bool> promise) {
    last_masterchain_block_handle_ = head;
    last_masterchain_block_id_ = head->id();
    last_masterchain_seqno_ = head->id().seqno();
    last_masterchain_state_ = std::move(head_state);
    install_loaded_consensus_cleanup_checkpoint(std::move(checkpoint), std::move(checkpoint_state));
    promise.set_value(bool{consensus_checkpoint_reached_});
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
  void admit(BlockIdExt head, td::Ref<MasterchainState> state, td::Promise<td::Unit> promise) {
    promise.set_result(admit_consensus_checkpoint_head(head, state));
  }
};

}  // namespace tos::validator

using namespace tos;
using namespace tos::validator;

namespace {

int g_failures = 0;
#define EXPECT(cond, what)                                                   \
  do {                                                                       \
    if (!(cond)) {                                                           \
      std::cerr << "CHECKPOINT_DB_FAILED: " << std::string(PSTRING() << what) << " (" #cond ")" << '\n'; \
      g_failures++;                                                          \
    } else {                                                                 \
      std::cout << "CHECKPOINT_DB_OK: " << std::string(PSTRING() << what) << '\n'; \
    }                                                                        \
  } while (0)

// ---- the chain --------------------------------------------------------------

struct ChainBlock {
  BlockIdExt id;
  td::Ref<MasterchainStateQ> state;
  std::optional<BlockIdExt> prev;
  std::optional<BlockIdExt> next;
};

struct Chain {
  td::BufferSlice genesis_boc;
  std::map<std::string, ChainBlock> blocks;  // "B0".."B6", "F4", "F5"
  const ChainBlock& operator[](const std::string& name) const {
    return blocks.at(name);
  }
};

td::Bits256 label_hash(td::Slice label) {
  return td::sha256_bits256(label);
}

// The state of `seqno` whose prev_blocks additionally records `prev`.
td::Result<td::Ref<vm::Cell>> derive_state(td::Ref<vm::Cell> prev_root, const BlockIdExt& prev, const BlockIdExt& genesis,
                                           LogicalTime genesis_lt) {
  block::gen::ShardStateUnsplit::Record info;
  if (!tlb::unpack_cell(prev_root, info)) {
    return td::Status::Error("cannot unpack the previous state");
  }
  auto prev_lt = info.gen_lt;
  info.seq_no = prev.seqno() + 1;
  info.gen_utime += 1;
  info.gen_lt += 1000000;
  vm::CellSlice custom = *info.custom;
  if (custom.fetch_ulong(1) != 1) {
    return td::Status::Error("the previous state has no masterchain extra");
  }
  block::gen::McStateExtra::Record extra;
  if (!tlb::unpack_cell(custom.prefetch_ref(), extra)) {
    return td::Status::Error("cannot unpack McStateExtra");
  }
  vm::AugmentedDictionary dict{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  vm::CellBuilder cb;
  if (!(cb.store_bool_bool(prev.seqno() == 0) && cb.store_long_bool(prev_lt, 64) &&
        cb.store_long_bool(prev.seqno(), 32) && cb.store_bits_bool(prev.root_hash) &&
        cb.store_bits_bool(prev.file_hash) &&
        dict.set_builder(td::BitArray<32>(prev.seqno()), cb, vm::Dictionary::SetMode::Add))) {
    return td::Status::Error("cannot add the previous block to prev_blocks");
  }
  extra.r1.prev_blocks = std::move(dict).extract_root();
  vm::CellBuilder last_key;
  if (!(last_key.store_bool_bool(true) && last_key.store_long_bool(genesis_lt, 64) &&
        last_key.store_long_bool(genesis.seqno(), 32) && last_key.store_bits_bool(genesis.root_hash) &&
        last_key.store_bits_bool(genesis.file_hash))) {
    return td::Status::Error("cannot store last_key_block");
  }
  extra.r1.last_key_block = vm::load_cell_slice_ref(last_key.finalize());
  extra.r1.after_key_block = prev.seqno() == 0;
  td::Ref<vm::Cell> extra_cell;
  if (!tlb::pack_cell(extra_cell, extra)) {
    return td::Status::Error("cannot pack McStateExtra");
  }
  vm::CellBuilder custom_cb;
  if (!(custom_cb.store_bool_bool(true) && custom_cb.store_ref_bool(extra_cell))) {
    return td::Status::Error("cannot store custom");
  }
  info.custom = vm::load_cell_slice_ref(custom_cb.finalize());
  td::Ref<vm::Cell> root;
  if (!tlb::pack_cell(root, info)) {
    return td::Status::Error("cannot pack the state");
  }
  return root;
}

td::Result<Chain> build_chain(const std::string& boc_path) {
  std::ifstream input(boc_path, std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    return td::Status::Error("cannot read the genesis BOC");
  }
  Chain chain;
  chain.genesis_boc = td::BufferSlice{bytes.str()};
  TRY_RESULT(root, vm::std_boc_deserialize(chain.genesis_boc.as_slice()));
  BlockIdExt zero{masterchainId, shardIdAll, 0, td::Bits256(root->get_hash().bits()),
                  block::compute_file_hash(chain.genesis_boc.as_slice())};
  TRY_RESULT(zero_state, MasterchainStateQ::fetch(zero, chain.genesis_boc.clone(), root));
  auto genesis_lt = zero_state->get_logical_time();
  chain.blocks["B0"] = ChainBlock{zero, zero_state, std::nullopt, std::nullopt};
  auto extend = [&](const std::string& parent, const std::string& name, BlockSeqno seqno) -> td::Status {
    const auto& p = chain.blocks.at(parent);
    TRY_RESULT(state_root, derive_state(p.state->root_cell(), p.id, zero, genesis_lt));
    BlockIdExt id{masterchainId, shardIdAll, seqno, label_hash(PSLICE() << "checkpoint-root-" << name),
                  label_hash(PSLICE() << "checkpoint-file-" << name)};
    TRY_RESULT(state, MasterchainStateQ::fetch(id, td::BufferSlice{}, state_root));
    chain.blocks[name] = ChainBlock{id, state, p.id, std::nullopt};
    return td::Status::OK();
  };
  for (BlockSeqno s = 1; s <= 6; s++) {
    TRY_STATUS(extend(PSTRING() << "B" << s - 1, PSTRING() << "B" << s, s));
    chain.blocks[PSTRING() << "B" << s - 1].next = chain.blocks[PSTRING() << "B" << s].id;
  }
  TRY_STATUS(extend("B3", "F4", 4));
  TRY_STATUS(extend("F4", "F5", 5));
  chain.blocks["F4"].next = chain.blocks["F5"].id;
  return chain;
}

// ---- running the production actors ----------------------------------------

using Body = std::function<td::actor::Task<td::Unit>(td::actor::ActorId<ConsensusCheckpointDbProbe>,
                                                     td::actor::ActorId<Db>)>;

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
};

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

int child_main(const std::string& mode, const std::string& boc, const std::string& root) {
  auto r_chain = build_chain(boc);
  if (r_chain.is_error()) {
    std::cerr << "child: " << r_chain.error().to_string() << '\n';
    return 1;
  }
  auto chain = r_chain.move_as_ok();
  auto opts = make_options(chain);
  if (mode == "truncate-below") {
    opts.write().truncate_db(2);
  } else if (mode == "truncate-descendant") {
    opts.write().truncate_db(5);
  } else if (mode == "hardfork-below") {
    opts.write().set_hardforks({BlockIdExt{masterchainId, shardIdAll, 3, label_hash("hardfork-root"),
                                           label_hash("hardfork-file")}});
  }
  std::string outcome;
  auto status = run_scenario(
      root, opts,
      [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
          td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
        auto [task, promise] = td::actor::StartedTask<ValidatorManagerInitResult>::make_bridge();
        validator_manager_init(opts, probe, db, std::move(promise));
        auto result = co_await std::move(task);
        auto ready = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::install_init_result, result.handle,
                                             result.state, result.consensus_cleanup_checkpoint_handle,
                                             result.consensus_cleanup_checkpoint_state);
        outcome = PSTRING() << "head=" << result.handle->id().seqno() << " checkpoint="
                            << (result.consensus_cleanup_checkpoint_handle
                                    ? result.consensus_cleanup_checkpoint_handle->id().to_str()
                                    : std::string("none"))
                            << " ready=" << ready;
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

int spawn_child(const char* program, const std::string& mode, const std::string& boc, const std::string& root) {
  std::string m = mode, b = boc, r = root;
  std::string flag = "--child";
  char* args[] = {const_cast<char*>(program), flag.data(), m.data(), b.data(), r.data(), nullptr};
  pid_t pid = -1;
  if (posix_spawn(&pid, program, nullptr, nullptr, args, environ) != 0) {
    return -1;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
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
      auto r = run_scenario(root, make_options(chain),
                            [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                                td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                              loaded = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
                              // State GC with the GC block at the checkpoint.
                              co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::set_gc, loaded->handle,
                                                      loaded->state);
                              state_gc_keeps_checkpoint = !co_await td::actor::ask(
                                  probe, &ValidatorManager::allow_block_state_gc, chain["B4"].id);
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
    EXPECT(consensus::is_consensus_checkpoint_refusal(boundary("F5", true)), "a higher block off its branch is refused");
    EXPECT(consensus::is_consensus_checkpoint_refusal(check_consensus_cleanup_checkpoint_boundary(
               cp, chain["B6"].id, chain["B5"].state, true, "test")),
           "a head whose state is not its own is refused");
  }

  // 4. RootDb::truncate refuses before dispatching any mutation.
  {
    auto root = fresh_root(base, "truncate");
    EXPECT(seed_db(root, chain, {}).is_ok(), "seed the truncation database");
    auto before = snapshot_db(root, chain);
    EXPECT(before.is_ok() && before.ok().handle_present.at("B6"), "B6 is readable before truncation");
    for (const auto& [seqno, name] : std::vector<std::pair<BlockSeqno, std::string>>{
             {2, "B2"}, {4, "F4"}, {5, "F5"}}) {
      auto r = run_scenario(root, make_options(chain), [&](auto, auto db) -> td::actor::Task<td::Unit> {
        auto handle = co_await td::actor::ask(db, &Db::get_block_handle, chain[name].id);
        co_await td::actor::ask(db, &Db::truncate, seqno, ConstBlockHandle{handle});
        co_return td::Unit{};
      });
      EXPECT(r.is_error() && consensus::is_consensus_checkpoint_refusal(r),
             "RootDb refuses truncation to " << name << ": " << r);
      auto after = snapshot_db(root, chain);
      EXPECT(after.is_ok() && after.ok().shard_client == chain["B6"].id && after.ok().init == std::optional<BlockIdExt>{chain["B6"].id} &&
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
  };
  std::vector<StartupCase> cases;
  cases.push_back({"plain", {}, [&](const std::string& root) { put_raw_checkpoint(root, td::Slice{"garbage"}); }, 2,
                   "a damaged checkpoint stops startup with exit status 2"});
  cases.push_back({"truncate-below", {}, nullptr, 2, "--truncate-db below the checkpoint is refused"});
  cases.push_back({"hardfork-below", {}, nullptr, 2, "a hardfork below the checkpoint is refused"});
  {
    Seed conflicting;
    conflicting.init = "F5";
    cases.push_back({"plain", conflicting, nullptr, 2, "an init block off the checkpoint's branch is refused"});
  }
  {
    Seed missing_init;
    missing_init.write_init = false;
    cases.push_back({"plain", missing_init, nullptr, 2,
                     "reinitialization below the checkpoint is refused before the shard client writes"});
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
    int code = spawn_child(argv[0], c.mode, boc, root);
    EXPECT(code == c.expected_exit, c.what << " (exit " << code << ")");
    if (c.expected_exit == 2 && !c.damage) {
      auto after = snapshot_db(root, chain);
      bool same = before.is_ok() && after.is_ok() && before.ok().init == after.ok().init &&
                  before.ok().gc == after.ok().gc && before.ok().shard_client == after.ok().shard_client &&
                  before.ok().checkpoint == after.ok().checkpoint &&
                  before.ok().hardforks == after.ok().hardforks &&
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
    auto r = run_scenario(root, make_options(chain),
                          [&](td::actor::ActorId<ConsensusCheckpointDbProbe> probe,
                              td::actor::ActorId<Db> db) -> td::actor::Task<td::Unit> {
                            auto cp = co_await load_consensus_cleanup_checkpoint_for_startup(db, probe);
                            auto handle = [&](const std::string& name) {
                              auto h = create_empty_block_handle(chain[name].id);
                              return h;
                            };
                            ready.push_back(co_await td::actor::ask(
                                probe, &ConsensusCheckpointDbProbe::install_init_result, handle("B2"),
                                td::Ref<MasterchainState>{chain["B2"].state}, cp.handle, cp.state));
                            for (const auto& name : {"B3", "B4", "B5"}) {
                              ready.push_back(co_await td::actor::ask(
                                  probe, &ConsensusCheckpointDbProbe::replay_head, handle(name),
                                  td::Ref<MasterchainState>{chain[name].state}));
                            }
                            for (const auto& name : {"F4", "F5", "B6", "B3"}) {
                              auto a = co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::admit,
                                                               chain[name].id,
                                                               td::Ref<MasterchainState>{chain[name].state})
                                           .wrap();
                              admitted.push_back(a.is_ok());
                            }
                            ready.push_back(co_await td::actor::ask(probe, &ConsensusCheckpointDbProbe::replay_head,
                                                                    handle("F5"),
                                                                    td::Ref<MasterchainState>{chain["F5"].state}));
                            co_return td::Unit{};
                          });
    EXPECT(r.is_ok(), "readiness scenario ran: " << r);
    EXPECT(ready == (std::vector<bool>{false, false, true, true, false}),
           "validation waits for the replay to reach the checkpoint, needs no rotation, and stops on a conflict");
    EXPECT(admitted == (std::vector<bool>{false, false, true, true}),
           "heads off the checkpoint's branch are refused before installation; descendants and older blocks are not");
  }

  td::rmrf(base).ignore();
  if (g_failures > 0) {
    std::cerr << "CHECKPOINT_DB_FAILED: " << g_failures << " failure(s)\n";
    return 1;
  }
  std::cout << "CHECKPOINT_DB_ALL_OK\n";
  return 0;
}
