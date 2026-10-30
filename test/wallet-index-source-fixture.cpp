/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Test fixture: a valid node database with no chain in it. Opens the node
// database at --db as its owner would, so every store it holds is created
// with its metadata, waits until each store has answered a request, then
// stops. A wallet-index service pointed at it starts normally and finds no
// applied masterchain block: the source's tip read fails with a retryable
// error, never a crash on opening it.
#include <atomic>
#include <iostream>
#include <string>

#include "td/actor/actor.h"
#include "td/utils/OptionParser.h"
#include "td/utils/port/path.h"
#include "validator/db/rootdb.hpp"
#include "validator/validator-options.hpp"

int main(int argc, char** argv) {
  using namespace tos;
  std::string path;
  td::OptionParser parser;
  parser.set_description("Create an empty, initialized node database for wallet-index tests.");
  parser.add_option('\0', "db", "node database directory to create", [&](td::Slice v) { path = v.str(); });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error() || path.empty()) {
    std::cerr << "specify --db\n";
    return 2;
  }
  auto made = td::mkpath(path + "/");
  if (made.is_error()) {
    std::cerr << "cannot create " << path << ": " << made.message().str() << '\n';
    return 1;
  }
  // Each store answers once it has opened: the state store (no shard client
  // state), the cell store (a reader) and the archive (no masterchain block 1).
  std::atomic<int> pending{3};
  std::atomic<bool> unexpected{false};
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<validator::RootDb> db;
  auto answered = [&](bool expected) {
    if (!expected) {
      unexpected = true;
    }
    if (--pending == 0) {
      db.reset();
      td::actor::SchedulerContext::get().stop();
    }
  };
  scheduler.run_in_context([&] {
    auto options = validator::ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
    options.write().set_disable_rocksdb_stats(true);
    db = td::actor::create_actor<validator::RootDb>("source-fixture", td::actor::ActorId<validator::ValidatorManager>{},
                                                    path, options, td::DbOpenMode::db_primary);
    td::actor::send_closure(db, &validator::RootDb::get_shard_client_state,
                            td::PromiseCreator::lambda([&](td::Result<BlockIdExt> state) { answered(state.is_error()); }));
    td::actor::send_closure(
        db, &validator::RootDb::get_cell_db_reader,
        td::PromiseCreator::lambda([&](td::Result<std::shared_ptr<vm::CellDbReader>> reader) {
          answered(reader.is_ok() && reader.ok() != nullptr);
        }));
    td::actor::send_closure(
        db, &validator::RootDb::get_block_by_seqno, AccountIdPrefixFull(masterchainId, shardIdAll), 1,
        td::PromiseCreator::lambda([&](td::Result<validator::ConstBlockHandle> block) { answered(block.is_error()); }));
  });
  while (scheduler.run(1)) {
  }
  if (unexpected.load()) {
    std::cerr << "the fixture database did not open as an empty node database\n";
    return 1;
  }
  return 0;
}
