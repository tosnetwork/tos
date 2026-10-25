/*
 * Copyright (c) 2026, TOS Blockchain Teams
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include <cstdlib>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

#include "td/actor/actor.h"
#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "tos/tos-tl.hpp"
#include "validator/consensus/db-path.h"
#include "validator/consensus/validator-cleanup-store.h"
#include "validator/db/statedb.hpp"

namespace {
using namespace tos::validator;

td::Bits256 fixture_hash(char value) {
  td::Bits256 hash;
  hash.as_slice().fill(value);
  return hash;
}
const tos::BlockIdExt block{tos::masterchainId, static_cast<tos::ShardId>(0x8000000000000000ULL), 7, fixture_hash(2),
                            fixture_hash(3)};

class Fixture {
 public:
  explicit Fixture(const std::string& path) : scheduler_({1}) {
    scheduler_.run_in_context([&] {
      db_ = td::actor::create_actor<StateDb>("state", td::actor::ActorId<RootDb>{}, path, td::DbOpenMode::db_primary);
    });
  }
  template <class T, class Send>
  T ask(Send send) {
    std::mutex mutex;
    std::optional<td::Result<T>> result;
    auto ready = [&] {
      std::lock_guard<std::mutex> lock(mutex);
      return result.has_value();
    };
    scheduler_.run_in_context([&] {
      send(td::PromiseCreator::lambda([&](td::Result<T> value) {
        std::lock_guard<std::mutex> lock(mutex);
        result.emplace(std::move(value));
      }));
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!ready()) {
      CHECK(!deadline.is_in_past());
      scheduler_.run(0.01);
    }
    std::lock_guard<std::mutex> lock(mutex);
    return result->move_as_ok();
  }
  void create() {
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_init_masterchain_block, block, std::move(promise));
    });
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_gc_masterchain_block, block, std::move(promise));
    });
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_shard_client_state, block, std::move(promise));
    });
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_destroyed_validator_sessions,
                              std::vector<tos::ValidatorSessionId>{td::Bits256::zero()}, std::move(promise));
    });
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_pending_consensus_db_cleanup, std::vector<std::string>{},
                              std::move(promise));
    });
    auto cleanup = cleanup_record();
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_pending_validator_consensus_db_cleanup, cleanup,
                              std::move(promise));
    });
    ask<td::Unit>([&](auto promise) {
      td::actor::send_closure(db_.get(), &StateDb::update_hardforks, std::vector<tos::BlockIdExt>{},
                              std::move(promise));
    });
  }
  void verify() {
    CHECK(ask<tos::BlockIdExt>([&](auto p) {
            td::actor::send_closure(db_.get(), &StateDb::get_init_masterchain_block, std::move(p));
          }) == block);
    CHECK(ask<tos::BlockIdExt>([&](auto p) {
            td::actor::send_closure(db_.get(), &StateDb::get_gc_masterchain_block, std::move(p));
          }) == block);
    CHECK(ask<tos::BlockIdExt>([&](auto p) {
            td::actor::send_closure(db_.get(), &StateDb::get_shard_client_state, std::move(p));
          }) == block);
    auto sessions = ask<std::vector<tos::ValidatorSessionId>>(
        [&](auto p) { td::actor::send_closure(db_.get(), &StateDb::get_destroyed_validator_sessions, std::move(p)); });
    CHECK(sessions == std::vector<tos::ValidatorSessionId>{td::Bits256::zero()});
    auto dirs = ask<std::vector<std::string>>(
        [&](auto p) { td::actor::send_closure(db_.get(), &StateDb::get_pending_consensus_db_cleanup, std::move(p)); });
    CHECK(dirs.empty());
    auto cleanup = ask<std::optional<consensus::PendingValidatorConsensusDbCleanup>>([&](auto p) {
      td::actor::send_closure(db_.get(), &StateDb::get_pending_validator_consensus_db_cleanup_record,
                              cleanup_record().session_id, std::move(p));
    });
    CHECK(cleanup.has_value() && cleanup.value() == cleanup_record());
  }

 private:
  static consensus::PendingValidatorConsensusDbCleanup cleanup_record() {
    td::Bits256 id;
    id.as_slice().fill(static_cast<char>(0xab));
    return {id, block,
            consensus::consensus_db_dir_name(tos::ShardIdFull{0, static_cast<tos::ShardId>(0x8000000000000000ULL)}, 1,
                                             id, "")};
  }
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<StateDb> db_;
};
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    LOG(ERROR) << "usage: test-node-store-fixture create-wal|verify STATE_DIRECTORY";
    return 2;
  }
  std::string mode = argv[1];
  if (mode != "create-wal" && mode != "verify") {
    return 2;
  }
  Fixture fixture(argv[2]);
  if (mode == "create-wal") {
    fixture.create();
    fixture.verify();
    // Leave only acknowledged WAL writes: no close/destructor-triggered flush.
    std::_Exit(0);
  }
  fixture.verify();
  LOG(INFO) << "NODE_STORE_NATIVE_REOPEN_OK";
  return 0;
}
