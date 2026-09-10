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
#include "validator/consensus/db-path.h"

#include "td/utils/Random.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

#include <set>

using namespace tos::validator::consensus;

namespace {

tos::ValidatorSessionId make_session_id(unsigned char seed) {
  tos::ValidatorSessionId id;
  for (size_t i = 0; i < id.as_slice().size(); i++) {
    id.as_slice()[i] = static_cast<char>(seed + i * 7);
  }
  return id;
}

const tos::ShardIdFull kShard{0, static_cast<tos::ShardId>(0x8000000000000000ULL)};

std::string make_temp_root() {
  auto root = PSTRING() << "test-consensus-sweep-" << td::Random::fast_uint32();
  td::rmrf(root).ignore();
  td::mkpath(consensus_db_root(root)).ensure();  // creates <root>/consensus/
  return root;
}

// Create <root>/consensus/<dir_name>/ so WalkPath sees it as a group directory.
void create_group_dir(const std::string &root, const std::string &dir_name) {
  td::mkpath(consensus_db_root(root) + dir_name + "/").ensure();
}

bool dir_exists(const std::string &root, const std::string &dir_name) {
  return td::stat(consensus_db_root(root) + dir_name).is_ok();
}

// A deleter that actually removes the directory and confirms via stat -- the
// production shape (minus RocksDb::destroy, which needs no real DB here).
bool confirming_deleter(td::CSlice full) {
  td::rmrf(full).ignore();
  return td::stat(full).is_error();
}

}  // namespace

// The sweep at startup decides what to delete by recovering a session id
// from a directory name. If the name cannot be parsed back, the sweep
// reclaims nothing and the leak it exists for stays: the guard would be
// there and do nothing. These pin the round trip in both directions.
TEST(ConsensusDbPath, name_round_trips_to_its_session) {
  auto session_id = make_session_id(3);
  tos::ShardIdFull shard{0, static_cast<tos::ShardId>(0x8000000000000000ULL)};

  for (const char* suffix : {"", ".observer", ".observer.2"}) {
    auto name = consensus_db_dir_name(shard, 42, session_id, td::Slice(suffix));
    auto recovered = consensus_db_session_id(name);
    ASSERT_TRUE(recovered.has_value());
    ASSERT_TRUE(recovered.value() == session_id);
  }
}

TEST(ConsensusDbPath, distinct_sessions_do_not_collide) {
  tos::ShardIdFull shard{-1, static_cast<tos::ShardId>(0x8000000000000000ULL)};
  auto first = consensus_db_dir_name(shard, 1, make_session_id(1), td::Slice(""));
  auto second = consensus_db_dir_name(shard, 1, make_session_id(2), td::Slice(""));
  ASSERT_TRUE(first != second);
  ASSERT_TRUE(consensus_db_session_id(first).value() != consensus_db_session_id(second).value());
}

// A directory this cannot parse is not ours, and deleting it would be a
// far worse failure than leaving a stale one behind.
TEST(ConsensusDbPath, unrelated_names_are_refused) {
  for (const char* name : {"", "consensus", "consensus.", "consensus.0.1.2", "consensus.0.1.2.",
                           "consensus.0.1.2.nothex", "catchains", "random-dir", "db", "consensus.0.1.2.abc"}) {
    ASSERT_TRUE(!consensus_db_session_id(td::Slice(name)).has_value());
  }
}

TEST(ConsensusDbPath, root_is_under_the_db_root) {
  auto root = consensus_db_root(td::Slice("/var/lib/tos"));
  ASSERT_STREQ("/var/lib/tos/consensus/", root);
}

// The cleanup sweep is what closes the orphan window: a retired group's
// directory that outlived its deletion (crash between the durable retirement
// record and the removal) must be reclaimed at startup. These drive the
// decision/reconciliation core with an injected deleter, so the logic is tested
// without a live validator manager.

// A queued directory is deleted and dequeued. Removing the pending gate (so a
// queued-only directory is skipped) makes reclaimed == 0 and leaves it queued.
TEST(ConsensusDbSweep, reclaims_queued_directory) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 7, make_session_id(9), td::Slice(""));
  create_group_dir(root, name);

  std::set<std::string> pending{name};
  std::set<tos::ValidatorSessionId> destroyed;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, confirming_deleter);

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(1));
  ASSERT_TRUE(pending.empty());
  ASSERT_TRUE(!dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A pre-upgrade directory recorded only by destroyed session id (not queued) is
// still migrated (deleted) as a legacy fallback.
TEST(ConsensusDbSweep, migrates_legacy_destroyed_directory) {
  auto root = make_temp_root();
  auto sid = make_session_id(11);
  auto name = consensus_db_dir_name(kShard, 3, sid, td::Slice(""));
  create_group_dir(root, name);

  std::set<std::string> pending;
  std::set<tos::ValidatorSessionId> destroyed{sid};
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, confirming_deleter);

  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(1));
  ASSERT_TRUE(!dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A directory that is neither queued nor recorded destroyed is a live/unrelated
// group and must never be touched.
TEST(ConsensusDbSweep, leaves_unrelated_directory) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(1), td::Slice(""));
  create_group_dir(root, name);

  std::set<std::string> pending;
  std::set<tos::ValidatorSessionId> destroyed;
  bool deleter_called = false;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, [&](td::CSlice) {
    deleter_called = true;
    return true;
  });

  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(0));
  ASSERT_TRUE(!deleter_called);
  ASSERT_TRUE(dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A deletion that is not confirmed gone keeps the directory queued for a later
// retry rather than dropping it (which would leak the orphan).
TEST(ConsensusDbSweep, unconfirmed_deletion_stays_queued) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(2), td::Slice(""));
  create_group_dir(root, name);

  std::set<std::string> pending{name};
  std::set<tos::ValidatorSessionId> destroyed;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, [](td::CSlice) { return false; });

  ASSERT_EQ(stats.failed, static_cast<size_t>(1));
  ASSERT_TRUE(pending.count(name) == 1);
  td::rmrf(root).ignore();
}

// After a fully successful walk, a queued name with no directory on disk was
// already deleted (its dequeue was lost to a crash), so it is reconciled away.
TEST(ConsensusDbSweep, reconciles_already_gone_entry_after_successful_walk) {
  auto root = make_temp_root();  // consensus/ exists but is empty
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(5), td::Slice(""));

  std::set<std::string> pending{name};
  std::set<tos::ValidatorSessionId> destroyed;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, confirming_deleter);

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_TRUE(pending.empty());
  td::rmrf(root).ignore();
}

// If enumeration fails (here: no consensus/ directory at all), absence is not
// proven, so a queued entry must NOT be reconciled away.
TEST(ConsensusDbSweep, keeps_queue_when_walk_fails) {
  auto root = PSTRING() << "test-consensus-sweep-missing-" << td::Random::fast_uint32();
  td::rmrf(root).ignore();  // neither root nor root/consensus exists
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(6), td::Slice(""));

  std::set<std::string> pending{name};
  std::set<tos::ValidatorSessionId> destroyed;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, destroyed, [](td::CSlice) { return true; });

  ASSERT_TRUE(!stats.walk_succeeded);
  ASSERT_TRUE(pending.count(name) == 1);
}
