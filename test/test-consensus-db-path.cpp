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

#include <cerrno>
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

// A deleter that removes the directory and confirms via stat, matching the
// production deleter exactly: only a "not found" error counts as gone (minus
// RocksDb::destroy, which needs no real DB here).
bool confirming_deleter(td::CSlice full) {
  td::rmrf(full).ignore();
  auto probe = td::stat(full);
  if (probe.is_ok()) {
    return false;
  }
#if TD_PORT_WINDOWS
  auto code = probe.error().code();
  return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
#else
  return probe.error().code() == ENOENT;
#endif
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
  auto name = consensus_db_dir_name(kShard, 7, make_session_id(9), td::Slice(".observer.ab"));
  create_group_dir(root, name);

  std::set<std::string> pending{name};
  auto stats = sweep_orphaned_consensus_dbs(root, pending, confirming_deleter);

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(1));
  ASSERT_TRUE(pending.empty());
  ASSERT_TRUE(!dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A validator directory (no observer suffix) that is NOT in the queue must never
// be deleted by the sweep, whatever else is on disk. Validator-group cleanup is
// checkpoint-bound in the manager (Finding 1 / PR B), never a fence match here,
// so a still-recreatable session can never lose its consensus state at startup.
// If the sweep regained a by-session-id deletion path, this would fail.
TEST(ConsensusDbSweep, never_sweeps_unqueued_validator_directory) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 4, make_session_id(13), td::Slice(""));  // validator dir
  create_group_dir(root, name);

  std::set<std::string> pending;  // empty queue: validators are never queued
  bool deleter_called = false;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, [&](td::CSlice) {
    deleter_called = true;
    return true;
  });

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(0));
  ASSERT_TRUE(!deleter_called);
  ASSERT_TRUE(dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A directory that is not queued is a live/unrelated group and must never be
// touched (observer or validator alike).
TEST(ConsensusDbSweep, leaves_unqueued_directory) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(1), td::Slice(""));
  create_group_dir(root, name);

  std::set<std::string> pending;
  bool deleter_called = false;
  auto stats = sweep_orphaned_consensus_dbs(root, pending, [&](td::CSlice) {
    deleter_called = true;
    return true;
  });

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_EQ(stats.reclaimed, static_cast<size_t>(0));
  ASSERT_TRUE(!deleter_called);
  ASSERT_TRUE(dir_exists(root, name));
  td::rmrf(root).ignore();
}

// A deletion that is not confirmed gone keeps the directory queued for a later
// retry rather than dropping it (which would leak the orphan).
TEST(ConsensusDbSweep, unconfirmed_deletion_stays_queued) {
  auto root = make_temp_root();
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(2), td::Slice(".observer.cd"));
  create_group_dir(root, name);

  std::set<std::string> pending{name};
  auto stats = sweep_orphaned_consensus_dbs(root, pending, [](td::CSlice) { return false; });

  ASSERT_EQ(stats.failed, static_cast<size_t>(1));
  ASSERT_TRUE(pending.count(name) == 1);
  td::rmrf(root).ignore();
}

// After a fully successful walk, a queued name with no directory on disk was
// already deleted (its dequeue was lost to a crash), so it is reconciled away.
TEST(ConsensusDbSweep, reconciles_already_gone_entry_after_successful_walk) {
  auto root = make_temp_root();  // consensus/ exists but is empty
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(5), td::Slice(".observer.ef"));

  std::set<std::string> pending{name};
  auto stats = sweep_orphaned_consensus_dbs(root, pending, confirming_deleter);

  ASSERT_TRUE(stats.walk_succeeded);
  ASSERT_TRUE(pending.empty());
  td::rmrf(root).ignore();
}

// If enumeration fails (here: no consensus/ directory at all), absence is not
// proven, so a queued entry must NOT be reconciled away.
TEST(ConsensusDbSweep, keeps_queue_when_walk_fails) {
  auto root = PSTRING() << "test-consensus-sweep-missing-" << td::Random::fast_uint32();
  td::rmrf(root).ignore();  // neither root nor root/consensus exists
  auto name = consensus_db_dir_name(kShard, 3, make_session_id(6), td::Slice(".observer.gh"));

  std::set<std::string> pending{name};
  auto stats = sweep_orphaned_consensus_dbs(root, pending, [](td::CSlice) { return true; });

  ASSERT_TRUE(!stats.walk_succeeded);
  ASSERT_TRUE(pending.count(name) == 1);
}
