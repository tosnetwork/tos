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

#include "td/utils/tests.h"

using namespace tos::validator::consensus;

namespace {

tos::ValidatorSessionId make_session_id(unsigned char seed) {
  tos::ValidatorSessionId id;
  for (size_t i = 0; i < id.as_slice().size(); i++) {
    id.as_slice()[i] = static_cast<char>(seed + i * 7);
  }
  return id;
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
