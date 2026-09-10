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
// Round-trips the validator cleanup records against a real RocksDb, exercising
// the SAME production store/erase/load functions StateDb uses (validator-cleanup-
// store.h). Disabling the production set/erase/scan fails these tests. Pins the
// scan bounds with valid, decodable records placed just outside them, and the
// decode-skip of malformed values.
#include "validator/consensus/validator-cleanup-store.h"

#include "td/db/RocksDb.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

#include <set>
#include <vector>

using namespace tos::validator::consensus;

namespace {

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

const tos::ShardId kMasterShard = static_cast<tos::ShardId>(0x8000000000000000ULL);
const tos::ShardIdFull kShard{0, kMasterShard};

tos::BlockIdExt make_checkpoint(tos::BlockSeqno seqno) {
  return tos::BlockIdExt{tos::masterchainId, kMasterShard, seqno, make_hash(static_cast<unsigned char>(seqno)),
                         make_hash(static_cast<unsigned char>(seqno + 128))};
}

PendingValidatorConsensusDbCleanup make_record(unsigned char sid_seed, tos::BlockSeqno retire_seqno,
                                               tos::CatchainSeqno cc = 7) {
  auto sid = make_session_id(sid_seed);
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  r.retirement_checkpoint = make_checkpoint(retire_seqno);
  r.dir_name = consensus_db_dir_name(kShard, cc, sid, td::Slice(""));
  return r;
}

// Write a raw value under an arbitrary key (for out-of-range and malformed
// fixtures that the production store functions would never create).
void put_raw(td::RocksDb& kv, td::Slice key, td::Slice value) {
  kv.begin_write_batch().ensure();
  kv.set(key, value).ensure();
  kv.commit_write_batch().ensure();
}

std::string temp_db_path() {
  auto path = PSTRING() << "test-validator-cleanup-statedb-" << td::Random::fast_uint32();
  td::rmrf(path).ignore();
  return path;
}

}  // namespace

// Two records persist via the production store function and reload intact; a
// malformed value under a real cleanup key is dropped; erasing one removes
// exactly it.
TEST(ValidatorCleanupStateDb, round_trip_and_erase) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();

    auto r1 = make_record(9, 100);
    auto r2 = make_record(200, 150);
    store_validator_cleanup_record(kv, r1);
    store_validator_cleanup_record(kv, r2);

    // Malformed value under a real cleanup key: skipped on load.
    put_raw(kv, td::Slice{validator_cleanup_key(make_session_id(50))}, td::Slice{"not-a-record"});

    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(2));
    std::set<std::string> got;
    for (const auto& r : loaded) {
      got.insert(r.session_id.to_hex());
    }
    ASSERT_TRUE(got.count(r1.session_id.to_hex()) == 1);
    ASSERT_TRUE(got.count(r2.session_id.to_hex()) == 1);

    erase_validator_cleanup_record(kv, r1.session_id);
    auto after = load_validator_cleanup_records(kv);
    ASSERT_EQ(after.size(), static_cast<size_t>(1));
    ASSERT_TRUE(after[0] == r2);
  }
  td::rmrf(path).ignore();
}

// Scan bounds: VALID, decodable records placed at keys just below the prefix and
// exactly at the exclusive upper bound must NOT be returned, while an in-range
// record is. Because these fixtures decode successfully, an over-broad begin or
// an inclusive/over-broad end would change the returned set -- which undecodable
// sentinels could not reveal.
TEST(ValidatorCleanupStateDb, scan_excludes_valid_records_outside_bounds) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();

    auto in_range = make_record(9, 100);
    store_validator_cleanup_record(kv, in_range);

    // LITERAL out-of-range keys, independent of the helpers, so mutating the
    // helper's bound (without also moving these fixtures) is caught. The valid
    // prefix is "...cleanup." (0x2e); a key with "...cleanup-" (0x2d) sorts just
    // below begin, and keys under "...cleanup/" (0x2f) sort at/after the exclusive
    // end. Both hold a VALID encoded record, so a too-low begin or an over-broad
    // end would change the returned set.
    const std::string below_key =
        std::string("tos.state.pending_validator_consensus_db_cleanup-") + make_session_id(40).to_hex();
    const std::string at_or_above_key =
        std::string("tos.state.pending_validator_consensus_db_cleanup/") + make_session_id(41).to_hex();
    put_raw(kv, td::Slice{below_key}, td::Slice{encode_validator_cleanup_record(make_record(40, 77))});
    put_raw(kv, td::Slice{at_or_above_key}, td::Slice{encode_validator_cleanup_record(make_record(41, 88))});

    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == in_range);
  }
  td::rmrf(path).ignore();
}

// Storing the same session again overwrites: one record, the latest value.
TEST(ValidatorCleanupStateDb, same_session_overwrites) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, make_record(9, 100));
    auto newer = make_record(9, 200);
    store_validator_cleanup_record(kv, newer);
    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == newer);
  }
  td::rmrf(path).ignore();
}

// Erasing a session that was never stored is a harmless no-op.
TEST(ValidatorCleanupStateDb, erase_absent_is_noop) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto r = make_record(9, 100);
    store_validator_cleanup_record(kv, r);
    erase_validator_cleanup_record(kv, make_session_id(123));  // never stored
    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == r);
  }
  td::rmrf(path).ignore();
}

// A stored record survives reopen; an erase also survives reopen (not just an
// in-memory deletion).
TEST(ValidatorCleanupStateDb, store_and_erase_survive_reopen) {
  auto path = temp_db_path();
  auto r = make_record(9, 100);
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, r);
  }
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == r);
    erase_validator_cleanup_record(kv, r.session_id);
  }
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
  }
  td::rmrf(path).ignore();
}
