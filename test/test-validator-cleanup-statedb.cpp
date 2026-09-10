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
// the exact persistence scheme StateDb uses (per-session key + codec + prefix
// range scan). This pins the scan bounds and the decode-skip of malformed or
// unrelated keys -- behavior the pure codec tests cannot see.
#include "validator/consensus/validator-cleanup.h"

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

// Mirrors StateDb::update/erase/get, so the test covers the real code path.
void put_record(td::RocksDb& kv, const PendingValidatorConsensusDbCleanup& r) {
  auto key = validator_cleanup_key(r.session_id);
  auto value = encode_validator_cleanup_record(r);
  kv.begin_write_batch().ensure();
  kv.set(td::Slice{key}, td::Slice{value}).ensure();
  kv.commit_write_batch().ensure();
}

void erase_record(td::RocksDb& kv, const tos::ValidatorSessionId& sid) {
  kv.begin_write_batch().ensure();
  kv.erase(td::Slice{validator_cleanup_key(sid)}).ensure();
  kv.commit_write_batch().ensure();
}

std::vector<PendingValidatorConsensusDbCleanup> load_records(td::RocksDb& kv) {
  std::vector<PendingValidatorConsensusDbCleanup> out;
  auto end = validator_cleanup_key_range_end();
  kv.for_each_in_range(validator_cleanup_key_prefix(), td::Slice{end},
                       [&out](td::Slice, td::Slice value) {
                         auto decoded = decode_validator_cleanup_record(value);
                         if (decoded) {
                           out.push_back(std::move(decoded.value()));
                         }
                         return td::Status::OK();
                       })
      .ensure();
  return out;
}

std::string temp_db_path() {
  auto path = PSTRING() << "test-validator-cleanup-statedb-" << td::Random::fast_uint32();
  td::rmrf(path).ignore();
  return path;
}

}  // namespace

// Two records persist and reload intact; a malformed value stored under a
// cleanup key is dropped on load; unrelated keys on either side of the range are
// ignored; erasing one record removes exactly it. If the range-end derivation or
// the decode-skip were wrong, one of these counts would be off.
TEST(ValidatorCleanupStateDb, round_trip_scan_and_erase) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();

    auto r1 = make_record(9, 100);
    auto r2 = make_record(200, 150);
    put_record(kv, r1);
    put_record(kv, r2);

    // A malformed value under a real cleanup key: must be skipped on load, never
    // surface as a usable record.
    auto bad_sid = make_session_id(50);
    kv.begin_write_batch().ensure();
    kv.set(td::Slice{validator_cleanup_key(bad_sid)}, td::Slice{"not-a-record"}).ensure();
    // Unrelated keys that bracket the prefix range: one sorts before it, one at
    // the exclusive upper bound. Neither may be returned.
    kv.set(td::Slice{"tos.state.pending_validator_consensus_db_cleanu"}, td::Slice{"x"}).ensure();
    kv.set(td::Slice{validator_cleanup_key_range_end()}, td::Slice{"y"}).ensure();
    kv.commit_write_batch().ensure();

    auto loaded = load_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(2));
    std::set<std::string> got;
    for (const auto& r : loaded) {
      got.insert(r.session_id.to_hex());
    }
    ASSERT_TRUE(got.count(r1.session_id.to_hex()) == 1);
    ASSERT_TRUE(got.count(r2.session_id.to_hex()) == 1);

    erase_record(kv, r1.session_id);
    auto after = load_records(kv);
    ASSERT_EQ(after.size(), static_cast<size_t>(1));
    ASSERT_TRUE(after[0].session_id.to_hex() == r2.session_id.to_hex());
    ASSERT_TRUE(after[0] == r2);
  }
  td::rmrf(path).ignore();
}

// A record survives closing and reopening the database: the write is durable,
// not just in-memory.
TEST(ValidatorCleanupStateDb, survives_reopen) {
  auto path = temp_db_path();
  auto r = make_record(9, 100);
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    put_record(kv, r);
  }
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto loaded = load_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == r);
  }
  td::rmrf(path).ignore();
}
