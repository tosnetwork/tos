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
#include <algorithm>
#include <functional>
#include <optional>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#include "td/db/RocksDb.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/consensus/validator-cleanup-store.h"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

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

// A thin KeyValue decorator that forwards everything to an inner RocksDb but
// counts write-batch commits, so a test can assert store_validator_retirement
// uses exactly ONE batch (crash-atomic) rather than a separate commit per record.
class CommitCountingKeyValue : public td::KeyValue {
 public:
  explicit CommitCountingKeyValue(td::RocksDb& inner) : inner_(inner) {
  }
  size_t commits = 0;

  td::Result<GetStatus> get(td::Slice key, std::string& value) override {
    return inner_.get(key, value);
  }
  td::Result<std::vector<GetStatus>> get_multi(td::Span<td::Slice> keys, std::vector<std::string>* values) override {
    return inner_.get_multi(keys, values);
  }
  td::Result<size_t> count(td::Slice prefix) override {
    return inner_.count(prefix);
  }
  td::Status for_each_in_range(td::Slice begin, td::Slice end, std::function<td::Status(td::Slice, td::Slice)> f) override {
    return inner_.for_each_in_range(begin, end, std::move(f));
  }
  td::Status set(td::Slice key, td::Slice value) override {
    return inner_.set(key, value);
  }
  td::Status erase(td::Slice key) override {
    return inner_.erase(key);
  }
  td::Status begin_write_batch() override {
    return inner_.begin_write_batch();
  }
  td::Status commit_write_batch() override {
    commits++;
    return inner_.commit_write_batch();
  }
  td::Status abort_write_batch() override {
    return inner_.abort_write_batch();
  }
  td::Status begin_transaction() override {
    return inner_.begin_transaction();
  }
  td::Status commit_transaction() override {
    return inner_.commit_transaction();
  }
  td::Status abort_transaction() override {
    return inner_.abort_transaction();
  }
  std::unique_ptr<td::KeyValueReader> snapshot() override {
    return inner_.snapshot();
  }

 private:
  td::RocksDb& inner_;
};

// Create <root>/consensus/<dir_name>/db/ with a real file inside, so there is a
// non-empty directory tree for the delete helper to remove.
void create_consensus_dir(const std::string& root, const std::string& dir_name) {
  auto db_dir = consensus_db_root(root) + dir_name + "/db/";
  td::mkpath(db_dir).ensure();
  td::write_file(db_dir + "CURRENT", td::Slice{"x"}).ensure();
}
bool consensus_dir_exists(const std::string& root, const std::string& dir_name) {
  return td::stat(consensus_db_root(root) + dir_name).is_ok();
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

// The physical delete helper removes a canonical validator directory and confirms
// it is gone. An already-absent canonical directory also reports gone (idempotent).
TEST(ValidatorCleanupStateDb, delete_helper_removes_canonical_dir) {
  auto path = temp_db_path();
  auto sid = make_session_id(9);
  auto dir = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));
  create_consensus_dir(path, dir);
  ASSERT_TRUE(consensus_dir_exists(path, dir));

  ASSERT_TRUE(delete_validator_consensus_db(td::Slice{path}, sid, dir));
  ASSERT_TRUE(!consensus_dir_exists(path, dir));

  // Already gone: canonical name, nothing on disk -> still reports confirmed gone.
  ASSERT_TRUE(delete_validator_consensus_db(td::Slice{path}, sid, dir));
  td::rmrf(path).ignore();
}

// The delete helper REFUSES a non-canonical / mismatched / observer directory name
// and does not touch the filesystem -- it never trusts a persisted path. If the
// revalidation were dropped, the directory would be deleted and this fails.
TEST(ValidatorCleanupStateDb, delete_helper_refuses_non_canonical) {
  auto path = temp_db_path();
  auto sid = make_session_id(9);

  // Observer directory for the same session: must be refused (this helper is
  // validator-only).
  auto observer = consensus_db_dir_name(kShard, 7, sid, td::Slice(".observer.xy"));
  create_consensus_dir(path, observer);
  ASSERT_TRUE(!delete_validator_consensus_db(td::Slice{path}, sid, observer));
  ASSERT_TRUE(consensus_dir_exists(path, observer));

  // Canonical validator name but a DIFFERENT session id than claimed: refused.
  auto dir = consensus_db_dir_name(kShard, 7, make_session_id(200), td::Slice(""));
  create_consensus_dir(path, dir);
  ASSERT_TRUE(!delete_validator_consensus_db(td::Slice{path}, sid, dir));  // sid != dir's session
  ASSERT_TRUE(consensus_dir_exists(path, dir));

  // A name with a path separator: refused, nothing deleted.
  ASSERT_TRUE(!delete_validator_consensus_db(td::Slice{path}, sid, std::string("../escape")));
  td::rmrf(path).ignore();
}

// The confirmation primitive: a present path is NOT confirmed absent; a removed
// path IS. If this returned true unconditionally, the delete helper would falsely
// report success while a directory lingers -- so this pins the "stat proves gone"
// contract independently of the delete flow.
TEST(ValidatorCleanupStateDb, path_is_confirmed_absent_requires_real_absence) {
  auto path = temp_db_path();
  auto full = consensus_db_root(path) + "probe-dir";
  td::mkpath(full + "/").ensure();
  ASSERT_TRUE(!path_is_confirmed_absent(full));  // present -> not absent
  td::rmrf(full).ignore();
  ASSERT_TRUE(path_is_confirmed_absent(full));  // removed -> absent
  td::rmrf(path).ignore();
}

#ifndef _WIN32
// Removal failure: when the parent is not writable (non-root), rmrf cannot remove
// the directory, so the helper must report false (unconfirmed) and the directory
// must remain. This falsifies a helper that returns true without confirming. Root
// bypasses directory permissions, so the assertion only runs as non-root; it is
// skipped (with a log) under root rather than passing vacuously.
TEST(ValidatorCleanupStateDb, delete_helper_returns_false_when_removal_blocked) {
  if (::geteuid() == 0) {
    LOG(WARNING) << "skipping removal-blocked assertion: running as root bypasses directory permissions";
    return;
  }
  auto path = temp_db_path();
  auto sid = make_session_id(9);
  auto dir = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));
  create_consensus_dir(path, dir);

  auto parent = consensus_db_root(path);  // <root>/consensus/
  ASSERT_TRUE(::chmod(parent.c_str(), 0555) == 0);  // read+execute, no write -> child cannot be removed

  bool deleted = delete_validator_consensus_db(td::Slice{path}, sid, dir);

  ::chmod(parent.c_str(), 0755);  // restore so cleanup can proceed
  ASSERT_TRUE(!deleted);
  ASSERT_TRUE(consensus_dir_exists(path, dir));
  td::rmrf(path).ignore();
}
#endif

// A record whose VALUE is internally valid but is stored under a DIFFERENT
// session's key must not be loaded: the key and the value's session id must
// agree, or an erase-by-session could never remove it and it would reappear.
// Also covers a non-canonical in-range key carrying a valid value.
TEST(ValidatorCleanupStateDb, mismatched_key_and_value_is_dropped) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();

    auto good = make_record(9, 100);
    store_validator_cleanup_record(kv, good);

    // Valid record for session B stored under session A's key.
    auto record_b = make_record(200, 150);
    put_raw(kv, td::Slice{validator_cleanup_key(make_session_id(201))},
            td::Slice{encode_validator_cleanup_record(record_b)});

    // A valid record value under a non-canonical (too-short) in-range key.
    auto record_c = make_record(202, 160);
    put_raw(kv, td::Slice{std::string("tos.state.pending_validator_consensus_db_cleanup.deadbeef")},
            td::Slice{encode_validator_cleanup_record(record_c)});

    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(1));
    ASSERT_TRUE(loaded[0] == good);
  }
  td::rmrf(path).ignore();
}

// The atomic retirement write persists the destroyed-session fence (an opaque
// key/value to this layer) together with every newly-retiring cleanup record in
// one batch: after it, the fence value is readable AND all records load. Dropping
// either the fence set or the record writes fails this test.
TEST(ValidatorCleanupStateDb, atomic_retirement_persists_fence_and_records) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();

    const std::string fence_key = "test.fence.destroyed_sessions";
    const std::string fence_value = "opaque-encoded-fence-blob";
    std::vector<PendingValidatorConsensusDbCleanup> records{make_record(9, 100), make_record(200, 150)};

    store_validator_retirement(kv, td::Slice{fence_key}, td::Slice{fence_value}, records);

    std::string got_fence;
    auto r = kv.get(td::Slice{fence_key}, got_fence);
    ASSERT_TRUE(r.is_ok() && r.move_as_ok() == td::KeyValue::GetStatus::Ok);
    ASSERT_TRUE(got_fence == fence_value);

    auto loaded = load_validator_cleanup_records(kv);
    ASSERT_EQ(loaded.size(), static_cast<size_t>(2));
    std::set<std::string> got;
    for (const auto& rec : loaded) {
      got.insert(rec.session_id.to_hex());
    }
    ASSERT_TRUE(got.count(make_session_id(9).to_hex()) == 1);
    ASSERT_TRUE(got.count(make_session_id(200).to_hex()) == 1);
  }
  td::rmrf(path).ignore();
}

// The retirement write must be ONE batch (crash-atomic), not a commit per
// record. A commit-counting decorator proves it: three records + the fence must
// produce exactly one commit. A split-per-record implementation would commit
// more than once and fail here.
TEST(ValidatorCleanupStateDb, retirement_uses_a_single_batch) {
  auto path = temp_db_path();
  {
    auto inner = td::RocksDb::open(path).move_as_ok();
    CommitCountingKeyValue counter{inner};
    std::vector<PendingValidatorConsensusDbCleanup> records{make_record(9, 100), make_record(200, 150),
                                                            make_record(201, 160)};
    store_validator_retirement(counter, td::Slice{"test.fence"}, td::Slice{"blob"}, records);
    ASSERT_EQ(counter.commits, static_cast<size_t>(1));
  }
  td::rmrf(path).ignore();
}

// An empty record list still writes the fence in one batch (a retirement update
// that only prunes the fence), and loads no records.
TEST(ValidatorCleanupStateDb, retirement_with_no_records_writes_fence_only) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_retirement(kv, td::Slice{"test.fence"}, td::Slice{"blob"}, {});
    std::string got;
    auto r = kv.get(td::Slice{"test.fence"}, got);
    ASSERT_TRUE(r.is_ok() && r.move_as_ok() == td::KeyValue::GetStatus::Ok && got == "blob");
    ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
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

namespace {

// A distinct session id for index `n` (up to 2^24), with the first byte chosen to place
// it in the key range.
tos::ValidatorSessionId indexed_session(uint8_t first, size_t n) {
  auto id = make_session_id(0x5A);
  id.as_slice()[0] = static_cast<char>(first);
  id.as_slice()[1] = static_cast<char>(n & 0xff);
  id.as_slice()[2] = static_cast<char>((n >> 8) & 0xff);
  id.as_slice()[3] = static_cast<char>((n >> 16) & 0xff);
  return id;
}

PendingValidatorConsensusDbCleanup indexed_record(uint8_t first, size_t n, tos::BlockSeqno retire_seqno) {
  PendingValidatorConsensusDbCleanup rec;
  rec.session_id = indexed_session(first, n);
  rec.retirement_checkpoint = make_checkpoint(retire_seqno);
  rec.dir_name = consensus_db_dir_name(kShard, 7, rec.session_id, td::Slice(""));
  return rec;
}

ValidatorCleanupOracles oracles_at(tos::BlockSeqno gc_seqno, const std::set<tos::ValidatorSessionId>* live) {
  ValidatorCleanupOracles o;
  o.gc = make_checkpoint(gc_seqno);
  o.ancestor_or_equal_of_gc = [gc_seqno](const tos::BlockIdExt& r) { return r.seqno() <= gc_seqno; };
  o.gc_shard_catchain_seqno = [](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
    return s == kShard ? std::optional<tos::CatchainSeqno>{10} : std::nullopt;
  };
  o.is_live = [live](const tos::ValidatorSessionId& s) { return live != nullptr && live->count(s) > 0; };
  return o;
}

// A reader over a real RocksDb whose page scans fail `failures` times: each failing
// scan visits `visit_before_failure` records first, then returns a storage error -- the
// shape of a real iterator error part-way through a page.
class FailingScanReader : public td::KeyValueReader {
 public:
  explicit FailingScanReader(td::RocksDb& inner) : inner_(inner) {
  }
  int failures = 0;
  size_t visit_before_failure = 0;

  td::Result<GetStatus> get(td::Slice key, std::string& value) override {
    return inner_.get(key, value);
  }
  td::Result<std::vector<GetStatus>> get_multi(td::Span<td::Slice> keys, std::vector<std::string>* values) override {
    return inner_.get_multi(keys, values);
  }
  td::Result<size_t> count(td::Slice prefix) override {
    return inner_.count(prefix);
  }
  td::Status for_each_in_range(td::Slice begin, td::Slice end,
                               std::function<td::Status(td::Slice, td::Slice)> f) override {
    if (failures <= 0) {
      return inner_.for_each_in_range(begin, end, std::move(f));
    }
    --failures;
    size_t visited = 0;
    auto status = inner_.for_each_in_range(begin, end, [&](td::Slice key, td::Slice value) -> td::Status {
      if (visited == visit_before_failure) {
        return td::Status::Error("injected iterator failure");
      }
      ++visited;
      return f(key, value);
    });
    return status.is_error() ? std::move(status) : td::Status::Error("injected iterator failure");
  }

 private:
  td::RocksDb& inner_;
};

// Drives the production driver over a real RocksDb exactly as the glue does, but
// synchronously: tick() is one timer tick -- skipped, or one pass of page read,
// examination, one point read per candidate, reservation, end of pass -- followed by
// the delete completions. Hooks run while the page is in flight and between
// examination and the point reads; failures can be injected per point read and delete,
// and page scans can go through a failing reader.
struct RocksScan {
  td::RocksDb& kv;
  ValidatorCleanupManager& m;
  ValidatorCleanupOracles oracles;
  td::KeyValueReader* reader = nullptr;  // page scans; the RocksDb itself by default
  std::function<void()> while_page_in_flight;
  std::function<void()> before_point_reads;
  std::function<bool(const PendingValidatorConsensusDbCleanup&)> fail_point;
  std::function<bool(const PendingValidatorConsensusDbCleanup&)> fail_delete;
  bool hold_deletes = false;
  std::vector<ReservedValidatorDelete> held;
  size_t ticks = 0;
  size_t page_reads = 0;
  size_t page_errors = 0;
  size_t erased_total = 0;
  size_t max_memory = 0;  // in-flight + open retirements + live incarnations

  size_t memory() const {
    return m.in_flight_count() + m.open_retirement_count() + m.live_session_count();
  }
  // One tick: the pass's reservations, or nothing if the tick was skipped.
  std::optional<std::vector<ReservedValidatorDelete>> tick() {
    ++ticks;
    auto request = m.begin_tick(oracles.gc);
    if (!request) {
      return std::nullopt;
    }
    ++page_reads;
    auto page = load_validator_cleanup_page(reader ? *reader : static_cast<td::KeyValueReader&>(kv), request->after_key,
                                            request->max_keys);
    if (while_page_in_flight) {
      while_page_in_flight();
    }
    std::vector<ReservedValidatorDelete> reserved;
    if (page.is_error()) {
      ++page_errors;
      ASSERT_TRUE(m.abort_pass(request->token).has_value());
      return reserved;
    }
    auto candidates = m.on_page(*request, page.ok(), oracles);
    if (before_point_reads) {
      before_point_reads();
    }
    for (const auto& c : candidates) {
      td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current =
          (fail_point && fail_point(c)) ? td::Result<std::optional<PendingValidatorConsensusDbCleanup>>(
                                              td::Status::Error("injected point read failure"))
                                        : load_validator_cleanup_record(kv, c.session_id);
      if (auto r = m.on_point_read_result(request->token, c, current, oracles.is_live)) {
        reserved.push_back(*r);
      }
    }
    ASSERT_TRUE(m.pass_verified());
    m.end_pass();
    max_memory = std::max(max_memory, memory());
    for (const auto& r : reserved) {
      if (hold_deletes) {
        held.push_back(r);
      } else {
        complete(r, !(fail_delete && fail_delete(r.record)));
      }
    }
    return reserved;
  }
  // Complete a delete attempt and, if it succeeded, its durable erase.
  void complete(const ReservedValidatorDelete& r, bool gone) {
    std::vector<std::tuple<tos::ValidatorSessionId, uint64_t, uint64_t>> acks;
    m.on_delete_completed(r.record.session_id, r.generation, r.attempt_id, gone,
                          [&](const tos::ValidatorSessionId& s, uint64_t g, uint64_t a) {
                            erase_validator_cleanup_record(kv, s);
                            acks.emplace_back(s, g, a);
                          });
    for (const auto& [s, g, a] : acks) {
      m.on_erase_acknowledged(s, g, a);
      ++erased_total;
    }
  }
  void run(size_t ticks_to_run) {
    for (size_t i = 0; i < ticks_to_run; i++) {
      tick();
    }
  }
  // Ticks until `done()` or `limit` ticks; returns the ticks used.
  size_t run_until(const std::function<bool()>& done, size_t limit) {
    size_t used = 0;
    while (used < limit && !done()) {
      tick();
      ++used;
    }
    return used;
  }
};

void retire_and_close(td::RocksDb& kv, ValidatorCleanupManager& m, const PendingValidatorConsensusDbCleanup& rec) {
  store_validator_cleanup_record(kv, rec);
  m.on_group_created(rec.session_id);
  m.on_close_confirmed(rec.session_id, m.on_group_retired(rec));
}

}  // namespace

// A large durable backlog is reclaimed by the ticks, and the driver's memory stays at
// the in-flight cap whatever the backlog size: 500 and 5000 records peak the same.
TEST(ValidatorCleanupStateDb, large_backlog_is_reclaimed_with_memory_independent_of_its_size) {
  for (size_t n : {static_cast<size_t>(500), static_cast<size_t>(5000)}) {
    auto path = temp_db_path();
    {
      auto kv = td::RocksDb::open(path).move_as_ok();
      for (size_t i = 0; i < n; i++) {
        store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i), i, 100));
      }
      ValidatorCleanupManager m;
      RocksScan scan{kv, m, oracles_at(500, nullptr)};
      auto used = scan.run_until([&] { return scan.erased_total == n; }, 10000);
      ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
      ASSERT_TRUE(scan.max_memory <= ValidatorCleanupManager::kMaxInFlight);
      // Dispatch-bound: ceil(n / 16) ticks.
      ASSERT_TRUE(used <=
                  (n + ValidatorCleanupManager::kDispatchBudget - 1) / ValidatorCleanupManager::kDispatchBudget + 1);
    }
    td::rmrf(path).ignore();
  }
}

// Memory follows open groups, not history: 5000 retirements awaiting their closes are
// held, and once every close arrives nothing is; the ticks then reclaim them all.
TEST(ValidatorCleanupStateDb, burst_of_retirements_then_closes_leaves_no_resident_state) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    ValidatorCleanupManager m;
    std::vector<std::pair<tos::ValidatorSessionId, uint64_t>> retired;
    for (size_t i = 0; i < 5000; i++) {
      auto rec = indexed_record(static_cast<uint8_t>(i), i, 100);
      store_validator_cleanup_record(kv, rec);
      m.on_group_created(rec.session_id);
      retired.emplace_back(rec.session_id, m.on_group_retired(rec));
    }
    ASSERT_EQ(m.open_retirement_count(), static_cast<size_t>(5000));
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    ASSERT_TRUE(scan.tick().value().empty());  // nothing is closed yet
    for (const auto& [s, g] : retired) {
      m.on_close_confirmed(s, g);
    }
    ASSERT_EQ(scan.memory(), static_cast<size_t>(0));
    scan.run_until([&] { return scan.erased_total == 5000; }, 10000);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(5000));
    ASSERT_EQ(scan.memory(), static_cast<size_t>(0));
  }
  td::rmrf(path).ignore();
}

// More than a thousand unrelated retirements and closes landing during every page
// read do not hold the scan back: an old eligible record is reclaimed on the first
// tick, and the cursor advances on every tick.
TEST(ValidatorCleanupStateDb, unrelated_retirements_during_every_read_do_not_stall_the_scan) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto eligible = indexed_record(0x80, 0, 100);
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t churned = 0;
    scan.while_page_in_flight = [&] {
      for (size_t n = 0; n < 1025; n++, churned++) {
        retire_and_close(kv, m, indexed_record(static_cast<uint8_t>(churned), 100000 + churned, 900));
      }
    };
    for (size_t t = 1; t <= 10; t++) {
      auto before = m.cursor();
      ASSERT_TRUE(scan.tick().has_value());
      ASSERT_TRUE(m.cursor() != before || m.cursor().empty());  // moved, or wrapped
      if (t == 1) {
        ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
      }
    }
    ASSERT_TRUE(!load_validator_cleanup_record(kv, eligible.session_id).move_as_ok().has_value());
    ASSERT_TRUE(scan.max_memory <= ValidatorCleanupManager::kMaxInFlight);  // churn leaves nothing resident
  }
  td::rmrf(path).ignore();
}

// An eligible record behind hundreds of ineligible ones is reached and reclaimed while
// closed, ineligible retirements keep landing during every read and before the point
// reads, with the GC block unchanged.
TEST(ValidatorCleanupStateDb, eligible_record_among_ineligible_ones_is_reclaimed_under_churn) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i % 0xF0), i, 900));
    }
    auto eligible = indexed_record(0xF8, 0, 100);  // at the end of the key range
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t churned = 0;
    auto churn = [&] {
      for (size_t n = 0; n < 4; n++, churned++) {
        retire_and_close(kv, m, indexed_record(static_cast<uint8_t>(churned % 0xF0), 200000 + churned, 900));
      }
    };
    scan.while_page_in_flight = churn;
    scan.before_point_reads = churn;
    scan.run_until([&] { return scan.erased_total == 1; }, 10);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(!load_validator_cleanup_record(kv, eligible.session_id).move_as_ok().has_value());
    ASSERT_EQ(load_validator_cleanup_records(kv).size(), 600 + churned);  // every ineligible record kept
  }
  td::rmrf(path).ignore();
}

// A page copy older than the durable record is never acted on: the session is
// recreated, retired again (a newer record) and closed between the page read and the
// point read, so the stale copy is skipped; the next cycle reserves the newer record.
TEST(ValidatorCleanupStateDb, stale_page_copy_is_skipped_for_the_newer_durable_record) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto old_copy = indexed_record(0x40, 0, 100);
    store_validator_cleanup_record(kv, old_copy);
    auto newer = indexed_record(0x40, 0, 300);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    bool replaced = false;
    scan.before_point_reads = [&] {
      if (!replaced) {
        replaced = true;
        retire_and_close(kv, m, newer);
      }
    };
    ASSERT_TRUE(scan.tick().value().empty());  // the stale copy was not reserved
    auto reserved = scan.tick().value();
    ASSERT_EQ(reserved.size(), static_cast<size_t>(1));
    ASSERT_TRUE(reserved[0].record == newer);
  }
  td::rmrf(path).ignore();
}

// A record erased between the page read and the point read is never re-admitted.
TEST(ValidatorCleanupStateDb, record_erased_before_its_point_read_is_not_readmitted) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto rec = indexed_record(0x40, 0, 100);
    store_validator_cleanup_record(kv, rec);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.before_point_reads = [&] { erase_validator_cleanup_record(kv, rec.session_id); };
    ASSERT_TRUE(scan.tick().value().empty());
    ASSERT_TRUE(!m.is_delete_in_flight(rec.session_id));
    ASSERT_EQ(m.in_flight_count(), static_cast<size_t>(0));
  }
  td::rmrf(path).ignore();
}

// With no churn, a full cycle over N records takes ceil(N / page size) ticks, and every
// eligible record is reserved by the end of it.
TEST(ValidatorCleanupStateDb, full_cycle_takes_ceil_n_over_page_ticks) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    const size_t kRecords = 1000;
    for (size_t i = 0; i < kRecords; i++) {
      // Every 100th record is eligible: at most 10, within one pass's dispatch budget.
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i), i, i % 100 == 0 ? 100 : 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t ticks_to_wrap = 0;
    for (;;) {
      ASSERT_TRUE(scan.tick().has_value());
      ++ticks_to_wrap;
      if (m.cursor().empty()) {
        break;
      }
    }
    ASSERT_EQ(ticks_to_wrap, (kRecords + ValidatorCleanupManager::kPageSize - 1) / ValidatorCleanupManager::kPageSize);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(10));
  }
  td::rmrf(path).ignore();
}

// ---- the fixed-period tick ------------------------------------------------------------

// An eligible record behind 999 ineligible ones is reclaimed within ceil(1000/256)+1
// ticks, and the scan keeps cycling after it (no pause).
TEST(ValidatorCleanupStateDb, record_behind_999_is_reclaimed_within_a_cycle_of_ticks) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 999; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i % 0xF0), i, 900));
    }
    auto eligible = indexed_record(0xF8, 0, 100);
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    auto used = scan.run_until([&] { return scan.erased_total == 1; }, 50);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(used <= (1000 + ValidatorCleanupManager::kPageSize - 1) / ValidatorCleanupManager::kPageSize + 1);
    auto reads = scan.page_reads;
    scan.run(3);
    ASSERT_EQ(scan.page_reads, reads + 3);  // still one page read per tick
  }
  td::rmrf(path).ignore();
}

// The GC block advances mid-cycle and makes a record already behind the cursor
// eligible: the next cycle reaches and reclaims it.
TEST(ValidatorCleanupStateDb, gc_advance_mid_cycle_is_picked_up_by_the_next_cycle) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto behind = indexed_record(0x01, 0, 600);  // first in key order; eligible once GC >= 600
    store_validator_cleanup_record(kv, behind);
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(0x10 + i % 0xE0), i, 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.tick();  // first page: the record is examined, not yet eligible
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(0));
    ASSERT_TRUE(!m.cursor().empty());
    scan.oracles = oracles_at(700, nullptr);  // the GC block advances mid-cycle
    auto used = scan.run_until([&] { return scan.erased_total == 1; }, 20);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(used <= (601 + ValidatorCleanupManager::kPageSize - 1) / ValidatorCleanupManager::kPageSize + 1);
  }
  td::rmrf(path).ignore();
}

// Real iterator failures, including ones after several records were visited, end the
// pass with nothing reserved and the cursor unchanged; the node is not aborted, and the
// next tick after the failures stop reads the page again and reclaims the record.
TEST(ValidatorCleanupStateDb, page_iterator_failures_are_retried_by_the_next_tick) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 8; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x40, i, 100));  // all eligible
    }
    ValidatorCleanupManager m;
    FailingScanReader failing(kv);
    failing.failures = 3;
    failing.visit_before_failure = 5;  // fail part-way through the page
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.reader = &failing;
    for (int t = 0; t < 3; t++) {
      auto reserved = scan.tick();
      ASSERT_TRUE(reserved.has_value() && reserved->empty());
      ASSERT_EQ(m.in_flight_count(), static_cast<size_t>(0));  // no partial reservations
      ASSERT_TRUE(m.cursor().empty());                         // the cursor did not move
      ASSERT_TRUE(!m.pass_running());
    }
    ASSERT_EQ(scan.page_errors, static_cast<size_t>(3));
    scan.tick();  // the failures are over
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(8));
  }
  td::rmrf(path).ignore();
}

// A persistent point-read failure on the first page does not hold the scan there: the
// cursor moves on, and an eligible record beyond the first page is reclaimed while the
// failure persists.
TEST(ValidatorCleanupStateDb, persistent_point_failure_does_not_block_later_records) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto bad = indexed_record(0x01, 0, 100);
    store_validator_cleanup_record(kv, bad);
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(0x10 + i % 0xE0), i, 900));
    }
    auto healthy = indexed_record(0xF8, 0, 100);  // beyond the first page
    store_validator_cleanup_record(kv, healthy);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.fail_point = [&](const PendingValidatorConsensusDbCleanup& c) { return c == bad; };
    scan.run_until([&] { return scan.erased_total == 1; }, 20);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(!load_validator_cleanup_record(kv, healthy.session_id).move_as_ok().has_value());
    ASSERT_TRUE(load_validator_cleanup_record(kv, bad.session_id).move_as_ok().has_value());
    scan.fail_point = nullptr;  // once the failure clears, the next cycle reclaims it
    scan.run_until([&] { return scan.erased_total == 2; }, 20);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(2));
  }
  td::rmrf(path).ignore();
}

// A page result for a pass that is no longer running -- success or failure -- changes
// nothing, and does not end the pass that is running.
TEST(ValidatorCleanupStateDb, stale_page_results_are_ignored) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, indexed_record(0x40, 0, 100));
    ValidatorCleanupManager m;
    auto o = oracles_at(500, nullptr);
    auto first = m.begin_tick(o.gc).value();
    ASSERT_TRUE(m.abort_pass(first.token).has_value());  // that page read failed
    auto second = m.begin_tick(o.gc).value();
    auto page = load_validator_cleanup_page(kv, first.after_key, first.max_keys).move_as_ok();
    ASSERT_TRUE(!m.is_current_pass(first.token));
    ASSERT_TRUE(m.on_page(first, page, o).empty());       // a stale success
    ASSERT_TRUE(!m.abort_pass(first.token).has_value());  // a stale failure
    ASSERT_TRUE(m.pass_running());
    ASSERT_TRUE(m.is_current_pass(second.token));
    ASSERT_EQ(m.on_page(second, page, o).size(), static_cast<size_t>(1));  // the running pass proceeds
  }
  td::rmrf(path).ignore();
}

// No overlap: a tick while the page or point reads of a pass are outstanding is skipped
// without reading anything.
TEST(ValidatorCleanupStateDb, tick_while_reads_are_outstanding_is_skipped) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, indexed_record(0x40, 0, 100));
    ValidatorCleanupManager m;
    auto o = oracles_at(500, nullptr);
    auto request = m.begin_tick(o.gc).value();
    ASSERT_TRUE(!m.begin_tick(o.gc).has_value());  // page read outstanding
    auto candidates =
        m.on_page(request, load_validator_cleanup_page(kv, request.after_key, request.max_keys).move_as_ok(), o);
    ASSERT_EQ(candidates.size(), static_cast<size_t>(1));
    ASSERT_TRUE(!m.begin_tick(o.gc).has_value());  // point read outstanding
    ASSERT_TRUE(m.on_point_read_result(request.token, candidates[0],
                                       load_validator_cleanup_record(kv, candidates[0].session_id), o.is_live)
                    .has_value());
    m.end_pass();
    ASSERT_TRUE(m.begin_tick(o.gc).has_value());  // free again
  }
  td::rmrf(path).ignore();
}

// Point reads of one pass may return in any order, failed or not. The pass finishes
// exactly once, after the last of them; the failed candidate is not reserved; a
// callback carrying another pass's token, or a duplicate, changes nothing.
TEST(ValidatorCleanupStateDb, point_reads_in_any_order_finish_the_pass_once) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 3; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x40, i, 100));
    }
    ValidatorCleanupManager m;
    auto o = oracles_at(500, nullptr);
    auto request = m.begin_tick(o.gc).value();
    auto candidates =
        m.on_page(request, load_validator_cleanup_page(kv, request.after_key, request.max_keys).move_as_ok(), o);
    ASSERT_EQ(candidates.size(), static_cast<size_t>(3));
    auto ok = [&](size_t k) { return load_validator_cleanup_record(kv, candidates[k].session_id); };
    td::Result<std::optional<PendingValidatorConsensusDbCleanup>> err = td::Status::Error("injected");
    ASSERT_TRUE(!m.on_point_read_result(request.token + 1, candidates[1], ok(1), o.is_live).has_value());
    ASSERT_TRUE(m.on_point_read_result(request.token, candidates[2], ok(2), o.is_live).has_value());
    ASSERT_TRUE(!m.pass_verified());
    ASSERT_TRUE(!m.on_point_read_result(request.token, candidates[0], err, o.is_live).has_value());
    ASSERT_TRUE(!m.pass_verified());
    ASSERT_TRUE(m.on_point_read_result(request.token, candidates[1], ok(1), o.is_live).has_value());
    ASSERT_TRUE(m.pass_verified());
    ASSERT_TRUE(!m.on_point_read_result(request.token, candidates[0], ok(0), o.is_live).has_value());
    ASSERT_EQ(m.in_flight_count(), static_cast<size_t>(2));
    ASSERT_TRUE(!m.is_delete_in_flight(candidates[0].session_id));
    auto summary = m.end_pass();
    ASSERT_TRUE(summary.point_failed && summary.wrapped);
    ASSERT_TRUE(!m.pass_running());
  }
  td::rmrf(path).ignore();
}

// At the in-flight cap a tick is skipped without reading; when the 64 held attempts
// then fail, later ticks resume scanning and reclaim a healthy record beyond them; the
// failed ones are reclaimed by a later cycle.
TEST(ValidatorCleanupStateDb, in_flight_cap_skips_ticks_and_failed_deletes_free_it) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 64; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x10, i, 100));  // the first 64 in key order
    }
    auto healthy = indexed_record(0x90, 0, 100);
    store_validator_cleanup_record(kv, healthy);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.hold_deletes = true;
    scan.run(4);  // 4 x 16 reservations
    ASSERT_EQ(scan.held.size(), ValidatorCleanupManager::kMaxInFlight);
    auto reads = scan.page_reads;
    ASSERT_TRUE(!scan.tick().has_value());  // skipped at the cap
    ASSERT_EQ(scan.page_reads, reads);      // without a read
    scan.hold_deletes = false;
    auto held = std::move(scan.held);
    for (const auto& r : held) {
      scan.complete(r, /*gone=*/false);  // every held attempt fails
    }
    scan.run_until([&] { return !load_validator_cleanup_record(kv, healthy.session_id).move_as_ok().has_value(); }, 5);
    ASSERT_TRUE(!load_validator_cleanup_record(kv, healthy.session_id).move_as_ok().has_value());
    scan.run_until([&] { return scan.erased_total == 65; }, 20);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(65));
  }
  td::rmrf(path).ignore();
}

// The page read itself: bounded by keys examined (malformed values included), resumes
// strictly after the last key, and reports the end of the range.
TEST(ValidatorCleanupStateDb, page_read_is_bounded_and_resumable) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (int i = 0; i < 5; i++) {
      store_validator_cleanup_record(kv, make_record(static_cast<unsigned char>(i), 100));
    }
    put_raw(kv, td::Slice{validator_cleanup_key(make_session_id(3)) + "x"}, td::Slice{"not-a-record"});
    std::set<std::string> seen;
    std::string cursor;
    size_t pages = 0;
    while (true) {
      auto page = load_validator_cleanup_page(kv, cursor, 2).move_as_ok();
      ++pages;
      ASSERT_TRUE(page.records.size() <= 2);
      for (const auto& r : page.records) {
        ASSERT_TRUE(seen.insert(r.session_id.to_hex()).second);  // never returned twice
      }
      if (page.reached_end) {
        break;
      }
      cursor = page.last_key;
    }
    ASSERT_EQ(seen.size(), static_cast<size_t>(5));
    ASSERT_TRUE(pages >= 3);  // six keys, two per page
    ASSERT_TRUE(load_validator_cleanup_page(kv, cursor, 0).move_as_ok().records.empty());
  }
  td::rmrf(path).ignore();
}
