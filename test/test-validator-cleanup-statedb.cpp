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

// Drives the production driver over a real RocksDb exactly as the glue does, but
// synchronously and deterministically: one scheduled callback at a time (a timer fires
// when the test says so, whatever its delay), page read, examination, one point read
// per candidate, reservation, end of pass, then the delete completions (each followed
// by a kick, as the glue does). Hooks run while the page is in flight and between
// examination and the point reads; failures can be injected per page, point read and
// delete.
struct RocksScan {
  td::RocksDb& kv;
  ValidatorCleanupManager& m;
  ValidatorCleanupOracles oracles;
  std::function<void()> while_page_in_flight;
  std::function<void()> before_point_reads;
  std::function<bool()> fail_page;
  std::function<bool(const PendingValidatorConsensusDbCleanup&)> fail_point;
  std::function<bool(const PendingValidatorConsensusDbCleanup&)> fail_delete;
  bool hold_deletes = false;
  std::vector<ReservedValidatorDelete> held;
  std::optional<ValidatorCleanupScheduleAction> pending;  // the one scheduled callback
  std::vector<double> timer_delays;
  size_t duplicate_schedules = 0;  // a second callback scheduled while one was pending
  size_t passes = 0;
  size_t erased_total = 0;
  size_t max_memory = 0;  // in-flight + open retirements + live incarnations

  size_t memory() const {
    return m.in_flight_count() + m.open_retirement_count() + m.live_session_count();
  }
  void take(const ValidatorCleanupScheduleAction& action) {
    if (action.kind == ValidatorCleanupScheduleAction::Kind::None) {
      return;
    }
    if (pending) {
      ++duplicate_schedules;
    }
    pending = action;
    if (action.kind == ValidatorCleanupScheduleAction::Kind::Timer) {
      timer_delays.push_back(action.delay_seconds);
    }
  }
  void kick() {
    take(m.kick(oracles.gc));
  }
  bool timer_pending() const {
    return pending && pending->kind == ValidatorCleanupScheduleAction::Kind::Timer;
  }
  // Fire the pending callback, if any; return the reservations of the pass it ran, or
  // nothing if nothing was pending. A stale callback runs no pass.
  std::optional<std::vector<ReservedValidatorDelete>> fire() {
    if (!pending) {
      return std::nullopt;
    }
    auto action = *pending;
    pending.reset();
    std::vector<ReservedValidatorDelete> reserved;
    if (!m.accept_scheduled(action.generation)) {
      return reserved;
    }
    ++passes;
    auto request = m.begin_pass(oracles.gc);
    ASSERT_TRUE(request.has_value());
    if (fail_page && fail_page()) {
      take(m.schedule_after_pass(m.abort_pass(), oracles.gc));
      return reserved;
    }
    auto page = load_validator_cleanup_page(kv, request->after_key, request->max_keys);
    if (while_page_in_flight) {
      while_page_in_flight();
    }
    auto candidates = m.on_page(*request, page, oracles);
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
    take(m.schedule_after_pass(m.end_pass(), oracles.gc));
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
  // One pass: kick first if nothing is scheduled. Nothing if the driver declined.
  std::optional<std::vector<ReservedValidatorDelete>> pass() {
    if (!pending) {
      kick();
    }
    return fire();
  }
  // Complete a delete attempt (and its durable erase), then kick as the glue does.
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
    kick();
  }
  // Passes until the driver declines or `limit` passes ran.
  void run(size_t limit) {
    for (size_t i = 0; i < limit; i++) {
      if (!pass()) {
        return;
      }
    }
  }
  // Fire scheduled callbacks only -- no external trigger -- until none is pending.
  void run_without_triggers(size_t limit) {
    for (size_t i = 0; i < limit && pending; i++) {
      fire();
    }
  }
};

void retire_and_close(td::RocksDb& kv, ValidatorCleanupManager& m, const PendingValidatorConsensusDbCleanup& rec) {
  store_validator_cleanup_record(kv, rec);
  m.on_group_created(rec.session_id);
  m.on_close_confirmed(rec.session_id, m.on_group_retired(rec));
}

}  // namespace

// A large durable backlog is reclaimed by the scan, and the driver's memory stays at
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
      scan.run(10000);
      ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
      ASSERT_EQ(scan.erased_total, n);
      ASSERT_TRUE(scan.max_memory <= ValidatorCleanupManager::kMaxInFlight);
      // Budget-bound: ceil(n / 16) reserving passes, plus the final wrap.
      ASSERT_TRUE(scan.passes <=
                  (n + ValidatorCleanupManager::kDispatchBudget - 1) / ValidatorCleanupManager::kDispatchBudget + 3);
    }
    td::rmrf(path).ignore();
  }
}

// Memory follows open groups, not history: 5000 retirements awaiting their closes are
// held, and once every close arrives nothing is; the scan then reclaims them all.
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
    ASSERT_TRUE(scan.pass().value().empty());  // nothing is closed yet
    for (const auto& [s, g] : retired) {
      m.on_close_confirmed(s, g);
    }
    ASSERT_EQ(scan.memory(), static_cast<size_t>(0));
    scan.run(10000);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(5000));
    ASSERT_EQ(scan.memory(), static_cast<size_t>(0));
  }
  td::rmrf(path).ignore();
}

// More than a thousand unrelated retirements and closes landing during every page
// read do not hold the scan back: an old eligible record is reclaimed on the first
// read, and the cursor advances on every pass.
TEST(ValidatorCleanupStateDb, unrelated_retirements_during_every_read_do_not_stall_the_scan) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto eligible = indexed_record(0x80, 0, 100);
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t churned = 0;
    std::optional<size_t> reclaimed_at;
    scan.while_page_in_flight = [&] {
      for (size_t n = 0; n < 1025; n++, churned++) {
        retire_and_close(kv, m, indexed_record(static_cast<uint8_t>(churned), 100000 + churned, 900));
      }
    };
    for (size_t read = 1; read <= 10; read++) {
      auto before = m.cursor();
      ASSERT_TRUE(scan.pass().has_value());
      ASSERT_TRUE(m.cursor() != before || m.cursor().empty());  // moved, or wrapped
      if (!reclaimed_at && scan.erased_total == 1) {
        reclaimed_at = read;
      }
    }
    ASSERT_TRUE(reclaimed_at.has_value());
    ASSERT_EQ(reclaimed_at.value(), static_cast<size_t>(1));
    ASSERT_TRUE(!load_validator_cleanup_record(kv, eligible.session_id).move_as_ok().has_value());
    ASSERT_TRUE(scan.max_memory <= ValidatorCleanupManager::kMaxInFlight);  // churn leaves nothing resident
  }
  td::rmrf(path).ignore();
}

// An eligible record behind hundreds of ineligible ones is reached and reclaimed while
// closed, ineligible retirements keep landing during every read -- before the scan
// could pause, and with the GC block unchanged.
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
    // Churn lands both while the page is in flight and between examination and the
    // point reads, so neither moment may set the scan back.
    auto churn = [&] {
      for (size_t n = 0; n < 4; n++, churned++) {
        retire_and_close(kv, m, indexed_record(static_cast<uint8_t>(churned % 0xF0), 200000 + churned, 900));
      }
    };
    scan.while_page_in_flight = churn;
    scan.before_point_reads = churn;
    for (size_t pass = 0; pass < 10 && scan.erased_total == 0; pass++) {
      ASSERT_TRUE(scan.pass().has_value());  // never paused while work remains
    }
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(!load_validator_cleanup_record(kv, eligible.session_id).move_as_ok().has_value());
    ASSERT_EQ(load_validator_cleanup_records(kv).size(), 600 + churned);  // every ineligible record kept
  }
  td::rmrf(path).ignore();
}

// A page copy older than the durable record is never acted on: the session is
// recreated, retired again (a newer record) and closed between the page read and the
// point read, so the stale copy is skipped; the next scan reserves the newer record.
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
    ASSERT_TRUE(scan.pass().value().empty());  // the stale copy was not reserved
    auto reserved = scan.pass().value();
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
    ASSERT_TRUE(scan.pass().value().empty());
    ASSERT_TRUE(!m.is_delete_in_flight(rec.session_id));
    ASSERT_EQ(m.in_flight_count(), static_cast<size_t>(0));
  }
  td::rmrf(path).ignore();
}

// A full scan that changed nothing pauses at its GC block, and scanning resumes when
// the GC block moves, or when a retirement or close arrives.
TEST(ValidatorCleanupStateDb, scan_pauses_and_resumes_on_gc_move_or_lifecycle_event) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 3; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x30, i, 900));  // retired after GC 500
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    ASSERT_TRUE(scan.pass().value().empty());  // a full scan (one page) that changed nothing
    ASSERT_TRUE(m.paused());
    ASSERT_TRUE(!scan.pass().has_value());  // paused at GC 500

    // A close arrives: scanning resumes at the same GC block; the sweep that starts
    // after it is clean, so the scanner pauses again.
    auto rec = indexed_record(0x31, 0, 900);
    retire_and_close(kv, m, rec);
    ASSERT_TRUE(scan.pass().has_value());
    ASSERT_TRUE(m.paused());
    ASSERT_TRUE(!scan.pass().has_value());

    // The GC block moves past the retirements: the scan resumes and reclaims them.
    scan.oracles = oracles_at(1000, nullptr);
    scan.run(10);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(4));
    ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
  }
  td::rmrf(path).ignore();
}

// Progress with the GC block fixed and no churn: a full scan of N records takes
// ceil(N / page size) passes, and every eligible record is reserved by the end of it.
TEST(ValidatorCleanupStateDb, full_scan_takes_ceil_n_over_page_passes) {
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
    size_t passes_to_wrap = 0;
    for (;;) {
      ASSERT_TRUE(scan.pass().has_value());
      ++passes_to_wrap;
      if (m.cursor().empty()) {
        break;
      }
    }
    ASSERT_EQ(passes_to_wrap, (kRecords + ValidatorCleanupManager::kPageSize - 1) / ValidatorCleanupManager::kPageSize);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(10));
  }
  td::rmrf(path).ignore();
}

// ---- scheduler: continuation, events, failures and backoff ---------------------------

// A point-read failure on the first page, followed by several healthy pages, does not
// strand the record: the sweep runs to its end on its own, backs off once, and the
// rescan reclaims the record -- with no external trigger after the first.
TEST(ValidatorCleanupStateDb, early_point_read_failure_is_rescanned_without_a_trigger) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto eligible = indexed_record(0x01, 0, 100);  // first in key order
    store_validator_cleanup_record(kv, eligible);
    for (size_t i = 0; i < 700; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(0x10 + i % 0xE0), i, 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    bool failed_once = false;
    scan.fail_point = [&](const PendingValidatorConsensusDbCleanup&) { return !failed_once && (failed_once = true); };
    scan.kick();  // the only trigger
    scan.run_without_triggers(100);
    ASSERT_TRUE(failed_once);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(!load_validator_cleanup_record(kv, eligible.session_id).move_as_ok().has_value());
    ASSERT_TRUE(scan.timer_delays == std::vector<double>{1});
    ASSERT_TRUE(m.paused());  // the rescan was clean
  }
  td::rmrf(path).ignore();
}

// A close behind the cursor makes an already-skipped record eligible mid-sweep; the
// sweep that saw it is followed by another, which reclaims it -- no external trigger.
TEST(ValidatorCleanupStateDb, close_behind_the_cursor_is_rescanned_without_a_trigger) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto rec = indexed_record(0x01, 0, 100);
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(0x10 + i % 0xE0), i, 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    store_validator_cleanup_record(kv, rec);
    m.on_group_created(rec.session_id);
    auto gen = m.on_group_retired(rec);  // retired, its close not yet confirmed: held
    scan.kick();
    ASSERT_TRUE(scan.fire().value().empty());  // first page: the record is skipped
    ASSERT_TRUE(!m.cursor().empty());
    m.on_close_confirmed(rec.session_id, gen);  // the close lands behind the cursor
    scan.kick();                                // the glue kicks on a close; a pass is queued
    scan.run_without_triggers(100);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(scan.timer_delays.empty());
    ASSERT_TRUE(m.paused());
  }
  td::rmrf(path).ignore();
}

// Once backing off, other triggers -- kicks on GC advances, erase acks -- neither run a
// pass early nor schedule a second callback.
TEST(ValidatorCleanupStateDb, triggers_during_backoff_do_not_shorten_it) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto rec = indexed_record(0x40, 0, 100);
    store_validator_cleanup_record(kv, rec);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    bool fail = true;
    scan.fail_point = [&](const PendingValidatorConsensusDbCleanup&) { return fail; };
    ASSERT_TRUE(scan.pass().value().empty());  // point read failed; the sweep wrapped
    ASSERT_TRUE(scan.timer_pending());
    auto timer = *scan.pending;
    for (int i = 0; i < 5; i++) {
      scan.kick();
      ASSERT_EQ(m.kick(make_checkpoint(500 + i)).kind, ValidatorCleanupScheduleAction::Kind::None);  // GC moves too
    }
    ASSERT_EQ(scan.duplicate_schedules, static_cast<size_t>(0));
    ASSERT_EQ(scan.pending->generation, timer.generation);
    ASSERT_EQ(m.schedule_state(), ValidatorCleanupManager::SchedState::Backoff);
    fail = false;
    scan.run_without_triggers(10);  // the timer fires; the rescan reclaims it
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
  }
  td::rmrf(path).ignore();
}

// 64 reservations held until the scanner stops at capacity; all fail. The capacity
// they free resumes the unfinished sweep, which reclaims the healthy records beyond
// them; the failed records are retried only after a backoff.
TEST(ValidatorCleanupStateDb, capacity_freed_by_failed_deletes_resumes_the_sweep) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 64; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x10, i, 100));  // the first 64 in key order
    }
    for (size_t i = 0; i < 16; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x90, i, 100));  // healthy, further on
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.hold_deletes = true;
    scan.kick();
    scan.run_without_triggers(100);
    ASSERT_EQ(scan.held.size(), ValidatorCleanupManager::kMaxInFlight);
    ASSERT_TRUE(!scan.pending);  // stopped at capacity, no trigger left
    ASSERT_EQ(m.schedule_state(), ValidatorCleanupManager::SchedState::Idle);
    scan.hold_deletes = false;
    auto held = std::move(scan.held);
    for (const auto& r : held) {
      scan.complete(r, /*gone=*/false);  // every held attempt fails
    }
    ASSERT_TRUE(scan.pending.has_value());
    ASSERT_EQ(scan.pending->kind, ValidatorCleanupScheduleAction::Kind::Queue);  // resume, not a retry
    scan.fire();  // the unfinished sweep resumes and reaches the healthy records
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(16));
    ASSERT_TRUE(scan.timer_pending());  // the failed records wait for a backoff
    ASSERT_EQ(load_validator_cleanup_records(kv).size(), static_cast<size_t>(64));
    scan.run_without_triggers(10);  // after the backoff the rescan reclaims them
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(80));
  }
  td::rmrf(path).ignore();
}

// A failed delete arriving after the scanner paused backs off; it does not start the
// ordinary immediate sweep an event would.
TEST(ValidatorCleanupStateDb, delete_failure_after_a_pause_backs_off) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, indexed_record(0x40, 0, 100));
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    scan.hold_deletes = true;
    ASSERT_EQ(scan.pass().value().size(), static_cast<size_t>(1));
    ASSERT_TRUE(m.paused());  // the delete is still in flight: that alone does not rescan
    scan.hold_deletes = false;
    auto held = std::move(scan.held);
    scan.complete(held.at(0), /*gone=*/false);
    ASSERT_TRUE(scan.timer_pending());
    ASSERT_TRUE(scan.timer_delays == std::vector<double>{1});
  }
  td::rmrf(path).ignore();
}

// Point reads of one pass may return in any order, failed or not. The pass ends exactly
// once, after the last of them; the failed candidate is not reserved; nothing is
// scheduled while callbacks are outstanding; a callback carrying another pass's token
// changes nothing.
TEST(ValidatorCleanupStateDb, point_reads_in_any_order_end_the_pass_once) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 3; i++) {
      store_validator_cleanup_record(kv, indexed_record(0x40, i, 100));
    }
    ValidatorCleanupManager m;
    auto o = oracles_at(500, nullptr);
    auto action = m.kick(o.gc);
    ASSERT_TRUE(m.accept_scheduled(action.generation));
    auto request = m.begin_pass(o.gc).value();
    auto candidates = m.on_page(request, load_validator_cleanup_page(kv, request.after_key, request.max_keys), o);
    ASSERT_EQ(candidates.size(), static_cast<size_t>(3));
    auto ok = [&](size_t k) { return load_validator_cleanup_record(kv, candidates[k].session_id); };
    td::Result<std::optional<PendingValidatorConsensusDbCleanup>> err = td::Status::Error("injected");
    // A stale token, then the real results out of order: 2 ok, 0 failed, 1 ok.
    ASSERT_TRUE(!m.on_point_read_result(request.token + 1, candidates[1], ok(1), o.is_live).has_value());
    ASSERT_TRUE(m.on_point_read_result(request.token, candidates[2], ok(2), o.is_live).has_value());
    ASSERT_TRUE(!m.pass_verified());
    ASSERT_TRUE(!m.on_point_read_result(request.token, candidates[0], err, o.is_live).has_value());
    ASSERT_TRUE(!m.pass_verified());
    ASSERT_EQ(m.schedule_state(), ValidatorCleanupManager::SchedState::Running);
    ASSERT_TRUE(m.on_point_read_result(request.token, candidates[1], ok(1), o.is_live).has_value());
    ASSERT_TRUE(m.pass_verified());
    // A duplicate callback after the last one changes nothing.
    ASSERT_TRUE(!m.on_point_read_result(request.token, candidates[0], ok(0), o.is_live).has_value());
    ASSERT_EQ(m.in_flight_count(), static_cast<size_t>(2));
    ASSERT_TRUE(!m.is_delete_in_flight(candidates[0].session_id));
    auto summary = m.end_pass();
    ASSERT_TRUE(summary.point_failed && summary.wrapped);
    ASSERT_EQ(m.schedule_after_pass(summary, o.gc).kind, ValidatorCleanupScheduleAction::Kind::Timer);
    ASSERT_EQ(m.schedule_after_pass(summary, o.gc).kind, ValidatorCleanupScheduleAction::Kind::None);  // once
  }
  td::rmrf(path).ignore();
}

// A persistent failure early in the store, with healthy pages after it: every sweep
// fails, so the backoff escalates 1, 2, 4 ... 64 and stays there; once the failure
// clears, an error-free sweep resets it and the next failure starts again at 1.
TEST(ValidatorCleanupStateDb, persistent_failure_escalates_the_backoff_until_a_clean_sweep) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto bad = indexed_record(0x01, 0, 100);
    store_validator_cleanup_record(kv, bad);
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(0x10 + i % 0xE0), i, 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    bool fail = true;
    scan.fail_point = [&](const PendingValidatorConsensusDbCleanup& c) { return fail && c == bad; };
    scan.kick();
    while (scan.timer_delays.size() < 9) {
      ASSERT_TRUE(scan.pending.has_value());
      scan.fire();
    }
    ASSERT_TRUE((scan.timer_delays == std::vector<double>{1, 2, 4, 8, 16, 32, 64, 64, 64}));
    fail = false;
    scan.run_without_triggers(100);  // the rescan succeeds and the sweep is clean
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(m.paused());
    // A new failure starts the backoff from 1 again.
    auto bad2 = indexed_record(0x02, 0, 100);
    store_validator_cleanup_record(kv, bad2);
    fail = true;
    scan.fail_point = [&](const PendingValidatorConsensusDbCleanup& c) { return fail && c == bad2; };
    scan.oracles = oracles_at(501, nullptr);  // a GC advance resumes the paused scanner
    scan.kick();
    scan.run_without_triggers(5);
    ASSERT_EQ(scan.timer_delays.back(), 1.0);
  }
  td::rmrf(path).ignore();
}

// Repeated failures of the SECOND page read back off each time, with the cursor left
// where the first page put it, and the sweep completes on its own once reads recover.
TEST(ValidatorCleanupStateDb, repeated_page_read_failures_keep_the_cursor_and_back_off) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i % 0xF0), i, 900));
    }
    auto eligible = indexed_record(0xF8, 0, 100);  // on the last page
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t page_reads = 0;
    scan.fail_page = [&] {
      ++page_reads;
      return page_reads >= 2 && page_reads <= 4;  // the second page fails three times
    };
    scan.kick();
    scan.fire();  // first page
    auto cursor = m.cursor();
    ASSERT_TRUE(!cursor.empty());
    for (int i = 0; i < 3; i++) {
      ASSERT_TRUE(scan.pending.has_value());
      scan.fire();  // fails
      ASSERT_TRUE(m.cursor() == cursor);
      ASSERT_TRUE(scan.timer_pending());  // a backoff, never an immediate retry
    }
    ASSERT_TRUE((scan.timer_delays == std::vector<double>{1, 2, 4}));
    scan.run_without_triggers(20);
    ASSERT_EQ(scan.erased_total, static_cast<size_t>(1));
  }
  td::rmrf(path).ignore();
}

// Scheduled callbacks carry the scheduler generation. After disabling and re-enabling,
// an OLD timer or continuation that fires changes nothing: no second pass overlaps the
// current one and the state is unchanged.
TEST(ValidatorCleanupStateDb, stale_scheduled_callbacks_change_nothing) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    for (size_t i = 0; i < 600; i++) {
      store_validator_cleanup_record(kv, indexed_record(static_cast<uint8_t>(i % 0xF0), i, 900));
    }
    ValidatorCleanupManager m;
    RocksScan scan{kv, m, oracles_at(500, nullptr)};
    size_t page_reads = 0;
    scan.fail_page = [&] { return ++page_reads == 2; };
    scan.kick();
    scan.fire();  // first page; a continuation is queued
    auto old_continuation = *scan.pending;
    ASSERT_EQ(old_continuation.kind, ValidatorCleanupScheduleAction::Kind::Queue);
    scan.fire();  // the second page fails: a backoff timer
    auto old_timer = *scan.pending;
    ASSERT_EQ(old_timer.kind, ValidatorCleanupScheduleAction::Kind::Timer);
    scan.pending.reset();

    m.disable();                           // cleanup disabled ...
    auto fresh = m.kick(scan.oracles.gc);  // ... and enabled again: the unfinished sweep continues
    ASSERT_EQ(fresh.kind, ValidatorCleanupScheduleAction::Kind::Queue);
    ASSERT_TRUE(m.accept_scheduled(fresh.generation));
    auto request = m.begin_pass(scan.oracles.gc);
    ASSERT_TRUE(request.has_value());
    // The old timer and the old continuation fire while that pass runs.
    ASSERT_TRUE(!m.accept_scheduled(old_timer.generation));
    ASSERT_TRUE(!m.accept_scheduled(old_continuation.generation));
    ASSERT_EQ(m.schedule_state(), ValidatorCleanupManager::SchedState::Running);
    ASSERT_TRUE(!m.begin_pass(scan.oracles.gc).has_value());  // no overlapping pass
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
      auto page = load_validator_cleanup_page(kv, cursor, 2);
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
    ASSERT_TRUE(load_validator_cleanup_page(kv, cursor, 0).records.empty());
  }
  td::rmrf(path).ignore();
}
