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

// Drives the production adapter over a real RocksDb exactly as the manager does:
// page in when asked, run a bounded pass, delete and durably erase what it reserved.
// Records the largest resident set seen. Stops when a round neither pages nor
// reserves anything.
struct BacklogDrive {
  td::RocksDb& kv;
  ValidatorCleanupManager& m;
  CleanupAncestorOfGcFn ancestor;
  size_t max_resident = 0;
  size_t pages = 0;
  size_t erased_total = 0;
  // Page reads completed when the first record was erased.
  std::optional<size_t> pages_at_first_erase;
  // Runs between a page read and its reply, i.e. while the page is in flight.
  std::function<void()> while_page_in_flight;

  void run() {
    auto gc = make_checkpoint(500);
    auto cc_past = [](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
      return s == kShard ? std::optional<tos::CatchainSeqno>{10} : std::nullopt;
    };
    auto not_live = [](const tos::ValidatorSessionId&) { return false; };
    for (int round = 0; round < 10000; round++) {
      bool progressed = false;
      if (auto request = m.next_page_request()) {
        auto page = load_validator_cleanup_page(kv, request->after_key, request->max_keys);
        if (while_page_in_flight) {
          while_page_in_flight();
        }
        m.on_page_loaded(*request, std::move(page));
        ++pages;
        progressed = true;
      }
      max_resident = std::max(max_resident, m.pending_count());
      auto reserved = m.begin_eligible_deletes(gc, ancestor, cc_past, not_live, 16, 256, 64);
      max_resident = std::max(max_resident, m.pending_count());
      std::vector<std::tuple<tos::ValidatorSessionId, uint64_t, uint64_t>> erased;
      for (const auto& item : reserved) {
        m.on_delete_completed(item.record.session_id, item.generation, item.attempt_id, /*confirmed_gone=*/true,
                              [&](const tos::ValidatorSessionId& s, uint64_t g, uint64_t a) {
                                erase_validator_cleanup_record(kv, s);
                                ++erased_total;
                                if (!pages_at_first_erase) {
                                  pages_at_first_erase = pages;
                                }
                                erased.emplace_back(s, g, a);
                              });
        progressed = true;
      }
      for (const auto& [s, g, a] : erased) {
        m.on_erase_acknowledged(s, g, a);
      }
      if (!progressed) {
        return;
      }
    }
    LOG(FATAL) << "backlog drive did not settle";
  }
};

}  // namespace

// A durable backlog far larger than the resident window (what a long run with cleanup
// disabled leaves behind) is fully reclaimed across passes, and the resident set never
// exceeds the window. Once everything is gone the adapter stops asking for pages.
TEST(ValidatorCleanupStateDb, paged_backlog_is_reclaimed_within_the_resident_bound) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    const int kRecords = 200;
    for (int i = 0; i < kRecords; i++) {
      store_validator_cleanup_record(kv, make_record(static_cast<unsigned char>(i), 100));
    }
    ValidatorCleanupManager m(16);
    BacklogDrive drive{kv, m, [](const tos::BlockIdExt&) { return true; }};
    drive.run();
    ASSERT_TRUE(load_validator_cleanup_records(kv).empty());
    ASSERT_EQ(m.pending_count(), static_cast<size_t>(0));
    ASSERT_TRUE(drive.max_resident <= m.resident_limit());
    ASSERT_TRUE(drive.pages > 1);  // more than one page was needed
    ASSERT_TRUE(!m.next_page_request().has_value());
  }
  td::rmrf(path).ignore();
}

// A window filled with records that are not yet eligible must not hide eligible
// records further along the store: a stalled window rotates. Every eligible record is
// reclaimed, every ineligible one keeps its durable record, and the bound holds.
TEST(ValidatorCleanupStateDb, stalled_window_rotates_to_reach_eligible_records) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    // Seeds 0..59 retire after the GC block (ineligible); seeds 60..99 before it.
    // Session ids grow with the seed, so the ineligible records come first in key order
    // and alone fill the first windows.
    for (int i = 0; i < 100; i++) {
      store_validator_cleanup_record(kv, make_record(static_cast<unsigned char>(i), i < 60 ? 900 : 100));
    }
    ValidatorCleanupManager m(16);
    BacklogDrive drive{kv, m, [](const tos::BlockIdExt& r) { return r.seqno() <= 500; }};
    drive.run();
    auto left = load_validator_cleanup_records(kv);
    ASSERT_EQ(left.size(), static_cast<size_t>(60));
    for (const auto& r : left) {
      ASSERT_EQ(r.retirement_checkpoint.seqno(), static_cast<tos::BlockSeqno>(900));
    }
    ASSERT_TRUE(drive.max_resident <= m.resident_limit());
  }
  td::rmrf(path).ignore();
}

// Runtime retirements keep the window bounded too: once a retirement's close is
// confirmed it may be evicted (its record is durable), so with cleanup never run the
// resident set stays within the limit plus the one retirement still awaiting its close.
TEST(ValidatorCleanupStateDb, runtime_retirements_stay_within_the_resident_bound) {
  ValidatorCleanupManager m(8);
  size_t max_resident = 0;
  for (int i = 0; i < 100; i++) {
    auto rec = make_record(static_cast<unsigned char>(i), 100);
    m.on_group_created(rec.session_id);
    auto gen = m.on_group_retired(rec);
    max_resident = std::max(max_resident, m.pending_count());
    m.on_close_confirmed(rec.session_id, gen);
  }
  ASSERT_TRUE(max_resident <= m.resident_limit() + 1);
  ASSERT_TRUE(m.pending_count() <= m.resident_limit());
}

// A page read before a retirement may carry the record that retirement superseded.
// If the newer incarnation was retired, closed and evicted while the page was in
// flight, admitting the page's copy would resurrect the superseded record: it must be
// skipped, while the rest of the page is admitted and the sweep moves on.
TEST(ValidatorCleanupStateDb, page_copy_of_a_session_retired_in_flight_is_skipped) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    store_validator_cleanup_record(kv, make_record(1, 100));
    store_validator_cleanup_record(kv, make_record(2, 100));  // older incarnation of session 2
    ValidatorCleanupManager m(3);
    auto request = m.next_page_request();
    ASSERT_TRUE(request.has_value());
    auto page = load_validator_cleanup_page(kv, request->after_key, request->max_keys);
    ASSERT_EQ(page.records.size(), static_cast<size_t>(2));
    // While the page is in flight: session 2 is recreated, retired again (new record),
    // and closed; three more retirements evict it; sessions 3 and 4 then go live again,
    // leaving room for both page records.
    auto retire_and_close = [&](PendingValidatorConsensusDbCleanup rec) {
      store_validator_cleanup_record(kv, rec);
      m.on_group_created(rec.session_id);
      auto gen = m.on_group_retired(rec);
      m.on_close_confirmed(rec.session_id, gen);
    };
    auto newer = make_record(2, 300);
    retire_and_close(newer);
    retire_and_close(make_record(3, 300));
    retire_and_close(make_record(4, 300));
    retire_and_close(make_record(5, 300));
    m.on_group_created(make_session_id(3));
    m.on_group_created(make_session_id(4));
    ASSERT_EQ(m.pending_count(), static_cast<size_t>(1));  // session 5
    // Session 1 is admitted; session 2's stale copy is not.
    ASSERT_EQ(m.on_page_loaded(*request, std::move(page)), static_cast<size_t>(1));
    ASSERT_EQ(m.pending_count(), static_cast<size_t>(2));
    // The skipped session's current record is still on disk and the adapter knows
    // the store holds records it does not.
    bool newer_on_disk = false;
    for (const auto& r : load_validator_cleanup_records(kv)) {
      newer_on_disk |= r == newer;
    }
    ASSERT_TRUE(newer_on_disk);
  }
  td::rmrf(path).ignore();
}

// A burst of retirements whose closes all arrive afterwards must not leave the window
// over its limit once they are closed -- even with cleanup disabled, when no pass or
// further retirement would trim it.
TEST(ValidatorCleanupStateDb, window_is_trimmed_when_a_burst_of_retirements_closes) {
  ValidatorCleanupManager m(8);
  std::vector<std::pair<tos::ValidatorSessionId, uint64_t>> retired;
  for (int i = 0; i < 20; i++) {
    auto rec = make_record(static_cast<unsigned char>(i), 100);
    m.on_group_created(rec.session_id);
    retired.emplace_back(rec.session_id, m.on_group_retired(rec));
  }
  ASSERT_EQ(m.pending_count(), static_cast<size_t>(20));  // none evictable before its close
  for (const auto& [session, gen] : retired) {
    m.on_close_confirmed(session, gen);
  }
  ASSERT_TRUE(m.pending_count() <= m.resident_limit());
}

// Retirements of unrelated sessions landing while every page is in flight must not
// starve paging: the cursor keeps advancing and the whole eligible backlog is reclaimed
// while the churn is still going on, not only after it stops.
TEST(ValidatorCleanupStateDb, unrelated_retirements_do_not_starve_paging) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    const size_t kEligible = 100;
    for (size_t i = 0; i < kEligible; i++) {
      store_validator_cleanup_record(kv, make_record(static_cast<unsigned char>(i), 100));
    }
    ValidatorCleanupManager m(16);
    const size_t kChurn = 2000;
    size_t churned = 0;
    std::optional<size_t> churned_when_reclaimed;
    BacklogDrive drive{kv, m, [](const tos::BlockIdExt& r) { return r.seqno() <= 500; }};
    drive.while_page_in_flight = [&] {
      if (!churned_when_reclaimed && drive.erased_total >= kEligible) {
        churned_when_reclaimed = churned;
      }
      if (churned == kChurn) {
        return;
      }
      // A distinct unrelated session retires (beyond the GC block, so it stays) and
      // closes before the page reply arrives.
      PendingValidatorConsensusDbCleanup rec;
      rec.session_id = make_session_id(200);
      rec.session_id.as_slice()[1] = static_cast<char>(churned & 0xff);
      rec.session_id.as_slice()[2] = static_cast<char>((churned >> 8) & 0xff);
      rec.retirement_checkpoint = make_checkpoint(900);
      rec.dir_name = consensus_db_dir_name(kShard, 7, rec.session_id, td::Slice(""));
      store_validator_cleanup_record(kv, rec);
      m.on_group_created(rec.session_id);
      auto gen = m.on_group_retired(rec);
      m.on_close_confirmed(rec.session_id, gen);
      ++churned;
    };
    drive.run();
    ASSERT_EQ(drive.erased_total, kEligible);
    ASSERT_TRUE(churned_when_reclaimed.has_value());
    ASSERT_TRUE(churned_when_reclaimed.value() < kChurn);  // reclaimed under churn
    for (const auto& r : load_validator_cleanup_records(kv)) {
      ASSERT_EQ(r.retirement_checkpoint.seqno(), static_cast<tos::BlockSeqno>(900));
    }
    ASSERT_TRUE(drive.max_resident <= m.resident_limit() + 1);
  }
  td::rmrf(path).ignore();
}

// More retirements overlapping every page read than the adapter tracks must still not
// starve paging: an old eligible record is admitted and reclaimed while every read is
// overlapped by kMaxRetiredDuringPage + 76 distinct unrelated retirements and closes.
TEST(ValidatorCleanupStateDb, retirement_overrun_on_every_read_still_progresses) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto eligible = make_record(0x80, 100);  // in the middle of the key range
    store_validator_cleanup_record(kv, eligible);
    ValidatorCleanupManager m(16);
    const size_t kPerRead = ValidatorCleanupManager::kMaxRetiredDuringPage + 76;
    const size_t kChurnReads = 10;
    size_t reads = 0;
    size_t churned = 0;
    BacklogDrive drive{kv, m, [](const tos::BlockIdExt& r) { return r.seqno() <= 500; }};
    drive.while_page_in_flight = [&] {
      if (++reads > kChurnReads) {
        return;
      }
      for (size_t n = 0; n < kPerRead; n++, churned++) {
        // Distinct sessions spread over the whole key range (first byte cycles).
        PendingValidatorConsensusDbCleanup rec;
        rec.session_id = make_session_id(0x11);
        rec.session_id.as_slice()[0] = static_cast<char>(churned & 0xff);
        rec.session_id.as_slice()[1] = static_cast<char>((churned >> 8) & 0xff);
        rec.session_id.as_slice()[2] = static_cast<char>(0xC3);
        rec.retirement_checkpoint = make_checkpoint(900);
        rec.dir_name = consensus_db_dir_name(kShard, 7, rec.session_id, td::Slice(""));
        store_validator_cleanup_record(kv, rec);
        m.on_group_created(rec.session_id);
        auto gen = m.on_group_retired(rec);
        m.on_close_confirmed(rec.session_id, gen);
      }
    };
    drive.run();
    ASSERT_EQ(drive.erased_total, static_cast<size_t>(1));
    ASSERT_TRUE(drive.pages_at_first_erase.has_value());
    // Reclaimed while every read so far was overrun.
    ASSERT_TRUE(drive.pages_at_first_erase.value() <= kChurnReads);
    for (const auto& r : load_validator_cleanup_records(kv)) {
      ASSERT_TRUE(!(r == eligible));
    }
  }
  td::rmrf(path).ignore();
}

// When more retirements overlap a page than the adapter tracks, the forgotten ones all
// lie above the largest tracked key, so a page record above that key must not be
// admitted -- it may be the superseded copy of a session retired, closed and evicted
// while the page was in flight. It is left for the next read instead.
TEST(ValidatorCleanupStateDb, page_record_beyond_the_tracked_retirements_is_not_admitted) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto churn_record = [](uint8_t first, size_t n) {
      PendingValidatorConsensusDbCleanup rec;
      rec.session_id = make_session_id(0x11);
      rec.session_id.as_slice()[0] = static_cast<char>(first);
      rec.session_id.as_slice()[1] = static_cast<char>(n & 0xff);
      rec.session_id.as_slice()[2] = static_cast<char>((n >> 8) & 0xff);
      rec.retirement_checkpoint = make_checkpoint(900);
      rec.dir_name = consensus_db_dir_name(kShard, 7, rec.session_id, td::Slice(""));
      return rec;
    };
    auto old_copy = churn_record(0xF0, 0);
    old_copy.retirement_checkpoint = make_checkpoint(100);
    store_validator_cleanup_record(kv, old_copy);
    ValidatorCleanupManager m(16);
    auto request = m.next_page_request();
    ASSERT_TRUE(request.has_value());
    auto page = load_validator_cleanup_page(kv, request->after_key, request->max_keys);
    ASSERT_EQ(page.records.size(), static_cast<size_t>(1));
    auto retire_and_close = [&](const PendingValidatorConsensusDbCleanup& rec) {
      store_validator_cleanup_record(kv, rec);
      m.on_group_created(rec.session_id);
      auto gen = m.on_group_retired(rec);
      m.on_close_confirmed(rec.session_id, gen);
    };
    // While the page is in flight: more low-key retirements than are tracked, then the
    // old copy's session retires again, then enough high-key retirements to evict it.
    for (size_t n = 0; n < ValidatorCleanupManager::kMaxRetiredDuringPage + 50; n++) {
      retire_and_close(churn_record(0x10, n));
    }
    auto newer = churn_record(0xF0, 0);
    retire_and_close(newer);
    for (size_t n = 0; n < 64; n++) {
      retire_and_close(churn_record(0xF8, n));
    }
    ASSERT_EQ(m.on_page_loaded(*request, std::move(page)), static_cast<size_t>(0));
    // The newer record is what the store holds; a later read admits it.
    bool newer_on_disk = false;
    for (const auto& r : load_validator_cleanup_records(kv)) {
      newer_on_disk |= r == newer;
    }
    ASSERT_TRUE(newer_on_disk);
  }
  td::rmrf(path).ignore();
}

// A full window must not evict a record admitted earlier in the same page before any
// pass has examined it. Here a four-record page (one eligible, three not yet) arrives
// while four closed, not-yet-eligible runtime retirements fill a window of four; the
// eligible record must still be examined and reclaimed with the GC block unchanged.
TEST(ValidatorCleanupStateDb, page_admissions_are_not_evicted_before_examination) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto with_first_byte = [](uint8_t first, tos::BlockSeqno retire_seqno) {
      PendingValidatorConsensusDbCleanup rec;
      rec.session_id = make_session_id(0x22);
      rec.session_id.as_slice()[0] = static_cast<char>(first);
      rec.retirement_checkpoint = make_checkpoint(retire_seqno);
      rec.dir_name = consensus_db_dir_name(kShard, 7, rec.session_id, td::Slice(""));
      return rec;
    };
    auto eligible = with_first_byte(0x80, 100);
    store_validator_cleanup_record(kv, eligible);
    for (uint8_t b = 0x81; b <= 0x83; b++) {
      store_validator_cleanup_record(kv, with_first_byte(b, 900));
    }
    ValidatorCleanupManager m(4);
    // A pass has already run at this GC block, as on a running node.
    ASSERT_TRUE(m.begin_eligible_deletes(
                     make_checkpoint(500), [](const tos::BlockIdExt& r) { return r.seqno() <= 500; },
                     [](tos::ShardIdFull) -> std::optional<tos::CatchainSeqno> { return 10; },
                     [](const tos::ValidatorSessionId&) { return false; }, 16, 256, 64)
                    .empty());
    bool filled = false;
    BacklogDrive drive{kv, m, [](const tos::BlockIdExt& r) { return r.seqno() <= 500; }};
    drive.while_page_in_flight = [&] {
      if (filled) {
        return;
      }
      filled = true;
      // Four lower-key runtime retirements, closed and not yet eligible.
      for (uint8_t b = 0x10; b < 0x14; b++) {
        auto rec = with_first_byte(b, 900);
        store_validator_cleanup_record(kv, rec);
        m.on_group_created(rec.session_id);
        auto gen = m.on_group_retired(rec);
        m.on_close_confirmed(rec.session_id, gen);
      }
    };
    drive.run();
    ASSERT_TRUE(filled);
    ASSERT_EQ(drive.erased_total, static_cast<size_t>(1));
    for (const auto& r : load_validator_cleanup_records(kv)) {
      ASSERT_TRUE(!(r == eligible));
    }
    ASSERT_TRUE(drive.max_resident <= m.resident_limit());
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
