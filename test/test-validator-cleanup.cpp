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
#include "validator/consensus/validator-cleanup.h"

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

tos::Bits256 make_hash(unsigned char seed) {
  tos::Bits256 h;
  for (size_t i = 0; i < h.as_slice().size(); i++) {
    h.as_slice()[i] = static_cast<char>(seed + i * 3 + 1);
  }
  return h;
}

const tos::ShardIdFull kShard{0, static_cast<tos::ShardId>(0x8000000000000000ULL)};

// A fully-specified masterchain checkpoint at a given seqno (distinct hashes so
// two seqnos are never accidentally equal).
tos::BlockIdExt make_checkpoint(tos::BlockSeqno seqno) {
  return tos::BlockIdExt{tos::masterchainId, static_cast<tos::ShardId>(0x8000000000000000ULL), seqno,
                         make_hash(static_cast<unsigned char>(seqno)),
                         make_hash(static_cast<unsigned char>(seqno + 128))};
}

PendingValidatorConsensusDbCleanup make_record(unsigned char sid_seed, tos::BlockSeqno retire_seqno,
                                               tos::CatchainSeqno cc = 7) {
  auto sid = make_session_id(sid_seed);
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  r.retirement_checkpoint = make_checkpoint(retire_seqno);
  r.dir_name = consensus_db_dir_name(kShard, cc, sid, td::Slice(""));  // validator dir, no suffix
  return r;
}

}  // namespace

// A record must survive a persistence round trip unchanged: if encode/decode
// drops or corrupts any field, the cleanup intent is silently lost. Removing any
// field from the encoder makes this fail.
TEST(ValidatorCleanup, record_round_trips) {
  auto r = make_record(9, 100);
  auto blob = encode_validator_cleanup_record(r);
  auto back = decode_validator_cleanup_record(td::Slice(blob));
  ASSERT_TRUE(back.has_value());
  ASSERT_TRUE(back.value() == r);
}

// A truncated, wrong-version, or empty blob must be rejected, never half-read
// into a record that authorizes deleting the wrong directory.
TEST(ValidatorCleanup, malformed_records_are_rejected) {
  auto r = make_record(9, 100);
  auto blob = encode_validator_cleanup_record(r);

  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice("")).has_value());
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob.substr(0, blob.size() - 5))).has_value());
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob.substr(0, 10))).has_value());

  auto bad_version = blob;
  bad_version[0] = static_cast<char>(0x7f);
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(bad_version)).has_value());
}

// An observer directory name must never decode into a validator cleanup record:
// observer cleanup is the queue's job (db-path.h), and treating an observer dir
// as a validator record would cross the safety boundary the split exists for.
TEST(ValidatorCleanup, observer_dir_name_is_rejected) {
  auto sid = make_session_id(5);
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  r.retirement_checkpoint = make_checkpoint(50);
  r.dir_name = consensus_db_dir_name(kShard, 7, sid, td::Slice(".observer.abc"));
  auto blob = encode_validator_cleanup_record(r);
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
}

// A record whose stored dir_name parses to a DIFFERENT session id is rejected:
// the directory and the authority must agree, or we could delete an unrelated
// group's DB.
TEST(ValidatorCleanup, mismatched_session_and_dir_is_rejected) {
  auto r = make_record(9, 100);
  r.dir_name = consensus_db_dir_name(kShard, 7, make_session_id(200), td::Slice(""));  // different sid
  auto blob = encode_validator_cleanup_record(r);
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
}

// An always-"ancestor" oracle: stands in for a checkpoint strictly ahead on the
// accepted chain.
CleanupAncestry always_ancestor(const tos::BlockIdExt&, const tos::BlockIdExt&) {
  return CleanupAncestry::Ancestor;
}
CleanupAncestry never_ancestor(const tos::BlockIdExt&, const tos::BlockIdExt&) {
  return CleanupAncestry::NotAncestor;
}
CleanupAncestry unknown_ancestry(const tos::BlockIdExt&, const tos::BlockIdExt&) {
  return CleanupAncestry::Unknown;
}

// Core safety predicate: a live/recreatable session is NEVER deletable, whatever
// the checkpoints say. Dropping the session_is_live short-circuit makes this
// fail -- it is the defense that closes the "delete-fail -> prune -> recreate"
// history.
TEST(ValidatorCleanup, live_session_is_never_deletable) {
  auto r = make_record(9, 100);
  auto safe = make_checkpoint(200);
  ASSERT_TRUE(!can_delete_validator_db(r, safe, /*session_is_live=*/true, always_ancestor));
}

// Retirement == safe checkpoint is deletable (when not live). The equality fast
// path must hold without consulting the oracle.
TEST(ValidatorCleanup, retirement_equal_to_safe_is_deletable) {
  auto r = make_record(9, 150);
  auto safe = r.retirement_checkpoint;
  bool oracle_called = false;
  auto spy = [&](const tos::BlockIdExt&, const tos::BlockIdExt&) {
    oracle_called = true;
    return CleanupAncestry::NotAncestor;
  };
  ASSERT_TRUE(can_delete_validator_db(r, safe, false, spy));
  ASSERT_TRUE(!oracle_called);
}

// A retirement that is a verified ancestor of the safe checkpoint is deletable;
// one that is NOT an ancestor, or whose ancestry is UNKNOWN, is retained
// (fail-closed). Collapsing Unknown into "deletable" makes the unknown case fail.
TEST(ValidatorCleanup, ancestry_decides_and_unknown_fails_closed) {
  auto r = make_record(9, 100);
  auto safe = make_checkpoint(200);
  ASSERT_TRUE(can_delete_validator_db(r, safe, false, always_ancestor));
  ASSERT_TRUE(!can_delete_validator_db(r, safe, false, never_ancestor));
  ASSERT_TRUE(!can_delete_validator_db(r, safe, false, unknown_ancestry));
}

// An invalid (e.g. default/empty) checkpoint on either side is never deletable:
// without a fully specified checkpoint there is no safety basis.
TEST(ValidatorCleanup, invalid_checkpoints_are_never_deletable) {
  auto r = make_record(9, 100);
  tos::BlockIdExt invalid;  // default-constructed, not valid_full
  ASSERT_TRUE(!can_delete_validator_db(r, invalid, false, always_ancestor));

  auto r_invalid = r;
  r_invalid.retirement_checkpoint = tos::BlockIdExt{};
  ASSERT_TRUE(!can_delete_validator_db(r_invalid, make_checkpoint(200), false, always_ancestor));
}

// Non-rotated retention: a session retired at R>C while the safe checkpoint is
// stuck at C (not an ancestor relation that reaches R) must stay ineligible --
// never prematurely deleted. This is the non-rotated-retirement case.
TEST(ValidatorCleanup, retirement_ahead_of_safe_is_retained) {
  auto r = make_record(9, 300);        // retired at seqno 300
  auto safe = make_checkpoint(100);    // durable floor only at 100
  // 300 is not an ancestor of 100.
  ASSERT_TRUE(!can_delete_validator_db(r, safe, false, never_ancestor));
}

// Safe-checkpoint monotonicity: adopt a strictly-ahead candidate (current is its
// ancestor); refuse a regression or an unknown/forked candidate, so a later
// restart that loads an older init block cannot lower the floor.
TEST(ValidatorCleanup, safe_checkpoint_is_monotonic) {
  auto c100 = make_checkpoint(100);
  auto c200 = make_checkpoint(200);
  tos::BlockIdExt none;

  ASSERT_TRUE(should_adopt_safe_checkpoint(none, c100, never_ancestor));   // first adoption
  ASSERT_TRUE(should_adopt_safe_checkpoint(c100, c200, always_ancestor));  // strictly ahead
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c200, c100, unknown_ancestry));  // would regress: refuse
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, c200, unknown_ancestry));  // unknown ancestry: refuse
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, c100, always_ancestor));   // equal: no change
  tos::BlockIdExt invalid;
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, invalid, always_ancestor));  // invalid candidate
}
