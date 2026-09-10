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

#include <string>

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

// A fully-specified MASTERCHAIN checkpoint on the canonical "main" chain at a
// given seqno. Distinct hashes per seqno so two seqnos never compare equal.
tos::BlockIdExt make_checkpoint(tos::BlockSeqno seqno) {
  return tos::BlockIdExt{tos::masterchainId, kMasterShard, seqno, make_hash(static_cast<unsigned char>(seqno)),
                         make_hash(static_cast<unsigned char>(seqno + 128))};
}

// A masterchain block at `seqno` on a DIFFERENT branch (forked hashes), so it is
// not recognized as a main-chain checkpoint by the oracle below.
tos::BlockIdExt make_fork_checkpoint(tos::BlockSeqno seqno) {
  return tos::BlockIdExt{tos::masterchainId, kMasterShard, seqno, make_hash(static_cast<unsigned char>(seqno + 31)),
                         make_hash(static_cast<unsigned char>(seqno + 47))};
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

// Argument-sensitive ancestry oracle over a single canonical main chain ordered
// by seqno. Reversing the two arguments flips Ancestor<->NotAncestor, so a test
// that depends on it would catch a caller that passes the arguments swapped. A
// checkpoint not on the main chain (a fork) resolves to Unknown.
bool on_main_chain(const tos::BlockIdExt& cp) {
  return cp == make_checkpoint(cp.seqno());
}
CleanupAncestry chain_oracle(const tos::BlockIdExt& a, const tos::BlockIdExt& b) {
  if (!on_main_chain(a) || !on_main_chain(b)) {
    return CleanupAncestry::Unknown;
  }
  if (a.seqno() < b.seqno()) {
    return CleanupAncestry::Ancestor;
  }
  return CleanupAncestry::NotAncestor;
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

// Golden wire-format vector, independent of the encoder's own put/get helpers:
// it pins the exact byte offsets and little-endian layout, so a coordinated
// change to BOTH encode and decode (which the round-trip test cannot see) still
// fails here. Checkpoint fields are chosen with distinct bytes to catch an
// endianness or offset regression.
TEST(ValidatorCleanup, wire_format_is_pinned) {
  auto sid = make_session_id(1);
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  // workchain = -1 (masterchain), shard = 0x8000000000000000, seqno = 0x01020304
  auto root = make_hash(10);
  auto file = make_hash(200);
  r.retirement_checkpoint = tos::BlockIdExt{tos::masterchainId, kMasterShard, 0x01020304u, root, file};
  r.dir_name = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));

  auto blob = encode_validator_cleanup_record(r);
  const auto* p = reinterpret_cast<const unsigned char*>(blob.data());

  ASSERT_EQ(blob.size(), static_cast<size_t>(113) + r.dir_name.size());
  ASSERT_EQ(p[0], static_cast<unsigned char>(1));  // version
  for (size_t i = 0; i < 32; i++) {                // session id
    ASSERT_EQ(p[1 + i], static_cast<unsigned char>(sid.as_slice()[i]));
  }
  // workchain -1 little-endian int32 == 0xFFFFFFFF
  for (size_t i = 0; i < 4; i++) {
    ASSERT_EQ(p[33 + i], static_cast<unsigned char>(0xff));
  }
  // shard 0x8000000000000000 little-endian uint64
  for (size_t i = 0; i < 7; i++) {
    ASSERT_EQ(p[37 + i], static_cast<unsigned char>(0x00));
  }
  ASSERT_EQ(p[44], static_cast<unsigned char>(0x80));
  // seqno 0x01020304 little-endian
  ASSERT_EQ(p[45], static_cast<unsigned char>(0x04));
  ASSERT_EQ(p[46], static_cast<unsigned char>(0x03));
  ASSERT_EQ(p[47], static_cast<unsigned char>(0x02));
  ASSERT_EQ(p[48], static_cast<unsigned char>(0x01));
  for (size_t i = 0; i < 32; i++) {  // root hash
    ASSERT_EQ(p[49 + i], static_cast<unsigned char>(root.as_slice()[i]));
  }
  for (size_t i = 0; i < 32; i++) {  // file hash
    ASSERT_EQ(p[81 + i], static_cast<unsigned char>(file.as_slice()[i]));
  }
  ASSERT_EQ(blob.substr(113), r.dir_name);

  auto back = decode_validator_cleanup_record(td::Slice(blob));
  ASSERT_TRUE(back.has_value());
  ASSERT_TRUE(back.value() == r);
}

// Every truncation of a valid blob must be rejected -- no prefix may be
// half-decoded into a usable record.
TEST(ValidatorCleanup, every_truncation_is_rejected) {
  auto r = make_record(9, 100);
  auto blob = encode_validator_cleanup_record(r);
  for (size_t n = 0; n < blob.size(); n++) {
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob.substr(0, n))).has_value());
  }
  // The full blob is the first length that must succeed.
  ASSERT_TRUE(decode_validator_cleanup_record(td::Slice(blob)).has_value());
}

// Wrong version is rejected even at full length.
TEST(ValidatorCleanup, wrong_version_is_rejected) {
  auto r = make_record(9, 100);
  auto blob = encode_validator_cleanup_record(r);
  blob[0] = static_cast<char>(0x7f);
  ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
}

// The directory must be the exact canonical validator basename for the session.
// Observer directories (full or truncated suffix), trailing garbage, extra
// fields, separators, and session mismatches are all rejected.
TEST(ValidatorCleanup, non_canonical_dir_names_are_rejected) {
  auto sid = make_session_id(9);
  auto canonical = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));
  for (const std::string &suffix : {std::string(".observer.abc"), std::string(".observer"), std::string("x"),
                                    std::string("/.."), std::string(".7"), std::string(".")}) {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = make_checkpoint(100);
    r.dir_name = canonical + suffix;
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
  // Non-canonical numeric field (leading zero) is rejected by the re-render check.
  {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = make_checkpoint(100);
    r.dir_name = PSTRING() << "consensus.0.09223372036854775808.007." << sid.to_hex();
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
  // Parseable directory but a DIFFERENT session id.
  {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = make_checkpoint(100);
    r.dir_name = consensus_db_dir_name(kShard, 7, make_session_id(200), td::Slice(""));
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
}

// The canonical happy path still passes (guards against a canonical check so
// strict it rejects everything).
TEST(ValidatorCleanup, canonical_dir_name_is_accepted) {
  for (tos::WorkchainId wc : {-1, 0, 1}) {
    auto sid = make_session_id(static_cast<unsigned char>(wc + 3));
    tos::ShardIdFull shard{wc, kMasterShard};
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = make_checkpoint(100);
    r.dir_name = consensus_db_dir_name(shard, 12345, sid, td::Slice(""));
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
}

// A checkpoint that is not a fully specified masterchain block must be rejected
// by decode: a shardchain block, and zero hashes.
TEST(ValidatorCleanup, non_masterchain_or_incomplete_checkpoint_is_rejected) {
  auto sid = make_session_id(9);
  auto dir = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));
  // Shardchain block (workchain 0), otherwise fully specified.
  {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = tos::BlockIdExt{0, kMasterShard, 100, make_hash(10), make_hash(20)};
    r.dir_name = dir;
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
  // Zero hashes (not valid_full).
  {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = tos::BlockIdExt{tos::masterchainId, kMasterShard, 100, tos::Bits256::zero(),
                                              tos::Bits256::zero()};
    r.dir_name = dir;
    auto blob = encode_validator_cleanup_record(r);
    ASSERT_TRUE(!decode_validator_cleanup_record(td::Slice(blob)).has_value());
  }
}

// Core safety predicate: a live/recreatable session is NEVER deletable, whatever
// the checkpoints say -- including when retirement == safe (the live guard must
// precede the equality fast path). Dropping the session_is_live short-circuit
// makes this fail; moving equality before the live guard makes the equal case
// fail.
TEST(ValidatorCleanup, live_session_is_never_deletable) {
  auto r = make_record(9, 100);
  ASSERT_TRUE(!can_delete_validator_db(r, make_checkpoint(200), /*session_is_live=*/true, chain_oracle));
  ASSERT_TRUE(!can_delete_validator_db(r, r.retirement_checkpoint, /*session_is_live=*/true, chain_oracle));
}

// Retirement == safe checkpoint is deletable (when not live), without consulting
// the oracle.
TEST(ValidatorCleanup, retirement_equal_to_safe_is_deletable) {
  auto r = make_record(9, 150);
  bool oracle_called = false;
  auto spy = [&](const tos::BlockIdExt&, const tos::BlockIdExt&) {
    oracle_called = true;
    return CleanupAncestry::NotAncestor;
  };
  ASSERT_TRUE(can_delete_validator_db(r, r.retirement_checkpoint, false, spy));
  ASSERT_TRUE(!oracle_called);
}

// Ancestry decides the unequal case via an argument-sensitive oracle: a
// retirement strictly before the safe checkpoint on the main chain is deletable;
// one after it (NotAncestor) or on a fork (Unknown) is retained. Because the
// oracle is argument-sensitive, a predicate that passed (safe, retirement) in the
// wrong order would fail the positive case.
TEST(ValidatorCleanup, ancestry_decides_and_unknown_fails_closed) {
  auto r = make_record(9, 100);
  ASSERT_TRUE(can_delete_validator_db(r, make_checkpoint(200), false, chain_oracle));    // ancestor
  ASSERT_TRUE(!can_delete_validator_db(r, make_checkpoint(50), false, chain_oracle));    // not ancestor
  ASSERT_TRUE(!can_delete_validator_db(r, make_fork_checkpoint(200), false, chain_oracle));  // unknown (fork)
}

// An invalid/non-masterchain checkpoint on either side is never deletable. This
// uses an Ancestor-returning spy -- which WOULD authorize deletion if the
// checkpoint guard were removed -- and asserts it is never called, so the test
// fails red if the guard is dropped (chain_oracle's Unknown would have masked
// that). Also covers equal-but-invalid checkpoints, pinning guard-before-equality
// ordering.
TEST(ValidatorCleanup, invalid_checkpoints_are_never_deletable) {
  auto r = make_record(9, 100);
  bool oracle_called = false;
  auto ancestor_spy = [&](const tos::BlockIdExt&, const tos::BlockIdExt&) {
    oracle_called = true;
    return CleanupAncestry::Ancestor;
  };

  tos::BlockIdExt invalid;  // default-constructed
  ASSERT_TRUE(!can_delete_validator_db(r, invalid, false, ancestor_spy));  // invalid safe

  auto r_shard = r;
  r_shard.retirement_checkpoint = tos::BlockIdExt{0, kMasterShard, 100, make_hash(1), make_hash(2)};  // shardchain
  ASSERT_TRUE(!can_delete_validator_db(r_shard, make_checkpoint(200), false, ancestor_spy));

  auto r_zero = r;  // full masterchain id but zero hashes -> not valid_full
  r_zero.retirement_checkpoint =
      tos::BlockIdExt{tos::masterchainId, kMasterShard, 100, tos::Bits256::zero(), tos::Bits256::zero()};
  ASSERT_TRUE(!can_delete_validator_db(r_zero, make_checkpoint(200), false, ancestor_spy));

  auto r_eq_invalid = r;  // retirement == safe == invalid: guard must beat the equality fast path
  r_eq_invalid.retirement_checkpoint = invalid;
  ASSERT_TRUE(!can_delete_validator_db(r_eq_invalid, invalid, false, ancestor_spy));

  ASSERT_TRUE(!oracle_called);  // the checkpoint guard short-circuits before the oracle
}

// Non-rotated retention: a session retired at R>C while the safe floor is only at
// C must stay ineligible (the oracle reports NotAncestor for 300 vs 100).
TEST(ValidatorCleanup, retirement_ahead_of_safe_is_retained) {
  auto r = make_record(9, 300);
  ASSERT_TRUE(!can_delete_validator_db(r, make_checkpoint(100), false, chain_oracle));
}

// The record builder produces a canonical VALIDATOR record (empty suffix) that
// always satisfies the decode contract: it encodes and decodes back to an equal
// record, and its directory is canonical for the session. A wrong suffix (e.g.
// observer) or a non-masterchain checkpoint would make the round trip fail.
TEST(ValidatorCleanup, make_record_is_canonical_and_round_trips) {
  auto sid = make_session_id(9);
  tos::ShardIdFull shard{0, kMasterShard};
  auto checkpoint = make_checkpoint(123);
  auto record = make_validator_cleanup_record(sid, shard, 4567, checkpoint);

  ASSERT_TRUE(record.session_id == sid);
  ASSERT_TRUE(record.retirement_checkpoint == checkpoint);
  ASSERT_TRUE(record.dir_name == consensus_db_dir_name(shard, 4567, sid, td::Slice("")));
  ASSERT_TRUE(is_canonical_validator_dir_name(record.dir_name, sid));

  auto blob = encode_validator_cleanup_record(record);
  auto back = decode_validator_cleanup_record(td::Slice(blob));
  ASSERT_TRUE(back.has_value());
  ASSERT_TRUE(back.value() == record);
}

// The parse recovers the shard and catchain seqno from a canonical validator
// directory (across workchains and non-root shards), and rejects
// observer/mismatched/non-canonical names.
TEST(ValidatorCleanup, parse_validator_dir_exposes_shard_and_cc) {
  auto sid = make_session_id(9);
  // A non-root child shard on a non-zero workchain, so hardcoding {0, master}
  // would be caught.
  tos::ShardIdFull shard{1, static_cast<tos::ShardId>(0x4000000000000000ULL)};
  auto name = consensus_db_dir_name(shard, 4242, sid, td::Slice(""));
  auto p = parse_canonical_validator_dir_name(name, sid);
  ASSERT_TRUE(p.has_value());
  ASSERT_TRUE(p->shard == shard);
  ASSERT_EQ(p->catchain_seqno, static_cast<tos::CatchainSeqno>(4242));

  // Masterchain workchain (-1) round-trips too.
  tos::ShardIdFull mshard{tos::masterchainId, kMasterShard};
  auto mp = parse_canonical_validator_dir_name(consensus_db_dir_name(mshard, 1, sid, td::Slice("")), sid);
  ASSERT_TRUE(mp.has_value() && mp->shard == mshard && mp->catchain_seqno == static_cast<tos::CatchainSeqno>(1));

  ASSERT_TRUE(
      !parse_canonical_validator_dir_name(consensus_db_dir_name(shard, 4242, sid, td::Slice(".observer.x")), sid)
           .has_value());
  ASSERT_TRUE(!parse_canonical_validator_dir_name(name, make_session_id(200)).has_value());  // session mismatch
}

// On-chain obsolescence: deletable (obsolescence portion) ONLY when the retirement
// is the GC block or a verified ancestor of it AND the shard's catchain seqno at
// GC is strictly greater than the record's (r < g excludes current g and next
// g+1). Every uncertain case keeps the DB. Uses argument-controllable oracles so
// each condition is pinned independently.
TEST(ValidatorCleanup, onchain_obsolete_requires_ancestor_and_cc_strictly_past) {
  auto sid = make_session_id(9);
  tos::ShardIdFull shard{0, kMasterShard};
  auto gc = make_checkpoint(500);

  // Build a record for this shard with a chosen retirement checkpoint and cc.
  auto record_with = [&](tos::BlockIdExt retirement, tos::CatchainSeqno rec_cc) {
    PendingValidatorConsensusDbCleanup r;
    r.session_id = sid;
    r.retirement_checkpoint = retirement;
    r.dir_name = consensus_db_dir_name(shard, rec_cc, sid, td::Slice(""));
    return r;
  };
  auto retirement = make_checkpoint(100);
  auto r = record_with(retirement, 7);  // cc = 7

  // ARGUMENT-SENSITIVE ancestry oracle: only the EXACT retirement full id is an
  // ancestor, so a predicate that passed the wrong block (e.g. gc) would fail.
  int ancestor_calls = 0;
  auto ancestor_is = [&](const tos::BlockIdExt& expected) {
    return [&ancestor_calls, expected](const tos::BlockIdExt& queried) {
      ancestor_calls++;
      return queried == expected;
    };
  };
  auto ancestor_no = [](const tos::BlockIdExt&) { return false; };
  auto cc = [&](tos::CatchainSeqno v) {
    return [&shard, v](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
      return s == shard ? std::optional<tos::CatchainSeqno>{v} : std::nullopt;
    };
  };

  // ancestor(exact retirement) + r(7) < g(10) -> obsolete.
  ASSERT_TRUE(validator_session_is_onchain_obsolete(r, gc, ancestor_is(retirement), cc(10)));
  // The oracle must be queried with the retirement id, not gc: a fork at the same
  // seqno (different hash) is NOT an ancestor -> keep.
  auto forked = make_fork_checkpoint(100);
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(record_with(forked, 7), gc, ancestor_is(retirement), cc(10)));

  // Strict r < g boundary: g == 8 (current=8,next=9) excludes r=7 -> obsolete;
  // g == 7 (r is the current set) -> keep.
  ASSERT_TRUE(validator_session_is_onchain_obsolete(r, gc, ancestor_is(retirement), cc(8)));
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(r, gc, ancestor_is(retirement), cc(7)));
  // Next and future counters must be RETAINED: r = g+1 and r > g+1 -> keep. (A
  // "!=" mutation of the strict compare would wrongly delete these.)
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(record_with(retirement, 8), gc, ancestor_is(retirement), cc(7)));
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(record_with(retirement, 20), gc, ancestor_is(retirement), cc(7)));

  // Not a GC ancestor -> keep.
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(r, gc, ancestor_no, cc(10)));
  // Unknown shard catchain seqno -> keep.
  auto cc_unknown = [](tos::ShardIdFull) -> std::optional<tos::CatchainSeqno> { return std::nullopt; };
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(r, gc, ancestor_is(retirement), cc_unknown));
  // Invalid / non-masterchain GC checkpoint -> keep.
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(r, tos::BlockIdExt{}, ancestor_is(retirement), cc(10)));
  // Non-canonical (observer) directory -> keep.
  auto r_obs = r;
  r_obs.dir_name = consensus_db_dir_name(shard, 7, sid, td::Slice(".observer.z"));
  ASSERT_TRUE(!validator_session_is_onchain_obsolete(r_obs, gc, ancestor_is(retirement), cc(10)));

  // Equality path: retirement == GC is accepted WITHOUT consulting the ancestor
  // oracle. A counting oracle that would REJECT proves both: the predicate still
  // returns true (so it took the equality branch) AND never queried the oracle.
  auto r_eq = record_with(gc, 7);
  ancestor_calls = 0;
  auto counting_reject = [&](const tos::BlockIdExt&) {
    ancestor_calls++;
    return false;
  };
  ASSERT_TRUE(validator_session_is_onchain_obsolete(r_eq, gc, counting_reject, cc(10)));
  ASSERT_EQ(ancestor_calls, 0);
}

// The full four-condition delete gate: eligible ONLY when not live (C-runtime),
// closed (D), and on-chain obsolete (B + C-onchain). Each condition independently
// vetoes; live is checked first (reopen safety). Removing any guard makes one of
// these go red.
TEST(ValidatorCleanup, cleanup_eligible_requires_all_four_conditions) {
  auto sid = make_session_id(9);
  tos::ShardIdFull shard{0, kMasterShard};
  PendingValidatorConsensusDbCleanup r;
  r.session_id = sid;
  auto retirement = make_checkpoint(100);
  r.retirement_checkpoint = retirement;
  r.dir_name = consensus_db_dir_name(shard, 7, sid, td::Slice(""));  // cc = 7
  auto gc = make_checkpoint(500);

  auto ancestor_ok = [retirement](const tos::BlockIdExt& q) { return q == retirement; };
  auto cc_past = [&shard](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
    return s == shard ? std::optional<tos::CatchainSeqno>{10} : std::nullopt;  // g=10 > r=7
  };
  auto not_live = [](const tos::ValidatorSessionId&) { return false; };
  auto live = [](const tos::ValidatorSessionId&) { return true; };
  auto closed = [](const tos::ValidatorSessionId&) { return true; };
  auto not_closed = [](const tos::ValidatorSessionId&) { return false; };

  // All four hold -> eligible.
  ASSERT_TRUE(validator_cleanup_eligible(r, gc, ancestor_ok, cc_past, not_live, closed));
  // Live/reopened -> keep (even though closed + obsolete).
  ASSERT_TRUE(!validator_cleanup_eligible(r, gc, ancestor_ok, cc_past, live, closed));
  // Not closed -> keep.
  ASSERT_TRUE(!validator_cleanup_eligible(r, gc, ancestor_ok, cc_past, not_live, not_closed));
  // Not on-chain obsolete (cc unknown) -> keep.
  auto cc_unknown = [](tos::ShardIdFull) -> std::optional<tos::CatchainSeqno> { return std::nullopt; };
  ASSERT_TRUE(!validator_cleanup_eligible(r, gc, ancestor_ok, cc_unknown, not_live, closed));
  // Not on-chain obsolete (not a GC ancestor) -> keep.
  auto ancestor_never = [](const tos::BlockIdExt&) { return false; };
  ASSERT_TRUE(!validator_cleanup_eligible(r, gc, ancestor_never, cc_past, not_live, closed));
}

// The cleanup sweep deletes+erases only eligible records, keeps the rest, retries
// unconfirmed deletions, reconciles already-gone directories, respects the delete
// budget, and never touches a reopened (live) session.
TEST(ValidatorCleanup, sweep_deletes_eligible_keeps_rest) {
  // All records share shard kShard, cc 7; g=10 so cc=7 is obsolete; all closed.
  auto gc = make_checkpoint(500);
  auto ancestor_ok = [](const tos::BlockIdExt&) { return true; };
  auto cc_past = [](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
    return s == kShard ? std::optional<tos::CatchainSeqno>{10} : std::nullopt;
  };
  auto closed = [](const tos::ValidatorSessionId&) { return true; };

  std::set<std::string> live_hex;  // sessions considered live/reopened
  auto is_live = [&](const tos::ValidatorSessionId& s) { return live_hex.count(s.to_hex()) > 0; };
  std::set<std::string> deleter_called;
  std::set<std::string> erased;
  auto make_deleter = [&](const std::set<std::string>& fail_for) {
    return [&, fail_for](const PendingValidatorConsensusDbCleanup& rec) {
      deleter_called.insert(rec.session_id.to_hex());
      return fail_for.count(rec.session_id.to_hex()) == 0;  // confirmed gone unless told to fail
    };
  };
  auto erase = [&](const tos::ValidatorSessionId& s) { erased.insert(s.to_hex()); };

  auto r1 = make_record(1, 100);
  auto r2 = make_record(2, 100);
  auto r3 = make_record(3, 100);

  // Mixed: r2 is live (reopened) -> kept + deleter NOT called; r1, r3 deleted+erased.
  live_hex = {r2.session_id.to_hex()};
  deleter_called.clear();
  erased.clear();
  auto res = sweep_pending_validator_cleanup({r1, r2, r3}, gc, ancestor_ok, cc_past, is_live, closed,
                                             make_deleter({}), erase, /*budget=*/10);
  ASSERT_EQ(res.deleted, static_cast<size_t>(2));
  ASSERT_EQ(res.kept, static_cast<size_t>(1));
  ASSERT_TRUE(deleter_called.count(r2.session_id.to_hex()) == 0);
  ASSERT_TRUE(erased.count(r1.session_id.to_hex()) == 1 && erased.count(r3.session_id.to_hex()) == 1);
  ASSERT_TRUE(erased.count(r2.session_id.to_hex()) == 0);

  // Unconfirmed deletion -> kept, NOT erased (retry next pass).
  live_hex.clear();
  deleter_called.clear();
  erased.clear();
  auto res2 = sweep_pending_validator_cleanup({r1}, gc, ancestor_ok, cc_past, is_live, closed,
                                              make_deleter({r1.session_id.to_hex()}), erase, 10);
  ASSERT_EQ(res2.deleted, static_cast<size_t>(0));
  ASSERT_EQ(res2.kept, static_cast<size_t>(1));
  ASSERT_TRUE(erased.empty());

  // Budget limits delete attempts: 3 eligible, budget 2 -> 2 attempts, 1 deferred.
  deleter_called.clear();
  erased.clear();
  auto res3 = sweep_pending_validator_cleanup({r1, r2, r3}, gc, ancestor_ok, cc_past, is_live, closed,
                                              make_deleter({}), erase, /*budget=*/2);
  ASSERT_EQ(res3.delete_attempts, static_cast<size_t>(2));
  ASSERT_EQ(res3.deleted, static_cast<size_t>(2));
  ASSERT_EQ(res3.kept, static_cast<size_t>(1));
  ASSERT_EQ(erased.size(), static_cast<size_t>(2));
}

// Fault-injection / crash-boundary scenarios driven through the pure coordinator
// (a "restart" is just re-invoking the sweep with the post-crash injected state).
// The retirement-side boundaries (persist-before-close) are established atomically
// in B1; these pin the delete-side boundaries.
TEST(ValidatorCleanup, fault_injection_scenarios) {
  auto gc = make_checkpoint(500);
  auto ancestor_ok = [](const tos::BlockIdExt&) { return true; };
  auto closed = [](const tos::ValidatorSessionId&) { return true; };
  auto cc = [](tos::CatchainSeqno v) {
    return [v](tos::ShardIdFull s) -> std::optional<tos::CatchainSeqno> {
      return s == kShard ? std::optional<tos::CatchainSeqno>{v} : std::nullopt;
    };
  };
  std::set<std::string> live_hex;
  auto is_live = [&](const tos::ValidatorSessionId& s) { return live_hex.count(s.to_hex()) > 0; };
  std::set<std::string> deleter_called;
  std::set<std::string> erased;
  auto erase = [&](const tos::ValidatorSessionId& s) { erased.insert(s.to_hex()); };

  auto r = make_record(1, 100);  // shard kShard, cc 7

  // --- CASE 6 (the core safety history): delete fails, then the session is
  // recreated (reopened), and a later pass MUST NOT delete it. ---
  {
    // Pass 1: eligible (not live, closed, obsolete g=10) but the delete fails.
    live_hex.clear();
    deleter_called.clear();
    erased.clear();
    auto fail_deleter = [&](const PendingValidatorConsensusDbCleanup& rec) {
      deleter_called.insert(rec.session_id.to_hex());
      return false;  // not confirmed gone
    };
    auto p1 = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, fail_deleter, erase, 10);
    ASSERT_EQ(p1.delete_attempts, static_cast<size_t>(1));
    ASSERT_EQ(p1.deleted, static_cast<size_t>(0));
    ASSERT_TRUE(erased.empty());  // record survives -- no orphan, no erase

    // The session is now recreated/live. Pass 2: the record still exists, but the
    // deleter MUST NOT be called and the record MUST NOT be erased.
    live_hex = {r.session_id.to_hex()};
    deleter_called.clear();
    bool fatal_deleter_called = false;
    auto forbidden_deleter = [&](const PendingValidatorConsensusDbCleanup&) {
      fatal_deleter_called = true;
      return true;
    };
    auto p2 = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, forbidden_deleter, erase,
                                              10);
    ASSERT_TRUE(!fatal_deleter_called);  // a live-again session's DB is never deleted
    ASSERT_EQ(p2.deleted, static_cast<size_t>(0));
    ASSERT_TRUE(erased.empty());
  }

  // --- Transient failure then success: pass 1 fails (kept), pass 2 succeeds. ---
  {
    live_hex.clear();
    erased.clear();
    bool fail = true;
    auto flaky = [&](const PendingValidatorConsensusDbCleanup&) { return !fail; };
    auto a = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, flaky, erase, 10);
    ASSERT_EQ(a.deleted, static_cast<size_t>(0));
    ASSERT_TRUE(erased.empty());
    fail = false;
    auto b = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, flaky, erase, 10);
    ASSERT_EQ(b.deleted, static_cast<size_t>(1));
    ASSERT_TRUE(erased.count(r.session_id.to_hex()) == 1);
  }

  // --- Crash after delete, before dequeue: record still present, directory gone.
  // Re-running the sweep reconciles it (deleter confirms absent -> erase). ---
  {
    live_hex.clear();
    erased.clear();
    auto already_gone = [&](const PendingValidatorConsensusDbCleanup&) { return true; };  // confirmed absent
    auto res = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, already_gone, erase, 10);
    ASSERT_EQ(res.deleted, static_cast<size_t>(1));
    ASSERT_TRUE(erased.count(r.session_id.to_hex()) == 1);
  }

  // --- Not obsolete yet, then GC advances: pass 1 (g=7, r not < g) keeps; pass 2
  // (g=10) deletes. ---
  {
    live_hex.clear();
    erased.clear();
    bool called = false;
    auto spy = [&](const PendingValidatorConsensusDbCleanup&) {
      called = true;
      return true;
    };
    auto a = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(7), is_live, closed, spy, erase, 10);
    ASSERT_TRUE(!called);  // not yet obsolete -> not even attempted
    ASSERT_EQ(a.deleted, static_cast<size_t>(0));
    auto b = sweep_pending_validator_cleanup({r}, gc, ancestor_ok, cc(10), is_live, closed, spy, erase, 10);
    ASSERT_EQ(b.deleted, static_cast<size_t>(1));
  }
}

// Pin the literal key prefix and range end independently of the helpers, so a
// change to the persisted key scheme (which would orphan existing on-disk
// records) is caught, and the range end is exactly the prefix with its final
// byte incremented.
TEST(ValidatorCleanup, persistence_key_literals) {
  ASSERT_TRUE(validator_cleanup_key_prefix().str() == "tos.state.pending_validator_consensus_db_cleanup.");
  ASSERT_TRUE(validator_cleanup_key_range_end() == "tos.state.pending_validator_consensus_db_cleanup/");
}

// Persistence-key bounds: every record key must start with the prefix and sort
// strictly inside [prefix, range_end), so a prefix range scan brackets exactly
// these records and nothing else. Session hex spanning the byte extremes (all
// 0x00 -> "0000...", all 0xff -> "ffff...") must still fall in range. If the
// range-end derivation were wrong, a boundary key would escape the scan.
TEST(ValidatorCleanup, persistence_key_bounds) {
  auto prefix = validator_cleanup_key_prefix().str();
  auto end = validator_cleanup_key_range_end();
  ASSERT_TRUE(prefix < end);

  tos::ValidatorSessionId lo;
  lo.as_slice().fill(0);
  tos::ValidatorSessionId hi;
  for (size_t i = 0; i < hi.as_slice().size(); i++) {
    hi.as_slice()[i] = static_cast<char>(0xff);
  }
  for (const auto& sid : {lo, hi, make_session_id(9), make_session_id(200)}) {
    auto key = validator_cleanup_key(sid);
    ASSERT_TRUE(key.rfind(prefix, 0) == 0);              // starts with prefix
    ASSERT_TRUE(key.substr(prefix.size()) == sid.to_hex());
    ASSERT_TRUE(prefix <= key && key < end);             // inside the scan range
  }
}

// Safe-checkpoint monotonicity under the argument-sensitive oracle: adopt a
// strictly-ahead candidate; refuse a regression (NotAncestor with a valid
// current), a forked candidate (Unknown), an equal candidate, and an invalid
// candidate. A later restart that loads an older init block cannot lower the
// floor.
TEST(ValidatorCleanup, safe_checkpoint_is_monotonic) {
  auto c100 = make_checkpoint(100);
  auto c200 = make_checkpoint(200);
  tos::BlockIdExt none;

  ASSERT_TRUE(should_adopt_safe_checkpoint(none, c100, chain_oracle));    // first adoption
  ASSERT_TRUE(should_adopt_safe_checkpoint(c100, c200, chain_oracle));    // strictly ahead -> adopt
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c200, c100, chain_oracle));   // regression -> refuse (NotAncestor)
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, make_fork_checkpoint(200), chain_oracle));  // fork -> refuse
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, c100, chain_oracle));   // equal -> no change

  // A non-masterchain candidate must never be adopted, with either a valid or an
  // absent current floor. The Ancestor spy would adopt it if the candidate guard
  // were removed (and an absent current would first-adopt it), so "spy never
  // called" + "never adopted" fails red if the guard is dropped.
  bool adopt_oracle_called = false;
  auto adopt_spy = [&](const tos::BlockIdExt&, const tos::BlockIdExt&) {
    adopt_oracle_called = true;
    return CleanupAncestry::Ancestor;
  };
  tos::BlockIdExt shard_candidate{0, kMasterShard, 200, make_hash(1), make_hash(2)};
  ASSERT_TRUE(!should_adopt_safe_checkpoint(c100, shard_candidate, adopt_spy));  // valid current
  ASSERT_TRUE(!should_adopt_safe_checkpoint(none, shard_candidate, adopt_spy));  // absent current
  ASSERT_TRUE(!adopt_oracle_called);
}
