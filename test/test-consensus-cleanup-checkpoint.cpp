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
// The consensus cleanup checkpoint's pure core: its record encoding, its
// persistence over a real RocksDb (the same functions StateDb calls), the
// head/rollback relation, and the advancement state machine the manager drives
// (validator/consensus/consensus-cleanup-checkpoint.h).
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>

#include "td/db/RocksDb.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator/consensus/consensus-cleanup-checkpoint.h"
#include "validator/db/archive-gc-floor.h"

using namespace tos;
using namespace tos::validator::consensus;

namespace {

td::Bits256 make_hash(unsigned branch, BlockSeqno seqno, unsigned salt) {
  td::Bits256 h;
  for (size_t i = 0; i < h.as_slice().size(); i++) {
    h.as_slice()[i] = static_cast<char>(branch * 31 + seqno * 7 + salt + i + 1);
  }
  return h;
}

// Block `seqno` on branch `branch`. Branches share no block ids.
BlockIdExt block(BlockSeqno seqno, unsigned branch = 0) {
  return BlockIdExt{masterchainId, shardIdAll, seqno, make_hash(branch, seqno, 3), make_hash(branch, seqno, 101)};
}

// A toy chain: a block's strict ancestors are the blocks below it on its branch,
// and, for a fork, the main branch below `fork_from`.
struct Chain {
  BlockSeqno fork_from = 0;
  bool verifies(const BlockIdExt& head, const BlockIdExt& id) const {
    if (id.seqno() >= head.seqno()) {
      return false;
    }
    for (unsigned branch : {0u, 1u}) {
      if (head == block(head.seqno(), branch)) {
        if (branch == 1 && id.seqno() < fork_from) {
          return id == block(id.seqno(), 0);
        }
        return id == block(id.seqno(), branch);
      }
    }
    return false;
  }
  VerifiesStrictAncestorFn of(const BlockIdExt& head) const {
    return [this, head](const BlockIdExt& id) { return verifies(head, id); };
  }
};

std::string temp_db_path() {
  auto path = PSTRING() << td::realpath(".").move_as_ok() << "/tmp-consensus-checkpoint-" << td::Random::fast_uint64();
  td::rmrf(path).ignore();
  return path;
}

void put_raw(td::KeyValue& kv, td::Slice value) {
  kv.begin_write_batch().ensure();
  kv.set(consensus_cleanup_checkpoint_key(), value).ensure();
  kv.commit_write_batch().ensure();
}

// The candidate payload the tests hand the tracker: what the manager would learn
// from the candidate's handle and state.
struct Facts {
  bool applied = true;
  bool state_matches = true;
};

using Tracker = ConsensusCleanupCheckpointTracker<std::pair<BlockIdExt, Facts>>;
using Outcome = Tracker::Outcome;
constexpr auto Synced = Tracker::WriteResult::Synced;
constexpr auto NotAttempted = Tracker::WriteResult::NotAttempted;
constexpr auto Uncertain = Tracker::WriteResult::Uncertain;

struct Env {
  Chain chain;
  bool gc_advancing = false;
  std::optional<BlockIdExt> gc = block(0);
  BlockIdExt head = block(1000);

  Tracker::Environment make() const {
    Tracker::Environment env;
    env.gc_advancing = gc_advancing;
    env.gc_block = gc;
    env.candidate_coherent = [](const std::pair<BlockIdExt, Facts>& c) {
      return c.second.applied && c.second.state_matches;
    };
    env.candidate_verifies = [this](const std::pair<BlockIdExt, Facts>& c, const BlockIdExt& id) {
      return chain.verifies(c.first, id);
    };
    env.head_covers = [this](const BlockIdExt& id) {
      return relate_to_consensus_cleanup_checkpoint(id, head, chain.of(head)) == CheckpointRelation::Reached;
    };
    return env;
  }
};

void offer(Tracker& t, const BlockIdExt& id, Facts facts = {}) {
  t.offer(id, {id, facts});
}

}  // namespace

// ---- encoding ---------------------------------------------------------------

TEST(ConsensusCleanupCheckpoint, encoding_round_trips_a_full_masterchain_id) {
  auto id = block(77);
  auto decoded = decode_consensus_cleanup_checkpoint(encode_consensus_cleanup_checkpoint(id));
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_TRUE(decoded.ok() == id);
}

TEST(ConsensusCleanupCheckpoint, damaged_or_foreign_records_are_errors) {
  auto good = encode_consensus_cleanup_checkpoint(block(5));
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(td::Slice{good}).is_ok());

  // Truncated.
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(td::Slice{good}.substr(0, 7)).is_error());
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(td::Slice{good}.substr(0, good.size() - 1)).is_error());
  // Trailing byte.
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(td::Slice{good + "x"}).is_error());
  // Foreign magic.
  auto foreign = good;
  foreign[0] = 'X';
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(td::Slice{foreign}).is_error());
  // Unsupported version.
  auto future = good;
  future[4] = 2;
  auto r_future = decode_consensus_cleanup_checkpoint(td::Slice{future});
  ASSERT_TRUE(r_future.is_error());
  ASSERT_TRUE(r_future.error().message().str().find("unsupported version") != std::string::npos);
  // A basechain id, a masterchain id with a partial shard, and zero hashes are not checkpoints.
  auto basechain = block(5);
  basechain.id.workchain = basechainId;
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(encode_consensus_cleanup_checkpoint(basechain)).is_error());
  auto partial = block(5);
  partial.id.shard = static_cast<ShardId>(0x4000000000000000ULL);
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(encode_consensus_cleanup_checkpoint(partial)).is_error());
  auto zero = block(5);
  zero.root_hash.set_zero();
  ASSERT_TRUE(decode_consensus_cleanup_checkpoint(encode_consensus_cleanup_checkpoint(zero)).is_error());
}

// ---- persistence (the functions StateDb calls) ------------------------------

TEST(ConsensusCleanupCheckpoint, absent_key_is_the_only_absence) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto absent = load_consensus_cleanup_checkpoint(kv);
    ASSERT_TRUE(absent.is_ok());
    ASSERT_TRUE(!absent.ok().has_value());

    // A damaged record is an error, never "absent" (which would select the GC
    // fallback and drop the protection).
    put_raw(kv, td::Slice{"garbage"});
    ASSERT_TRUE(load_consensus_cleanup_checkpoint(kv).is_error());
    auto future = encode_consensus_cleanup_checkpoint(block(9));
    future[4] = 7;
    put_raw(kv, td::Slice{future});
    ASSERT_TRUE(load_consensus_cleanup_checkpoint(kv).is_error());
    // A store over a damaged record refuses too: it cannot prove monotonicity.
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(10)).is_error());
    std::string raw;
    ASSERT_TRUE(kv.get(consensus_cleanup_checkpoint_key(), raw).ok() == td::KeyValue::GetStatus::Ok);
    ASSERT_EQ(raw, future);
  }
  td::rmrf(path).ignore();
}

TEST(ConsensusCleanupCheckpoint, store_is_monotonic_and_survives_reopen) {
  auto path = temp_db_path();
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(10)).is_ok());
    // Rewriting the same block is a no-op.
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(10)).is_ok());
    // A regression and a different block at the same height are refused.
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(9)).is_error());
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(10, 1)).is_error());
    // Not a masterchain id.
    auto basechain = block(11);
    basechain.id.workchain = basechainId;
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, basechain).is_error());
    ASSERT_TRUE(load_consensus_cleanup_checkpoint(kv).ok().value() == block(10));
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(74)).is_ok());
  }
  {
    auto kv = td::RocksDb::open(path).move_as_ok();
    auto loaded = load_consensus_cleanup_checkpoint(kv);
    ASSERT_TRUE(loaded.is_ok());
    ASSERT_TRUE(loaded.ok().value() == block(74));
  }
  td::rmrf(path).ignore();
}

// ---- head and rollback relation ---------------------------------------------

TEST(ConsensusCleanupCheckpoint, head_relation) {
  Chain chain{.fork_from = 50};
  auto cp = block(60);
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(59), chain.of(block(59))) == CheckpointRelation::Behind);
  // Behind even on another branch: replay below the height is not judged yet.
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(55, 1), chain.of(block(55, 1))) ==
              CheckpointRelation::Behind);
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, cp, chain.of(cp)) == CheckpointRelation::Reached);
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(61), chain.of(block(61))) ==
              CheckpointRelation::Reached);
  // Same height, different block.
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(60, 1), chain.of(block(60, 1))) ==
              CheckpointRelation::Conflict);
  // A higher block on a branch that excludes the checkpoint.
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(70, 1), chain.of(block(70, 1))) ==
              CheckpointRelation::Conflict);
  // A higher block whose state cannot answer is a conflict, not a pass.
  ASSERT_TRUE(relate_to_consensus_cleanup_checkpoint(cp, block(70), {}) == CheckpointRelation::Conflict);
}

TEST(ConsensusCleanupCheckpoint, rollback_is_refused_below_or_off_the_checkpoint) {
  Chain chain{.fork_from = 50};
  std::optional<BlockIdExt> cp = block(60);
  ASSERT_TRUE(check_consensus_checkpoint_rollback(std::nullopt, block(1), chain.of(block(1))).is_ok());
  ASSERT_TRUE(check_consensus_checkpoint_rollback(cp, block(60), chain.of(block(60))).is_ok());
  ASSERT_TRUE(check_consensus_checkpoint_rollback(cp, block(65), chain.of(block(65))).is_ok());
  for (const auto& target : {block(59), block(0), block(60, 1), block(65, 1)}) {
    auto status = check_consensus_checkpoint_rollback(cp, target, chain.of(target));
    ASSERT_TRUE(status.is_error());
    ASSERT_TRUE(is_consensus_checkpoint_refusal(status));
    ASSERT_TRUE(status.message().str().find("prohibited") != std::string::npos);
  }
}

// ---- advancement ------------------------------------------------------------

TEST(ConsensusCleanupCheckpoint, first_checkpoint_needs_the_gc_block_or_a_verified_descendant) {
  Env env;
  env.chain.fork_from = 5;
  {
    Tracker t;
    offer(t, block(0));  // equal to the GC block
    auto a = t.try_issue(0, env.make());
    ASSERT_TRUE(a.outcome == Outcome::Issued);
    ASSERT_TRUE(a.id == block(0));
  }
  {
    Tracker t;
    offer(t, block(40));
    ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
  }
  {
    // A candidate on a branch that excludes the GC block.
    Env forked = env;
    forked.gc = block(8);
    Tracker t;
    offer(t, block(40, 1));
    ASSERT_TRUE(t.try_issue(0, forked.make()).outcome == Outcome::Dropped);
    ASSERT_TRUE(!t.in_flight());
  }
  {
    // GC handle and state disagree: no GC block, no first checkpoint.
    Env broken = env;
    broken.gc = std::nullopt;
    Tracker t;
    offer(t, block(40));
    ASSERT_TRUE(t.try_issue(0, broken.make()).outcome == Outcome::Dropped);
  }
  {
    // Below the GC block.
    Env later = env;
    later.gc = block(50);
    Tracker t;
    offer(t, block(40));
    ASSERT_TRUE(t.try_issue(0, later.make()).outcome == Outcome::Dropped);
  }
}

TEST(ConsensusCleanupCheckpoint, candidates_that_do_not_extend_the_checkpoint_are_dropped) {
  Env env;
  env.chain.fork_from = 50;
  auto installed = block(100);
  auto run = [&](const BlockIdExt& id, Facts facts) {
    Tracker t;
    t.set_installed(installed);
    offer(t, id, facts);
    return t.try_issue(1000, env.make()).outcome;
  };
  auto basechain = block(200);
  basechain.id.workchain = basechainId;
  ASSERT_TRUE(run(basechain, {}) == Outcome::Dropped);
  ASSERT_TRUE(run(block(200), Facts{.applied = false}) == Outcome::Dropped);
  ASSERT_TRUE(run(block(200), Facts{.state_matches = false}) == Outcome::Dropped);
  ASSERT_TRUE(run(block(100), {}) == Outcome::Dropped);     // already the checkpoint
  ASSERT_TRUE(run(block(99), {}) == Outcome::Dropped);      // regression
  ASSERT_TRUE(run(block(100, 1), {}) == Outcome::Dropped);  // same height, different block
  ASSERT_TRUE(run(block(200, 1), {}) == Outcome::Dropped);  // foreign ancestry
  ASSERT_TRUE(run(block(200), {}) == Outcome::Issued);      // valid descendant
}

TEST(ConsensusCleanupCheckpoint, the_applied_head_must_cover_every_advancement) {
  Env env;
  env.head = block(30);  // startup replay: the head is still below the candidate
  Tracker t;
  offer(t, block(40));
  auto a = t.try_issue(0, env.make());
  ASSERT_TRUE(a.outcome == Outcome::Waiting);
  ASSERT_TRUE(t.has_pending());
  env.head = block(45);
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
  t.complete(block(40), Synced);
  // A later advancement needs the head too, not only the first one.
  env.head = block(140);
  offer(t, block(150));
  ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Waiting);
  // A head on another branch never covers it.
  env.chain.fork_from = 41;
  env.head = block(160, 1);
  ASSERT_TRUE(t.try_issue(200, env.make()).outcome == Outcome::Waiting);
  env.head = block(160);
  ASSERT_TRUE(t.try_issue(200, env.make()).outcome == Outcome::Issued);
}

TEST(ConsensusCleanupCheckpoint, one_write_in_flight_coalesces_and_ignores_stale_completions) {
  Env env;
  Tracker t;
  offer(t, block(10));
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
  // Newer candidates coalesce while the write is in flight; nothing else is issued.
  offer(t, block(20));
  offer(t, block(90));
  offer(t, block(80));  // older than what is pending: ignored
  ASSERT_TRUE(t.try_issue(500, env.make()).outcome == Outcome::Idle);
  // A completion for a block that is not in flight changes nothing.
  ASSERT_TRUE(!t.complete(block(90), Synced));
  ASSERT_TRUE(!t.installed());
  ASSERT_TRUE(t.in_flight() == std::optional<BlockIdExt>{block(10)});
  auto installed = t.complete(block(10), Synced);
  ASSERT_TRUE(installed.has_value());
  ASSERT_TRUE(t.installed() == std::optional<BlockIdExt>{block(10)});
  // A duplicate completion of the same write is stale now.
  ASSERT_TRUE(!t.complete(block(10), Synced));
  auto a = t.try_issue(500, env.make());
  ASSERT_TRUE(a.outcome == Outcome::Issued);
  ASSERT_TRUE(a.id == block(90));
}

TEST(ConsensusCleanupCheckpoint, refused_write_keeps_the_checkpoint_and_counts_as_an_attempt) {
  Env env;
  Tracker t;
  t.set_installed(block(10));
  offer(t, block(20));
  ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Issued);
  ASSERT_TRUE(!t.complete(block(20), NotAttempted));
  ASSERT_TRUE(t.installed() == std::optional<BlockIdExt>{block(10)});
  ASSERT_TRUE(!t.in_flight());
  // The failed attempt is rate-limited like a successful one.
  offer(t, block(21));
  ASSERT_TRUE(t.try_issue(100.5, env.make()).outcome == Outcome::Waiting);
  ASSERT_TRUE(t.try_issue(130, env.make()).outcome == Outcome::Waiting);
  ASSERT_TRUE(t.try_issue(160, env.make()).outcome == Outcome::Issued);
}

TEST(ConsensusCleanupCheckpoint, attempts_are_rate_limited_by_blocks_or_time) {
  Env env;
  Tracker t;
  t.set_installed(block(100));
  offer(t, block(101));
  ASSERT_TRUE(t.try_issue(1000, env.make()).outcome == Outcome::Issued);
  t.complete(block(101), Synced);
  // 63 blocks later and 30 s later: wait.
  offer(t, block(164));
  ASSERT_TRUE(t.try_issue(1030, env.make()).outcome == Outcome::Waiting);
  // 64 blocks later: allowed once a second has passed.
  offer(t, block(165));
  ASSERT_TRUE(t.try_issue(1000.5, env.make()).outcome == Outcome::Waiting);
  ASSERT_TRUE(t.try_issue(1001, env.make()).outcome == Outcome::Issued);
  t.complete(block(165), Synced);
  // Few blocks, but 60 s since the last attempt.
  offer(t, block(166));
  ASSERT_TRUE(t.try_issue(1060.9, env.make()).outcome == Outcome::Waiting);
  ASSERT_TRUE(t.try_issue(1061, env.make()).outcome == Outcome::Issued);
}

TEST(ConsensusCleanupCheckpoint, block_threshold_does_not_overflow_near_the_seqno_limit) {
  Env env;
  env.head = block(0x7fffffff);
  Tracker t;
  t.set_installed(block(0x7fffffc0));  // the threshold is past this one only by 63 blocks
  offer(t, block(0x7fffffff));
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
  t.complete(block(0x7fffffff), Synced);
  ASSERT_TRUE(t.installed() == std::optional<BlockIdExt>{block(0x7fffffff)});
  // GC next-seqno arithmetic at the top of the range.
  ASSERT_TRUE(t.gc_may_start_advance(0x7ffffffe));
  ASSERT_TRUE(!t.gc_may_start_advance(0x7fffffff));
  ASSERT_TRUE(!t.gc_may_start_advance(std::numeric_limits<BlockSeqno>::max()));
}

// GC starts advancing first; the first checkpoint proposed meanwhile is not
// written, and is revalidated against the GC block that results.
TEST(ConsensusCleanupCheckpoint, gc_in_flight_defers_the_first_checkpoint) {
  Env env;
  env.gc = block(7);
  env.gc_advancing = true;
  Tracker t;
  offer(t, block(7));  // equal to the GC block that is being left behind
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Waiting);
  ASSERT_TRUE(!t.in_flight());
  // GC persisted block 8: the candidate (7) is now below it and is dropped.
  env.gc_advancing = false;
  env.gc = block(8);
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Dropped);
  // The next candidate equal to GC is accepted.
  offer(t, block(8));
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
}

// The first checkpoint write starts first; GC may neither start nor persist an
// advance until it is installed, and then never passes it.
TEST(ConsensusCleanupCheckpoint, checkpoint_in_flight_blocks_gc_until_installed) {
  Env env;
  env.gc = block(7);
  Tracker t;
  ASSERT_TRUE(t.gc_may_start_advance(7));  // no checkpoint: GC is unbounded
  ASSERT_TRUE(t.gc_may_persist(1000));
  offer(t, block(7));
  ASSERT_TRUE(t.try_issue(0, env.make()).outcome == Outcome::Issued);
  ASSERT_TRUE(!t.installed());
  ASSERT_TRUE(!t.gc_may_start_advance(7));
  ASSERT_TRUE(!t.gc_may_persist(8));
  ASSERT_TRUE(!t.gc_may_persist(7));
  t.complete(block(7), Synced);
  // GC equals the checkpoint: it may not move.
  ASSERT_TRUE(!t.gc_may_start_advance(7));
  ASSERT_TRUE(t.gc_may_persist(7));
  ASSERT_TRUE(!t.gc_may_persist(8));
  t.set_installed(block(70));
  ASSERT_TRUE(t.gc_may_start_advance(69));
  ASSERT_TRUE(t.gc_may_persist(70));
  ASSERT_TRUE(!t.gc_may_persist(71));
  ASSERT_TRUE(!t.gc_may_start_advance(70));
}

// ---- retention ----------------------------------------------------------------

// Archive TTL pruning keeps the checkpoint's package whenever the GC block is at
// or below the checkpoint (the bound GC is held to), because pruning is keyed on
// the GC block's time and masterchain time is monotonic. The archive needs no
// retention mechanism of its own for the checkpoint; this exercises the real
// pruning selection and admission (validator/db/archive-gc-floor.h).
namespace {
// Package i holds masterchain blocks [100 i, 100 i + 99]; block s was generated
// at time 1000 + s.
size_t pruned_checkpoint_package(BlockSeqno checkpoint, BlockSeqno gc, double archive_ttl) {
  std::vector<tos::validator::ArchivePackage> packages;
  for (uint32_t i = 0; i < 20; i++) {
    packages.push_back({1000.0 + 100.0 * i, i + 1 < 20 ? (i + 1) * 100 : tos::validator::kNoArchiveGcFloor});
  }
  tos::validator::reset_archive_retention_for_testing();
  size_t checkpoint_package = checkpoint / 100;
  size_t removed_checkpoint_package = 0;
  tos::validator::prune_archive_packages(packages, 1000.0 + gc, archive_ttl, /*shard_client_seqno=*/1u << 30,
                                         [&](size_t index) {
                                           if (index == checkpoint_package) {
                                             removed_checkpoint_package++;
                                           }
                                         });
  tos::validator::reset_archive_retention_for_testing();
  return removed_checkpoint_package;
}
}  // namespace

TEST(ConsensusCleanupCheckpoint, archive_ttl_pruning_keeps_the_checkpoint_package_while_gc_stays_behind) {
  size_t cases = 0;
  for (BlockSeqno checkpoint : {0u, 1u, 99u, 100u, 150u, 199u, 1234u, 1899u}) {
    for (double ttl : {0.5, 1.0, 50.0, 100.0, 500.0}) {
      for (BlockSeqno gc = 0; gc <= checkpoint; gc += 7) {
        ASSERT_EQ(pruned_checkpoint_package(checkpoint, gc, ttl), 0u);
        cases++;
      }
      ASSERT_EQ(pruned_checkpoint_package(checkpoint, checkpoint, ttl), 0u);
    }
  }
  ASSERT_TRUE(cases > 500);
  // Sensitivity: once GC is far past the checkpoint, the same pruning does take
  // the checkpoint's package. The instrument can see a deletion.
  ASSERT_EQ(pruned_checkpoint_package(150, 900, 50.0), 1u);
}

// ---- uncertain writes ----------------------------------------------------------

// A failed write may or may not become durable. GC stays excluded, nothing new is
// written, and the same id is rewritten (rate-limited) until a synced write
// succeeds; only then is it installed and GC released. Repeated failures keep it so.
TEST(ConsensusCleanupCheckpoint, uncertain_write_keeps_gc_excluded_until_a_synced_rewrite) {
  Env env;
  Tracker t;
  t.set_installed(block(10));
  offer(t, block(80));
  ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Issued);
  ASSERT_TRUE(!t.complete(block(80), Uncertain));
  ASSERT_TRUE(t.uncertain());
  ASSERT_TRUE(t.in_flight() == std::optional<BlockIdExt>{block(80)});
  ASSERT_TRUE(t.installed() == std::optional<BlockIdExt>{block(10)});
  ASSERT_TRUE(!t.gc_may_start_advance(5));
  ASSERT_TRUE(!t.gc_may_persist(6));
  // Nothing else is issued meanwhile.
  offer(t, block(200));
  ASSERT_TRUE(t.try_issue(500, env.make()).outcome == Outcome::Idle);
  // Rewrites are rate-limited, and one at a time.
  ASSERT_TRUE(!t.try_retry(100.5));
  ASSERT_TRUE(t.try_retry(101) == std::optional<BlockIdExt>{block(80)});
  ASSERT_TRUE(!t.try_retry(105));
  // Repeated failures keep the exclusion.
  for (double now : {110.0, 120.0, 130.0}) {
    ASSERT_TRUE(!t.complete(block(80), Uncertain));
    ASSERT_TRUE(!t.gc_may_persist(6));
    ASSERT_TRUE(t.try_retry(now) == std::optional<BlockIdExt>{block(80)});
  }
  auto installed = t.complete(block(80), Synced);
  ASSERT_TRUE(installed.has_value());
  ASSERT_TRUE(t.installed() == std::optional<BlockIdExt>{block(80)});
  ASSERT_TRUE(!t.in_flight());
  ASSERT_TRUE(!t.uncertain());
  ASSERT_TRUE(t.gc_may_start_advance(5));
  ASSERT_TRUE(!t.try_retry(500));
  // The coalesced candidate is issued next.
  ASSERT_TRUE(t.try_issue(500, env.make()).outcome == Outcome::Issued);
}

// Rewrites of an uncertain write back off: 1 s after the failed attempt, then
// twice as long after each further uncertain result, capped at 60 s. A "not
// attempted" result leaves the wait unchanged, and only a settled write (synced,
// or released) resets it for the next write.
TEST(ConsensusCleanupCheckpoint, uncertain_rewrites_back_off_to_a_cap_and_reset_once_settled) {
  Env env;
  Tracker t;
  t.set_installed(block(10));
  offer(t, block(80));
  ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Issued);
  ASSERT_TRUE(!t.complete(block(80), Uncertain));
  double last = 100;
  std::vector<double> waits;
  for (int i = 0; i < 9; i++) {
    double wait = t.retry_delay();
    waits.push_back(wait);
    // Not one moment sooner, and exactly then.
    ASSERT_TRUE(!t.try_retry(last + wait - 0.01));
    ASSERT_TRUE(t.try_retry(last + wait) == std::optional<BlockIdExt>{block(80)});
    last += wait;
    ASSERT_TRUE(!t.complete(block(80), Uncertain));
    ASSERT_TRUE(!t.gc_may_persist(6));
  }
  ASSERT_TRUE(waits == (std::vector<double>{1, 2, 4, 8, 16, 32, 60, 60, 60}));
  // "Not attempted" after an uncertain attempt changes neither the exclusion nor
  // the wait.
  double wait = t.retry_delay();
  ASSERT_TRUE(t.try_retry(last + wait) == std::optional<BlockIdExt>{block(80)});
  last += wait;
  ASSERT_TRUE(!t.complete(block(80), NotAttempted));
  ASSERT_TRUE(t.uncertain() && t.retry_delay() == 60);
  ASSERT_TRUE(!t.try_retry(last + 59));
  ASSERT_TRUE(t.try_retry(last + 60) == std::optional<BlockIdExt>{block(80)});
  last += 60;
  ASSERT_TRUE(t.complete(block(80), Synced).has_value());
  ASSERT_TRUE(t.retry_delay() == 1);
  // The next write's first rewrite waits 1 s again.
  offer(t, block(200));
  ASSERT_TRUE(t.try_issue(last + 60, env.make()).outcome == Outcome::Issued);
  ASSERT_TRUE(!t.complete(block(200), Uncertain));
  ASSERT_TRUE(t.try_retry(last + 61) == std::optional<BlockIdExt>{block(200)});
}

// "Not attempted" (nothing was written) releases a write only when no earlier
// attempt of it was uncertain.
TEST(ConsensusCleanupCheckpoint, not_attempted_releases_only_without_an_earlier_uncertain_attempt) {
  Env env;
  {
    Tracker t;
    t.set_installed(block(10));
    offer(t, block(80));
    ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Issued);
    ASSERT_TRUE(!t.complete(block(80), NotAttempted));
    ASSERT_TRUE(!t.in_flight());
    ASSERT_TRUE(t.gc_may_persist(10));
  }
  {
    Tracker t;
    t.set_installed(block(10));
    offer(t, block(80));
    ASSERT_TRUE(t.try_issue(100, env.make()).outcome == Outcome::Issued);
    ASSERT_TRUE(!t.complete(block(80), Uncertain));
    ASSERT_TRUE(t.try_retry(101) == std::optional<BlockIdExt>{block(80)});
    ASSERT_TRUE(!t.complete(block(80), NotAttempted));
    ASSERT_TRUE(t.in_flight() == std::optional<BlockIdExt>{block(80)});
    ASSERT_TRUE(t.uncertain());
    ASSERT_TRUE(!t.gc_may_persist(10));
    ASSERT_TRUE(t.try_retry(102) == std::optional<BlockIdExt>{block(80)});
    ASSERT_TRUE(t.complete(block(80), Synced).has_value());
  }
}

namespace {
// A KeyValue over a real RocksDb whose writes can be made to fail, before or
// after the underlying synced write batch.
class FaultyKeyValue final : public td::KeyValue {
 public:
  explicit FaultyKeyValue(td::KeyValue& inner) : inner_(inner) {
  }
  bool fail_set = false;
  bool fail_after_batch = false;
  int synced_batches = 0;

  td::Result<GetStatus> get(td::Slice key, std::string& value) override {
    return inner_.get(key, value);
  }
  td::Result<std::vector<GetStatus>> get_multi(td::Span<td::Slice> keys, std::vector<std::string>* values) override {
    return inner_.get_multi(keys, values);
  }
  td::Result<size_t> count(td::Slice prefix) override {
    return inner_.count(prefix);
  }
  td::Status set(td::Slice key, td::Slice value) override {
    if (fail_set) {
      return td::Status::Error("injected set failure");
    }
    return inner_.set(key, value);
  }
  td::Status erase(td::Slice key) override {
    return inner_.erase(key);
  }
  td::Status begin_write_batch() override {
    return inner_.begin_write_batch();
  }
  td::Status commit_write_batch() override {
    auto status = inner_.commit_write_batch();
    if (status.is_ok()) {
      synced_batches++;
      if (fail_after_batch) {
        return td::Status::Error("injected failure after the write batch");
      }
    }
    return status;
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
  td::KeyValue& inner_;
};
}  // namespace

// The store helper reports every failure, and a store of the value already
// present is a real synced write, so a rewrite after an uncertain outcome is a
// durability confirmation and not a no-op.
TEST(ConsensusCleanupCheckpoint, store_failures_are_reported_and_a_same_id_store_writes) {
  auto path = temp_db_path();
  {
    auto inner = td::RocksDb::open(path).move_as_ok();
    FaultyKeyValue kv(inner);
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(10)).is_ok());
    ASSERT_EQ(kv.synced_batches, 1);
    // A failed set: an error, and the old value stays.
    kv.fail_set = true;
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(20)).is_error());
    ASSERT_TRUE(load_consensus_cleanup_checkpoint(kv).ok().value() == block(10));
    kv.fail_set = false;
    // The new value is visible, but the store reports a failure: the caller must
    // not take visibility as durability.
    kv.fail_after_batch = true;
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(20)).is_error());
    ASSERT_TRUE(load_consensus_cleanup_checkpoint(kv).ok().value() == block(20));
    kv.fail_after_batch = false;
    // Rewriting the same id performs another synced write.
    int before = kv.synced_batches;
    ASSERT_TRUE(store_consensus_cleanup_checkpoint(kv, block(20)).is_ok());
    ASSERT_EQ(kv.synced_batches, before + 1);
  }
  td::rmrf(path).ignore();
}
