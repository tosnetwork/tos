/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.

    Copyright 2025-2026 TOS Blockchain Teams
*/
// Marker encode/decode coverage for the wc0 wallet index's crash-recovery
// marker (WalletIndexDb::put_incomplete_block / for_each_incomplete_block).
// Regression coverage for two bugs found on a long-running validator: a
// seqno-only marker couldn't distinguish blocks at the same seqno in
// different shards, and a legacy-format marker left on disk by an older
// binary must not crash the new scanner or be silently treated as a valid
// entry.
#include "td/db/RocksDb.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

#include "../validator-engine/wallet-index.h"
#include "../validator-engine/wallet-index-writer.h"

#include <set>
#include <string>
#include <vector>

namespace {

tos::BlockIdExt make_test_block_id(tos::WorkchainId workchain, tos::ShardId shard, tos::BlockSeqno seqno,
                                   uint8_t root_fill, uint8_t file_fill) {
  tos::RootHash root_hash;
  tos::FileHash file_hash;
  std::string root_bytes(32, static_cast<char>(root_fill));
  std::string file_bytes(32, static_cast<char>(file_fill));
  root_hash.as_slice().copy_from(td::Slice{root_bytes.data(), root_bytes.size()});
  file_hash.as_slice().copy_from(td::Slice{file_bytes.data(), file_bytes.size()});
  return tos::BlockIdExt{workchain, shard, seqno, root_hash, file_hash};
}

std::unique_ptr<tos_wallet_index::WalletIndexDb> open_fresh_db(const std::string &path) {
  td::rmrf(path).ignore();
  auto r = tos_wallet_index::WalletIndexDb::open(path);
  r.ensure();
  return r.move_as_ok();
}

}  // namespace

TEST(WalletIndex, HostileAcceptCannotRaiseGetMethodGasLimit) {
  auto limits = tos_wallet_index::wallet_index_get_method_gas_limits();
  ASSERT_EQ(limits.gas_limit, tos_wallet_index::kWalletIndexGetMethodGasLimit);
  ASSERT_EQ(limits.gas_max, tos_wallet_index::kWalletIndexGetMethodGasLimit);
  limits.change_limit(vm::GasLimits::infty);
  ASSERT_EQ(limits.gas_limit, tos_wallet_index::kWalletIndexGetMethodGasLimit);
}

TEST(WalletIndex, AggregateGetMethodGasIsBoundedPerBlock) {
  tos_wallet_index::WalletIndexVerificationBudget budget;
  for (long long consumed = 0; consumed < tos_wallet_index::kWalletIndexBlockVerificationGasLimit;
       consumed += tos_wallet_index::kWalletIndexGetMethodGasLimit) {
    budget.begin_candidate((tos_wallet_index::kWalletIndexBlockVerificationGasLimit - consumed) /
                           tos_wallet_index::kWalletIndexGetMethodGasLimit);
    ASSERT_EQ(budget.acquire(), tos_wallet_index::kWalletIndexGetMethodGasLimit);
  }
  ASSERT_EQ(budget.acquire(), 0);
}

TEST(WalletIndex, VerificationBudgetIsFairAcrossCandidates) {
  tos_wallet_index::WalletIndexVerificationBudget budget;
  budget.begin_candidate(20);
  ASSERT_EQ(budget.acquire(), tos_wallet_index::kWalletIndexBlockVerificationGasLimit / 20);
  ASSERT_EQ(budget.acquire(), 0);
  budget.begin_candidate(19);
  ASSERT_TRUE(budget.acquire() > 0);
}

TEST(WalletIndex, ReducedShareOutOfGasIsIndeterminate) {
  auto reduced_share = tos_wallet_index::kWalletIndexGetMethodGasLimit / 2;
  auto out_of_gas = ~static_cast<td::int32>(vm::Excno::out_of_gas);
  ASSERT_EQ(tos_wallet_index::wallet_index_classify_get_method_failure(reduced_share, out_of_gas, reduced_share),
            tos_wallet_index::WalletIndexGetMethodStatus::Indeterminate);
}

TEST(WalletIndex, FullLimitOutOfGasIsContractFailure) {
  auto full_limit = tos_wallet_index::kWalletIndexGetMethodGasLimit;
  auto out_of_gas = ~static_cast<td::int32>(vm::Excno::out_of_gas);
  ASSERT_EQ(tos_wallet_index::wallet_index_classify_get_method_failure(full_limit, out_of_gas, full_limit),
            tos_wallet_index::WalletIndexGetMethodStatus::ContractFailure);
}

TEST(WalletIndex, ReducedShareEarlyOutOfGasIsContractFailure) {
  auto reduced_share = tos_wallet_index::kWalletIndexGetMethodGasLimit / 2;
  auto out_of_gas = ~static_cast<td::int32>(vm::Excno::out_of_gas);
  ASSERT_EQ(tos_wallet_index::wallet_index_classify_get_method_failure(reduced_share, out_of_gas, reduced_share - 1),
            tos_wallet_index::WalletIndexGetMethodStatus::ContractFailure);
}

TEST(WalletIndex, ReducedShareNonGasFailureIsContractFailure) {
  auto reduced_share = tos_wallet_index::kWalletIndexGetMethodGasLimit / 2;
  auto type_check_error = ~static_cast<td::int32>(vm::Excno::type_chk);
  ASSERT_EQ(tos_wallet_index::wallet_index_classify_get_method_failure(reduced_share, type_check_error, reduced_share),
            tos_wallet_index::WalletIndexGetMethodStatus::ContractFailure);
}

TEST(WalletIndex, VirtualizationFailureIsIndeterminate) {
  auto virtualization_error = ~static_cast<td::int32>(vm::Excno::virt_err);
  ASSERT_EQ(tos_wallet_index::wallet_index_classify_get_method_failure(tos_wallet_index::kWalletIndexGetMethodGasLimit,
                                                                       virtualization_error, 0),
            tos_wallet_index::WalletIndexGetMethodStatus::Indeterminate);
}

TEST(WalletIndex, ForeignShardAbsenceIsNotAuthoritative) {
  auto left = tos::shard_child(tos::ShardIdFull{0}, true);
  td::Bits256 low = td::Bits256::zero();
  td::Bits256 high;
  high.as_slice().fill(0xff);
  ASSERT_TRUE(tos_wallet_index::wallet_index_state_contains(left, low));
  ASSERT_TRUE(!tos_wallet_index::wallet_index_state_contains(left, high));
}

TEST(WalletIndex, AccountEventExactLookupAndCursorPagination) {
  auto path = std::string("test-wallet-index-db-events");
  auto db = open_fresh_db(path);
  tos_wallet_index::HashKey account = td::Bits256::zero();
  account.as_slice()[31] = 0x42;
  std::vector<td::Ref<vm::Cell>> cells;
  for (uint64_t lt : {100ULL, 200ULL, 300ULL}) {
    vm::CellBuilder builder;
    builder.store_long(static_cast<long long>(lt), 64);
    cells.push_back(builder.finalize());
    ASSERT_TRUE(db->put_event(account, lt, cells.back()).is_ok());
  }
  auto exact = db->get_event(account, 200);
  ASSERT_TRUE(exact.is_ok());
  ASSERT_TRUE(exact.ok()->get_hash() == cells[1]->get_hash());
  ASSERT_TRUE(db->get_event(account, 201).is_error());

  std::vector<uint64_t> first_page;
  db->for_each_event(account, 2, [&](uint64_t lt, td::Ref<vm::Cell>) {
    first_page.push_back(lt);
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(first_page, (std::vector<uint64_t>{300, 200}));
  std::vector<uint64_t> second_page;
  db->for_each_event_before(account, 200, 2, [&](uint64_t lt, td::Ref<vm::Cell>) {
    second_page.push_back(lt);
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(second_page, (std::vector<uint64_t>{100}));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, NftReverseOwnerCanBeRemovedAfterOwnershipEnds) {
  auto path = std::string("test-wallet-index-db-nft-owner");
  auto db = open_fresh_db(path);
  tos_wallet_index::HashKey nft = td::Bits256::zero();
  tos_wallet_index::HashKey owner = td::Bits256::zero();
  nft.as_slice()[31] = 0x11;
  owner.as_slice()[31] = 0x22;

  ASSERT_TRUE(db->put_nft_owner(nft, owner).is_ok());
  tos_wallet_index::HashKey found;
  auto before = db->get_nft_owner(nft, found);
  ASSERT_TRUE(before.is_ok() && before.ok());
  ASSERT_TRUE(found == owner);

  ASSERT_TRUE(db->erase_nft_owner(nft).is_ok());
  auto after = db->get_nft_owner(nft, found);
  ASSERT_TRUE(after.is_ok() && !after.ok());
  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerRoundTrip) {
  auto path = std::string("test-wallet-index-db-roundtrip");
  auto db = open_fresh_db(path);

  auto id = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 42, 0xAB, 0xCD);

  ASSERT_TRUE(db->put_incomplete_block(id).is_ok());

  auto has_r = db->has_incomplete_block(id);
  ASSERT_TRUE(has_r.is_ok());
  ASSERT_TRUE(has_r.ok());

  std::vector<tos::BlockIdExt> found;
  auto scan_status = db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
    found.push_back(scanned);
    return td::Status::OK();
  });
  ASSERT_TRUE(scan_status.is_ok());
  ASSERT_EQ(found.size(), static_cast<size_t>(1));
  // Full round trip: workchain, shard, seqno, and both hashes must all
  // survive the encode (put) / decode (for_each) cycle unchanged.
  ASSERT_TRUE(found[0] == id);

  ASSERT_TRUE(db->delete_incomplete_block(id).is_ok());
  auto has_after_r = db->has_incomplete_block(id);
  ASSERT_TRUE(has_after_r.is_ok());
  ASSERT_TRUE(!has_after_r.ok());

  found.clear();
  db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
                        found.push_back(scanned);
                        return td::Status::OK();
                      })
      .ensure();
  ASSERT_TRUE(found.empty());

  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerDistinguishesSameSeqnoDifferentShard) {
  // Regression test for the bug the full-BlockIdExt marker redesign fixed:
  // a seqno-only marker couldn't tell two different shards' blocks apart,
  // and an ambiguous seqno-only lookup during recovery wasn't guaranteed to
  // resolve back to the right one.
  auto path = std::string("test-wallet-index-db-shard-collision");
  auto db = open_fresh_db(path);

  auto id_a = make_test_block_id(0, 0x2000000000000000ULL, 100, 0x11, 0x22);
  auto id_b = make_test_block_id(0, 0x6000000000000000ULL, 100, 0x33, 0x44);
  ASSERT_TRUE(id_a.id.workchain == id_b.id.workchain);
  ASSERT_TRUE(id_a.id.seqno == id_b.id.seqno);
  ASSERT_TRUE(id_a.id.shard != id_b.id.shard);

  ASSERT_TRUE(db->put_incomplete_block(id_a).is_ok());
  ASSERT_TRUE(db->put_incomplete_block(id_b).is_ok());

  std::set<tos::ShardId> seen_shards;
  int count = 0;
  auto status = db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
    count++;
    seen_shards.insert(scanned.id.shard);
    ASSERT_TRUE(scanned.id.seqno == 100);
    return td::Status::OK();
  });
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(count, 2);
  ASSERT_EQ(seen_shards.size(), static_cast<size_t>(2));

  // Deleting one must not touch the other — they are distinct entries, not
  // one seqno-keyed slot two different puts happened to share.
  ASSERT_TRUE(db->delete_incomplete_block(id_a).is_ok());
  auto has_b_r = db->has_incomplete_block(id_b);
  ASSERT_TRUE(has_b_r.is_ok());
  ASSERT_TRUE(has_b_r.ok());

  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerDistinguishesSamePositionDifferentHash) {
  // If the same (workchain,shard,seqno) position were ever re-applied with a
  // different block hash, the marker must not silently conflate the two —
  // this is why both hashes are part of the key, not just the value.
  auto path = std::string("test-wallet-index-db-hash-collision");
  auto db = open_fresh_db(path);

  auto id_a = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 7, 0xAA, 0xAA);
  auto id_b = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 7, 0xBB, 0xBB);

  ASSERT_TRUE(db->put_incomplete_block(id_a).is_ok());
  ASSERT_TRUE(db->put_incomplete_block(id_b).is_ok());

  int count = 0;
  db->for_each_incomplete_block([&](const tos::BlockIdExt &) -> td::Status {
                        count++;
                        return td::Status::OK();
                      })
      .ensure();
  ASSERT_EQ(count, 2);

  td::rmrf(path).ignore();
}

TEST(WalletIndex, LegacySeqnoOnlyMarkerNotSurfaced) {
  // A marker written by any binary before the full-BlockIdExt redesign (a
  // bare "0x1E + seqno_be(8)" key, 9 bytes total) must not crash the
  // scanner and must not be handed to the callback as if it were a valid
  // BlockIdExt.
  auto path = std::string("test-wallet-index-db-legacy");
  td::rmrf(path).ignore();
  {
    // Write the raw legacy-format key directly, bypassing WalletIndexDb
    // (whose own put_incomplete_block always writes the new format now) to
    // simulate what an older binary left on disk.
    auto raw_r = td::RocksDb::open(path);
    ASSERT_TRUE(raw_r.is_ok());
    auto raw = raw_r.move_as_ok();
    char key[9];
    key[0] = 0x1E;
    uint64_t seqno = 999;
    for (int i = 7; i >= 0; --i) {
      key[1 + i] = static_cast<char>(seqno & 0xff);
      seqno >>= 8;
    }
    char val[1] = {0};
    raw.set(td::Slice{key, 9}, td::Slice{val, 1}).ensure();
  }

  auto db_r = tos_wallet_index::WalletIndexDb::open(path);
  ASSERT_TRUE(db_r.is_ok());
  auto db = db_r.move_as_ok();

  int count = 0;
  auto status = db->for_each_incomplete_block([&](const tos::BlockIdExt &) -> td::Status {
    count++;
    return td::Status::OK();
  });
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(count, 0);

  td::rmrf(path).ignore();
}

// Every workchain-zero transaction adds an event row holding the whole
// transaction, and nothing removed one: the index grew for the life of the
// node and outlived the archive retention bounding everything else. The
// bound is per account and drops the oldest, so a caller reading recent
// history never notices it, and rows written before the bound existed are
// reached too -- they are found by the same account prefix, not by a
// companion index they do not have.
TEST(WalletIndex, EventHistoryIsBoundedPerAccount) {
  auto path = std::string("test-wallet-index-db-trim");
  auto db = open_fresh_db(path);
  tos_wallet_index::HashKey account = td::Bits256::zero();
  account.as_slice()[31] = 0x77;

  // kMax drives the test's block count (how far to run to reach the bound);
  // it may be the code's own constant. The *assertions* below instead use the
  // absolute expected value kExpectedBound: tying the pass/fail check to
  // kMaxEventsPerAccount would let a mis-sized cap (say 10000 -> 5000) move the
  // code and the test together and stay green, which is exactly what must be
  // caught. If the retention bound is changed on purpose, update this literal.
  constexpr size_t kMax = tos_wallet_index::kMaxEventsPerAccount;
  constexpr size_t kExpectedBound = 10000;
  // Add far more than the per-pass drain each block. A trim that could only
  // ever delete a fixed number per pass (the bug this guards) could not keep
  // up at this rate, so the account would grow without bound. It is also above
  // any realistic per-account per-block transaction count.
  constexpr size_t kPerBlock = tos_wallet_index::kEventTrimDrainPerPass + 200;

  auto count_events = [&]() {
    size_t n = 0;
    db->for_each_event(account, size_t{1} << 20, [&](uint64_t, td::Ref<vm::Cell>) {
      n++;
      return td::Status::OK();
    }).ensure();
    return n;
  };

  // Drive the *production* write path: each block opens the block batch, writes
  // kPerBlock events, trims the account once with that count, and commits. The
  // trim's scan runs before commit and cannot see the batch's own writes, which
  // is exactly the condition the fix has to handle. Run enough blocks to climb
  // well past the retention bound, then several more to show it holds steady
  // instead of creeping upward.
  const size_t warmup_blocks = kMax / kPerBlock + 5;
  const size_t total_blocks = warmup_blocks + 20;

  uint64_t lt = 1;
  uint64_t newest = 0;
  for (size_t block = 0; block < total_blocks; block++) {
    ASSERT_TRUE(db->begin_batch().is_ok());
    for (size_t i = 0; i < kPerBlock; i++, lt++) {
      vm::CellBuilder builder;
      builder.store_long(static_cast<long long>(lt), 64);
      ASSERT_TRUE(db->put_event(account, lt, builder.finalize()).is_ok());
      newest = lt;
    }
    ASSERT_TRUE(db->trim_events(account, kPerBlock).is_ok());
    ASSERT_TRUE(db->commit_batch().is_ok());

    size_t retained = count_events();
    // The bound may momentarily hold up to one block's additions above it on the
    // block that first crosses it (trim leaves room for the additions still in
    // the batch), but it must never grow beyond that.
    ASSERT_TRUE(retained <= kExpectedBound + kPerBlock);
    // Once warmed up the account is pinned at the bound. The pre-fix trim would
    // instead be at roughly kExpectedBound + (block - warmup) * (kPerBlock -
    // fixed_cap) here -- growing every block. Compared against the absolute
    // literal (see kExpectedBound), not the code's own constant.
    if (block >= warmup_blocks) {
      ASSERT_EQ(retained, kExpectedBound);
    }
  }
  // Newest events are the ones kept.
  uint64_t seen_newest = 0;
  uint64_t seen_oldest = std::numeric_limits<uint64_t>::max();
  db->for_each_event(account, size_t{1} << 20, [&](uint64_t l, td::Ref<vm::Cell>) {
    seen_newest = std::max(seen_newest, l);
    seen_oldest = std::min(seen_oldest, l);
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(seen_newest, newest);  // newest kept
  ASSERT_TRUE(seen_oldest > 1);    // oldest dropped

  // A second account keeps its own history: the bound is per account, not a
  // global cap that one busy address could spend on behalf of others.
  tos_wallet_index::HashKey other = td::Bits256::zero();
  other.as_slice()[31] = 0x78;
  ASSERT_TRUE(db->begin_batch().is_ok());
  vm::CellBuilder builder;
  builder.store_long(1, 64);
  ASSERT_TRUE(db->put_event(other, 1, builder.finalize()).is_ok());
  ASSERT_TRUE(db->trim_events(other, 1).is_ok());
  ASSERT_TRUE(db->commit_batch().is_ok());
  size_t other_rows = 0;
  db->for_each_event(other, 10, [&](uint64_t, td::Ref<vm::Cell>) {
    other_rows++;
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(other_rows, 1u);
}

// The per-account cap above bounds one account's history but not the number of
// accounts: a fresh account with a single transaction never trips its own trim
// and would be kept forever, so the index grew with distinct-account count.
// The companion age index (0x14) + per-block time prune drops whole dormant
// accounts once they fall out of the retention window, so the total is bounded
// by the window, not by how many accounts were ever seen. Disabling either the
// age writes or the prune below makes the "bounded" assertions fail.
TEST(WalletIndex, EventHistoryIsGloballyBoundedByAge) {
  auto path = std::string("test-wallet-index-db-age");
  auto db = open_fresh_db(path);

  constexpr uint32_t kDay = 24 * 60 * 60;
  constexpr uint32_t kBase = 1700000000;
  const uint32_t retention = tos_wallet_index::kEventRetentionSeconds;
  const uint32_t window_blocks = retention / kDay;  // 7 for a 7-day window
  ASSERT_TRUE(retention % kDay == 0);

  auto make_account = [](uint32_t n) {
    tos_wallet_index::HashKey a = td::Bits256::zero();
    a.as_slice()[28] = static_cast<char>((n >> 24) & 0xff);
    a.as_slice()[29] = static_cast<char>((n >> 16) & 0xff);
    a.as_slice()[30] = static_cast<char>((n >> 8) & 0xff);
    a.as_slice()[31] = static_cast<char>(n & 0xff);
    return a;
  };
  auto count_prefix = [&](uint8_t tag) {
    size_t n = 0;
    char prefix[1] = {static_cast<char>(tag)};
    db->for_each_key_with_prefix(td::Slice{prefix, 1}, size_t{1} << 30, [&](td::Slice) {
      n++;
      return td::Status::OK();
    }).ensure();
    return n;
  };
  // Mirror wc0_index_block's DB-level sequence: write (event, age) pairs, then
  // advance the non-decreasing watermark and prune with a budget proportional
  // to the rows just added (this is what keeps the bound from being outrun).
  auto index_block = [&](const std::vector<std::pair<tos_wallet_index::HashKey, uint64_t>>& events,
                         uint32_t gen_utime) {
    ASSERT_TRUE(db->begin_batch().is_ok());
    size_t age_added = 0;
    for (const auto& [account, lt] : events) {
      vm::CellBuilder builder;
      builder.store_long(static_cast<long long>(lt), 64);
      ASSERT_TRUE(db->put_event(account, lt, builder.finalize()).is_ok());
      ASSERT_TRUE(db->put_event_age(account, lt, gen_utime).is_ok());
      age_added++;
    }
    auto wm_r = db->get_event_watermark();
    ASSERT_TRUE(wm_r.is_ok());
    uint32_t stored = wm_r.move_as_ok();
    uint32_t watermark = stored > gen_utime ? stored : gen_utime;
    ASSERT_TRUE(db->put_event_watermark(watermark).is_ok());
    uint32_t cutoff = watermark > retention ? watermark - retention : 0;
    ASSERT_TRUE(db->prune_events_by_age(cutoff, age_added + tos_wallet_index::kEventPruneDrainPerBlock).is_ok());
    ASSERT_TRUE(db->commit_batch().is_ok());
  };

  // One brand-new account per block, one event each, one block per day. Without
  // the age prune this climbs to `total_blocks`; with it, it must hold at the
  // window size.
  const uint32_t total_blocks = window_blocks + 25;
  for (uint32_t b = 0; b < total_blocks; b++) {
    uint32_t gen_utime = kBase + b * kDay;
    index_block({{make_account(b), 1}}, gen_utime);

    // Every event has exactly one companion age row -- no orphans in either
    // direction.
    ASSERT_EQ(count_prefix(0x12), count_prefix(0x14));

    if (b >= window_blocks) {
      // Retained accounts are exactly those whose gen_utime >= cutoff =
      // (kBase + b*kDay) - retention = kBase + (b - window_blocks)*kDay. The
      // exclusive upper bound keeps the account exactly at the cutoff, so blocks
      // [b - window_blocks .. b] survive: window_blocks + 1 rows, regardless of
      // how many total blocks have been processed. The pre-fix index would be at
      // b + 1 here and rising every block.
      ASSERT_EQ(count_prefix(0x12), static_cast<size_t>(window_blocks + 1));
      // The account exactly at the cutoff is retained; the one just older is gone.
      ASSERT_TRUE(db->get_event(make_account(b - window_blocks), 1).is_ok());
      ASSERT_TRUE(db->get_event(make_account(b - window_blocks - 1), 1).is_error());
    }
  }

  // Burst: one block introduces far more fresh accounts than a single prune's
  // drain, at a timestamp that is already outside the window relative to a later
  // block. A fixed per-block budget could never catch up; the proportional
  // budget + drain does, over a bounded number of later blocks.
  const size_t burst = tos_wallet_index::kEventPruneDrainPerBlock + 500;
  uint32_t burst_time = kBase + total_blocks * kDay;
  {
    std::vector<std::pair<tos_wallet_index::HashKey, uint64_t>> events;
    for (size_t i = 0; i < burst; i++) {
      events.emplace_back(make_account(1000000 + static_cast<uint32_t>(i)), 1);
    }
    index_block(events, burst_time);
  }
  // Now advance well past the window with empty blocks (age_added == 0, so each
  // prune still gets a full drain budget) and confirm the burst fully drains --
  // the backlog shrinks by at least the drain each block and reaches the steady
  // window size, it does not plateau above it.
  size_t drained_after = 0;
  for (uint32_t k = 1; k <= 20; k++) {
    index_block({}, burst_time + retention + k * kDay);
    if (count_prefix(0x12) == 0) {
      drained_after = k;
      break;
    }
  }
  ASSERT_TRUE(drained_after != 0);          // the burst was fully reclaimed
  ASSERT_TRUE(drained_after <= burst / tos_wallet_index::kEventPruneDrainPerBlock + 2);
  ASSERT_EQ(count_prefix(0x12), count_prefix(0x14));  // still paired at zero

  // A late block carrying an old gen_utime must not regress the cutoff: its
  // event is (correctly) already expired, so after its own prune nothing from
  // before the true watermark reappears, and the count stays at zero.
  index_block({{make_account(2000000), 1}}, kBase);  // far in the past
  ASSERT_TRUE(count_prefix(0x12) <= 1);

  td::rmrf(path).ignore();
}
