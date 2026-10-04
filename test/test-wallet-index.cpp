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
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../validator-engine/wallet-index-queue.h"
#include "../validator-engine/wallet-index-writer.h"
#include "../validator-engine/wallet-index.h"
#include "td/db/RocksDb.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

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
    // Drive the real consolidated retention path (watermark max + prune),
    // exactly as wc0_index_block does.
    ASSERT_TRUE(db->advance_retention(gen_utime, age_added).is_ok());
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

TEST(WalletIndex, MigrationClearsEventNamespacesPreservesOthers) {
  // A database written before schema versioning (no version key) can hold an
  // unbounded 0x12 event namespace. Opening it migrates v0 -> v1, range-deleting
  // the 0x12 and 0x14 namespaces (bounded work, not an enumerate-all that could
  // OOM the very node this fixes), while leaving jetton (0x10), NFT (0x11),
  // nft-owner (0x13) and incomplete-block (0x1E) data intact.
  auto path = std::string("test-wallet-index-db-migration");
  td::rmrf(path).ignore();
  auto put_raw = [](td::RocksDb &raw, std::initializer_list<uint8_t> key) {
    std::string k;
    for (uint8_t b : key) {
      k.push_back(static_cast<char>(b));
    }
    char v[1] = {0};
    raw.set(td::Slice{k}, td::Slice{v, 1}).ensure();
  };
  auto count_raw_prefix = [](td::RocksDb &raw, uint8_t tag) {
    size_t n = 0;
    char begin[1] = {static_cast<char>(tag)};
    char end[1] = {static_cast<char>(static_cast<uint8_t>(tag + 1))};
    raw.for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1}, [&](td::Slice, td::Slice) {
         n++;
         return td::Status::OK();
       }).ensure();
    return n;
  };
  {
    auto raw_r = td::RocksDb::open(path);
    ASSERT_TRUE(raw_r.is_ok());
    auto raw = raw_r.move_as_ok();
    for (uint8_t i = 0; i < 5; i++) {
      put_raw(raw, {0x12, i});  // old event rows (unbounded namespace)
      put_raw(raw, {0x14, i});  // old age rows
    }
    put_raw(raw, {0x10, 0x01});  // jetton
    put_raw(raw, {0x11, 0x01});  // nft
    put_raw(raw, {0x13, 0x01});  // nft-owner
    put_raw(raw, {0x1E, 0x01});  // incomplete-block marker
    // No 0x00 schema key -> version 0.
  }

  {
    auto db_r = tos_wallet_index::WalletIndexDb::open(path);  // triggers migration
    ASSERT_TRUE(db_r.is_ok());
  }

  auto raw_r = td::RocksDb::open(path);
  ASSERT_TRUE(raw_r.is_ok());
  auto raw = raw_r.move_as_ok();
  ASSERT_EQ(count_raw_prefix(raw, 0x12), 0u);  // event namespace cleared
  ASSERT_EQ(count_raw_prefix(raw, 0x14), 0u);  // age namespace cleared
  ASSERT_EQ(count_raw_prefix(raw, 0x10), 1u);  // jetton preserved
  ASSERT_EQ(count_raw_prefix(raw, 0x11), 1u);  // nft preserved
  ASSERT_EQ(count_raw_prefix(raw, 0x13), 1u);  // nft-owner preserved
  ASSERT_EQ(count_raw_prefix(raw, 0x1E), 1u);  // marker preserved
  ASSERT_EQ(count_raw_prefix(raw, 0x00), 1u);  // schema version key written

  td::rmrf(path).ignore();
}

TEST(WalletIndex, RetentionMaintenanceFailsClosedOnWatermarkReadError) {
  // The retention watermark must be non-decreasing; a read failure must never
  // fall back to 0 and let a block write a lower watermark. advance_retention
  // returns the error (so the writer aborts the block) and leaves the stored
  // watermark untouched -- it does not overwrite it with a regressed value.
  auto path = std::string("test-wallet-index-db-wm-failclosed");
  td::rmrf(path).ignore();
  const std::string wm_key = {static_cast<char>(0x00), static_cast<char>(0x02)};
  {
    auto raw_r = td::RocksDb::open(path);
    ASSERT_TRUE(raw_r.is_ok());
    auto raw = raw_r.move_as_ok();
    char bad[3] = {0x01, 0x02, 0x03};  // not 4 bytes -> get_event_watermark errors
    raw.set(td::Slice{wm_key}, td::Slice{bad, 3}).ensure();
  }

  auto db_r = tos_wallet_index::WalletIndexDb::open(path);
  ASSERT_TRUE(db_r.is_ok());
  auto db = db_r.move_as_ok();

  ASSERT_TRUE(db->begin_batch().is_ok());
  auto status = db->advance_retention(/*gen_utime=*/1000, /*age_rows_added=*/0);
  ASSERT_TRUE(status.is_error());  // fails closed on the malformed watermark
  db->abort_batch();

  // The malformed watermark was not overwritten with a 0-fallback value: a fresh
  // read still errors on the same malformed bytes.
  auto again = db->get_event_watermark();
  ASSERT_TRUE(again.is_error());

  td::rmrf(path).ignore();
}

namespace {

using tos_wallet_index::kMaxTokenCandidatesPerBlock;
using tos_wallet_index::ScheduledTokenCandidate;
using tos_wallet_index::TokenCandidate;
using tos_wallet_index::TokenKind;

const tos::ShardIdFull kWholeBasechain{0, tos::shardIdAll};

// An address in queue (bucket) `top`; `n` makes it distinct within the queue.
td::Bits256 token_address(uint32_t n, uint8_t top = 0) {
  td::Bits256 address = td::Bits256::zero();
  address.data()[0] = top;
  address.data()[28] = static_cast<unsigned char>(n >> 24);
  address.data()[29] = static_cast<unsigned char>(n >> 16);
  address.data()[30] = static_cast<unsigned char>(n >> 8);
  address.data()[31] = static_cast<unsigned char>(n);
  return address;
}

std::vector<TokenCandidate> token_candidates(uint32_t first, uint32_t count, uint8_t top = 0) {
  std::vector<TokenCandidate> out;
  for (uint32_t i = first; i < first + count; ++i) {
    auto kind = i % 2 == 0 ? TokenKind::Jetton : TokenKind::Nft;
    out.push_back(TokenCandidate{kind, token_address(i, top)});
  }
  return out;
}

// One block's scheduling pass, committed.
std::vector<ScheduledTokenCandidate> schedule_block(tos_wallet_index::WalletIndexDb &db,
                                                    const std::vector<TokenCandidate> &block_candidates,
                                                    tos::ShardIdFull shard = kWholeBasechain,
                                                    size_t capacity = kMaxTokenCandidatesPerBlock) {
  db.begin_batch().ensure();
  auto chosen = db.schedule_token_candidates(block_candidates, shard, capacity).move_as_ok();
  db.commit_batch().ensure();
  return chosen;
}

std::set<TokenCandidate> candidates_of(const std::vector<ScheduledTokenCandidate> &scheduled) {
  std::set<TokenCandidate> out;
  for (auto &s : scheduled) {
    out.insert(s.candidate);
  }
  return out;
}

size_t backlog_size(tos_wallet_index::WalletIndexDb &db) {
  size_t n = 0;
  db.for_each_deferred_token_candidate(1u << 20, [&](const TokenCandidate &) -> td::Status {
      ++n;
      return td::Status::OK();
    }).ensure();
  return n;
}

tos_wallet_index::TokenBacklogStats backlog_stats(tos_wallet_index::WalletIndexDb &db) {
  return db.token_backlog_stats().move_as_ok();
}

}  // namespace

TEST(WalletIndex, TokenCandidatesPastTheBoundAreDeferredNotDropped) {
  auto path = std::string("test-wallet-index-db-token-backlog");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 3000);

  auto first = schedule_block(*db, block);
  ASSERT_EQ(first.size(), kMaxTokenCandidatesPerBlock);
  ASSERT_EQ(backlog_size(*db), block.size() - kMaxTokenCandidatesPerBlock);
  ASSERT_EQ(backlog_stats(*db).entries, block.size() - kMaxTokenCandidatesPerBlock);

  // The backlog is durable: a restart picks up where the last block stopped.
  db.reset();
  auto reopened = tos_wallet_index::WalletIndexDb::open(path);
  reopened.ensure();
  db = reopened.move_as_ok();
  ASSERT_EQ(backlog_size(*db), block.size() - kMaxTokenCandidatesPerBlock);

  auto verified = candidates_of(first);
  size_t verifications = first.size();
  for (int i = 0; i < 2; ++i) {
    auto chosen = schedule_block(*db, {});
    ASSERT_TRUE(chosen.size() <= kMaxTokenCandidatesPerBlock);
    verifications += chosen.size();
    auto set = candidates_of(chosen);
    verified.insert(set.begin(), set.end());
  }
  // Every candidate verified exactly once, the last one included.
  ASSERT_EQ(verifications, block.size());
  ASSERT_EQ(verified.size(), block.size());
  ASSERT_TRUE(verified.count(block.back()) == 1);
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(0));
  ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(0));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, TokenBacklogDrainsUnderSustainedFullLoad) {
  using tos_wallet_index::kTokenBacklogDrainPerBlock;
  auto path = std::string("test-wallet-index-db-token-backlog-load");
  auto db = open_fresh_db(path);

  // Every block nominates more than the bound on its own. The first block's
  // deferred candidates must still be verified within a bounded number of blocks.
  const uint32_t per_block = 2000;
  auto first_block = token_candidates(0, per_block);
  std::set<TokenCandidate> pending_from_first(first_block.begin(), first_block.end());
  for (auto &c : candidates_of(schedule_block(*db, first_block))) {
    pending_from_first.erase(c);
  }
  ASSERT_EQ(pending_from_first.size(), per_block - kMaxTokenCandidatesPerBlock);
  for (uint32_t b = 1; b < 4; ++b) {
    auto block = token_candidates(b * per_block, per_block);
    std::set<TokenCandidate> own_candidates(block.begin(), block.end());
    auto chosen = schedule_block(*db, block);
    ASSERT_EQ(chosen.size(), kMaxTokenCandidatesPerBlock);
    size_t own = 0;
    for (auto &c : candidates_of(chosen)) {
      pending_from_first.erase(c);
      own += own_candidates.count(c);
    }
    // While a backlog exists, the block's own load cannot take its reserved share.
    ASSERT_TRUE(own <= kMaxTokenCandidatesPerBlock - kTokenBacklogDrainPerBlock);
  }
  // 976 deferred, drained at >= 512 per block, oldest first: gone after two blocks.
  ASSERT_TRUE(pending_from_first.empty());
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnotherShardsBacklogCannotBlockThisShard) {
  auto path = std::string("test-wallet-index-db-token-backlog-shard");
  auto db = open_fresh_db(path);
  auto left = tos::shard_child(kWholeBasechain, true);
  auto right = tos::shard_child(kWholeBasechain, false);

  // 5000 deferred candidates of the left half, queued before 10 of the right half.
  auto left_block = token_candidates(0, 5000, 0x00);
  auto right_block = token_candidates(0, 10, 0x80);
  ASSERT_TRUE(schedule_block(*db, left_block, kWholeBasechain, 0).empty());
  ASSERT_TRUE(schedule_block(*db, right_block, kWholeBasechain, 0).empty());
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5010));

  // The right half's block reaches its own ten at once, behind the left half's 5000.
  auto right_chosen = candidates_of(schedule_block(*db, {}, right));
  ASSERT_EQ(right_chosen, std::set<TokenCandidate>(right_block.begin(), right_block.end()));
  // And the left half's block never takes the right half's candidates.
  auto left_chosen = schedule_block(*db, {}, left);
  ASSERT_EQ(left_chosen.size(), kMaxTokenCandidatesPerBlock);
  for (auto &s : left_chosen) {
    ASSERT_TRUE(tos::shard_contains(left, tos::AccountIdPrefixFull{0, tos::extract_top64(s.candidate.address)}));
  }
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5000 - kMaxTokenCandidatesPerBlock));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, SiblingShardsSharingAQueueTakeOnlyTheirOwn) {
  auto path = std::string("test-wallet-index-db-token-backlog-deep-shard");
  auto db = open_fresh_db(path);
  // Depth-9 siblings both read queue 0x00; the ninth address bit tells them apart.
  const tos::ShardIdFull low{0, 1ULL << 54};
  const tos::ShardIdFull high{0, (1ULL << 55) | (1ULL << 54)};
  std::vector<TokenCandidate> low_block, high_block;
  for (uint32_t i = 0; i < 10; ++i) {
    auto low_address = token_address(i, 0x00);
    auto high_address = token_address(i, 0x00);
    high_address.data()[1] = 0x80;
    low_block.push_back(TokenCandidate{TokenKind::Jetton, low_address});
    high_block.push_back(TokenCandidate{TokenKind::Jetton, high_address});
  }
  ASSERT_TRUE(schedule_block(*db, low_block, kWholeBasechain, 0).empty());
  ASSERT_TRUE(schedule_block(*db, high_block, kWholeBasechain, 0).empty());

  auto high_chosen = candidates_of(schedule_block(*db, {}, high));
  ASSERT_EQ(high_chosen, std::set<TokenCandidate>(high_block.begin(), high_block.end()));
  ASSERT_EQ(backlog_size(*db), low_block.size());
  auto low_chosen = candidates_of(schedule_block(*db, {}, low));
  ASSERT_EQ(low_chosen, std::set<TokenCandidate>(low_block.begin(), low_block.end()));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AFullQueueCannotStarveTheOthers) {
  auto path = std::string("test-wallet-index-db-token-backlog-round-robin");
  auto db = open_fresh_db(path);
  // Queue 0x00 holds 3000 older entries; queue 0x80 one newer entry.
  ASSERT_TRUE(schedule_block(*db, token_candidates(0, 3000, 0x00), kWholeBasechain, 0).empty());
  auto lone = token_candidates(0, 1, 0x80);
  ASSERT_TRUE(schedule_block(*db, lone, kWholeBasechain, 0).empty());

  // Each block brings a full load into queue 0x00 as well; the lone entry is
  // still served in the very next block.
  auto chosen = candidates_of(schedule_block(*db, token_candidates(10000, 2000, 0x00)));
  ASSERT_EQ(chosen.count(lone[0]), static_cast<size_t>(1));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, IndeterminateVerificationIsRetriedThenCounted) {
  using tos_wallet_index::kMaxTokenCandidateAttempts;
  auto path = std::string("test-wallet-index-db-token-retry");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 1);
  std::vector<TokenCandidate> next_block = block;
  for (uint8_t attempt = 0; attempt < kMaxTokenCandidateAttempts; ++attempt) {
    db->begin_batch().ensure();
    auto chosen = db->schedule_token_candidates(next_block, kWholeBasechain).move_as_ok();
    ASSERT_EQ(chosen.size(), static_cast<size_t>(1));
    ASSERT_EQ(chosen[0].attempts, attempt);
    // The node could not decide: hand it back.
    db->retry_token_candidate(chosen[0]).ensure();
    db->commit_batch().ensure();
    next_block.clear();
    if (attempt + 1 < kMaxTokenCandidateAttempts) {
      ASSERT_EQ(backlog_size(*db), static_cast<size_t>(1));
      ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(0));
    }
  }
  // Out of attempts: given up, and counted.
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(1));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, BlockWithoutStateDefersItsCandidates) {
  auto path = std::string("test-wallet-index-db-token-no-state");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 7);
  ASSERT_TRUE(schedule_block(*db, block, kWholeBasechain, 0).empty());
  ASSERT_EQ(backlog_size(*db), block.size());
  ASSERT_EQ(candidates_of(schedule_block(*db, {})), std::set<TokenCandidate>(block.begin(), block.end()));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, TokenBacklogHoldsOneEntryPerCandidateAndIsBounded) {
  auto path = std::string("test-wallet-index-db-token-bound");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 5);
  // Nominated again and again, a candidate waits once.
  ASSERT_TRUE(schedule_block(*db, block, kWholeBasechain, 0).empty());
  ASSERT_TRUE(schedule_block(*db, block, kWholeBasechain, 0).empty());
  ASSERT_EQ(backlog_size(*db), block.size());
  ASSERT_EQ(backlog_stats(*db).entries, block.size());

  // At the bound, further deferrals are refused and counted, not silently dropped.
  db->set_token_backlog_limit(7);
  ASSERT_TRUE(schedule_block(*db, token_candidates(100, 4), kWholeBasechain, 0).empty());
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(7));
  ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(2));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AbortedBlockLeavesTokenBacklogUnchanged) {
  auto path = std::string("test-wallet-index-db-token-backlog-abort");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, kMaxTokenCandidatesPerBlock + 5);

  // Scheduling outside a batch would write past the block's atomicity.
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain).is_error());
  // So would a retry before anything was scheduled.
  db->begin_batch().ensure();
  ASSERT_TRUE(db->retry_token_candidate(ScheduledTokenCandidate{block[0], 0}).is_error());
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain).is_ok());
  // A second pass in one batch would start from counters already moved on.
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain).is_error());
  db->abort_batch();
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(0));

  ASSERT_EQ(schedule_block(*db, block).size(), kMaxTokenCandidatesPerBlock);
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5));
  // Drained entries are erased only when the draining block commits.
  db->begin_batch().ensure();
  ASSERT_EQ(db->schedule_token_candidates({}, kWholeBasechain).move_as_ok().size(), static_cast<size_t>(5));
  db->abort_batch();
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5));
  // Only a wc=0 shard can be scheduled.
  db->begin_batch().ensure();
  ASSERT_TRUE(db->schedule_token_candidates({}, tos::ShardIdFull{-1, tos::shardIdAll}).is_error());
  db->abort_batch();
  td::rmrf(path).ignore();
}

TEST(WalletIndex, CandidatesOfAnotherShardWaitForThatShard) {
  auto path = std::string("test-wallet-index-db-token-foreign");
  auto db = open_fresh_db(path);
  auto left = tos::shard_child(kWholeBasechain, true);
  auto right = tos::shard_child(kWholeBasechain, false);
  auto own = token_candidates(0, 3, 0x00);
  auto foreign = token_candidates(0, 2, 0x80);
  std::vector<TokenCandidate> block = own;
  block.insert(block.end(), foreign.begin(), foreign.end());
  // The left shard's state cannot verify the right shard's accounts.
  ASSERT_EQ(candidates_of(schedule_block(*db, block, left)), std::set<TokenCandidate>(own.begin(), own.end()));
  ASSERT_EQ(backlog_size(*db), foreign.size());
  ASSERT_EQ(candidates_of(schedule_block(*db, {}, right)), std::set<TokenCandidate>(foreign.begin(), foreign.end()));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, ASiblingsLongRunCannotHideThisShardsEntry) {
  using tos_wallet_index::kTokenBacklogScanPerBucket;
  auto path = std::string("test-wallet-index-db-token-deep-run");
  auto db = open_fresh_db(path);
  const tos::ShardIdFull low{0, 1ULL << 54};
  const tos::ShardIdFull high{0, (1ULL << 55) | (1ULL << 54)};
  // More of the low sibling's entries than one block examines, then one of the high sibling's.
  auto low_run = token_candidates(0, static_cast<uint32_t>(kTokenBacklogScanPerBucket + 1000), 0x00);
  ASSERT_TRUE(schedule_block(*db, low_run, kWholeBasechain, 0).empty());
  auto high_address = token_address(7, 0x00);
  high_address.data()[1] = 0x80;
  TokenCandidate high_candidate{TokenKind::Nft, high_address};
  ASSERT_TRUE(schedule_block(*db, {high_candidate}, kWholeBasechain, 0).empty());
  ASSERT_TRUE(tos::shard_contains(high, tos::AccountIdPrefixFull{0, tos::extract_top64(high_address)}));
  ASSERT_TRUE(tos::shard_contains(low, tos::AccountIdPrefixFull{0, tos::extract_top64(low_run[0].address)}));

  // Only the high sibling's blocks run. Each examines a bounded run and resumes after it.
  ASSERT_TRUE(schedule_block(*db, {}, high).empty());
  auto second = candidates_of(schedule_block(*db, {}, high));
  ASSERT_EQ(second.count(high_candidate), static_cast<size_t>(1));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, ProcessingRetriesCountsAndStopsOnAWriteFailure) {
  using tos_wallet_index::TokenVerifyOutcome;
  auto path = std::string("test-wallet-index-db-token-process");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 4);
  db->begin_batch().ensure();
  auto chosen = db->schedule_token_candidates(block, kWholeBasechain).move_as_ok();
  ASSERT_EQ(chosen.size(), static_cast<size_t>(4));
  std::vector<size_t> remaining_seen;
  auto status = db->process_token_candidates(chosen, [&](const ScheduledTokenCandidate &s, size_t remaining) {
    remaining_seen.push_back(remaining);
    if (s.candidate == block[0]) {
      return TokenVerifyOutcome::Done;
    }
    if (s.candidate == block[1]) {
      return TokenVerifyOutcome::Retry;
    }
    if (s.candidate == block[2]) {
      return TokenVerifyOutcome::Unverifiable;
    }
    throw std::runtime_error("verifier gave up");
  });
  ASSERT_TRUE(status.is_ok());
  db->commit_batch().ensure();
  ASSERT_TRUE(remaining_seen == (std::vector<size_t>{4, 3, 2, 1}));
  // Retry and the exception wait again; Unverifiable is counted.
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(2));
  ASSERT_EQ(backlog_stats(*db).unverifiable, static_cast<uint64_t>(1));

  db->begin_batch().ensure();
  auto again = db->schedule_token_candidates({}, kWholeBasechain).move_as_ok();
  ASSERT_EQ(again.size(), static_cast<size_t>(2));
  auto failed = db->process_token_candidates(
      again, [](const ScheduledTokenCandidate &, size_t) { return TokenVerifyOutcome::WriteFailed; });
  ASSERT_TRUE(failed.is_error());
  db->abort_batch();
  // The aborted block took nothing out of the backlog.
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(2));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, TokenIndexStateSaysWhenItIsIncomplete) {
  using tos_wallet_index::format_token_index_state;
  ASSERT_EQ(format_token_index_state({0, 0, 0, false}),
            std::string("{\"complete\":true,\"pending\":0,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false}"));
  ASSERT_EQ(format_token_index_state({3, 0, 0, false}),
            std::string("{\"complete\":false,\"pending\":3,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false}"));
  ASSERT_EQ(format_token_index_state({0, 1, 0, false}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":1,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false}"));
  ASSERT_EQ(format_token_index_state({0, 0, 2, false}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":0,\"unverifiable\":2,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false}"));
  ASSERT_EQ(format_token_index_state({0, 0, 0, true}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":true,"
                        "\"needs_rebuild\":false}"));
}

TEST(WalletIndex, ABlockWhoseIndexingDidNotCommitLeavesTheIndexIncomplete) {
  auto path = std::string("test-wallet-index-db-token-incomplete-block");
  auto db = open_fresh_db(path);
  ASSERT_TRUE(!backlog_stats(*db).unfinished_block);
  // The writer marks a block before indexing it; a failed block aborts its
  // batch, so the mark stays while nothing else changed.
  for (tos::BlockSeqno seqno = 7; seqno < 10; ++seqno) {
    db->put_incomplete_block(make_test_block_id(0, tos::shardIdAll, seqno, 0x11, 0x22)).ensure();
  }
  db->begin_batch().ensure();
  db->schedule_token_candidates(token_candidates(0, 3), kWholeBasechain).ensure();
  db->abort_batch();
  auto stats = backlog_stats(*db);
  ASSERT_TRUE(stats.unfinished_block);
  ASSERT_EQ(stats.entries + stats.lost + stats.unverifiable, static_cast<uint64_t>(0));
  ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AReadSnapshotIgnoresLaterCommits) {
  auto path = std::string("test-wallet-index-db-token-snapshot");
  auto db = open_fresh_db(path);
  auto view = tos_wallet_index::WalletIndexSnapshot::of(*db).move_as_ok();
  ASSERT_TRUE(schedule_block(*db, token_candidates(0, 5), kWholeBasechain, 0).empty());
  auto owner = token_address(1, 0x40);
  auto master = token_address(2, 0x40);
  vm::CellBuilder cb;
  cb.store_long(1, 8);
  db->put_jetton(owner, master, cb.finalize()).ensure();
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(5));
  // The view still answers as of when it was taken, for the state and the list alike.
  ASSERT_EQ(view.token_backlog_stats().move_as_ok().entries, static_cast<uint64_t>(0));
  size_t listed = 0;
  view.for_each_jetton(owner, 16,
                       [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
                         ++listed;
                         return td::Status::OK();
                       })
      .ensure();
  ASSERT_EQ(listed, static_cast<size_t>(0));
  size_t live = 0;
  db->for_each_jetton(owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
      ++live;
      return td::Status::OK();
    }).ensure();
  ASSERT_EQ(live, static_cast<size_t>(1));
  td::rmrf(path).ignore();
}

namespace {

std::string raw_queue_key(uint8_t bucket, uint64_t seq) {
  std::string key(10, '\0');
  key[0] = 0x15;
  key[1] = static_cast<char>(bucket);
  for (int i = 7; i >= 0; --i) {
    key[2 + i] = static_cast<char>(seq & 0xff);
    seq >>= 8;
  }
  return key;
}

std::string raw_index_key(const TokenCandidate &c) {
  std::string key(34, '\0');
  key[0] = 0x16;
  key[1] = static_cast<char>(c.kind);
  std::memcpy(&key[2], c.address.data(), 32);
  return key;
}

std::string raw_u64(uint64_t v) {
  std::string out(8, '\0');
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<char>(v & 0xff);
    v >>= 8;
  }
  return out;
}

}  // namespace

TEST(WalletIndex, ARenominatedCandidateKeepsItsAttemptsAndItsSlot) {
  auto path = std::string("test-wallet-index-db-token-claim");
  auto db = open_fresh_db(path);
  // 1100 older entries, more than one block collects, then the target with
  // two attempts used, written directly at the back of the same queue.
  ASSERT_TRUE(schedule_block(*db, token_candidates(0, 1100), kWholeBasechain, 0).empty());
  db.reset();
  auto target = token_candidates(5000, 1)[0];
  {
    auto raw = td::RocksDb::open(path).move_as_ok();
    std::string value(34, '\0');
    value[0] = static_cast<char>(target.kind);
    std::memcpy(&value[1], target.address.data(), 32);
    value[33] = 2;
    auto queue = raw_queue_key(0, 1100);
    raw.set(queue, value).ensure();
    raw.set(raw_index_key(target), queue.substr(1)).ensure();
    raw.set(std::string("\x00\x04", 2), raw_u64(1101)).ensure();
    raw.set(std::string("\x00\x03", 2), raw_u64(1101)).ensure();
  }
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();

  // A block nominates it and verifies it directly, beyond what the backlog
  // share reached: it carries its attempts, and its backlog entry goes with it.
  auto chosen = schedule_block(*db, {target});
  bool found = false;
  for (auto &s : chosen) {
    if (s.candidate == target) {
      found = true;
      ASSERT_EQ(s.attempts, static_cast<uint8_t>(2));
    }
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(1100 - (chosen.size() - 1)));
  bool still_waiting = false;
  db->for_each_deferred_token_candidate(1u << 20, [&](const TokenCandidate &c) -> td::Status {
      still_waiting = still_waiting || c == target;
      return td::Status::OK();
    }).ensure();
  ASSERT_TRUE(!still_waiting);
  td::rmrf(path).ignore();
}

TEST(WalletIndex, MalformedBacklogEntriesAreDroppedCountedAndDoNotBlockTheirCandidate) {
  auto path = std::string("test-wallet-index-db-token-corrupt");
  auto db = open_fresh_db(path);
  db.reset();
  auto readable = token_candidates(0, 1)[0];    // value intact but attempts out of range
  auto unreadable = token_candidates(1, 1)[0];  // value truncated: its candidate cannot be read back
  {
    auto raw = td::RocksDb::open(path).move_as_ok();
    std::string value(34, '\0');
    value[0] = static_cast<char>(readable.kind);
    std::memcpy(&value[1], readable.address.data(), 32);
    value[33] = static_cast<char>(0xff);
    auto readable_queue = raw_queue_key(0, 0);
    raw.set(readable_queue, value).ensure();
    raw.set(raw_index_key(readable), readable_queue.substr(1)).ensure();
    auto unreadable_queue = raw_queue_key(0, 1);
    raw.set(unreadable_queue, std::string(5, '\x01')).ensure();
    raw.set(raw_index_key(unreadable), unreadable_queue.substr(1)).ensure();
    raw.set(std::string("\x00\x04", 2), raw_u64(2)).ensure();
    raw.set(std::string("\x00\x03", 2), raw_u64(2)).ensure();
  }
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();

  // The next block of the shard drops both instead of failing on them.
  ASSERT_TRUE(schedule_block(*db, {}).empty());
  ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(2));
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(0));
  // The entry that still named its candidate took that candidate's index row with it.
  db.reset();
  {
    auto raw = td::RocksDb::open(path).move_as_ok();
    std::string value;
    ASSERT_TRUE(raw.get(raw_index_key(readable), value).move_as_ok() == td::KeyValue::GetStatus::NotFound);
  }
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  // Both candidates can wait again: neither leftover index entry refuses them.
  ASSERT_TRUE(schedule_block(*db, {readable, unreadable}, kWholeBasechain, 0).empty());
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(2));
  ASSERT_EQ(candidates_of(schedule_block(*db, {})), (std::set<TokenCandidate>{readable, unreadable}));
  td::rmrf(path).ignore();
}

namespace {

// A truncated row for `broken` that its index still points to, and a valid
// row of the other depth-9 sibling in the same queue.
void write_broken_entry_beside_a_sibling(const std::string &path, const TokenCandidate &broken,
                                         const TokenCandidate &sibling) {
  auto raw = td::RocksDb::open(path).move_as_ok();
  auto broken_queue = raw_queue_key(0, 0);
  raw.set(broken_queue, std::string(5, '\x01')).ensure();
  raw.set(raw_index_key(broken), broken_queue.substr(1)).ensure();
  std::string value(34, '\0');
  value[0] = static_cast<char>(sibling.kind);
  std::memcpy(&value[1], sibling.address.data(), 32);
  auto sibling_queue = raw_queue_key(0, 1);
  raw.set(sibling_queue, value).ensure();
  raw.set(raw_index_key(sibling), sibling_queue.substr(1)).ensure();
  raw.set(std::string("\x00\x04", 2), raw_u64(2)).ensure();
  raw.set(std::string("\x00\x03", 2), raw_u64(2)).ensure();
}

TokenCandidate deep_candidate(uint32_t n, bool high) {
  auto address = token_address(n, 0x00);
  address.data()[1] = high ? 0x80 : 0x00;
  return TokenCandidate{TokenKind::Jetton, address};
}

}  // namespace

TEST(WalletIndex, AnEntryDroppedAsMalformedIsNotCountedTwiceWhenItsCandidateReturns) {
  auto path = std::string("test-wallet-index-db-token-corrupt-claim");
  auto db = open_fresh_db(path);
  db.reset();
  const tos::ShardIdFull high{0, (1ULL << 55) | (1ULL << 54)};
  auto broken = deep_candidate(1, true);
  auto sibling = deep_candidate(2, false);
  write_broken_entry_beside_a_sibling(path, broken, sibling);
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();

  // In one block: the broken row is dropped, and the same candidate arrives
  // from the block and is verified directly.
  auto chosen = candidates_of(schedule_block(*db, {broken}, high));
  ASSERT_EQ(chosen, std::set<TokenCandidate>{broken});
  auto stats = backlog_stats(*db);
  ASSERT_EQ(stats.lost, static_cast<uint64_t>(1));
  // The sibling's row is still there, and still counted.
  ASSERT_EQ(stats.entries, static_cast<uint64_t>(1));
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(1));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnEntryDroppedAsMalformedDoesNotHideItsCandidateDeferredInTheSameBlock) {
  auto path = std::string("test-wallet-index-db-token-corrupt-defer");
  auto db = open_fresh_db(path);
  db.reset();
  const tos::ShardIdFull high{0, (1ULL << 55) | (1ULL << 54)};
  auto broken = deep_candidate(1, true);
  auto sibling = deep_candidate(2, false);
  write_broken_entry_beside_a_sibling(path, broken, sibling);
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();

  // Capacity 1: another candidate takes the slot and the broken row's
  // candidate is deferred in the very block that drops that row.
  auto first = deep_candidate(3, true);
  auto chosen = candidates_of(schedule_block(*db, {first, broken}, high, 1));
  ASSERT_EQ(chosen, std::set<TokenCandidate>{first});
  bool waiting = false;
  db->for_each_deferred_token_candidate(16, [&](const TokenCandidate &c) -> td::Status {
      waiting = waiting || c == broken;
      return td::Status::OK();
    }).ensure();
  ASSERT_TRUE(waiting);
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(2));
  td::rmrf(path).ignore();
}

namespace {

struct QueueLog {
  std::mutex mutex;
  std::vector<int> recorded;
  std::vector<int> processed;
  // Every id processed had been recorded first.
  bool processed_before_recorded = false;
};

}  // namespace

TEST(WalletIndexQueue, PushingNeverWaitsForTheWork) {
  QueueLog log;
  std::atomic<bool> release{false};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8,
        [&](const std::vector<int> &ids) -> bool {
          std::lock_guard<std::mutex> lock(log.mutex);
          log.recorded.insert(log.recorded.end(), ids.begin(), ids.end());
          return true;
        },
        [&](int &) {
          while (!release.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
          }
        });
    auto started = std::chrono::steady_clock::now();
    for (int i = 0; i < 4; ++i) {
      ASSERT_TRUE(queue.push(i, i));
    }
    auto took = std::chrono::steady_clock::now() - started;
    // The worker is stuck on the first item; pushing did not wait for it.
    ASSERT_TRUE(took < std::chrono::milliseconds(50));
    release = true;
  }
}

TEST(WalletIndexQueue, WorkIsRecordedFirstAndDoneInOrder) {
  QueueLog log;
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        64,
        [&](const std::vector<int> &ids) -> bool {
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
          std::lock_guard<std::mutex> lock(log.mutex);
          log.recorded.insert(log.recorded.end(), ids.begin(), ids.end());
          return true;
        },
        [&](int &item) {
          std::lock_guard<std::mutex> lock(log.mutex);
          if (std::find(log.recorded.begin(), log.recorded.end(), item) == log.recorded.end()) {
            log.processed_before_recorded = true;
          }
          log.processed.push_back(item);
        });
    for (int i = 0; i < 40; ++i) {
      ASSERT_TRUE(queue.push(i, i));
    }
    for (int spin = 0; spin < 400; ++spin) {
      {
        std::lock_guard<std::mutex> lock(log.mutex);
        if (log.processed.size() == 40) {
          break;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }
  ASSERT_TRUE(!log.processed_before_recorded);
  ASSERT_EQ(log.processed.size(), static_cast<size_t>(40));
  for (int i = 0; i < 40; ++i) {
    ASSERT_EQ(log.processed[i], i);
  }
}

TEST(WalletIndexQueue, AFullQueueDropsTheWorkButStillRecordsIt) {
  QueueLog log;
  std::atomic<bool> release{false};
  std::atomic<bool> first_started{false};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        2,
        [&](const std::vector<int> &ids) -> bool {
          std::lock_guard<std::mutex> lock(log.mutex);
          log.recorded.insert(log.recorded.end(), ids.begin(), ids.end());
          return true;
        },
        [&](int &item) {
          first_started = true;
          while (!release.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
          }
          std::lock_guard<std::mutex> lock(log.mutex);
          log.processed.push_back(item);
        });
    ASSERT_TRUE(queue.push(0, 0));
    while (!first_started.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // One item is being worked on; two may wait; the next is dropped.
    ASSERT_TRUE(queue.push(1, 1));
    ASSERT_TRUE(queue.push(2, 2));
    ASSERT_TRUE(!queue.push(3, 3));
    ASSERT_EQ(queue.dropped(), static_cast<size_t>(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    release = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  // The dropped item was never done, but its id was recorded, so it is not lost.
  ASSERT_TRUE(std::find(log.processed.begin(), log.processed.end(), 3) == log.processed.end());
  for (int id = 0; id < 4; ++id) {
    ASSERT_TRUE(std::find(log.recorded.begin(), log.recorded.end(), id) != log.recorded.end());
  }
}

TEST(WalletIndexQueue, WorkLeftAtShutdownStaysRecordedAndUndone) {
  QueueLog log;
  std::atomic<bool> release{false};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8,
        [&](const std::vector<int> &ids) -> bool {
          std::lock_guard<std::mutex> lock(log.mutex);
          log.recorded.insert(log.recorded.end(), ids.begin(), ids.end());
          return true;
        },
        [&](int &item) {
          while (!release.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
          }
          std::lock_guard<std::mutex> lock(log.mutex);
          log.processed.push_back(item);
        });
    for (int i = 0; i < 5; ++i) {
      queue.push(i, i);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    release = true;
  }
  // Shutdown finished the item in hand and left the rest to recovery.
  ASSERT_TRUE(log.processed.size() < 5);
  ASSERT_EQ(log.recorded.size(), static_cast<size_t>(5));
}

TEST(WalletIndex, MarkingQueuedBlocksDoesNotJoinAnOpenBatch) {
  auto path = std::string("test-wallet-index-db-mark-queued");
  auto db = open_fresh_db(path);
  auto first = make_test_block_id(0, tos::shardIdAll, 11, 0x01, 0x02);
  auto second = make_test_block_id(0, tos::shardIdAll, 12, 0x03, 0x04);
  // The indexing worker has a block's batch open on another thread.
  db->begin_batch().ensure();
  db->mark_blocks_incomplete({first, second}).ensure();
  db->abort_batch();
  // The marks were written directly and survive the aborted batch.
  ASSERT_TRUE(db->has_incomplete_block(first).move_as_ok());
  ASSERT_TRUE(db->has_incomplete_block(second).move_as_ok());
  td::rmrf(path).ignore();
}

TEST(WalletIndexQueue, NothingIsDoneUntilItsRecordSucceeds) {
  std::atomic<int> attempts{0};
  std::atomic<int> processed{0};
  std::atomic<bool> allow{false};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8,
        [&](const std::vector<int> &) -> bool {
          attempts++;
          if (attempts.load() == 2) {
            throw std::runtime_error("recorder failed");
          }
          return allow.load();
        },
        [&](int &) { processed++; });
    queue.push(1, 1);
    queue.push(2, 2);
    // Recording keeps failing (once by throwing): the work waits, and is retried.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_TRUE(attempts.load() >= 2);
    ASSERT_EQ(processed.load(), 0);
    ASSERT_TRUE(!queue.degraded());
    allow = true;
    for (int spin = 0; spin < 600 && processed.load() < 2; ++spin) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(processed.load(), 2);
  }
}

TEST(WalletIndexQueue, AnIdThatCannotBeRecordedMarksTheQueueDegraded) {
  std::atomic<int> degraded_calls{0};
  std::atomic<bool> allow{false};
  {
    // Room for one id awaiting record; recording blocked until released.
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8, [&](const std::vector<int> &) -> bool { return allow.load(); }, [](int &) {},
        [&] {
          degraded_calls++;
          return true;
        },
        1);
    queue.push(1, 1);
    ASSERT_TRUE(!queue.degraded());
    queue.push(2, 2);
    queue.push(3, 3);
    ASSERT_TRUE(queue.degraded());
    // Persisted in the background, once.
    for (int spin = 0; spin < 300 && degraded_calls.load() == 0; ++spin) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_EQ(degraded_calls.load(), 1);
    allow = true;
  }
}

TEST(WalletIndexQueue, IdsStillUnrecordedAtShutdownMarkTheQueueDegraded) {
  std::atomic<int> degraded_calls{0};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8, [](const std::vector<int> &) -> bool { return false; }, [](int &) {},
        [&] {
          degraded_calls++;
          return true;
        });
    queue.push(1, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_EQ(degraded_calls.load(), 1);
}

TEST(WalletIndex, AnOlderBlocksVerdictNeverUndoesANewerOne) {
  auto path = std::string("test-wallet-index-db-nft-order");
  auto db = open_fresh_db(path);
  auto item = token_address(1, 0x40);
  auto old_owner = token_address(2, 0x40);
  auto new_owner = token_address(3, 0x40);
  vm::CellBuilder cb;
  cb.store_long(1, 8);
  auto value = cb.finalize();
  using Verdict = tos_wallet_index::WalletIndexDb::NftVerdict;
  auto apply = [&](const Verdict &verdict, uint64_t lt) {
    db->begin_batch().ensure();
    db->apply_nft_verdict(item, verdict, lt).ensure();
    db->commit_batch().ensure();
  };
  auto owner_of = [&]() {
    td::Bits256 owner;
    return db->get_nft_owner(item, owner).move_as_ok() ? owner : td::Bits256::zero();
  };
  auto listed_for = [&](const td::Bits256 &owner) {
    size_t n = 0;
    db->for_each_nft(owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
        ++n;
        return td::Status::OK();
      }).ensure();
    return n;
  };

  // The newer block (lt 200) is indexed first; recovery then indexes lt 100.
  apply(Verdict{true, new_owner, value}, 200);
  apply(Verdict{true, old_owner, value}, 100);
  ASSERT_TRUE(owner_of() == new_owner);
  ASSERT_EQ(listed_for(new_owner), static_cast<size_t>(1));
  ASSERT_EQ(listed_for(old_owner), static_cast<size_t>(0));

  // Found unowned at lt 300; an older "owned" verdict cannot bring it back.
  apply(Verdict{false, td::Bits256::zero(), {}}, 300);
  ASSERT_TRUE(owner_of() == td::Bits256::zero());
  apply(Verdict{true, old_owner, value}, 250);
  ASSERT_TRUE(owner_of() == td::Bits256::zero());
  ASSERT_EQ(listed_for(old_owner), static_cast<size_t>(0));

  // In order, a newer verdict moves the item.
  apply(Verdict{true, old_owner, value}, 400);
  ASSERT_TRUE(owner_of() == old_owner);
  ASSERT_EQ(listed_for(new_owner), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, ARecordFromAnOlderBinaryCountsAsOldest) {
  auto path = std::string("test-wallet-index-db-nft-legacy");
  auto db = open_fresh_db(path);
  auto item = token_address(1, 0x40);
  auto owner = token_address(2, 0x40);
  // An older binary stored the owner alone: 0x13 + nft(32) -> owner(32).
  db.reset();
  {
    auto raw = td::RocksDb::open(path).move_as_ok();
    std::string key(33, '\0');
    key[0] = 0x13;
    std::memcpy(&key[1], item.data(), 32);
    raw.set(key, td::Slice(owner.as_slice()).str()).ensure();
  }
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  td::Bits256 before;
  ASSERT_TRUE(db->get_nft_owner(item, before).move_as_ok());
  ASSERT_TRUE(before == owner);
  db->begin_batch().ensure();
  db->apply_nft_verdict(item, {false, td::Bits256::zero(), {}}, 1).ensure();
  db->commit_batch().ensure();
  td::Bits256 found;
  ASSERT_TRUE(!db->get_nft_owner(item, found).move_as_ok());
  td::rmrf(path).ignore();
}

TEST(WalletIndex, ALostBlockKeepsTheIndexIncompleteUntilRebuilt) {
  auto path = std::string("test-wallet-index-db-needs-rebuild");
  auto db = open_fresh_db(path);
  ASSERT_TRUE(!backlog_stats(*db).needs_rebuild);
  db->begin_batch().ensure();
  db->mark_needs_rebuild().ensure();
  db->abort_batch();
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  auto stats = backlog_stats(*db);
  ASSERT_TRUE(stats.needs_rebuild);
  ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  td::rmrf(path).ignore();
}

TEST(WalletIndexQueue, OverflowNeverMakesPushWaitForPersistence) {
  std::atomic<bool> release{false};
  std::atomic<int> persisted{0};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8, [&](const std::vector<int> &) -> bool { return release.load(); }, [](int &) {},
        [&] {
          // A slow disk.
          std::this_thread::sleep_for(std::chrono::milliseconds(300));
          persisted++;
          return true;
        },
        1);
    queue.push(1, 1);
    auto started = std::chrono::steady_clock::now();
    for (int i = 2; i < 6; ++i) {
      queue.push(i, i);
    }
    ASSERT_TRUE(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(50));
    ASSERT_TRUE(queue.degraded());
    release = true;
    ASSERT_TRUE(queue.wait_recorded(std::chrono::milliseconds(3000)));
  }
  ASSERT_EQ(persisted.load(), 1);
}

TEST(WalletIndexQueue, ADegradedStateThatFailsToPersistIsRetried) {
  std::atomic<int> tries{0};
  {
    tos_wallet_index::BoundedWorkQueue<int, int> queue(
        8, [](const std::vector<int> &) -> bool { return false; }, [](int &) {},
        [&] {
          tries++;
          return tries.load() >= 3;
        },
        1);
    queue.push(1, 1);
    queue.push(2, 2);  // no room to record: degraded
    for (int spin = 0; spin < 400 && tries.load() < 3; ++spin) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  ASSERT_TRUE(tries.load() >= 3);
}

TEST(WalletIndexQueue, APausedQueueRecordsButDoesNotProcess) {
  std::atomic<int> recorded{0};
  std::atomic<int> processed{0};
  tos_wallet_index::BoundedWorkQueue<int, int> queue(
      8,
      [&](const std::vector<int> &ids) -> bool {
        recorded += static_cast<int>(ids.size());
        return true;
      },
      [&](int &) { processed++; }, nullptr, 0, true);
  queue.push(1, 1);
  queue.push(2, 2);
  ASSERT_TRUE(queue.wait_recorded(std::chrono::milliseconds(2000)));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_EQ(recorded.load(), 2);
  ASSERT_EQ(processed.load(), 0);
  queue.resume();
  for (int spin = 0; spin < 200 && processed.load() < 2; ++spin) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_EQ(processed.load(), 2);
  // Paused again, as before an abrupt exit: new blocks are still recorded.
  queue.pause();
  queue.push(3, 3);
  ASSERT_TRUE(queue.wait_recorded(std::chrono::milliseconds(2000)));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_EQ(recorded.load(), 3);
  ASSERT_EQ(processed.load(), 2);
}

TEST(WalletIndexQueue, WaitingForRecordsGivesUpWhenRecordingKeepsFailing) {
  tos_wallet_index::BoundedWorkQueue<int, int> queue(
      8, [](const std::vector<int> &) -> bool { return false; }, [](int &) {});
  queue.push(1, 1);
  ASSERT_TRUE(!queue.wait_recorded(std::chrono::milliseconds(200)));
}
