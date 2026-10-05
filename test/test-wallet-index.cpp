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
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../validator-engine/wallet-index-queue.h"
#include "../validator-engine/wallet-index-writer.h"
#include "../validator-engine/wallet-index.h"
#include "../validator/db/archive-gc-floor.h"
#include "../validator/wc0-block-hook.h"
#include "td/db/RocksDb.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"

#include "wallet-index-chain-fixture.h"

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
    // The current schema, so the database is kept as it is.
    const char version_key[2] = {0x00, 0x01};
    const char current[4] = {0, 0, 0, static_cast<char>(tos_wallet_index::kWalletIndexSchemaVersion)};
    raw.set(td::Slice{version_key, 2}, td::Slice{current, 4}).ensure();
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
// The end logical time of the blocks these tests schedule for.
constexpr uint64_t kTestLt = 1000;

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
                                                    size_t capacity = kMaxTokenCandidatesPerBlock,
                                                    uint64_t end_lt = kTestLt) {
  db.begin_batch().ensure();
  auto chosen = db.schedule_token_candidates(block_candidates, shard, capacity, end_lt).move_as_ok();
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

TEST(WalletIndex, IndeterminateVerificationIsRetriedThenParkedWithItsIdentity) {
  using tos_wallet_index::kMaxTokenCandidateAttempts;
  auto path = std::string("test-wallet-index-db-token-retry");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 1);
  std::vector<TokenCandidate> next_block = block;
  for (uint8_t attempt = 0; attempt < kMaxTokenCandidateAttempts; ++attempt) {
    db->begin_batch().ensure();
    auto chosen =
        db->schedule_token_candidates(next_block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok();
    ASSERT_EQ(chosen.size(), static_cast<size_t>(1));
    ASSERT_EQ(chosen[0].attempts, attempt);
    // The node could not decide: hand it back.
    db->retry_token_candidate(chosen[0]).ensure();
    db->commit_batch().ensure();
    next_block.clear();
    if (attempt + 1 < kMaxTokenCandidateAttempts) {
      ASSERT_EQ(backlog_size(*db), static_cast<size_t>(1));
      ASSERT_EQ(backlog_stats(*db).parked, static_cast<uint64_t>(0));
    }
  }
  // Out of attempts: it no longer waits in a queue, but it is not given up.
  // Its identity is kept, nothing is counted as lost, and the index says it
  // is incomplete.
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  auto stats = backlog_stats(*db);
  ASSERT_EQ(stats.parked, static_cast<uint64_t>(1));
  ASSERT_EQ(stats.lost, static_cast<uint64_t>(0));
  ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  // Blocks that do not nominate it leave it parked across a restart.
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  ASSERT_TRUE(schedule_block(*db, {}).empty());
  ASSERT_EQ(backlog_stats(*db).parked, static_cast<uint64_t>(1));
  // A later nomination verifies it afresh; once verified, nothing is parked.
  auto chosen = schedule_block(*db, block);
  ASSERT_EQ(chosen.size(), static_cast<size_t>(1));
  ASSERT_EQ(chosen[0].attempts, static_cast<uint8_t>(0));
  stats = backlog_stats(*db);
  ASSERT_EQ(stats.parked, static_cast<uint64_t>(0));
  ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":true") != std::string::npos);
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

  // At the bound, deferring stops at the first candidate without room and
  // says which one; nothing is dropped or counted as lost.
  db->set_token_backlog_limit(7);
  auto more = token_candidates(100, 4);
  db->begin_batch().ensure();
  ASSERT_TRUE(db->schedule_token_candidates(more, kWholeBasechain, 0, kTestLt).move_as_ok().empty());
  auto stopped_at = db->first_unhandled_block_candidate();
  db->commit_batch().ensure();
  std::set<TokenCandidate> ordered(more.begin(), more.end());
  auto third = std::next(ordered.begin(), 2);
  ASSERT_TRUE(static_cast<bool>(stopped_at));
  ASSERT_TRUE(stopped_at.value() == *third);
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(7));
  ASSERT_EQ(backlog_stats(*db).lost, static_cast<uint64_t>(0));
  ASSERT_TRUE(!db->token_backlog_has_room().move_as_ok());
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AbortedBlockLeavesTokenBacklogUnchanged) {
  auto path = std::string("test-wallet-index-db-token-backlog-abort");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, kMaxTokenCandidatesPerBlock + 5);

  // Scheduling outside a batch would write past the block's atomicity.
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).is_error());
  // So would a retry before anything was scheduled.
  db->begin_batch().ensure();
  ASSERT_TRUE(db->retry_token_candidate(ScheduledTokenCandidate{block[0], 0}).is_error());
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).is_ok());
  // A second pass in one batch would start from counters already moved on.
  ASSERT_TRUE(db->schedule_token_candidates(block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).is_error());
  db->abort_batch();
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(0));

  ASSERT_EQ(schedule_block(*db, block).size(), kMaxTokenCandidatesPerBlock);
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5));
  // Drained entries are erased only when the draining block commits.
  db->begin_batch().ensure();
  ASSERT_EQ(
      db->schedule_token_candidates({}, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok().size(),
      static_cast<size_t>(5));
  db->abort_batch();
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(5));
  // Only a wc=0 shard can be scheduled.
  db->begin_batch().ensure();
  ASSERT_TRUE(
      db->schedule_token_candidates({}, tos::ShardIdFull{-1, tos::shardIdAll}, kMaxTokenCandidatesPerBlock, kTestLt)
          .is_error());
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
  auto chosen =
      db->schedule_token_candidates(block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok();
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
  // Retry and the exception wait again; Unverifiable is parked with its
  // identity, not merely counted.
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(2));
  ASSERT_EQ(backlog_stats(*db).unverifiable, static_cast<uint64_t>(0));
  ASSERT_EQ(backlog_stats(*db).parked, static_cast<uint64_t>(1));

  db->begin_batch().ensure();
  auto again = db->schedule_token_candidates({}, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok();
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
                        "\"needs_rebuild\":false,\"parked\":0}"));
  ASSERT_EQ(format_token_index_state({3, 0, 0, false}),
            std::string("{\"complete\":false,\"pending\":3,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false,\"parked\":0}"));
  ASSERT_EQ(format_token_index_state({0, 1, 0, false}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":1,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false,\"parked\":0}"));
  ASSERT_EQ(format_token_index_state({0, 0, 2, false}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":0,\"unverifiable\":2,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false,\"parked\":0}"));
  tos_wallet_index::TokenBacklogStats parked{0, 0, 0, false};
  parked.parked = 2;
  ASSERT_EQ(format_token_index_state(parked),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":false,"
                        "\"needs_rebuild\":false,\"parked\":2}"));
  ASSERT_EQ(format_token_index_state({0, 0, 0, true}),
            std::string("{\"complete\":false,\"pending\":0,\"lost\":0,\"unverifiable\":0,\"unfinished_block\":true,"
                        "\"needs_rebuild\":false,\"parked\":0}"));
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
  db->schedule_token_candidates(token_candidates(0, 3), kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).ensure();
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
  auto wallet = token_address(3, 0x40);
  vm::CellBuilder cb;
  cb.store_bits(wallet.bits(), 256);
  cb.store_long(500, 64);
  db->begin_batch().ensure();
  db->apply_jetton_verdict(wallet, {true, owner, master, cb.finalize()}, 500).ensure();
  db->commit_batch().ensure();
  ASSERT_EQ(backlog_stats(*db).entries, static_cast<uint64_t>(5));
  // The view still answers as of when it was taken, for the state and the list alike.
  ASSERT_EQ(view.token_backlog_stats().move_as_ok().entries, static_cast<uint64_t>(0));
  size_t listed = 0;
  view.for_each_current_jetton(owner, 16,
                               [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
                                 ++listed;
                                 return td::Status::OK();
                               })
      .ensure();
  ASSERT_EQ(listed, static_cast<size_t>(0));
  size_t live = 0;
  db->for_each_current_jetton(owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
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
    std::string value(42, '\0');  // lt 0
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
    std::string value(42, '\0');  // lt 0
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
  std::string value(42, '\0');  // lt 0
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

  // Capacity 1: another candidate, earlier in candidate order, takes the slot
  // and the broken row's candidate is deferred in the very block that drops
  // that row.
  auto first = deep_candidate(0, true);
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

TEST(WalletIndex, AFirstAbsentVerdictStillOutranksAnOlderOwnedOne) {
  auto path = std::string("test-wallet-index-db-nft-first-absent");
  auto db = open_fresh_db(path);
  auto item = token_address(5, 0x40);
  auto old_owner = token_address(6, 0x40);
  vm::CellBuilder cb;
  cb.store_long(1, 8);
  using Verdict = tos_wallet_index::WalletIndexDb::NftVerdict;
  // Nothing indexed yet; block B (lt 500) finds the item unowned. Block A
  // (lt 400), whose recovery failed earlier, is indexed afterwards.
  db->begin_batch().ensure();
  db->apply_nft_verdict(item, Verdict{false, td::Bits256::zero(), {}}, 500).ensure();
  db->commit_batch().ensure();
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  db->begin_batch().ensure();
  db->apply_nft_verdict(item, Verdict{true, old_owner, cb.finalize()}, 400).ensure();
  db->commit_batch().ensure();
  td::Bits256 owner;
  ASSERT_TRUE(!db->get_nft_owner(item, owner).move_as_ok());
  size_t listed = 0;
  db->for_each_nft(old_owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
      ++listed;
      return td::Status::OK();
    }).ensure();
  ASSERT_EQ(listed, static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

namespace {

td::Ref<vm::Cell> jetton_value(const td::Bits256 &wallet, uint64_t lt) {
  vm::CellBuilder cb;
  cb.store_bits(wallet.bits(), 256);
  cb.store_long(static_cast<long long>(lt), 64);
  return cb.finalize();
}

using JettonVerdict = tos_wallet_index::WalletIndexDb::JettonVerdict;

JettonVerdict jetton_present(const td::Bits256 &wallet, const td::Bits256 &owner, const td::Bits256 &master,
                             uint64_t lt) {
  return JettonVerdict{true, owner, master, jetton_value(wallet, lt)};
}

JettonVerdict jetton_absent() {
  return JettonVerdict{false, td::Bits256::zero(), td::Bits256::zero(), {}};
}

void apply_jetton(tos_wallet_index::WalletIndexDb &db, const td::Bits256 &wallet, const JettonVerdict &verdict,
                  uint64_t lt) {
  db.begin_batch().ensure();
  db.apply_jetton_verdict(wallet, verdict, lt).ensure();
  db.commit_batch().ensure();
}

// Masters listed for `owner`, each with the wallet its entry names.
std::vector<std::pair<td::Bits256, td::Bits256>> jettons_of(tos_wallet_index::WalletIndexDb &db,
                                                            const td::Bits256 &owner) {
  std::vector<std::pair<td::Bits256, td::Bits256>> out;
  db.for_each_jetton(owner, 16, [&](const td::Bits256 &master, td::Ref<vm::Cell> value) -> td::Status {
      td::Bits256 wallet;
      vm::CellSlice cs = vm::load_cell_slice(value);
      CHECK(cs.prefetch_bits_to(wallet.bits(), 256));
      out.emplace_back(master, wallet);
      return td::Status::OK();
    }).ensure();
  return out;
}

}  // namespace

TEST(WalletIndex, AJettonWalletsChangedOwnerOrMasterLeavesNoStaleEntry) {
  auto path = std::string("test-wallet-index-db-jetton-move");
  auto db = open_fresh_db(path);
  auto wallet = token_address(1, 0x50);
  auto owner_a = token_address(2, 0x50);
  auto owner_b = token_address(3, 0x50);
  auto master_x = token_address(4, 0x50);
  auto master_y = token_address(5, 0x50);

  apply_jetton(*db, wallet, jetton_present(wallet, owner_a, master_x, 100), 100);
  ASSERT_EQ(jettons_of(*db, owner_a).size(), static_cast<size_t>(1));

  // The owner changes: the old owner's entry goes.
  apply_jetton(*db, wallet, jetton_present(wallet, owner_b, master_x, 200), 200);
  ASSERT_EQ(jettons_of(*db, owner_a).size(), static_cast<size_t>(0));
  auto listed = jettons_of(*db, owner_b);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].first == master_x && listed[0].second == wallet);

  // The master changes: the old pair's entry goes.
  apply_jetton(*db, wallet, jetton_present(wallet, owner_b, master_y, 300), 300);
  listed = jettons_of(*db, owner_b);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].first == master_y);

  td::Bits256 owner, master;
  ASSERT_TRUE(db->get_jetton_wallet(wallet, owner, master).move_as_ok());
  ASSERT_TRUE(owner == owner_b && master == master_y);
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AJettonWalletThatStopsVerifyingIsRemoved) {
  auto path = std::string("test-wallet-index-db-jetton-gone");
  auto db = open_fresh_db(path);
  auto wallet = token_address(1, 0x51);
  auto owner = token_address(2, 0x51);
  auto master = token_address(3, 0x51);

  apply_jetton(*db, wallet, jetton_present(wallet, owner, master, 100), 100);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(1));
  apply_jetton(*db, wallet, jetton_absent(), 200);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(0));
  td::Bits256 found_owner, found_master;
  ASSERT_TRUE(!db->get_jetton_wallet(wallet, found_owner, found_master).move_as_ok());
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnOlderBlocksJettonVerdictNeverUndoesANewerOne) {
  auto path = std::string("test-wallet-index-db-jetton-order");
  auto db = open_fresh_db(path);
  auto wallet = token_address(1, 0x52);
  auto old_owner = token_address(2, 0x52);
  auto new_owner = token_address(3, 0x52);
  auto master = token_address(4, 0x52);

  // The newer block (lt 200) is indexed first; recovery then indexes lt 100.
  apply_jetton(*db, wallet, jetton_present(wallet, new_owner, master, 200), 200);
  apply_jetton(*db, wallet, jetton_present(wallet, old_owner, master, 100), 100);
  ASSERT_EQ(jettons_of(*db, new_owner).size(), static_cast<size_t>(1));
  ASSERT_EQ(jettons_of(*db, old_owner).size(), static_cast<size_t>(0));

  // Gone at lt 300; an older "present" verdict cannot bring it back.
  apply_jetton(*db, wallet, jetton_absent(), 300);
  apply_jetton(*db, wallet, jetton_present(wallet, old_owner, master, 250), 250);
  ASSERT_EQ(jettons_of(*db, old_owner).size(), static_cast<size_t>(0));
  ASSERT_EQ(jettons_of(*db, new_owner).size(), static_cast<size_t>(0));

  // A first verdict that finds the wallet absent still outranks an older one.
  auto other = token_address(5, 0x52);
  apply_jetton(*db, other, jetton_absent(), 500);
  apply_jetton(*db, other, jetton_present(other, old_owner, master, 400), 400);
  ASSERT_EQ(jettons_of(*db, old_owner).size(), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, RemovingAStaleJettonEntryKeepsAnotherWalletsEntry) {
  auto path = std::string("test-wallet-index-db-jetton-other");
  auto db = open_fresh_db(path);
  auto first = token_address(1, 0x53);
  auto second = token_address(2, 0x53);
  auto owner = token_address(3, 0x53);
  auto master = token_address(4, 0x53);

  // The master resolved the owner to `first`, then to `second`.
  apply_jetton(*db, first, jetton_present(first, owner, master, 100), 100);
  apply_jetton(*db, second, jetton_present(second, owner, master, 200), 200);
  // `first` stops verifying: the entry now names `second` and stays.
  apply_jetton(*db, first, jetton_absent(), 300);
  auto listed = jettons_of(*db, owner);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].second == second);

  // The same within one block, the new wallet's entry written first.
  auto third = token_address(5, 0x53);
  db->begin_batch().ensure();
  db->apply_jetton_verdict(third, jetton_present(third, owner, master, 400), 400).ensure();
  db->apply_jetton_verdict(second, jetton_absent(), 400).ensure();
  db->commit_batch().ensure();
  listed = jettons_of(*db, owner);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].second == third);
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnInconclusiveJettonCheckIsNotADisappearance) {
  auto path = std::string("test-wallet-index-db-jetton-inconclusive");
  auto db = open_fresh_db(path);
  auto wallet = token_address(1, 0x54);
  auto owner = token_address(2, 0x54);
  auto master = token_address(3, 0x54);
  using tos_wallet_index::JettonWalletCheck;
  using tos_wallet_index::TokenVerifyOutcome;
  auto check = [&](JettonWalletCheck result, uint64_t lt) {
    db->begin_batch().ensure();
    auto outcome = tos_wallet_index::record_jetton_wallet_check(
        *db, wallet, result, owner, master,
        result == JettonWalletCheck::Verified ? jetton_value(wallet, lt) : td::Ref<vm::Cell>{}, lt);
    db->commit_batch().ensure();
    return outcome;
  };

  ASSERT_TRUE(check(JettonWalletCheck::Verified, 100) == TokenVerifyOutcome::Done);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(1));
  ASSERT_TRUE(check(JettonWalletCheck::Indeterminate, 200) == TokenVerifyOutcome::Retry);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(1));
  ASSERT_TRUE(check(JettonWalletCheck::OtherShard, 300) == TokenVerifyOutcome::Unverifiable);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(1));
  td::Bits256 found_owner, found_master;
  ASSERT_TRUE(db->get_jetton_wallet(wallet, found_owner, found_master).move_as_ok());

  // An inconclusive check left no record that would outrank an older verdict.
  ASSERT_TRUE(check(JettonWalletCheck::Rejected, 150) == TokenVerifyOutcome::Done);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnOlderWalletVerdictNeverReplacesANewerPairDecision) {
  auto path = std::string("test-wallet-index-db-jetton-pair-order");
  auto db = open_fresh_db(path);
  auto wallet_a = token_address(1, 0x55);
  auto wallet_b = token_address(2, 0x55);
  auto owner = token_address(3, 0x55);
  auto master = token_address(4, 0x55);
  auto named = [&]() {
    auto listed = jettons_of(*db, owner);
    CHECK(listed.size() <= 1);
    return listed.empty() ? td::Bits256::zero() : listed[0].second;
  };

  // Across batches: A holds the pair at lt 100, B takes it at lt 200, then a
  // recovered block observes A at lt 150.
  apply_jetton(*db, wallet_a, jetton_present(wallet_a, owner, master, 100), 100);
  apply_jetton(*db, wallet_b, jetton_present(wallet_b, owner, master, 200), 200);
  apply_jetton(*db, wallet_a, jetton_present(wallet_a, owner, master, 150), 150);
  ASSERT_TRUE(named() == wallet_b);

  // Across a restart the decision still holds, for a claim and for a removal.
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  apply_jetton(*db, wallet_a, jetton_present(wallet_a, owner, master, 180), 180);
  ASSERT_TRUE(named() == wallet_b);
  apply_jetton(*db, wallet_a, jetton_absent(), 300);
  ASSERT_TRUE(named() == wallet_b);

  // B is removed at lt 400; an older observation of another wallet cannot
  // restore the pair, before or after a restart.
  apply_jetton(*db, wallet_b, jetton_absent(), 400);
  ASSERT_TRUE(named() == td::Bits256::zero());
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  auto wallet_c = token_address(5, 0x55);
  apply_jetton(*db, wallet_c, jetton_present(wallet_c, owner, master, 350), 350);
  ASSERT_TRUE(named() == td::Bits256::zero());

  // A newer observation decides the pair again.
  apply_jetton(*db, wallet_c, jetton_present(wallet_c, owner, master, 500), 500);
  ASSERT_TRUE(named() == wallet_c);
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnOlderWalletVerdictInTheSameBatchNeverReplacesANewerPairDecision) {
  auto path = std::string("test-wallet-index-db-jetton-pair-batch");
  auto db = open_fresh_db(path);
  auto wallet_a = token_address(1, 0x56);
  auto wallet_b = token_address(2, 0x56);
  auto owner = token_address(3, 0x56);
  auto master = token_address(4, 0x56);
  apply_jetton(*db, wallet_a, jetton_present(wallet_a, owner, master, 100), 100);

  // In one batch, B's newer claim is written first and A's older one second;
  // the older one must see the newer decision before it is committed.
  db->begin_batch().ensure();
  db->apply_jetton_verdict(wallet_b, jetton_present(wallet_b, owner, master, 200), 200).ensure();
  db->apply_jetton_verdict(wallet_a, jetton_present(wallet_a, owner, master, 150), 150).ensure();
  db->commit_batch().ensure();
  auto listed = jettons_of(*db, owner);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].second == wallet_b);

  // An older removal in the same batch as a newer claim leaves the claim.
  auto wallet_c = token_address(5, 0x56);
  db->begin_batch().ensure();
  db->apply_jetton_verdict(wallet_c, jetton_present(wallet_c, owner, master, 300), 300).ensure();
  db->apply_jetton_verdict(wallet_b, jetton_absent(), 250).ensure();
  db->commit_batch().ensure();
  listed = jettons_of(*db, owner);
  ASSERT_EQ(listed.size(), static_cast<size_t>(1));
  ASSERT_TRUE(listed[0].second == wallet_c);

  // A removal in the same batch before an older claim keeps the pair removed.
  db->begin_batch().ensure();
  db->apply_jetton_verdict(wallet_c, jetton_absent(), 600).ensure();
  db->apply_jetton_verdict(wallet_a, jetton_present(wallet_a, owner, master, 550), 550).ensure();
  db->commit_batch().ensure();
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, AnOlderReleaseNeverRewindsANewerPairRemoval) {
  auto path = std::string("test-wallet-index-db-jetton-pair-release");
  auto db = open_fresh_db(path);
  auto wallet_x = token_address(1, 0x57);
  auto wallet_w = token_address(2, 0x57);
  auto wallet_y = token_address(3, 0x57);
  auto owner = token_address(4, 0x57);
  auto master = token_address(5, 0x57);

  // X holds the pair and is removed at lt 300.
  apply_jetton(*db, wallet_x, jetton_present(wallet_x, owner, master, 100), 100);
  apply_jetton(*db, wallet_x, jetton_absent(), 300);
  // A recovered block observes W under the pair at lt 150 (too old to claim
  // it), then W gone at lt 200: W's release is older than the removal.
  apply_jetton(*db, wallet_w, jetton_present(wallet_w, owner, master, 150), 150);
  apply_jetton(*db, wallet_w, jetton_absent(), 200);
  // An observation of Y at lt 250 is still older than the removal at lt 300.
  apply_jetton(*db, wallet_y, jetton_present(wallet_y, owner, master, 250), 250);
  ASSERT_EQ(jettons_of(*db, owner).size(), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

namespace {

td::Ref<vm::Cell> empty_cell() {
  vm::CellBuilder cb;
  return cb.finalize();
}

tos::BlockIdExt worker_block_id(tos::BlockSeqno seqno) {
  return make_test_block_id(0, tos::shardIdAll, seqno, 0x61, 0x62);
}

// Leaves the process-wide index state as a fresh process would have it.
void reset_index_singletons() {
  tos::validator::reset_archive_retention_for_testing();
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(false);
  tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
  tos_wallet_index::stop_wc0_index_worker();
  tos_wallet_index::set_wc0_index_block_fetcher(nullptr);
  tos_wallet_index::set_wc0_index_fetch_timeout_for_testing(std::chrono::seconds(60));
  tos_wallet_index::set_wallet_index_db(nullptr);
  tos_wallet_index::set_wallet_index_unavailable("");
}

// Opens the index at `path` as the process-wide singleton, as a node start does.
tos_wallet_index::WalletIndexDb &install_db(const std::string &path) {
  auto r = tos_wallet_index::WalletIndexDb::open(path);
  r.ensure();
  tos_wallet_index::set_wallet_index_db(r.move_as_ok());
  return *tos_wallet_index::wallet_index_db();
}

using Producers = tos_wallet_index::Wc0IndexProducers;

bool run_active(tos_wallet_index::WalletIndexDb &db) {
  return db.indexing_run_active().move_as_ok();
}

template <class F>
bool eventually(F &&condition, std::chrono::milliseconds limit = std::chrono::milliseconds(10000)) {
  auto deadline = std::chrono::steady_clock::now() + limit;
  while (!condition()) {
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

// A fetcher whose reads the test answers, or holds unanswered.
struct TestFetcher {
  std::mutex mutex;
  std::vector<std::pair<tos::BlockIdExt, std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)>>> pending;
  std::atomic<int> calls{0};

  tos_wallet_index::Wc0IndexBlockFetcher fetcher() {
    return [this](const tos::BlockIdExt &id, bool,
                  std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
      std::lock_guard<std::mutex> guard(mutex);
      pending.emplace_back(id, std::move(done));
      calls++;
    };
  }
  // Answer every read asked so far with `answer`.
  void answer_all(const std::function<td::Result<tos_wallet_index::Wc0FetchedBlock>(const tos::BlockIdExt &)> &answer) {
    decltype(pending) taken;
    {
      std::lock_guard<std::mutex> guard(mutex);
      taken.swap(pending);
    }
    for (auto &p : taken) {
      p.second(answer(p.first));
    }
  }
};

}  // namespace

TEST(WalletIndexWorker, WithoutAnIndexNoWorkerStartsAndNoBlockIsHeld) {
  reset_index_singletons();
  ASSERT_TRUE(!tos_wallet_index::start_wc0_index_worker(false));
  auto block = empty_cell();
  auto state = empty_cell();
  // More than the queue holds and enough to fill the id list: with a worker
  // and nothing to mark into, every one would be kept and retried forever.
  for (tos::BlockSeqno seqno = 1; seqno <= 4200; ++seqno) {
    tos_wallet_index::enqueue_wc0_index_block(block, state, worker_block_id(seqno));
  }
  ASSERT_EQ(block->get_refcnt(), 1);
  ASSERT_EQ(state->get_refcnt(), 1);
  ASSERT_TRUE(!tos_wallet_index::wc0_index_degraded());
  reset_index_singletons();
}

TEST(WalletIndexWorker, AnIndexThatFailsToOpenIsReportedUnavailable) {
  reset_index_singletons();
  // A regular file where the database directory's parent should be.
  auto root = std::string("test-wallet-index-root-is-a-file");
  td::rmrf(root).ignore();
  td::write_file(root, "not a directory").ensure();
  ASSERT_TRUE(!tos_wallet_index::open_wallet_index_db(root));
  ASSERT_TRUE(tos_wallet_index::wallet_index_db() == nullptr);
  ASSERT_TRUE(!tos_wallet_index::wallet_index_unavailable_reason().empty());
  ASSERT_TRUE(!tos_wallet_index::start_wc0_index_worker(true));
  td::unlink(root).ignore();
  reset_index_singletons();
}

// A block whose apply was persisted but which the recorder never marked (the
// process stopped first) leaves no trace in the index itself; only the run
// marker can tell the next start that the index may be missing it.
TEST(WalletIndexWorker, AStopBeforeABlockIsMarkedKeepsTheIndexIncomplete) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-unclean-stop");
  td::rmrf(path).ignore();
  {
    auto &db = install_db(path);
    ASSERT_TRUE(!run_active(db));
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(run_active(db));
    // The disk refuses the recorder's writes, so the block is never marked and
    // its loss cannot be recorded either; then the process stops without the
    // exit flush.
    tos_wallet_index::set_wc0_index_marking_fault_for_testing(true);
    tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(7));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wc0_index_marking_fault_for_testing(false);
    ASSERT_TRUE(!db.has_incomplete_block(worker_block_id(7)).move_as_ok());
    ASSERT_TRUE(!backlog_stats(db).needs_rebuild);
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.needs_rebuild);
    ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

TEST(WalletIndexWorker, ACleanFinishClearsTheRunAndNeedsNoRebuild) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-clean-stop");
  td::rmrf(path).ignore();
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(8));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    ASSERT_TRUE(!run_active(db));
    ASSERT_TRUE(db.has_incomplete_block(worker_block_id(8)).move_as_ok());
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    ASSERT_TRUE(!backlog_stats(db).needs_rebuild);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

TEST(WalletIndexWorker, AFlushThatCouldNotMarkEveryBlockLeavesTheRunUnfinished) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-flush-fails");
  td::rmrf(path).ignore();
  auto &db = install_db(path);
  ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(true);
  tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(10));
  ASSERT_TRUE(!tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced, std::chrono::milliseconds(200)));
  ASSERT_TRUE(run_active(db));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

TEST(WalletIndexWorker, AFlushAfterALostBlockLeavesTheRunUnfinished) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-flush-degraded");
  td::rmrf(path).ignore();
  auto &db = install_db(path);
  ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
  // While marking fails, more ids arrive than the list keeps: one is lost.
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(true);
  for (tos::BlockSeqno seqno = 1;
       seqno <= static_cast<tos::BlockSeqno>(16 * tos_wallet_index::kWc0IndexQueueCapacity + 1); ++seqno) {
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, td::Ref<vm::Cell>{}, worker_block_id(seqno));
  }
  ASSERT_TRUE(tos_wallet_index::wc0_index_degraded());
  // The disk recovers, so every remaining id is marked in time.
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(false);
  ASSERT_TRUE(!tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced, std::chrono::milliseconds(10000)));
  ASSERT_TRUE(run_active(db));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// While blocks can still be applied, the exit flush leaves the run active: a
// block applied after it whose mark and rebuild record both fail is then still
// covered by the run marker.
TEST(WalletIndexWorker, AFlushWhileBlocksMayStillApplyLeavesTheRunActive) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-flush-producers-active");
  td::rmrf(path).ignore();
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    ASSERT_TRUE(!tos_wallet_index::flush_wc0_index_for_exit(Producers::MayStillApply));
    ASSERT_TRUE(run_active(db));
    // A block applied after the flush is still marked, by the recorder.
    tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(9));
    ASSERT_TRUE(eventually([&] { return db.has_incomplete_block(worker_block_id(9)).move_as_ok(); }));
    // The next one can be neither marked nor recorded as lost.
    tos_wallet_index::set_wc0_index_marking_fault_for_testing(true);
    tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(11));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wc0_index_marking_fault_for_testing(false);
    ASSERT_TRUE(!db.has_incomplete_block(worker_block_id(11)).move_as_ok());
    ASSERT_TRUE(!backlog_stats(db).needs_rebuild);
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.needs_rebuild);
    ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// A block handed over without its data is read by the worker. A read that
// fails, or finds nothing, leaves the block marked for recovery through a
// clean exit.
TEST(WalletIndexWorker, ABlockWhoseDataCouldNotBeFetchedStaysMarked) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-unreadable-block");
  td::rmrf(path).ignore();
  TestFetcher reads;
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_block_fetcher(reads.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, empty_cell(), worker_block_id(12));
    ASSERT_TRUE(eventually([&] { return reads.calls.load() == 1; }));
    reads.answer_all([](const tos::BlockIdExt &) -> td::Result<tos_wallet_index::Wc0FetchedBlock> {
      return td::Status::Error("not found");
    });
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, empty_cell(), worker_block_id(13));
    ASSERT_TRUE(eventually([&] { return reads.calls.load() == 2; }));
    reads.answer_all([](const tos::BlockIdExt &) -> td::Result<tos_wallet_index::Wc0FetchedBlock> {
      return tos_wallet_index::Wc0FetchedBlock{};
    });
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    ASSERT_TRUE(!run_active(db));
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(db.has_incomplete_block(worker_block_id(12)).move_as_ok());
    ASSERT_TRUE(db.has_incomplete_block(worker_block_id(13)).move_as_ok());
    ASSERT_TRUE(backlog_stats(db).unfinished_block);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The hook takes only a lock nothing holds across I/O: neither a stalled
// recorder (its WAL sync hanging) nor an exit flush waiting on that recorder
// holds it up.
TEST(WalletIndexWorker, TheHookNeverWaitsForAStalledRecorderOrAWaitingFlush) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-hook-never-waits");
  td::rmrf(path).ignore();
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    auto handed_over_within = [](tos::BlockSeqno seqno, std::chrono::milliseconds limit) {
      std::atomic<bool> returned{false};
      std::thread producer([&] {
        tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(seqno));
        returned = true;
      });
      bool in_time = eventually([&] { return returned.load(); }, limit);
      if (!in_time) {
        // Let the stuck producer go before failing.
        tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
      }
      producer.join();
      return in_time;
    };
    ASSERT_TRUE(handed_over_within(20, std::chrono::milliseconds(500)));
    std::atomic<bool> flushed{true};
    std::thread flusher(
        [&] { flushed = tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced, std::chrono::seconds(20)); });
    // Let the flush take the lifecycle lock and start waiting on the stalled
    // recorder.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(handed_over_within(21, std::chrono::milliseconds(500)));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    flusher.join();
    // A block arrived after the queue was closed: the run is not finished.
    ASSERT_TRUE(!flushed.load());
    ASSERT_TRUE(eventually([&] {
      return db.has_incomplete_block(worker_block_id(20)).move_as_ok() &&
             db.has_incomplete_block(worker_block_id(21)).move_as_ok();
    }));
    ASSERT_TRUE(run_active(db));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.needs_rebuild);
    ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// A producer that should no longer exist hands a block over after the exit
// flush recorded the run as finished. The hook still does not write; the
// recorder records the run as active again, then marks the block, and the
// next start does not report the index complete.
TEST(WalletIndexWorker, ABlockAfterACleanFlushRecordsTheRunAsActiveAgain) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-late-block");
  td::rmrf(path).ignore();
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    ASSERT_TRUE(!run_active(db));
    tos_wallet_index::enqueue_wc0_index_block(empty_cell(), empty_cell(), worker_block_id(30));
    ASSERT_TRUE(eventually([&] { return run_active(db); }));
    ASSERT_TRUE(eventually([&] { return db.has_incomplete_block(worker_block_id(30)).move_as_ok(); }));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.needs_rebuild);
    ASSERT_TRUE(stats.unfinished_block);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Blocks the worker had no room for, and the block whose read it was waiting
// on, are all marked; a crash then (no exit flush) never leaves an index the
// next start reports complete.
TEST(WalletIndexWorker, ACrashWithAFullQueueNeverReportsCompleteness) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-full-queue-crash");
  td::rmrf(path).ignore();
  TestFetcher reads;
  const auto total = static_cast<tos::BlockSeqno>(tos_wallet_index::kWc0IndexQueueCapacity + 4);
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_block_fetcher(reads.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    // The first block's read never answers: the worker holds it, and the
    // queue fills behind it.
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, empty_cell(), worker_block_id(1));
    ASSERT_TRUE(eventually([&] { return reads.calls.load() == 1; }));
    for (tos::BlockSeqno seqno = 2; seqno <= total; ++seqno) {
      tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, empty_cell(), worker_block_id(seqno));
    }
    ASSERT_TRUE(eventually([&] { return db.has_incomplete_block(worker_block_id(total)).move_as_ok(); }));
    // The process dies: no exit flush.
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    for (tos::BlockSeqno seqno = 1; seqno <= total; ++seqno) {
      ASSERT_TRUE(db.has_incomplete_block(worker_block_id(seqno)).move_as_ok());
    }
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.needs_rebuild);
    ASSERT_TRUE(stats.unfinished_block);
    ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The run is durably recorded as active before any block can be handed over:
// when that record cannot be written, no producer is ever accepted.
TEST(WalletIndexWorker, NoBlockIsAcceptedBeforeTheRunIsRecorded) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-run-before-producers");
  td::rmrf(path).ignore();
  install_db(path);
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(true);
  ASSERT_TRUE(!tos_wallet_index::start_wc0_index_worker(false));
  tos_wallet_index::set_wc0_index_marking_fault_for_testing(false);
  auto block = empty_cell();
  tos_wallet_index::enqueue_wc0_index_block(block, empty_cell(), worker_block_id(40));
  // Nothing took the block: no queue holds it.
  ASSERT_EQ(block->get_refcnt(), 1);
  ASSERT_TRUE(tos_wallet_index::wallet_index_db() == nullptr);
  ASSERT_TRUE(!tos_wallet_index::wallet_index_unavailable_reason().empty());
  reset_index_singletons();
  td::rmrf(path).ignore();
}

namespace {

constexpr uint32_t kJettonTransferOp = 0x0f8a7ea5;

// A real block in which `count` distinct accounts each receive a jetton
// transfer, so each is nominated as a jetton-wallet candidate. None of them
// is a contract in `state`, so each verification is definite (the wallet is
// absent) and leaves a wallet record behind.
struct OverflowingBlock {
  tos::BlockIdExt id;
  td::Ref<vm::Cell> root;
  td::Ref<vm::Cell> state;
  std::vector<td::Bits256> wallets;  // in candidate order
};

OverflowingBlock overflowing_block(tos::BlockSeqno seqno, size_t count, uint32_t first = 0, uint64_t end_lt = 5000) {
  OverflowingBlock block;
  block.id = worker_block_id(seqno);
  std::vector<wallet_index_fixture::Tx> txs;
  std::set<td::Bits256> wallets;
  for (size_t i = 0; i < count; ++i) {
    auto account = token_address(static_cast<uint32_t>(first + i), static_cast<uint8_t>(0x10 + i % 64));
    txs.push_back(wallet_index_fixture::Tx{account, 10 + i, kJettonTransferOp});
    wallets.insert(account);
  }
  block.root = wallet_index_fixture::block(seqno, end_lt, 1000, txs);
  block.state = wallet_index_fixture::shard_state({});
  block.wallets.assign(wallets.begin(), wallets.end());
  return block;
}

struct IndexView {
  tos_wallet_index::TokenBacklogStats stats;
  bool complete;
  bool final_processed;
};

// Completeness and whether the block's last candidate was verified, from one
// snapshot, so the two cannot straddle a commit.
IndexView view_of(tos_wallet_index::WalletIndexDb &db, const OverflowingBlock &block) {
  auto snapshot = tos_wallet_index::WalletIndexSnapshot::of(db).move_as_ok();
  IndexView view;
  view.stats = snapshot.token_backlog_stats().move_as_ok();
  view.complete = tos_wallet_index::format_token_index_state(view.stats).find("\"complete\":true") != std::string::npos;
  view.final_processed = snapshot.has_jetton_wallet_record(block.wallets.back()).move_as_ok();
  return view;
}

size_t processed_count(tos_wallet_index::WalletIndexDb &db, const OverflowingBlock &block) {
  size_t n = 0;
  for (const auto &wallet : block.wallets) {
    n += db.has_jetton_wallet_record(wallet).move_as_ok() ? 1 : 0;
  }
  return n;
}

// Polls until the index reports itself complete, failing if it ever does so
// while the block's last candidate is still unverified.
bool complete_only_after_the_final_candidate(tos_wallet_index::WalletIndexDb &db, const OverflowingBlock &block,
                                             std::chrono::milliseconds limit) {
  auto deadline = std::chrono::steady_clock::now() + limit;
  while (std::chrono::steady_clock::now() < deadline) {
    auto view = view_of(db, block);
    if (view.complete) {
      return view.final_processed;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return false;
}

// A block fetcher for a node whose archive has pruned everything: every read
// fails.
struct PrunedArchive {
  std::atomic<int> calls{0};
  tos_wallet_index::Wc0IndexBlockFetcher fetcher() {
    return
        [this](const tos::BlockIdExt &, bool, std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
          calls++;
          done(td::Status::Error("pruned"));
        };
  }
};

// The node's newest state, as the state fetcher reports it; the test can
// replace it, as new blocks would.
struct NewestState {
  std::mutex mutex;
  tos_wallet_index::Wc0NewestState state;
  std::atomic<int> calls{0};
  void set(tos::BlockSeqno seqno, uint64_t end_lt, td::Ref<vm::Cell> root) {
    std::lock_guard<std::mutex> lock(mutex);
    state = tos_wallet_index::Wc0NewestState{worker_block_id(seqno), end_lt, std::move(root)};
  }
  tos_wallet_index::Wc0IndexStateFetcher fetcher() {
    return [this](const td::Bits256 &, std::function<void(td::Result<tos_wallet_index::Wc0NewestState>)> done) {
      calls++;
      tos_wallet_index::Wc0NewestState answer;
      {
        std::lock_guard<std::mutex> lock(mutex);
        answer = state;
      }
      done(std::move(answer));
    };
  }
};

std::vector<wallet_index_fixture::Contract> codeless(const OverflowingBlock &block) {
  std::vector<wallet_index_fixture::Contract> out;
  for (const auto &wallet : block.wallets) {
    out.push_back(wallet_index_fixture::without_code(wallet));
  }
  return out;
}

}  // namespace

// One block nominates more candidates than the per-block bound and the
// backlog together can take. Nothing is dropped or counted as lost: what does
// not fit is persisted with the block, the backlog drains with no new block,
// the rest is verified, and the index reports itself complete only after
// every candidate of the block is verified.
TEST(WalletIndexWorker, AnOverflowingBlockIsFinishedAndOnlyThenComplete) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-overflow-resume");
  td::rmrf(path).ignore();
  auto block = overflowing_block(5, kMaxTokenCandidatesPerBlock + 40);
  {
    auto &db = install_db(path);
    // Room for 16 of the block's 40 deferrals.
    db.set_token_backlog_limit(16);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(block.root, block.state, block.id);
    // Once the recorder has marked the block, the index is incomplete until
    // the block is finished.
    ASSERT_TRUE(eventually([&] { return !view_of(db, block).complete || view_of(db, block).final_processed; }));
    ASSERT_TRUE(complete_only_after_the_final_candidate(db, block, std::chrono::seconds(60)));
    ASSERT_EQ(processed_count(db, block), block.wallets.size());
    ASSERT_TRUE(!db.has_incomplete_block(block.id).move_as_ok());
    ASSERT_TRUE(!db.get_pending_block(block.id).move_as_ok());
    auto stats = backlog_stats(db);
    ASSERT_EQ(stats.lost + stats.parked + stats.entries, static_cast<uint64_t>(0));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The node stops while a block's overflow is still waiting, with the backlog
// full. While it is down the archive prunes the block and its state. After
// the restart no block arrives and nothing nominates the candidates again,
// yet every one of them is verified, against the node's newest state, and
// only then is the index complete.
TEST(WalletIndexWorker, AnOverflowSurvivesRestartAndPruningWithNoLaterBlock) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-overflow-restart");
  td::rmrf(path).ignore();
  auto block = overflowing_block(6, kMaxTokenCandidatesPerBlock + 40);
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    // Indexed as startup recovery does, synchronously and with no worker.
    tos_wallet_index::wc0_index_block(block.root, block.state, block.id);
    auto view = view_of(db, block);
    ASSERT_TRUE(!view.complete);
    ASSERT_TRUE(!view.final_processed);
    ASSERT_EQ(view.stats.entries, static_cast<uint64_t>(16));
    ASSERT_EQ(view.stats.lost, static_cast<uint64_t>(0));
    ASSERT_TRUE(db.has_incomplete_block(block.id).move_as_ok());
    // The candidates that found no room are persisted, not a pointer into
    // the block.
    auto pending = db.get_pending_block(block.id).move_as_ok();
    ASSERT_TRUE(static_cast<bool>(pending));
    ASSERT_EQ(pending.value().remaining.size(), static_cast<size_t>(24));
    ASSERT_TRUE(pending.value().remaining.back().candidate.address == block.wallets.back());
    // The process stops here.
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  PrunedArchive archive;
  NewestState newest;
  // The chain moved on: the node's newest state is a later block's.
  newest.set(90, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    // The restarted node allows no more than the 16 already waiting.
    db.set_token_backlog_limit(16);
    ASSERT_TRUE(!db.token_backlog_has_room().move_as_ok());
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(complete_only_after_the_final_candidate(db, block, std::chrono::seconds(60)));
    ASSERT_EQ(processed_count(db, block), block.wallets.size());
    ASSERT_TRUE(!db.has_incomplete_block(block.id).move_as_ok());
    ASSERT_TRUE(!db.get_pending_block(block.id).move_as_ok());
    ASSERT_TRUE(newest.calls.load() >= 1);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The index holds no more unfinished blocks than its bound: the worker
// finishes one before it indexes the next.
TEST(WalletIndexWorker, UnfinishedBlocksAreBounded) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-overflow-bound");
  td::rmrf(path).ignore();
  auto first = overflowing_block(7, kMaxTokenCandidatesPerBlock + 40);
  auto second = overflowing_block(8, kMaxTokenCandidatesPerBlock + 40, 5000, 5100);
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(1);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    tos_wallet_index::enqueue_wc0_index_block(first.root, first.state, first.id);
    tos_wallet_index::enqueue_wc0_index_block(second.root, second.state, second.id);
    tos_wallet_index::resume_wc0_index_worker();
    uint64_t most = 0;
    ASSERT_TRUE(eventually(
        [&] {
          most = std::max(most, db.pending_block_count().move_as_ok());
          return processed_count(db, second) == second.wallets.size() &&
                 !db.has_incomplete_block(second.id).move_as_ok();
        },
        std::chrono::seconds(60)));
    ASSERT_TRUE(most <= 1);
    ASSERT_EQ(processed_count(db, first), first.wallets.size());
  }
  tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(tos_wallet_index::kMaxPendingTokenBlocks);
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Every candidate of a block fails to verify through all its attempts (the
// node cannot run its code) and is parked, its identity kept. Parked
// candidates fill more than the backlog, yet another block's overflow is
// still finished. After a restart, still with no new block and no new
// nomination, the worker retries the parked candidates against the node's
// newest state; once that state can decide them, each is verified and the
// index becomes complete.
TEST(WalletIndexWorker, ParkedCandidatesAreRetriedWithoutANewNomination) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-parked-retry");
  td::rmrf(path).ignore();
  auto failing = overflowing_block(9, kMaxTokenCandidatesPerBlock + 40);
  // Its state holds every wallet without code: no verification can finish.
  failing.state = wallet_index_fixture::shard_state(codeless(failing));
  auto other = overflowing_block(10, kMaxTokenCandidatesPerBlock + 40, 5000, 5500);
  other.state = failing.state;
  NewestState newest;
  newest.set(10, 5500, failing.state);
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds(0));
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(failing.root, failing.state, failing.id);
    ASSERT_TRUE(
        eventually([&] { return backlog_stats(db).parked == failing.wallets.size(); }, std::chrono::seconds(60)));
    auto stats = backlog_stats(db);
    ASSERT_TRUE(stats.parked > 16);
    ASSERT_EQ(stats.lost, static_cast<uint64_t>(0));
    ASSERT_EQ(processed_count(db, failing), static_cast<size_t>(0));
    // Another block overflows while the parked candidates exceed the backlog
    // bound: it is still finished.
    tos_wallet_index::enqueue_wc0_index_block(other.root, other.state, other.id);
    ASSERT_TRUE(eventually(
        [&] {
          return processed_count(db, other) == other.wallets.size() && !db.has_incomplete_block(other.id).move_as_ok();
        },
        std::chrono::seconds(60)));
    ASSERT_EQ(backlog_stats(db).parked, failing.wallets.size());
    // A clean stop: only the parked candidates keep the index incomplete.
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    // Restarted, the node can still not decide them: they stay parked and
    // the index incomplete.
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] { return newest.calls.load() >= 2; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto stats = backlog_stats(db);
    ASSERT_EQ(stats.parked, failing.wallets.size());
    ASSERT_TRUE(tos_wallet_index::format_token_index_state(stats).find("\"complete\":false") != std::string::npos);
    // The chain moves on to a state that decides them (the wallets are gone).
    newest.set(11, 9000, wallet_index_fixture::shard_state({}));
    ASSERT_TRUE(eventually([&] { return backlog_stats(db).parked == 0; }, std::chrono::seconds(60)));
    ASSERT_EQ(processed_count(db, failing), failing.wallets.size());
    bool complete = eventually([&] {
      return tos_wallet_index::format_token_index_state(backlog_stats(db)).find("\"complete\":true") !=
             std::string::npos;
    });
    if (!complete) {
      LOG(ERROR) << "index state: " << tos_wallet_index::format_token_index_state(backlog_stats(db));
    }
    ASSERT_TRUE(complete);
  }
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::minutes(10));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// With no parking room left, a candidate that exhausts its attempts waits in
// its queue again, identity kept, instead of being given up.
TEST(WalletIndex, ACandidateWithNoParkingRoomWaitsInItsQueue) {
  using tos_wallet_index::kMaxTokenCandidateAttempts;
  auto path = std::string("test-wallet-index-db-parked-bound");
  auto db = open_fresh_db(path);
  db->set_parked_token_limit(1);
  auto block = token_candidates(0, 2);
  std::vector<TokenCandidate> next_block = block;
  for (uint8_t attempt = 0; attempt < kMaxTokenCandidateAttempts; ++attempt) {
    db->begin_batch().ensure();
    auto chosen =
        db->schedule_token_candidates(next_block, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok();
    ASSERT_EQ(chosen.size(), static_cast<size_t>(2));
    for (auto &c : chosen) {
      db->retry_token_candidate(c).ensure();
    }
    db->commit_batch().ensure();
    next_block.clear();
  }
  auto stats = backlog_stats(*db);
  ASSERT_EQ(stats.parked, static_cast<uint64_t>(1));
  ASSERT_EQ(stats.entries, static_cast<uint64_t>(1));
  ASSERT_EQ(stats.lost, static_cast<uint64_t>(0));
  // It keeps coming back with one attempt left.
  db->begin_batch().ensure();
  auto chosen = db->schedule_token_candidates({}, kWholeBasechain, kMaxTokenCandidatesPerBlock, kTestLt).move_as_ok();
  ASSERT_EQ(chosen.size(), static_cast<size_t>(1));
  ASSERT_EQ(chosen[0].attempts, static_cast<uint8_t>(kMaxTokenCandidateAttempts - 1));
  db->commit_batch().ensure();
  td::rmrf(path).ignore();
}

// A backlog pass against an older state leaves a candidate a newer block
// nominated: it waits for a state at least that new.
TEST(WalletIndex, AnOlderStateNeverTakesANewerNomination) {
  auto path = std::string("test-wallet-index-db-token-lt-order");
  auto db = open_fresh_db(path);
  auto block = token_candidates(0, 3);
  ASSERT_TRUE(schedule_block(*db, block, kWholeBasechain, 0, 2000).empty());
  ASSERT_TRUE(schedule_block(*db, {}, kWholeBasechain, kMaxTokenCandidatesPerBlock, 1000).empty());
  ASSERT_EQ(backlog_size(*db), block.size());
  // An older block nominating one of them verifies it itself but leaves the
  // newer nomination waiting.
  auto older = schedule_block(*db, {block[0]}, kWholeBasechain, kMaxTokenCandidatesPerBlock, 1500);
  ASSERT_EQ(candidates_of(older), std::set<TokenCandidate>{block[0]});
  ASSERT_EQ(backlog_size(*db), block.size());
  auto newer = schedule_block(*db, {}, kWholeBasechain, kMaxTokenCandidatesPerBlock, 2000);
  ASSERT_EQ(candidates_of(newer), std::set<TokenCandidate>(block.begin(), block.end()));
  ASSERT_EQ(backlog_size(*db), static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

namespace {

constexpr uint32_t kNftTransferOp = 0x5fcc3d14;
const tos::ShardId kLeftShard = 0x4000000000000000ULL;
const tos::ShardId kRightShard = 0xC000000000000000ULL;

tos::BlockIdExt shard_block_id(tos::ShardId shard, tos::BlockSeqno seqno) {
  return make_test_block_id(0, shard, seqno, 0x51, 0x52);
}

// The node's newest state of each basechain half, either of which the test
// can make unavailable or replace.
struct HalvesState {
  std::mutex mutex;
  td::Ref<vm::Cell> left, right;
  uint64_t left_lt = 0, right_lt = 0;
  std::atomic<int> calls{0};
  void set(bool right_half, td::Ref<vm::Cell> state, uint64_t end_lt) {
    std::lock_guard<std::mutex> lock(mutex);
    (right_half ? right : left) = std::move(state);
    (right_half ? right_lt : left_lt) = end_lt;
  }
  tos_wallet_index::Wc0IndexStateFetcher fetcher() {
    return [this](const td::Bits256 &address, std::function<void(td::Result<tos_wallet_index::Wc0NewestState>)> done) {
      calls++;
      bool right_half = (address.data()[0] & 0x80) != 0;
      td::Ref<vm::Cell> state;
      uint64_t end_lt = 0;
      {
        std::lock_guard<std::mutex> lock(mutex);
        state = right_half ? right : left;
        end_lt = right_half ? right_lt : left_lt;
      }
      if (state.is_null()) {
        done(td::Status::Error("this shard's state is not available"));
        return;
      }
      done(tos_wallet_index::Wc0NewestState{shard_block_id(right_half ? kRightShard : kLeftShard, 900), end_lt, state});
    };
  }
};

// An archive of blocks, each with its generation time, pruned the way the
// node's archive is: by archive_packages_to_delete, honouring the floor the
// index publishes.
struct FakeArchive {
  struct Stored {
    td::Ref<vm::Cell> root;
    uint32_t gen_utime;
  };
  std::mutex mutex;
  std::map<tos::BlockIdExt, Stored> blocks;
  void add(const tos::BlockIdExt &id, td::Ref<vm::Cell> root, uint32_t gen_utime) {
    std::lock_guard<std::mutex> lock(mutex);
    blocks[id] = Stored{std::move(root), gen_utime};
  }
  // Prunes as at `gc_ts` with `ttl`, through the node's own admission;
  // returns how many blocks went. `after_admission` runs once, after the
  // first deletion is admitted and before it is carried out; `before_admission`
  // before each admission.
  size_t prune(double gc_ts, double ttl, uint32_t floor, std::function<void()> after_admission = nullptr,
               std::function<void()> before_admission = nullptr) {
    std::unique_lock<std::mutex> lock(mutex);
    std::vector<std::pair<uint32_t, tos::BlockIdExt>> order;
    for (auto &entry : blocks) {
      order.emplace_back(entry.second.gen_utime, entry.first);
    }
    std::sort(order.begin(), order.end());
    std::vector<double> first_ts;
    for (auto &entry : order) {
      first_ts.push_back(entry.first);
    }
    (void)floor;
    return tos::validator::prune_archive_packages(
        first_ts, gc_ts, ttl,
        [&](size_t index) {
          if (after_admission) {
            lock.unlock();
            after_admission();
            after_admission = nullptr;
            lock.lock();
          }
          blocks.erase(order[index].second);
        },
        [&](size_t) {
          if (before_admission) {
            lock.unlock();
            before_admission();
            before_admission = nullptr;
            lock.lock();
          }
        });
  }
  bool has(const tos::BlockIdExt &id) {
    std::lock_guard<std::mutex> lock(mutex);
    return blocks.count(id) != 0;
  }
  tos_wallet_index::Wc0IndexBlockFetcher fetcher() {
    return [this](const tos::BlockIdExt &id, bool,
                  std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
      td::Ref<vm::Cell> root;
      {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = blocks.find(id);
        if (it != blocks.end()) {
          root = it->second.root;
        }
      }
      if (root.is_null()) {
        done(td::Status::Error("pruned"));
        return;
      }
      // The block's own state is long gone; its candidates wait for a newer one.
      done(tos_wallet_index::Wc0FetchedBlock{root, {}});
    };
  }
};

std::string complete_flag(tos_wallet_index::WalletIndexDb &db) {
  return tos_wallet_index::format_token_index_state(backlog_stats(db));
}

bool is_complete(tos_wallet_index::WalletIndexDb &db) {
  return complete_flag(db).find("\"complete\":true") != std::string::npos;
}

}  // namespace

TEST(WalletIndex, ArchivePruningHonoursTheIndexFloor) {
  using tos::validator::archive_packages_to_delete;
  using tos::validator::kNoArchiveGcFloor;
  std::vector<double> first_ts = {100, 200, 300, 400, 500};
  // TTL alone: everything before 450 qualifies; the newest of those stays.
  ASSERT_EQ(archive_packages_to_delete(first_ts, 550, 100, kNoArchiveGcFloor), (std::vector<size_t>{0, 1, 2}));
  // A floor at 250 keeps every package that may hold a block from 250 on.
  ASSERT_EQ(archive_packages_to_delete(first_ts, 550, 100, 250), (std::vector<size_t>{0}));
  ASSERT_TRUE(archive_packages_to_delete(first_ts, 550, 100, 150).empty());
}

// A jetton wallet whose master, and an NFT item whose collection, live in the
// other half of the basechain. The block's own shard state cannot verify
// them, and the other half's state is not available at first: both are kept,
// parked with their identity. Once that state is available, the worker
// verifies both, with no further block or nomination.
TEST(WalletIndexWorker, CrossShardCandidatesAreKeptThenVerified) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-cross-shard");
  td::rmrf(path).ignore();
  auto owner = token_address(1, 0x10);
  auto wallet = token_address(2, 0x11);      // left
  auto master = token_address(3, 0x91);      // right
  auto item = token_address(4, 0x12);        // left
  auto collection = token_address(5, 0x92);  // right
  auto left_state = wallet_index_fixture::shard_state({wallet_index_fixture::jetton_wallet(wallet, owner, master),
                                                       wallet_index_fixture::nft_item(item, collection, owner)});
  auto right_state = wallet_index_fixture::shard_state(
      {wallet_index_fixture::jetton_master(master, wallet), wallet_index_fixture::nft_collection(collection, item)});
  auto root =
      wallet_index_fixture::block(20, 5000, 1000, {{wallet, 10, kJettonTransferOp}, {item, 11, kNftTransferOp}});
  HalvesState newest;
  newest.set(false, left_state, 6000);
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds(0));
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(root, left_state, shard_block_id(kLeftShard, 20), 1000);
    ASSERT_TRUE(eventually([&] { return backlog_stats(db).parked == 2; }));
    ASSERT_TRUE(!is_complete(db));
    ASSERT_TRUE(jettons_of(db, owner).empty());
    td::Bits256 recorded_owner;
    ASSERT_TRUE(!db.get_nft_owner(item, recorded_owner).move_as_ok());
    // The other half's state becomes available.
    newest.set(true, right_state, 6000);
    ASSERT_TRUE(eventually([&] { return backlog_stats(db).parked == 0; }, std::chrono::seconds(30)));
    ASSERT_EQ(jettons_of(db, owner), (std::vector<std::pair<td::Bits256, td::Bits256>>{{master, wallet}}));
    ASSERT_TRUE(db.get_nft_owner(item, recorded_owner).move_as_ok());
    ASSERT_TRUE(recorded_owner == owner);
    ASSERT_TRUE(eventually([&] { return is_complete(db); }));
  }
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::minutes(10));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Parked candidates and an unfinished block in each half. The left half can
// never progress (its candidates stay indeterminate; its newest state is older
// than its unfinished block); the right half can. Across a restart and with
// no new block, the right half's work completes while the left half's stays
// kept and the index incomplete.
TEST(WalletIndexWorker, AShardThatCannotProgressDoesNotHoldUpAnother) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-rotation");
  td::rmrf(path).ignore();
  std::vector<td::Bits256> left_parked, right_parked, left_pending, right_pending;
  for (uint32_t i = 0; i < 8; ++i) {
    left_parked.push_back(token_address(100 + i, 0x05));
    right_parked.push_back(token_address(200 + i, 0x85));
    left_pending.push_back(token_address(300 + i, 0x06));
    right_pending.push_back(token_address(400 + i, 0x86));
  }
  auto left_block = shard_block_id(kLeftShard, 30);
  auto right_block = shard_block_id(kRightShard, 31);
  {
    auto &db = install_db(path);
    db.begin_batch().ensure();
    db.begin_token_pass().ensure();
    for (auto &address : left_parked) {
      ASSERT_TRUE(db.park_token_candidate({{TokenKind::Jetton, address}, 0, 100}).move_as_ok());
    }
    for (auto &address : right_parked) {
      ASSERT_TRUE(db.park_token_candidate({{TokenKind::Jetton, address}, 0, 100}).move_as_ok());
    }
    tos_wallet_index::WalletIndexDb::PendingBlock left_pending_block, right_pending_block;
    left_pending_block.end_lt = 9000;
    for (auto &address : left_pending) {
      left_pending_block.remaining.push_back({{TokenKind::Jetton, address}, 0, 9000});
    }
    right_pending_block.end_lt = 5000;
    for (auto &address : right_pending) {
      right_pending_block.remaining.push_back({{TokenKind::Jetton, address}, 0, 5000});
    }
    db.put_pending_block(left_block, left_pending_block).ensure();
    db.put_pending_block(right_block, right_pending_block).ensure();
    db.save_token_counters().ensure();
    db.commit_batch().ensure();
    db.put_incomplete_block(left_block, 1000).ensure();
    db.put_incomplete_block(right_block, 1000).ensure();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  std::vector<wallet_index_fixture::Contract> codeless_left;
  for (auto &address : left_parked) {
    codeless_left.push_back(wallet_index_fixture::without_code(address));
  }
  HalvesState newest;
  // The left half's newest state is older than its unfinished block, and
  // runs no code for its parked wallets; the right half's is unavailable for
  // now.
  newest.set(false, wallet_index_fixture::shard_state(codeless_left), 5000);
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds(0));
  auto right_done = [&](tos_wallet_index::WalletIndexDb &db) {
    for (auto &address : right_parked) {
      if (!db.has_jetton_wallet_record(address).move_as_ok()) {
        return false;
      }
    }
    for (auto &address : right_pending) {
      if (!db.has_jetton_wallet_record(address).move_as_ok()) {
        return false;
      }
    }
    return !db.has_incomplete_block(right_block).move_as_ok();
  };
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] { return newest.calls.load() >= 4; }));
    ASSERT_TRUE(!right_done(db));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  // After a restart the right half's state is available.
  newest.set(true, wallet_index_fixture::shard_state({}), 6000);
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] { return right_done(db); }, std::chrono::seconds(30)));
    // The left half's work is all still kept.
    ASSERT_EQ(backlog_stats(db).parked, left_parked.size());
    auto left_left = db.get_pending_block(left_block).move_as_ok();
    ASSERT_TRUE(static_cast<bool>(left_left));
    ASSERT_EQ(left_left.value().remaining.size(), left_pending.size());
    ASSERT_TRUE(db.has_incomplete_block(left_block).move_as_ok());
    ASSERT_TRUE(!is_complete(db));
  }
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::minutes(10));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The backlog queue and parking are both full while candidates keep failing.
// No transition overfills either: a backlog entry goes back only into the
// slot it kept, a block's own candidate that cannot be queued or parked stays
// with its block, and a parked candidate nominated again with no queue room
// stays parked. After a restart, once a state decides them, every candidate
// is verified with no new nomination.
TEST(WalletIndexWorker, FullQueueAndParkingAreNeverOverfilled) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-both-full");
  td::rmrf(path).ignore();
  auto block = overflowing_block(40, 10);
  auto filler = overflowing_block(43, 10, 1000, 5050);
  auto failing = codeless(block);
  auto more = codeless(filler);
  failing.insert(failing.end(), more.begin(), more.end());
  block.state = wallet_index_fixture::shard_state(failing);
  NewestState newest;
  newest.set(40, 5100, block.state);
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds(0));
  uint64_t most_entries = 0, most_parked = 0;
  auto watch = [&](tos_wallet_index::WalletIndexDb &db) {
    auto stats = backlog_stats(db);
    most_entries = std::max(most_entries, stats.entries);
    most_parked = std::max(most_parked, stats.parked);
    return stats;
  };
  auto settle = [&](tos_wallet_index::WalletIndexDb &db) {
    for (int i = 0; i < 100; ++i) {
      watch(db);
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  };
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(4);
    db.set_parked_token_limit(2);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(block.root, block.state, block.id, 1000);
    // Parking fills up; the block keeps what fits neither in the queue nor
    // in parking.
    ASSERT_TRUE(eventually([&] { return watch(db).parked == 2; }));
    settle(db);
    ASSERT_TRUE(static_cast<bool>(db.get_pending_block(block.id).move_as_ok()));
    // Another block, applied without its state, can only defer: it fills the
    // queue and keeps the rest.
    tos_wallet_index::enqueue_wc0_index_block(filler.root, td::Ref<vm::Cell>{}, filler.id, 1001);
    ASSERT_TRUE(eventually([&] { return watch(db).entries == 4; }));
    settle(db);
    // A parked candidate nominated again while the queue is full stays parked.
    td::optional<td::Bits256> parked_wallet;
    auto kept = db.get_pending_block(block.id).move_as_ok();
    for (auto &wallet : block.wallets) {
      bool elsewhere = false;
      db.for_each_deferred_token_candidate(16, [&](const TokenCandidate &c) -> td::Status {
          elsewhere = elsewhere || c.address == wallet;
          return td::Status::OK();
        }).ensure();
      if (kept) {
        for (auto &entry : kept.value().remaining) {
          elsewhere = elsewhere || entry.candidate.address == wallet;
        }
      }
      if (!elsewhere && !db.has_jetton_wallet_record(wallet).move_as_ok()) {
        parked_wallet = wallet;
      }
    }
    ASSERT_TRUE(static_cast<bool>(parked_wallet));
    auto again = wallet_index_fixture::block(41, 5200, 1002, {{parked_wallet.value(), 20, kJettonTransferOp}});
    tos_wallet_index::enqueue_wc0_index_block(again, td::Ref<vm::Cell>{}, worker_block_id(41), 1002);
    ASSERT_TRUE(eventually([&] { return !db.has_incomplete_block(worker_block_id(41)).move_as_ok(); }));
    settle(db);
    ASSERT_EQ(watch(db).parked, static_cast<uint64_t>(2));
    bool requeued = false;
    db.for_each_deferred_token_candidate(16, [&](const TokenCandidate &c) -> td::Status {
        requeued = requeued || c.address == parked_wallet.value();
        return td::Status::OK();
      }).ensure();
    ASSERT_TRUE(!requeued);
    ASSERT_TRUE(most_entries <= 4);
    ASSERT_TRUE(most_parked <= 2);
    ASSERT_EQ(backlog_stats(db).lost, static_cast<uint64_t>(0));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  // Restarted, with a state that decides them (the wallets are gone).
  newest.set(42, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(4);
    db.set_parked_token_limit(2);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually(
        [&] {
          watch(db);
          return processed_count(db, block) == block.wallets.size() &&
                 processed_count(db, filler) == filler.wallets.size() && is_complete(db);
        },
        std::chrono::seconds(30)));
    ASSERT_TRUE(most_entries <= 4);
    ASSERT_TRUE(most_parked <= 2);
  }
  tos_wallet_index::set_wc0_index_parked_retry_pause_for_testing(std::chrono::minutes(10));
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Startup recovery finds more blocks with overflowing candidates than the
// index may hold unfinished. It admits them through the same bound: never
// more unfinished at once, and every candidate is verified in the end.
TEST(WalletIndexWorker, RecoveryHonoursTheBoundOnUnfinishedBlocks) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-recovery-bound");
  td::rmrf(path).ignore();
  std::vector<OverflowingBlock> blocks;
  for (uint32_t i = 0; i < 3; ++i) {
    blocks.push_back(overflowing_block(50 + i, kMaxTokenCandidatesPerBlock + 40, 10000 * (i + 1), 5000 + i));
  }
  FakeArchive archive;
  {
    auto &db = install_db(path);
    std::vector<tos_wallet_index::MarkedBlock> marked;
    for (auto &b : blocks) {
      archive.add(b.id, b.root, 1000);
      marked.push_back({b.id, 1000});
    }
    // An earlier run applied them and stopped before indexing any.
    db.mark_blocks_incomplete(marked).ensure();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  NewestState newest;
  newest.set(90, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(1);
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    uint64_t most = 0;
    ASSERT_TRUE(eventually(
        [&] {
          most = std::max(most, db.pending_block_count().move_as_ok());
          for (auto &b : blocks) {
            if (processed_count(db, b) != b.wallets.size() || db.has_incomplete_block(b.id).move_as_ok()) {
              return false;
            }
          }
          return true;
        },
        std::chrono::seconds(60)));
    ASSERT_TRUE(most <= 1);
  }
  tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(tos_wallet_index::kMaxPendingTokenBlocks);
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// The worker waits at the bound of unfinished blocks while blocks keep being
// applied, so its queue saturates and later blocks are only marked. The
// archive is then pruned and the node restarts. The index's floor kept every
// marked block it has yet to read, so every candidate of every block is
// verified in the end, with no new block or nomination.
TEST(WalletIndexWorker, BlocksWaitingAtTheBoundSurvivePruning) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-bound-pruning");
  td::rmrf(path).ignore();
  const uint32_t base = 2000000;
  // The first block's leftover candidates cannot be finished in this run.
  auto first = overflowing_block(60, kMaxTokenCandidatesPerBlock + 40, 0, 5000);
  first.state = wallet_index_fixture::shard_state(codeless(first));
  std::vector<OverflowingBlock> later;
  const size_t later_count = tos_wallet_index::kWc0IndexQueueCapacity + 20;
  for (size_t i = 0; i < later_count; ++i) {
    later.push_back(
        overflowing_block(static_cast<tos::BlockSeqno>(61 + i), 1, static_cast<uint32_t>(100000 + i), 5001 + i));
  }
  // An old block, indexed long ago: pruning may take it.
  auto old_id = worker_block_id(58);
  FakeArchive archive;
  archive.add(old_id, wallet_index_fixture::block(58, 3000, base - 200000, {}), base - 200000);
  archive.add(worker_block_id(59), wallet_index_fixture::block(59, 4000, base - 100000, {}), base - 100000);
  archive.add(first.id, first.root, base);
  for (size_t i = 0; i < later.size(); ++i) {
    archive.add(later[i].id, later[i].root, static_cast<uint32_t>(base + 1 + i));
  }
  NewestState newest;
  newest.set(60, 5000, first.state);
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    db.set_parked_token_limit(0);
    tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(1);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::enqueue_wc0_index_block(first.root, first.state, first.id, base);
    ASSERT_TRUE(eventually([&] { return db.get_pending_block(first.id).move_as_ok(); }));
    // Applied with their data in hand; the worker cannot take them.
    for (size_t i = 0; i < later.size(); ++i) {
      tos_wallet_index::enqueue_wc0_index_block(later[i].root, later[i].state, later[i].id,
                                                static_cast<uint32_t>(base + 1 + i));
    }
    ASSERT_TRUE(eventually([&] { return db.has_incomplete_block(later.back().id).move_as_ok(); }));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    // The archive is pruned as the node would, with the index's floor.
    auto floor = tos::validator::archive_floor();
    ASSERT_TRUE(floor <= base);
    ASSERT_EQ(archive.prune(base + 1000000.0, 1000.0, floor), static_cast<size_t>(1));
    ASSERT_TRUE(!archive.has(old_id));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  // Restarted; a newer state now decides the first block's candidates.
  newest.set(400, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    db.set_token_backlog_limit(16);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually(
        [&] {
          if (processed_count(db, first) != first.wallets.size()) {
            return false;
          }
          for (auto &b : later) {
            if (processed_count(db, b) != b.wallets.size()) {
              return false;
            }
          }
          return is_complete(db);
        },
        std::chrono::seconds(120)));
  }
  tos_wallet_index::set_wc0_index_pending_block_limit_for_testing(tos_wallet_index::kMaxPendingTokenBlocks);
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// A floor lowered after pruning selected its packages, but before it admits
// a deletion, saves a package it now covers.
TEST(WalletIndex, ArchivePruningAdmitsEachDeletionAgainstTheCurrentFloor) {
  tos::validator::reset_archive_retention_for_testing();
  std::vector<double> first_ts = {100, 200, 300, 400, 500};
  std::vector<size_t> deleted;
  bool lowered = false;
  auto removed = tos::validator::prune_archive_packages(
      first_ts, 550, 100, [&](size_t index) { deleted.push_back(index); },
      [&](size_t) {
        // A reader retains from 250 on, between the selection and the first
        // admission.
        if (!lowered) {
          ASSERT_TRUE(tos::validator::archive_retain(250, 3600 + 250));
          lowered = true;
        }
      });
  ASSERT_EQ(removed, static_cast<size_t>(1));
  ASSERT_EQ(deleted, (std::vector<size_t>{0}));
  // What pruning gave up is now refused to a later reader.
  ASSERT_TRUE(!tos::validator::archive_retain(150, 3600 + 150));
  ASSERT_TRUE(tos::validator::archive_retain(200, 3600 + 200));
  tos::validator::reset_archive_retention_for_testing();
}

namespace {

// An archive whose block reads answer, but whose state reads never do.
struct ArchiveWithoutStates {
  FakeArchive *archive;
  std::mutex mutex;
  std::vector<std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)>> held;
  std::atomic<int> state_requests{0};
  tos_wallet_index::Wc0IndexBlockFetcher fetcher() {
    return [this](const tos::BlockIdExt &id, bool need_state,
                  std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
      if (need_state) {
        state_requests++;
        std::lock_guard<std::mutex> lock(mutex);
        held.push_back(std::move(done));
        return;
      }
      archive->fetcher()(id, false, std::move(done));
    };
  }
};

}  // namespace

// A block applied while the recorder's write is stalled is already kept by
// the archive: pruning in that window leaves it, and once the recorder goes
// on, the worker reads it back and indexes it.
TEST(WalletIndexWorker, ABlockIsKeptByTheArchiveFromTheMomentItIsHandedOver) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-handover-floor");
  td::rmrf(path).ignore();
  const uint32_t base = 3000000;
  auto block = overflowing_block(70, 5, 0, 5000);
  FakeArchive archive;
  archive.add(worker_block_id(68), wallet_index_fixture::block(68, 3000, base - 200000, {}), base - 200000);
  archive.add(worker_block_id(69), wallet_index_fixture::block(69, 4000, base - 100000, {}), base - 100000);
  archive.add(block.id, block.root, base);
  // A later package, so the block's is not the newest one pruning reaches.
  archive.add(worker_block_id(71), wallet_index_fixture::block(71, 5100, base + 10, {}), base + 10);
  NewestState newest;
  newest.set(70, 5000, block.state);
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    // Handed over by id alone: the worker must read it from the archive.
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, block.state, block.id, base);
    // Not marked yet, and pruning runs.
    ASSERT_TRUE(!db.has_incomplete_block(block.id).move_as_ok());
    archive.prune(base + 1000000.0, 1000.0, 0);
    ASSERT_TRUE(archive.has(block.id));
    ASSERT_TRUE(!archive.has(worker_block_id(68)));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, block) == block.wallets.size() && !db.has_incomplete_block(block.id).move_as_ok();
    }));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Recovery reads a marked block without its state, and does not wait for a
// state that never comes: newer states verify its candidates.
TEST(WalletIndexWorker, RecoveryNeverWaitsForTheBlocksOwnState) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-recovery-block-only");
  td::rmrf(path).ignore();
  auto block = overflowing_block(71, 5, 0, 5000);
  FakeArchive archive;
  archive.add(block.id, block.root, 1000);
  ArchiveWithoutStates reads;
  reads.archive = &archive;
  NewestState newest;
  newest.set(90, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    db.mark_blocks_incomplete(std::vector<tos_wallet_index::MarkedBlock>{{block.id, 1000}}).ensure();
    tos_wallet_index::set_wc0_index_fetch_timeout_for_testing(std::chrono::milliseconds(500));
    tos_wallet_index::set_wc0_index_block_fetcher(reads.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, block) == block.wallets.size() && !db.has_incomplete_block(block.id).move_as_ok();
    }));
    ASSERT_EQ(reads.state_requests.load(), 0);
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// A recovered block whose indexing fails once is tried again in the same run,
// after a pause, while other recovered blocks go on.
TEST(WalletIndexWorker, ARecoveredBlockThatFailsOnceIsRetried) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-recovery-retry");
  td::rmrf(path).ignore();
  auto first = overflowing_block(72, 5, 0, 5000);
  auto second = overflowing_block(73, 5, 100, 5001);
  FakeArchive archive;
  archive.add(first.id, first.root, 1000);
  archive.add(second.id, second.root, 1001);
  NewestState newest;
  newest.set(90, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    db.mark_blocks_incomplete(std::vector<tos_wallet_index::MarkedBlock>{{first.id, 1000}, {second.id, 1001}}).ensure();
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    tos_wallet_index::set_wc0_index_commit_faults_for_testing(1);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, first) == first.wallets.size() &&
             processed_count(db, second) == second.wallets.size() && !db.has_incomplete_block(first.id).move_as_ok() &&
             !db.has_incomplete_block(second.id).move_as_ok();
    }));
  }
  tos_wallet_index::set_wc0_index_commit_faults_for_testing(0);
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// One unfinished block holds more candidates than one pass examines, and the
// first pass's worth belong to a shard whose state cannot be had. The rest
// are still verified, across a restart and with no new nomination.
TEST(WalletIndexWorker, AnUnavailablePrefixDoesNotStarveTheRestOfABlock) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-pending-rotation");
  td::rmrf(path).ignore();
  auto id = shard_block_id(kLeftShard, 80);
  std::vector<td::Bits256> stuck, reachable;
  for (uint32_t i = 0; i < kMaxTokenCandidatesPerBlock; ++i) {
    stuck.push_back(token_address(i, 0x01));
  }
  for (uint32_t i = 0; i < 8; ++i) {
    reachable.push_back(token_address(5000 + i, 0x81));
  }
  {
    auto &db = install_db(path);
    tos_wallet_index::WalletIndexDb::PendingBlock pending;
    pending.end_lt = 5000;
    for (auto &a : stuck) {
      pending.remaining.push_back({{TokenKind::Jetton, a}, 0, 5000});
    }
    for (auto &a : reachable) {
      pending.remaining.push_back({{TokenKind::Jetton, a}, 0, 5000});
    }
    db.begin_batch().ensure();
    db.put_pending_block(id, pending).ensure();
    db.commit_batch().ensure();
    db.put_incomplete_block(id, 1000).ensure();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  HalvesState newest;  // the left half's state never comes
  auto reachable_done = [&](tos_wallet_index::WalletIndexDb &db) {
    for (auto &a : reachable) {
      if (!db.has_jetton_wallet_record(a).move_as_ok()) {
        return false;
      }
    }
    return true;
  };
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] { return newest.calls.load() >= 3; }));
    ASSERT_TRUE(!reachable_done(db));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  newest.set(true, wallet_index_fixture::shard_state({}), 6000);
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually([&] { return reachable_done(db); }, std::chrono::seconds(30)));
    auto left = db.get_pending_block(id).move_as_ok();
    ASSERT_TRUE(static_cast<bool>(left));
    ASSERT_EQ(left.value().remaining.size(), stuck.size());
    ASSERT_TRUE(!is_complete(db));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// While a handed-over block waits for its marker, the index recomputes its
// floor (another block is extracted meanwhile). The recomputation still
// counts the waiting block, so pruning keeps it.
TEST(WalletIndexWorker, RecomputingTheFloorKeepsBlocksNotYetMarked) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-floor-recompute");
  td::rmrf(path).ignore();
  const uint32_t base = 4000000;
  auto earlier = overflowing_block(74, 3, 0, 4000);
  auto waiting = overflowing_block(75, 3, 100, 5000);
  FakeArchive archive;
  archive.add(worker_block_id(73), wallet_index_fixture::block(73, 3000, base - 300000, {}), base - 300000);
  archive.add(earlier.id, earlier.root, base - 200000);
  archive.add(waiting.id, waiting.root, base);
  archive.add(worker_block_id(76), wallet_index_fixture::block(76, 5100, base + 10, {}), base + 10);
  NewestState newest;
  newest.set(90, 9000, wallet_index_fixture::shard_state({}));
  {
    auto &db = install_db(path);
    // Left unfinished by an earlier run.
    db.mark_blocks_incomplete(std::vector<tos_wallet_index::MarkedBlock>{{earlier.id, base - 200000}}).ensure();
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, waiting.state, waiting.id, base);
    tos_wallet_index::resume_wc0_index_worker();
    // The earlier block is recovered and extracted, which recomputes the floor.
    ASSERT_TRUE(eventually([&] { return !db.has_incomplete_block(earlier.id).move_as_ok(); }));
    ASSERT_TRUE(!db.has_incomplete_block(waiting.id).move_as_ok());
    archive.prune(base + 1000000.0, 1000.0, 0);
    ASSERT_TRUE(archive.has(waiting.id));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, waiting) == waiting.wallets.size() &&
             !db.has_incomplete_block(waiting.id).move_as_ok();
    }));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

namespace {

size_t count_raw_prefix(td::RocksDb &raw, uint8_t tag) {
  size_t n = 0;
  char begin[1] = {static_cast<char>(tag)};
  char end[1] = {static_cast<char>(static_cast<uint8_t>(tag + 1))};
  raw.for_each_in_range(td::Slice{begin, 1}, td::Slice{end, 1},
                        [&](td::Slice, td::Slice) {
                          n++;
                          return td::Status::OK();
                        })
      .ensure();
  return n;
}

}  // namespace

// A database written under any other schema is reset when opened: nothing of
// it is imported or served, and the index starts fresh and forward-only.
TEST(WalletIndex, AnOldSchemaIsResetToAFreshIndex) {
  auto path = std::string("test-wallet-index-db-reset");
  auto owner = token_address(1, 0x40);
  for (int version : {-1, 1, 2}) {
    td::rmrf(path).ignore();
    {
      auto raw = td::RocksDb::open(path).move_as_ok();
      if (version >= 0) {
        const char version_key[2] = {0x00, 0x01};
        const char v[4] = {0, 0, 0, static_cast<char>(version)};
        raw.set(td::Slice{version_key, 2}, td::Slice{v, 4}).ensure();
      }
      // A jetton row, with the pair record a current binary would write, an
      // NFT row, events, a marker, a backlog entry and a needs-rebuild mark.
      std::string jetton(65, '\x02');
      jetton[0] = 0x10;
      std::memcpy(&jetton[1], owner.data(), 32);
      vm::CellBuilder cb;
      cb.store_bits(token_address(3, 0x40).bits(), 256);
      cb.store_long(5, 64);
      raw.set(jetton, vm::std_boc_serialize(cb.finalize()).move_as_ok().as_slice()).ensure();
      std::string pair = jetton;
      pair[0] = 0x18;
      raw.set(pair, std::string(1 + 32 + 8, '\x01')).ensure();
      for (int tag : {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1E}) {
        raw.set(std::string(1, static_cast<char>(tag)) + std::string(40, '\x03'), "x").ensure();
      }
      raw.set(std::string("\x00\x09", 2), std::string(1, '\x01')).ensure();
    }
    {
      auto db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
      size_t served = 0;
      db->for_each_current_jetton(owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
          ++served;
          return td::Status::OK();
        }).ensure();
      ASSERT_EQ(served, static_cast<size_t>(0));
      auto stats = backlog_stats(*db);
      ASSERT_TRUE(!stats.needs_rebuild && !stats.unfinished_block);
    }
    auto raw = td::RocksDb::open(path).move_as_ok();
    for (uint8_t tag = 0x01; tag < 0xff; ++tag) {
      ASSERT_EQ(count_raw_prefix(raw, tag), 0u);
    }
    ASSERT_EQ(count_raw_prefix(raw, 0x00), 1u);  // the schema version only
  }
  td::rmrf(path).ignore();
}

// A database of the current schema is kept as it is across a restart: the
// unfinished work of the run before survives.
TEST(WalletIndex, ACurrentSchemaRestartKeepsUnfinishedWork) {
  auto path = std::string("test-wallet-index-db-keep");
  auto db = open_fresh_db(path);
  auto id = make_test_block_id(0, tos::shardIdAll, 9, 0x11, 0x22);
  ASSERT_TRUE(schedule_block(*db, token_candidates(0, 3), kWholeBasechain, 0).empty());
  db->begin_batch().ensure();
  db->begin_token_pass().ensure();
  ASSERT_TRUE(db->park_token_candidate({token_candidates(10, 1)[0], 0, 100}).move_as_ok());
  tos_wallet_index::WalletIndexDb::PendingBlock pending;
  pending.end_lt = 100;
  pending.remaining.push_back({token_candidates(20, 1)[0], 1, 100});
  db->put_pending_block(id, pending).ensure();
  db->save_token_counters().ensure();
  db->commit_batch().ensure();
  db->put_incomplete_block(id, 1000).ensure();
  db.reset();
  db = tos_wallet_index::WalletIndexDb::open(path).move_as_ok();
  auto stats = backlog_stats(*db);
  ASSERT_EQ(stats.entries, static_cast<uint64_t>(3));
  ASSERT_EQ(stats.parked, static_cast<uint64_t>(1));
  ASSERT_TRUE(stats.unfinished_block);
  auto kept = db->get_pending_block(id).move_as_ok();
  ASSERT_TRUE(static_cast<bool>(kept));
  ASSERT_EQ(kept.value().remaining.size(), static_cast<size_t>(1));
  td::rmrf(path).ignore();
}

// A jetton row with no pair record beside it is not a verified fact: it is
// never served.
TEST(WalletIndex, AJettonRowWithoutItsPairRecordIsNeverServed) {
  auto path = std::string("test-wallet-index-db-unverified-row");
  auto db = open_fresh_db(path);
  auto owner = token_address(1, 0x40);
  vm::CellBuilder cb;
  cb.store_bits(token_address(3, 0x40).bits(), 256);
  cb.store_long(5, 64);
  db->begin_batch().ensure();
  db->put_jetton(owner, token_address(2, 0x40), cb.finalize()).ensure();
  db->commit_batch().ensure();
  size_t served = 0;
  db->for_each_current_jetton(owner, 16, [&](const td::Bits256 &, td::Ref<vm::Cell>) -> td::Status {
      ++served;
      return td::Status::OK();
    }).ensure();
  ASSERT_EQ(served, static_cast<size_t>(0));
  td::rmrf(path).ignore();
}

// Pruning has admitted the deletion of a package (it read the floor for the
// last time and recorded the package as given up) but not yet carried it out
// when a block from that package is handed over. The index is refused
// retention for it, so it never relies on the archive for that block: with
// the block's data in hand, it indexes the block from memory; without it, it
// records that the index needs a rebuild instead of claiming completeness.
TEST(WalletIndexWorker, ABlockHandedOverAfterItsPackageWasGivenUpNeverReliesOnIt) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-after-admission");
  td::rmrf(path).ignore();
  const uint32_t base = 5000000;
  auto in_hand = overflowing_block(81, 3, 0, 5000);
  auto without_data = overflowing_block(82, 3, 100, 5001);
  FakeArchive archive;
  archive.add(in_hand.id, in_hand.root, base);
  archive.add(without_data.id, without_data.root, base + 1);
  archive.add(worker_block_id(83), wallet_index_fixture::block(83, 5002, base + 100000, {}), base + 100000);
  archive.add(worker_block_id(84), wallet_index_fixture::block(84, 5003, base + 200000, {}), base + 200000);
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    archive.prune(base + 1000000.0, 1000.0, 0, [&] {
      // The first package is admitted for deletion, not yet deleted.
      tos_wallet_index::enqueue_wc0_index_block(in_hand.root, in_hand.state, in_hand.id, base);
      tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, without_data.state, without_data.id, base + 1);
    });
    ASSERT_TRUE(!archive.has(in_hand.id));
    // Indexed from what the hook held.
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, in_hand) == in_hand.wallets.size() &&
             !db.has_incomplete_block(in_hand.id).move_as_ok();
    }));
    // The other could not be kept anywhere: the index says so.
    ASSERT_TRUE(eventually([&] { return backlog_stats(db).needs_rebuild; }));
    ASSERT_TRUE(!is_complete(db));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// A block is handed over after pruning selected its package but before the
// deletion is admitted: the admission sees the lowered floor and the package
// survives, so the worker reads the block from it.
TEST(WalletIndexWorker, ABlockHandedOverBeforeAdmissionKeepsItsPackage) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-before-admission");
  td::rmrf(path).ignore();
  const uint32_t base = 6000000;
  auto block = overflowing_block(85, 3, 0, 5000);
  FakeArchive archive;
  archive.add(worker_block_id(80), wallet_index_fixture::block(80, 3000, base - 200000, {}), base - 200000);
  archive.add(worker_block_id(84), wallet_index_fixture::block(84, 4000, base - 100000, {}), base - 100000);
  archive.add(block.id, block.root, base);
  archive.add(worker_block_id(86), wallet_index_fixture::block(86, 5002, base + 100000, {}), base + 100000);
  archive.add(worker_block_id(87), wallet_index_fixture::block(87, 5003, base + 200000, {}), base + 200000);
  {
    auto &db = install_db(path);
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    archive.prune(base + 1000000.0, 1000.0, 0, nullptr,
                  [&] { tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, block.state, block.id, base); });
    ASSERT_TRUE(archive.has(block.id));
    ASSERT_TRUE(!archive.has(worker_block_id(80)));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    ASSERT_TRUE(eventually([&] {
      return processed_count(db, block) == block.wallets.size() && !db.has_incomplete_block(block.id).move_as_ok();
    }));
  }
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// Far more blocks are handed over than are tracked one by one, and more than
// the worker's queue holds, while the recorder's writes are stalled. The
// bookkeeping that keeps them in the archive stays bounded, the hook never
// waits, every one of them is kept through pruning, and after the recorder
// recovers and the node restarts, every candidate is verified.
TEST(WalletIndexWorker, RetentionBookkeepingIsBoundedWhileRecordingStalls) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-bounded-tracking");
  td::rmrf(path).ignore();
  const uint32_t base = 7000000;
  const size_t count = tos_wallet_index::kWc0IndexQueueCapacity + 64;
  std::vector<OverflowingBlock> blocks;
  FakeArchive archive;
  archive.add(worker_block_id(99), wallet_index_fixture::block(99, 3000, base - 300000, {}), base - 300000);
  archive.add(worker_block_id(98), wallet_index_fixture::block(98, 3001, base - 200000, {}), base - 200000);
  for (size_t i = 0; i < count; ++i) {
    blocks.push_back(
        overflowing_block(static_cast<tos::BlockSeqno>(100 + i), 1, static_cast<uint32_t>(10 * i), 6000 + i));
    archive.add(blocks.back().id, blocks.back().root, static_cast<uint32_t>(base + 100 * i));
  }
  archive.add(worker_block_id(5000), wallet_index_fixture::block(5000, 9000, base + 100000, {}), base + 100000);
  // Left unfinished by an earlier run; recovering it during the stall makes
  // the index recompute its floor.
  auto earlier = overflowing_block(97, 1, 900000, 2000);
  archive.add(earlier.id, earlier.root, base - 50000);
  NewestState newest;
  newest.set(5000, 9000, wallet_index_fixture::shard_state({}));
  tos_wallet_index::set_wc0_index_tracking_capacity_for_testing(8);
  {
    auto &db = install_db(path);
    db.mark_blocks_incomplete(std::vector<tos_wallet_index::MarkedBlock>{{earlier.id, base - 50000}}).ensure();
    tos_wallet_index::set_wc0_index_block_fetcher(archive.fetcher());
    tos_wallet_index::set_wc0_index_state_fetcher(newest.fetcher());
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    auto started = std::chrono::steady_clock::now();
    // Newest first, so the blocks handed over once tracking is full are the
    // oldest: only the overflow floor keeps them.
    for (size_t k = 0; k < count; ++k) {
      size_t i = count - 1 - k;
      tos_wallet_index::enqueue_wc0_index_block(blocks[i].root, blocks[i].state, blocks[i].id,
                                                static_cast<uint32_t>(base + 100 * i));
      ASSERT_TRUE(tos_wallet_index::wc0_index_tracked_handovers_for_testing() <= 8);
    }
    ASSERT_TRUE(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    tos_wallet_index::resume_wc0_index_worker();
    ASSERT_TRUE(eventually([&] { return !db.has_incomplete_block(earlier.id).move_as_ok(); }));
    ASSERT_TRUE(tos::validator::archive_floor() <= base);
    ASSERT_EQ(archive.prune(base + 1000000.0, 1000.0, 0), static_cast<size_t>(2));
    for (auto &b : blocks) {
      ASSERT_TRUE(archive.has(b.id));
    }
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    // Every hand-over recorded: nothing is tracked any more.
    ASSERT_TRUE(eventually([&] { return tos_wallet_index::wc0_index_tracked_handovers_for_testing() == 0; }));
    ASSERT_TRUE(tos_wallet_index::flush_wc0_index_for_exit(Producers::Quiesced));
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wallet_index_db(nullptr);
  }
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(false));
    ASSERT_TRUE(eventually(
        [&] {
          for (auto &b : blocks) {
            if (processed_count(db, b) != b.wallets.size()) {
              return false;
            }
          }
          return is_complete(db);
        },
        std::chrono::seconds(120)));
  }
  tos_wallet_index::set_wc0_index_tracking_capacity_for_testing(4096);
  reset_index_singletons();
  td::rmrf(path).ignore();
}

// More blocks are handed over than even the recorder's id list holds while
// its writes are stalled. Memory stays bounded and the hook never waits; the
// blocks whose ids found no room cannot be found again, and the index records
// that it needs a rebuild rather than claiming completeness.
TEST(WalletIndexWorker, HandOversBeyondTheRecorderStayBoundedAndAreReported) {
  reset_index_singletons();
  auto path = std::string("test-wallet-index-db-beyond-recorder");
  td::rmrf(path).ignore();
  tos_wallet_index::set_wc0_index_tracking_capacity_for_testing(8);
  {
    auto &db = install_db(path);
    ASSERT_TRUE(tos_wallet_index::start_wc0_index_worker(true));
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
    const size_t count = 16 * tos_wallet_index::kWc0IndexQueueCapacity + 1000;
    auto started = std::chrono::steady_clock::now();
    for (size_t i = 0; i < count; ++i) {
      tos_wallet_index::enqueue_wc0_index_block(td::Ref<vm::Cell>{}, td::Ref<vm::Cell>{},
                                                worker_block_id(static_cast<tos::BlockSeqno>(1 + i)),
                                                static_cast<uint32_t>(8000000 + i));
    }
    ASSERT_TRUE(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    ASSERT_TRUE(tos_wallet_index::wc0_index_tracked_handovers_for_testing() <= 8);
    ASSERT_TRUE(tos::validator::archive_floor() <= 8000000);
    ASSERT_TRUE(tos_wallet_index::wc0_index_degraded());
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    ASSERT_TRUE(eventually([&] { return backlog_stats(db).needs_rebuild; }));
  }
  tos_wallet_index::set_wc0_index_tracking_capacity_for_testing(4096);
  reset_index_singletons();
  td::rmrf(path).ignore();
}
