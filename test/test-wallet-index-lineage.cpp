/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <vector>

#include "../validator-engine/wallet-index-lineage.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"

namespace {
using tos_wallet_index::AccountHead;
using tos_wallet_index::LineageVerdict;
using tos_wallet_index::verify_account_lineage;
using tos_wallet_index::window_lt_bound;
using tos_wallet_index::WindowShardTip;

constexpr size_t kCap = 10000;

td::Bits256 address(unsigned char top) {
  td::Bits256 out = td::Bits256::zero();
  out.as_slice()[0] = static_cast<char>(top);
  out.as_slice()[31] = 1;
  return out;
}

// A transaction cell with the header fields the check reads and a body
// byte, so two transactions with equal links still differ.
td::Ref<vm::Cell> transaction(const td::Bits256& account, uint64_t lt, const td::Bits256& prev_hash, uint64_t prev_lt,
                              uint32_t now, unsigned body = 0) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(7, 4) && cb.store_bits_bool(account.cbits(), 256) && cb.store_long_bool(lt, 64) &&
        cb.store_bits_bool(prev_hash.cbits(), 256) && cb.store_long_bool(prev_lt, 64) && cb.store_long_bool(now, 32) &&
        cb.store_long_bool(body, 8));
  return cb.finalize();
}

// An account's transactions oldest first: the first has predecessor
// (first_prev_lt, a fixed hash), or none when first_prev_lt is 0.
std::vector<td::Ref<vm::Cell>> chain(const td::Bits256& account, const std::vector<uint64_t>& lts,
                                     uint64_t first_prev_lt) {
  std::vector<td::Ref<vm::Cell>> out;
  td::Bits256 prev = first_prev_lt == 0 ? td::Bits256::zero() : address(0xEE);
  uint64_t prev_lt = first_prev_lt;
  for (auto lt : lts) {
    out.push_back(transaction(account, lt, prev, prev_lt, static_cast<uint32_t>(lt / 10)));
    prev = out.back()->get_hash().bits();
    prev_lt = lt;
  }
  return out;
}

// The index's row order: newest first.
std::vector<td::Ref<vm::Cell>> newest_first(std::vector<td::Ref<vm::Cell>> rows) {
  std::reverse(rows.begin(), rows.end());
  return rows;
}

AccountHead head_of(const std::vector<td::Ref<vm::Cell>>& oldest_first) {
  auto link = tos_wallet_index::parse_transaction_link(oldest_first.back()).move_as_ok();
  return AccountHead{link.lt, link.hash};
}

// Keep only the rows of `all` above the window bound, as an honest index does.
std::vector<td::Ref<vm::Cell>> in_window(const std::vector<td::Ref<vm::Cell>>& all, uint64_t bound) {
  std::vector<td::Ref<vm::Cell>> out;
  for (const auto& row : all) {
    if (tos_wallet_index::parse_transaction_link(row).move_as_ok().lt > bound) {
      out.push_back(row);
    }
  }
  return newest_first(out);
}
}  // namespace

TEST(WalletIndexLineage, HistoryLinkedBelowTheWindowIsComplete) {
  auto account = address(0x10);
  auto all = chain(account, {100, 200, 1100, 1200, 1300}, 50);
  auto result = verify_account_lineage(account, head_of(all), 1000, in_window(all, 1000), kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Complete);
}

TEST(WalletIndexLineage, TamperedRowIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200, 1300}, 50);
  auto rows = in_window(all, 1000);
  auto link = tos_wallet_index::parse_transaction_link(rows[1]).move_as_ok();
  rows[1] = transaction(account, link.lt, link.prev_hash, link.prev_lt, link.now, 1);
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, TamperedNewestRowIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200}, 50);
  auto rows = in_window(all, 1000);
  auto link = tos_wallet_index::parse_transaction_link(rows[0]).move_as_ok();
  rows[0] = transaction(account, link.lt, link.prev_hash, link.prev_lt, link.now, 1);
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, OmittedMiddleRowIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200, 1300}, 50);
  auto rows = in_window(all, 1000);
  rows.erase(rows.begin() + 1);
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, TruncatedInWindowHistoryIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200, 1300}, 50);
  auto rows = in_window(all, 1000);
  rows.pop_back();
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, MissingHistoryOfAnActiveAccountIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100}, 50);
  auto result = verify_account_lineage(account, head_of(all), 1000, {}, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, InjectedRowsForAnAccountOutsideTheWindowAreRefused) {
  auto account = address(0x10);
  auto real = chain(account, {100, 200}, 50);
  auto forged = chain(account, {1100}, 200);
  auto result = verify_account_lineage(account, head_of(real), 1000, newest_first(forged), kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
  auto quiet = verify_account_lineage(account, head_of(real), 1000, {}, kCap);
  ASSERT_TRUE(quiet.verdict == LineageVerdict::OutsideWindow);
}

TEST(WalletIndexLineage, RowOfAnotherAccountIsRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200}, 50);
  auto rows = in_window(all, 1000);
  auto other = chain(address(0x11), {1150}, 100);
  rows.insert(rows.begin() + 1, other[0]);
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, AccountCreatedInTheWindowNeedsBlocks) {
  auto account = address(0x10);
  auto all = chain(account, {1100, 1200}, 0);
  auto result = verify_account_lineage(account, head_of(all), 1000, in_window(all, 1000), kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::NeedsBlocks);
}

// Deleting an account resets its predecessor. The current incarnation alone
// links cleanly to a creation, so a snapshot that drops the first
// incarnation's in-window rows must not be taken as complete.
TEST(WalletIndexLineage, RecreatedAccountWithoutItsFirstIncarnationNeedsBlocks) {
  auto account = address(0x10);
  auto first = chain(account, {1100, 1200}, 50);
  auto second = chain(account, {1300, 1400}, 0);
  auto result = verify_account_lineage(account, head_of(second), 1000, newest_first(second), kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::NeedsBlocks);
  std::vector<td::Ref<vm::Cell>> both = first;
  both.insert(both.end(), second.begin(), second.end());
  auto with_first = verify_account_lineage(account, head_of(second), 1000, newest_first(both), kCap);
  ASSERT_TRUE(with_first.verdict == LineageVerdict::NeedsBlocks);
}

TEST(WalletIndexLineage, AccountAbsentFromTheStateNeedsBlocks) {
  auto account = address(0x10);
  auto all = chain(account, {1100, 1200}, 50);
  auto result = verify_account_lineage(account, {}, 1000, in_window(all, 1000), kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::NeedsBlocks);
}

// An account destroyed inside the window is absent from H, and a snapshot
// may drop its whole history: H cannot tell that from an account that never
// existed, so an empty history of an absent account is not verified.
TEST(WalletIndexLineage, OmittedHistoryOfAnAbsentAccountNeedsBlocks) {
  auto result = verify_account_lineage(address(0x10), {}, 1000, {}, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::NeedsBlocks);
}

TEST(WalletIndexLineage, HistoryCutAtTheRetentionCapIsComplete) {
  auto account = address(0x10);
  auto all = chain(account, {1100, 1200, 1300, 1400}, 1050);
  auto rows = in_window(all, 1000);
  rows.pop_back();
  auto capped = verify_account_lineage(account, head_of(all), 1000, rows, 3);
  ASSERT_TRUE(capped.verdict == LineageVerdict::Complete);
  auto over = verify_account_lineage(account, head_of(all), 1000, in_window(all, 1000), 3);
  ASSERT_TRUE(over.verdict == LineageVerdict::Refused);
}

TEST(WalletIndexLineage, RowsOutOfOrderAreRefused) {
  auto account = address(0x10);
  auto all = chain(account, {100, 1100, 1200}, 50);
  auto rows = in_window(all, 1000);
  std::swap(rows[0], rows[1]);
  auto result = verify_account_lineage(account, head_of(all), 1000, rows, kCap);
  ASSERT_TRUE(result.verdict == LineageVerdict::Refused);
}

// Two basechain shards whose logical time advanced at very different rates:
// the window bound is the tip of each account's own shard.
TEST(WalletIndexLineage, WindowBoundFollowsEachShardUnderSkewedProgress) {
  tos::ShardIdFull left{tos::basechainId, 0x4000000000000000ULL};
  tos::ShardIdFull right{tos::basechainId, 0xC000000000000000ULL};
  std::vector<WindowShardTip> tips{{left, 1000}, {right, 900000}};
  auto slow = address(0x10);
  auto fast = address(0x90);
  auto slow_bound = window_lt_bound(tips, slow).move_as_ok();
  auto fast_bound = window_lt_bound(tips, fast).move_as_ok();
  ASSERT_EQ(slow_bound, 1000u);
  ASSERT_EQ(fast_bound, 900000u);
  // The slow shard's account transacted inside the window, at an lt the
  // fast shard passed long before the window began.
  auto slow_all = chain(slow, {900, 1500, 1600}, 800);
  ASSERT_TRUE(
      verify_account_lineage(slow, head_of(slow_all), slow_bound, in_window(slow_all, slow_bound), kCap).verdict ==
      LineageVerdict::Complete);
  ASSERT_TRUE(verify_account_lineage(slow, head_of(slow_all), slow_bound, {}, kCap).verdict == LineageVerdict::Refused);
  // The fast shard's account last transacted before the window began, at an
  // lt far above the slow shard's bound: it rightly has no rows.
  auto fast_all = chain(fast, {800000, 850000}, 700000);
  ASSERT_TRUE(verify_account_lineage(fast, head_of(fast_all), fast_bound, {}, kCap).verdict ==
              LineageVerdict::OutsideWindow);
}

TEST(WalletIndexLineage, WindowTipsMustCoverEachAccountOnce) {
  tos::ShardIdFull left{tos::basechainId, 0x4000000000000000ULL};
  tos::ShardIdFull all{tos::basechainId, tos::shardIdAll};
  ASSERT_TRUE(window_lt_bound({{left, 10}}, address(0x90)).is_error());
  ASSERT_TRUE(window_lt_bound({{left, 10}, {all, 20}}, address(0x10)).is_error());
  ASSERT_TRUE(window_lt_bound({{tos::ShardIdFull{tos::masterchainId, tos::shardIdAll}, 10}}, address(0x10)).is_error());
}
