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

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The JSON-RPC serves an account's storage metadata so that a client can bound what
// the account's next transaction is charged. The values must be the ones the
// storage phase uses, so each case is held to block::Account::unpack over the same
// account: with a storage debt, without one, and for an account that does not exist.

#include "block/block-parse.h"
#include "block/transaction.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

#include "json-rpc-server-internal.h"
#include "json-rpc-server-storage.h"

namespace {

constexpr td::uint8 kAddressByte = 0x11;

// account$1 addr:addr_std storage_stat:StorageInfo storage:AccountStorage, with an
// uninitialized state. `due` null stores due_payment as nothing.
td::Ref<vm::Cell> make_account(td::uint64 cells, td::uint64 bits, td::uint32 last_paid, td::RefInt256 due) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(1, 1));                                   // account$1
  CHECK(cb.store_long_bool(0b100, 3) && cb.store_long_bool(-1, 8));  // addr_std$10, no anycast, wc -1
  for (int i = 0; i < 32; i++) {
    CHECK(cb.store_long_bool(kAddressByte, 8));
  }
  CHECK(block::tlb::t_VarUInteger_7.store_integer_value(cb, td::BigInt256(cells)));
  CHECK(block::tlb::t_VarUInteger_7.store_integer_value(cb, td::BigInt256(bits)));
  CHECK(cb.store_long_bool(0, 3));  // storage_extra_none$000
  CHECK(cb.store_long_bool(last_paid, 32));
  if (due.is_null()) {
    CHECK(cb.store_long_bool(0, 1));
  } else {
    CHECK(cb.store_long_bool(1, 1) && block::tlb::t_Tomis.store_integer_ref(cb, due));
  }
  CHECK(cb.store_long_bool(10, 64));                                                   // last_trans_lt
  CHECK(block::tlb::t_Tomis.store_integer_value(cb, td::BigInt256(5'000'000'000LL)));  // balance
  CHECK(cb.store_long_bool(0, 1));                                                     // no extra currencies
  CHECK(cb.store_long_bool(0, 2));                                                     // account_uninit$00
  return cb.finalize();
}

// What the storage phase reads: block::Account unpacked from the ShardAccount.
block::Account executor_view(td::Ref<vm::Cell> account) {
  vm::CellBuilder shard;
  CHECK(shard.store_ref_bool(std::move(account)));
  CHECK(shard.store_zeroes_bool(256) && shard.store_long_bool(5, 64));  // last_trans_hash, last_trans_lt
  td::Bits256 address;
  address.as_slice().fill(kAddressByte);
  block::Account view(-1, address.cbits());
  CHECK(view.unpack(vm::load_cell_slice_ref(shard.finalize()), 1'800'000'000, false));
  return view;
}

void expect_matches_executor(td::Ref<vm::Cell> account) {
  auto parsed = tos::parse_account_storage_stat(account);
  ASSERT_TRUE(parsed.is_ok());
  auto stat = parsed.move_as_ok();
  ASSERT_TRUE(bool(stat));
  auto view = executor_view(account);
  ASSERT_EQ(view.storage_used.cells, stat.value().used_cells);
  ASSERT_EQ(view.storage_used.bits, stat.value().used_bits);
  ASSERT_EQ(view.last_paid, stat.value().last_paid);
  // The executor holds "no debt" as zero; the RPC reports it as absent.
  auto served_due = stat.value().due_payment.is_null() ? td::zero_refint() : stat.value().due_payment;
  ASSERT_TRUE(td::cmp(view.due_payment, served_due) == 0);
}

}  // namespace

TEST(JsonRpcStorage, an_account_with_storage_debt_reports_what_the_executor_charges) {
  auto account = make_account(7, 4321, 1'700'000'123, td::make_refint(2'000'000'000));
  expect_matches_executor(account);
  auto stat = tos::parse_account_storage_stat(account).move_as_ok().value();
  ASSERT_EQ(tos::account_storage_stat_json(stat),
            std::string("{\"@type\":\"storage.stat\",\"used_cells\":\"7\",\"used_bits\":\"4321\","
                        "\"last_paid\":1700000123,\"due_payment\":\"2000000000\"}"));
}

TEST(JsonRpcStorage, an_account_without_debt_reports_null) {
  auto account = make_account(3, 900, 1'700'000'000, td::RefInt256{});
  expect_matches_executor(account);
  auto stat = tos::parse_account_storage_stat(account).move_as_ok().value();
  ASSERT_TRUE(stat.due_payment.is_null());
  ASSERT_EQ(tos::account_storage_stat_json(stat),
            std::string("{\"@type\":\"storage.stat\",\"used_cells\":\"3\",\"used_bits\":\"900\","
                        "\"last_paid\":1700000000,\"due_payment\":null}"));
}

TEST(JsonRpcStorage, a_nonexistent_account_has_no_storage_metadata) {
  vm::CellBuilder none;
  CHECK(none.store_long_bool(0, 1));  // account_none$0
  auto parsed = tos::parse_account_storage_stat(none.finalize());
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(!parsed.ok());
  ASSERT_TRUE(tos::parse_account_storage_stat(td::Ref<vm::Cell>{}).is_ok());
}

TEST(JsonRpcStorage, a_malformed_account_is_an_error_not_an_exception) {
  vm::CellBuilder truncated;
  CHECK(truncated.store_long_bool(1, 1) && truncated.store_long_bool(0b10, 2));
  ASSERT_TRUE(tos::parse_account_storage_stat(truncated.finalize()).is_error());
}

// The field rides along on both account methods, additively: an account without
// storage metadata (one that does not exist) keeps the old shape.
TEST(JsonRpcStorage, both_account_methods_carry_storage_stat_additively) {
  tos::ParsedAccountState state;
  ASSERT_TRUE(state.to_address_info_json().find("storage_stat") == std::string::npos);
  ASSERT_TRUE(state.to_extended_info_json("-1:00").find("storage_stat") == std::string::npos);
  state.storage_stat =
      tos::parse_account_storage_stat(make_account(7, 4321, 1'700'000'123, td::make_refint(5))).move_as_ok();
  auto expected = std::string(",\"storage_stat\":") + tos::account_storage_stat_json(state.storage_stat.value()) + "}";
  auto info = state.to_address_info_json();
  ASSERT_TRUE(info.size() >= expected.size() &&
              info.compare(info.size() - expected.size(), expected.size(), expected) == 0);
  auto extended = state.to_extended_info_json("-1:00");
  ASSERT_TRUE(extended.size() >= expected.size() &&
              extended.compare(extended.size() - expected.size(), expected.size(), expected) == 0);
}
