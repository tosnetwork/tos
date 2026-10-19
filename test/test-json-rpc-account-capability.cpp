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

// The restricted-wallet delegation views behind getAccountDelegations and the
// delegation check of a transaction intent. These run the production
// functions from json-rpc-server-account-capability-views.h, the ones the
// handlers call, against a fake liteserver that answers synchronously.
//
// The vesting start is read from the account context's data cell. When the
// context was moved into the continuation before the view read it, the view
// saw a null cell and reported start 0: not_before was always null and a
// vesting-locked wallet was answered as unlocked. A data root that cannot be
// read at all must refuse the view rather than report start 0.

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "auto/tl/lite_api.hpp"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"
#include "tl-utils/common-utils.hpp"
#include "tl/tl_object_parse.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/stack.hpp"

#include "json-rpc-server-account-capability-views.h"

namespace {

constexpr td::uint32 kSyncUtime = 1789434000;
constexpr td::int64 kFullBalance = 5000000000;
constexpr td::int64 kAvailableBalance = 2000000000;

td::Bits256 fill(char byte) {
  return td::Bits256(td::Slice(std::string(32, byte)).ubegin());
}

td::int64 method_id(td::Slice name) {
  return (td::crc16(name) & 0xffff) | 0x10000;
}

td::BufferSlice stack_boc(td::RefInt256 value) {
  vm::Stack stack;
  stack.push_int(std::move(value));
  vm::CellBuilder cb;
  CHECK(stack.serialize(cb));
  return vm::std_boc_serialize(cb.finalize()).move_as_ok();
}

tos::lite_api::object_ptr<tos::lite_api::tosNode_blockIdExt> block_id() {
  return tos::lite_api::make_object<tos::lite_api::tosNode_blockIdExt>(-1, std::numeric_limits<td::int64>::min(), 12345,
                                                                       fill('\x11'), fill('\x22'));
}

// A liteserver that answers getMasterchainInfo and the two get-methods of a
// restricted wallet, counts every query, and records any other query as a
// failure (answered with an error so the caller cannot mistake it for data).
struct FakeLiteserver {
  int queries = 0;
  std::string unexpected;
  // What the wallet's balance get-method returns.
  td::RefInt256 balance = td::make_refint(kAvailableBalance);

  td::BufferSlice answer(td::BufferSlice query) {
    queries++;
    auto wrapper = tos::fetch_tl_object<tos::lite_api::liteServer_query>(std::move(query), true);
    if (wrapper.is_error()) {
      unexpected = "not a liteServer.query";
      return {};
    }
    auto function = tos::fetch_tl_object<tos::lite_api::Function>(std::move(wrapper.ok_ref()->data_), true);
    if (function.is_error()) {
      unexpected = "undecodable function";
      return {};
    }
    auto f = function.move_as_ok();
    if (f->get_id() == tos::lite_api::liteServer_getMasterchainInfo::ID) {
      return tos::create_serialize_tl_object<tos::lite_api::liteServer_masterchainInfo>(
          block_id(), fill('\x33'),
          tos::lite_api::make_object<tos::lite_api::tosNode_zeroStateIdExt>(-1, fill('\x44'), fill('\x55')));
    }
    if (f->get_id() != tos::lite_api::liteServer_runSmcMethod::ID) {
      unexpected = "unexpected function";
      return {};
    }
    auto& run = static_cast<const tos::lite_api::liteServer_runSmcMethod&>(*f);
    td::BufferSlice result;
    if (run.method_id_ == method_id("get_public_key")) {
      result = stack_boc(td::make_refint(0x1234567));
    } else if (run.method_id_ == method_id("balance")) {
      result = stack_boc(balance);
    } else {
      unexpected = "unexpected get-method";
      return {};
    }
    return tos::create_serialize_tl_object<tos::lite_api::liteServer_runMethodResult>(
        4, block_id(), block_id(), td::BufferSlice(), td::BufferSlice(), td::BufferSlice(), td::BufferSlice(),
        td::BufferSlice(), 0, std::move(result));
  }

  auto send_query() {
    return [this](td::BufferSlice query, td::Promise<td::BufferSlice> promise) {
      auto reply = answer(std::move(query));
      if (!unexpected.empty()) {
        promise.set_error(td::Status::Error(unexpected));
        return;
      }
      promise.set_value(std::move(reply));
    };
  }
};

enum class DataRoot { Wallet, Null, Library };

tos::AccountCapabilityContext restricted_context(DataRoot root, td::uint32 start_at) {
  tos::AccountCapabilityContext ctx;
  ctx.addr = block::StdAddress(0, fill('\x66'));
  ctx.addr_str = ctx.addr.rserialize(true);
  ctx.account_model = "advanced.wallet.restricted";
  ctx.parsed.balance = kFullBalance;
  ctx.parsed.sync_utime = kSyncUtime;
  if (root == DataRoot::Wallet) {
    vm::CellBuilder cb;
    CHECK(cb.store_long_bool(7, 32));          // seqno
    CHECK(cb.store_long_bool(698983191, 32));  // subwallet_id
    cb.store_zeroes(256);                      // public_key
    CHECK(cb.store_long_bool(start_at, 32));   // start_at
    ctx.parsed.data_cell = cb.finalize();
  } else if (root == DataRoot::Library) {
    // library#02 hash:bits256: a level-0 exotic root that cannot be read as data.
    vm::CellBuilder cb;
    CHECK(cb.store_long_bool(static_cast<int>(vm::Cell::SpecialType::Library), 8));
    cb.store_zeroes(256);
    ctx.parsed.data_cell = cb.finalize(true);
  }
  return ctx;
}

struct Outcome {
  td::Result<std::string> delegations = td::Status::Error("not called");
  td::Result<td::Unit> check = td::Status::Error("not called");
  bool delegations_called = false;
  bool check_called = false;
  int delegations_queries = 0;
  int check_queries = 0;
};

Outcome run_both(DataRoot root, td::uint32 start_at, td::RefInt256 balance = td::make_refint(kAvailableBalance)) {
  Outcome outcome;
  {
    FakeLiteserver server;
    server.balance = balance;
    tos::PermissionInspectionQuery query_opts;
    query_opts.include_inactive = true;
    tos::restricted_delegations_json(server.send_query(), restricted_context(root, start_at), query_opts,
                                     td::PromiseCreator::lambda([&](td::Result<std::string> R) {
                                       outcome.delegations_called = true;
                                       outcome.delegations = std::move(R);
                                     }));
    ASSERT_STREQ("", server.unexpected);
    outcome.delegations_queries = server.queries;
  }
  {
    FakeLiteserver server;
    server.balance = balance;
    auto ctx = restricted_context(root, start_at);
    auto ref = ctx.addr_str + ":restricted-vesting:0";
    tos::check_restricted_delegation_ref(server.send_query(), std::move(ctx), std::move(ref),
                                         td::PromiseCreator::lambda([&](td::Result<td::Unit> R) {
                                           outcome.check_called = true;
                                           outcome.check = std::move(R);
                                         }));
    ASSERT_STREQ("", server.unexpected);
    outcome.check_queries = server.queries;
  }
  ASSERT_TRUE(outcome.delegations_called);
  ASSERT_TRUE(outcome.check_called);
  return outcome;
}

bool has_text(td::Slice haystack, td::Slice needle) {
  return haystack.str().find(needle.str()) != std::string::npos;
}

std::string field(const char* name, td::uint32 value) {
  return PSTRING() << "\"" << name << "\":" << value;
}

void expect_unreadable_root_refused(DataRoot root) {
  auto outcome = run_both(root, 0);
  ASSERT_TRUE(outcome.delegations.is_error());
  ASSERT_TRUE(has_text(outcome.delegations.error().message(), "DELEGATION_UNAVAILABLE"));
  ASSERT_TRUE(outcome.check.is_error());
  ASSERT_TRUE(has_text(outcome.check.error().message(), "DELEGATION_UNAVAILABLE"));
  // The refusal came from the root check, before any liteserver query.
  ASSERT_EQ(0, outcome.delegations_queries);
  ASSERT_EQ(0, outcome.check_queries);
}

}  // namespace

TEST(JsonRpcAccountCapability, future_vesting_start_is_reported_and_refused) {
  const td::uint32 start_at = kSyncUtime + 3600;
  auto outcome = run_both(DataRoot::Wallet, start_at);
  ASSERT_TRUE(outcome.delegations.is_ok());
  const auto& json = outcome.delegations.ok();
  ASSERT_TRUE(has_text(json, field("not_before", start_at)));
  ASSERT_TRUE(has_text(json, field("vesting_start", start_at)));
  ASSERT_TRUE(outcome.check.is_error());
  ASSERT_TRUE(has_text(outcome.check.error().message(), "DELEGATION_SCOPE_VIOLATION"));
  ASSERT_TRUE(has_text(outcome.check.error().message(), PSTRING() << "vesting_start=" << start_at));
  // getMasterchainInfo and runSmcMethod for each of get_public_key and balance.
  ASSERT_EQ(4, outcome.delegations_queries);
  ASSERT_EQ(4, outcome.check_queries);
}

TEST(JsonRpcAccountCapability, zero_vesting_start_has_no_not_before_and_is_allowed) {
  auto outcome = run_both(DataRoot::Wallet, 0);
  ASSERT_TRUE(outcome.delegations.is_ok());
  ASSERT_TRUE(has_text(outcome.delegations.ok(), "\"not_before\":null"));
  ASSERT_TRUE(outcome.check.is_ok());
}

TEST(JsonRpcAccountCapability, past_vesting_start_is_reported_and_allowed) {
  const td::uint32 start_at = kSyncUtime - 1;
  auto outcome = run_both(DataRoot::Wallet, start_at);
  ASSERT_TRUE(outcome.delegations.is_ok());
  ASSERT_TRUE(has_text(outcome.delegations.ok(), field("not_before", start_at)));
  ASSERT_TRUE(outcome.check.is_ok());
}

TEST(JsonRpcAccountCapability, null_data_root_is_unavailable) {
  expect_unreadable_root_refused(DataRoot::Null);
}

TEST(JsonRpcAccountCapability, exotic_data_root_is_unavailable) {
  expect_unreadable_root_refused(DataRoot::Library);
}

TEST(JsonRpcAccountCapability, reserve_subtraction_is_checked) {
  ASSERT_EQ(3, tos::restricted_reserve(5, 2).move_as_ok());
  // More available than held: nothing is reserved.
  ASSERT_EQ(0, tos::restricted_reserve(2, 5).move_as_ok());
  const auto min = std::numeric_limits<td::int64>::min();
  const auto max = std::numeric_limits<td::int64>::max();
  for (auto [full, available] : {std::pair<td::int64, td::int64>{min, 1}, {max, -1}}) {
    auto r = tos::restricted_reserve(full, available);
    ASSERT_TRUE(r.is_error());
    ASSERT_TRUE(has_text(r.error().message(), "DELEGATION_UNAVAILABLE: reserve overflow"));
  }
}

TEST(JsonRpcAccountCapability, balance_outside_int64_is_unavailable) {
  // The conversion returns a sentinel for a value that does not fit; reading it
  // as a balance would silently report nothing available.
  auto wide = td::make_refint(1) << 70;
  auto outcome = run_both(DataRoot::Wallet, 0, wide);
  ASSERT_TRUE(outcome.delegations.is_error());
  ASSERT_TRUE(has_text(outcome.delegations.error().message(), "DELEGATION_UNAVAILABLE"));
  ASSERT_TRUE(has_text(outcome.delegations.error().message(), "outside int64"));
  ASSERT_TRUE(outcome.check.is_error());
  ASSERT_TRUE(has_text(outcome.check.error().message(), "outside int64"));
}
