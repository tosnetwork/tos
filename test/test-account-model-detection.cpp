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

// The JSON-RPC surface tells a caller what an account is before the caller
// signs anything for it, so the recognition tables have to describe the code
// this build actually carries. These tests pin that: every entry keyed on a
// contract compiled from crypto/smartcont is looked up by the hash of that
// compiled code, so changing a contract source without touching anything else
// goes red here instead of silently reporting an account as unknown.

#include "json-rpc-account-model.h"
#include "smc-envelope/SmartContractCode.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

namespace {

td::Ref<vm::Cell> compiled(tos::SmartContractCode::Type type) {
  auto code = tos::SmartContractCode::get_code(type);
  CHECK(code.not_null());
  return code;
}

// A cell no contract in this repository compiles to.
td::Ref<vm::Cell> foreign_code() {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0xdeadbeef, 32));
  return cb.finalize();
}

}  // namespace

TEST(AccountModel, compiled_wallets_are_recognised_by_their_compiled_hash) {
  ASSERT_EQ("wallet v3 r2", tos::detect_wallet_type(compiled(tos::SmartContractCode::WalletV3)->get_hash(0)));
  ASSERT_EQ("wallet v4 r2", tos::detect_wallet_type(compiled(tos::SmartContractCode::WalletV4)->get_hash(0)));
  ASSERT_EQ("wallet v5 r1", tos::detect_wallet_type(compiled(tos::SmartContractCode::WalletV5)->get_hash(0)));
}

TEST(AccountModel, unknown_code_is_not_claimed_to_be_a_wallet) {
  ASSERT_EQ("", tos::detect_wallet_type(foreign_code()->get_hash(0)));
}

TEST(AccountModel, contracts_compiled_here_report_their_own_model) {
  ASSERT_EQ("advanced.wallet.multisig",
            tos::detect_account_model_for(compiled(tos::SmartContractCode::Multisig), "active", ""));
  ASSERT_EQ("advanced.wallet.restricted",
            tos::detect_account_model_for(compiled(tos::SmartContractCode::RestrictedWallet), "active", ""));
  ASSERT_EQ("advanced.wallet.session",
            tos::detect_account_model_for(compiled(tos::SmartContractCode::SessionWallet), "active", ""));
  ASSERT_EQ("contract.agent.account",
            tos::detect_account_model_for(compiled(tos::SmartContractCode::AgentAccount), "active", ""));
}

TEST(AccountModel, wallet_type_routes_before_code_comparison) {
  ASSERT_EQ("default.wallet.v1", tos::detect_account_model_for(foreign_code(), "active", "wallet v5 r1"));
  ASSERT_EQ("advanced.wallet.highload", tos::detect_account_model_for(foreign_code(), "active", "highload v2"));
  ASSERT_EQ("contract.pool.nominator",
            tos::detect_account_model_for(foreign_code(), "active", "nominator pool v1"));
  ASSERT_EQ("unknown.wallet", tos::detect_account_model_for(foreign_code(), "active", "something else"));
}

TEST(AccountModel, states_without_recognised_code_fall_back_to_state) {
  ASSERT_EQ("advanced.unknown", tos::detect_account_model_for(foreign_code(), "active", ""));
  ASSERT_EQ("state.active", tos::detect_account_model_for({}, "active", ""));
  ASSERT_EQ("state.uninitialized", tos::detect_account_model_for({}, "uninitialized", ""));
  ASSERT_EQ("state.frozen", tos::detect_account_model_for({}, "frozen", ""));
  ASSERT_EQ("unknown", tos::detect_account_model_for({}, "something else", ""));
}
