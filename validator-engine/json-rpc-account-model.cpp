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
#include "json-rpc-account-model.h"

#include <map>

#include "crypto/smc-envelope/SmartContractCode.h"
#include "td/utils/check.h"

namespace tos {
namespace {

// Code this build compiles from crypto/smartcont, keyed by the hash of that
// code rather than by a copy of it. A contract change then cannot leave this
// table describing bytecode the chain no longer runs: there is no second copy
// of the value to forget to update.
std::string compiled_code_hash(SmartContractCode::Type type) {
  auto code = SmartContractCode::get_code(type);
  CHECK(code.not_null());
  return code->get_hash().to_hex();
}

bool code_is(const td::Ref<vm::Cell>& code_cell, SmartContractCode::Type type) {
  auto code = SmartContractCode::get_code(type);
  return code.not_null() && code_cell->get_hash(0) == code->get_hash(0);
}

}  // namespace

std::string detect_wallet_type(const vm::CellHash& code_hash) {
  static const std::map<std::string, std::string> known_wallets = [] {
    // Foreign wallet code this chain did not build: the hash is the only
    // description we have of it, so it stays a literal.
    std::map<std::string, std::string> wallets = {
        {"89C890A6C9B5A3828B38570A93DFC93C792EE9147933DE8F21F5840AE19AB1AA", "wallet v1 r1"},
        {"27B5063EBDB6E5ECEC073F57451A4BE095EB68777496B65449B1B49FA09A43D9", "wallet v1 r2"},
        {"1F08EBE871907C8B60AA1BB9C22A54CB095D1DC0E007A3D7AF827D1C4DE23910", "wallet v1 r3"},
        {"8369FDDA46A532A8302037D955D92D7A3308422EADF0074C497CECD209832C3A", "wallet v2 r1"},
        {"9264711341AB55499665D16B4589A148ED6AB8A4AED3AE9FCF805295EEE7B927", "wallet v2 r2"},
        {"F475EC633EA8EC25B6872878B95996AEEA061198BD1C86180D3984EA7E1E6FB4", "wallet v3 r1"},
        {"09BE881BEFFE710D6BB4BD030A2506BEF85C10FF1AC44DF93B0B29282945916F", "wallet v3 r2"},
        {"6B5FD33048D2DB82650B36F47CED9714A1C0B573AA08447E23F96629364DDA2A", "wallet v4 r1"},
        {"288014A04D551904D623C826512FFEB16AD4DF6130195EA537050B35207E5FC3", "wallet v4 r2"},
        {"7AFA0EACBAF9E9EAA19AE93E61354540C9335B52F1ADD44E7A8E2D9089212B3E", "wallet v5 r1"},
        // Recognizing an account as a staking pool tells a depositor that the
        // code holding their principal is the audited contract in this
        // repository, so this entry has to stay reproducible from
        // crypto/smartcont/nominator-pool.
        // scripts/check-nominator-pool-code-lock.sh enforces that.
        {"9A3EC14BC098F6B44064C305222CAEA2800F17DDA85EE6A8198A7095EDE10DCF", "nominator pool v1"},
        {"BCD75D29A1D932013CF31300C5D924A5F02EAA92CD830EC0330104FFBAD07928", "wallet v1 r1"},
        {"9CEC5155DCB2B37716C032C5EF85947C01E32C4405A2611EE8D1122AFFF0E0C1", "highload v1"},
        {"DE7D8832DDC838811F940EF0CECBBC95C6CD2CEF83E9D22ABCE5E1A1DBA5638A", "highload v2"},
    };
    // Network-bound wallets compiled from crypto/smartcont: each signed body
    // starts with the network global_id and the code rejects any other value,
    // so a message signed for one network cannot be replayed on another.
    wallets[compiled_code_hash(SmartContractCode::WalletV3)] = "wallet v3 r2";
    wallets[compiled_code_hash(SmartContractCode::WalletV4)] = "wallet v4 r2";
    wallets[compiled_code_hash(SmartContractCode::WalletV5)] = "wallet v5 r1";
    return wallets;
  }();
  auto it = known_wallets.find(code_hash.to_hex());
  return it != known_wallets.end() ? it->second : "";
}

std::string detect_account_model_for(const td::Ref<vm::Cell>& code_cell, td::Slice state_str,
                                     const std::string& wallet_type) {
  if (!wallet_type.empty()) {
    if (wallet_type.rfind("wallet ", 0) == 0) {
      return "default.wallet.v1";
    }
    if (wallet_type.rfind("highload", 0) == 0) {
      return "advanced.wallet.highload";
    }
    if (wallet_type.rfind("nominator pool", 0) == 0) {
      return "contract.pool.nominator";
    }
    return "unknown.wallet";
  }
  if (code_cell.not_null()) {
    if (code_is(code_cell, SmartContractCode::Type::Multisig)) {
      return "advanced.wallet.multisig";
    }
    if (code_is(code_cell, SmartContractCode::Type::RestrictedWallet)) {
      return "advanced.wallet.restricted";
    }
    if (code_is(code_cell, SmartContractCode::Type::SessionWallet)) {
      return "advanced.wallet.session";
    }
    // An agent account is not a wallet: it spends under a stored policy on
    // behalf of an owner, so it reports its own model rather than falling
    // through to "advanced.unknown".
    if (code_is(code_cell, SmartContractCode::Type::AgentAccount)) {
      return "contract.agent.account";
    }
  }
  if (state_str == "uninitialized") {
    return "state.uninitialized";
  }
  if (state_str == "frozen") {
    return "state.frozen";
  }
  if (state_str == "active") {
    return code_cell.not_null() ? "advanced.unknown" : "state.active";
  }
  return "unknown";
}

}  // namespace tos
