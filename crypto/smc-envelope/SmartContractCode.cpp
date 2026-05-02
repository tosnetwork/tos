/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <map>

#include "td/utils/base64.h"
#include "vm/boc.h"

#include "SmartContractCode.h"

namespace tos {
namespace {
// WALLET_REVISION = 2;
// WALLET2_REVISION = 2;
// WALLET3_REVISION = 2;
// WALLET4_REVISION = 2;
// HIGHLOAD_WALLET_REVISION = 2;
// HIGHLOAD_WALLET2_REVISION = 2;
// DNS_REVISION = 1;
const auto& get_map() {
  static auto map = [] {
    std::map<std::string, td::Ref<vm::Cell>, std::less<>> map;
    auto with_tvm_code = [&](auto name, td::Slice code_str) {
      map[name] = vm::std_boc_deserialize(td::base64_decode(code_str).move_as_ok()).move_as_ok();
    };
#include "smartcont/auto/dns-manual-code.cpp"
#include "smartcont/auto/highload-wallet-code.cpp"
#include "smartcont/auto/highload-wallet-v2-code.cpp"
#include "smartcont/auto/multisig-code.cpp"
#include "smartcont/auto/payment-channel-code.cpp"
#include "smartcont/auto/restricted-wallet3-code.cpp"
#include "smartcont/auto/wallet-code.cpp"

#include "smartcont/auto/session-wallet-code.cpp"
#include "smartcont/auto/wallet3-code.cpp"
#include "smartcont/auto/wallet-v4-code.cpp"
#include "smartcont/auto/wallet-v5-code.cpp"
    return map;
  }();
  return map;
}
}  // namespace

td::Result<td::Ref<vm::Cell>> SmartContractCode::load(td::Slice name) {
  auto& map = get_map();
  auto it = map.find(name);
  if (it == map.end()) {
    return td::Status::Error(PSLICE() << "Can't load td::Ref<vm::Cell> " << name);
  }
  return it->second;
}

td::Span<int> SmartContractCode::get_revisions(Type type) {
  switch (type) {
    case Type::WalletV3: {
      static int res[] = {-1};
      return res;
    }
    case Type::HighloadWalletV1: {
      static int res[] = {-1};
      return res;
    }
    case Type::HighloadWalletV2: {
      static int res[] = {-1};
      return res;
    }
    case Type::Multisig: {
      static int res[] = {-1};
      return res;
    }
    case Type::ManualDns: {
      static int res[] = {-1};
      return res;
    }
    case Type::PaymentChannel: {
      static int res[] = {-1};
      return res;
    }
    case Type::RestrictedWallet: {
      static int res[] = {-1};
      return res;
    }
    case Type::WalletV4: {
      static int res[] = {-1};
      return res;
    }
    case Type::WalletV5: {
      static int res[] = {-1};
      return res;
    }
    case Type::SessionWallet: {
      static int res[] = {-1};
      return res;
    }
  }
  UNREACHABLE();
}

td::Result<int> SmartContractCode::validate_revision(Type type, int revision) {
  auto revisions = get_revisions(type);
  if (revision == -1) {
    if (revisions[0] == -1) {
      return -1;
    }
    return revisions[revisions.size() - 1];
  }
  if (revision == 0) {
    return revisions[revisions.size() - 1];
  }
  for (auto x : revisions) {
    if (x == revision) {
      return revision;
    }
  }
  return td::Status::Error("No such revision");
}

td::Ref<vm::Cell> SmartContractCode::get_code(Type type, int ext_revision) {
  auto revision = validate_revision(type, ext_revision).move_as_ok();
  auto basename = [](Type type) -> td::Slice {
    switch (type) {
      case Type::WalletV3:
        return "wallet3";
      case Type::HighloadWalletV1:
        return "highload-wallet";
      case Type::HighloadWalletV2:
        return "highload-wallet-v2";
      case Type::Multisig:
        return "multisig";
      case Type::ManualDns:
        return "dns-manual";
      case Type::PaymentChannel:
        return "payment-channel";
      case Type::RestrictedWallet:
        return "restricted-wallet3";
      case Type::WalletV4:
        return "wallet_v4";
      case Type::WalletV5:
        return "wallet_v5";
      case Type::SessionWallet:
        return "session-wallet";
    }
    UNREACHABLE();
  }(type);
  if (revision == -1) {
    return load(basename).move_as_ok();
  }
  return load(PSLICE() << basename << "-r" << revision).move_as_ok();
}

}  // namespace tos
