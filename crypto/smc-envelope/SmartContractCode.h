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
#pragma once
#include "td/utils/Span.h"
#include "vm/cells.h"

namespace tos {
class SmartContractCode {
 public:
  static td::Result<td::Ref<vm::Cell>> load(td::Slice name);

  enum Type {
    WalletV3 = 4,
    HighloadWalletV1,
    HighloadWalletV2,
    ManualDns,
    Multisig,
    PaymentChannel,
    RestrictedWallet,
    WalletV4,
    WalletV5,
    SessionWallet
  };
  static td::Span<int> get_revisions(Type type);
  static td::Result<int> validate_revision(Type type, int revision);
  static td::Ref<vm::Cell> get_code(Type type, int revision = 0);
};
}  // namespace tos
