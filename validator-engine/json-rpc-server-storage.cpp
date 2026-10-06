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
#include <limits>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "td/utils/StringBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

#include "json-rpc-server-storage.h"

namespace tos {

namespace {

td::Result<td::optional<AccountStorageStat>> unpack_storage_stat(td::Ref<vm::Cell> account_root) {
  auto cs = vm::load_cell_slice(std::move(account_root));
  if (block::gen::t_Account.get_tag(cs) == block::gen::Account::account_none) {
    return td::optional<AccountStorageStat>{};
  }
  block::gen::Account::Record_account account;
  if (!tlb::unpack(cs, account)) {
    return td::Status::Error("account cell does not unpack");
  }
  // The same fields, in the same order, that block::Account::unpack_storage_info
  // reads for the storage phase.
  block::gen::StorageInfo::Record info;
  block::gen::StorageUsed::Record used;
  if (!tlb::csr_unpack(account.storage_stat, info) || !tlb::csr_unpack(info.used, used)) {
    return td::Status::Error("account storage_stat does not unpack");
  }
  AccountStorageStat stat;
  stat.used_cells = block::tlb::t_VarUInteger_7.as_uint(*used.cells);
  stat.used_bits = block::tlb::t_VarUInteger_7.as_uint(*used.bits);
  if (stat.used_cells == std::numeric_limits<td::uint64>::max() ||
      stat.used_bits == std::numeric_limits<td::uint64>::max()) {
    return td::Status::Error("account storage_used does not unpack");
  }
  stat.last_paid = info.last_paid;
  if (info.due_payment->prefetch_ulong(1) == 1) {
    vm::CellSlice& due = info.due_payment.write();
    due.advance(1);
    stat.due_payment = block::tlb::t_Tomis.as_integer_skip(due);
    if (stat.due_payment.is_null() || !due.empty_ext()) {
      return td::Status::Error("account due_payment does not unpack");
    }
  }
  return td::optional<AccountStorageStat>(std::move(stat));
}

}  // namespace

td::Result<td::optional<AccountStorageStat>> parse_account_storage_stat(td::Ref<vm::Cell> account_root) {
  if (account_root.is_null()) {
    return td::optional<AccountStorageStat>{};
  }
  // The account is contract-controlled data reached from an unauthenticated request:
  // a malformed or exotic cell must become an error, not an exception in the actor.
  try {
    return unpack_storage_stat(std::move(account_root));
  } catch (vm::VmError& error) {
    return td::Status::Error(PSLICE() << "account storage_stat: " << error.get_msg());
  } catch (vm::VmVirtError& error) {
    return td::Status::Error(PSLICE() << "account storage_stat: " << error.get_msg());
  }
}

std::string account_storage_stat_json(const AccountStorageStat& stat) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"storage.stat\""
     << ",\"used_cells\":\"" << stat.used_cells << "\""
     << ",\"used_bits\":\"" << stat.used_bits << "\""
     << ",\"last_paid\":" << stat.last_paid << ",\"due_payment\":";
  if (stat.due_payment.is_null()) {
    sb << "null";
  } else {
    sb << "\"" << stat.due_payment->to_dec_string() << "\"";
  }
  sb << "}";
  return sb.as_cslice().str();
}

}  // namespace tos
