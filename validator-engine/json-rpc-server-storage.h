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
#pragma once

// An account's storage metadata, as the storage phase reads it: the cells and bits
// the account is charged for, when it last paid, and any storage debt it carries.
// A client bounding what a wallet will be charged for its next transaction needs all
// four; code and data alone are not a bound (they omit the library dictionary,
// extra currencies under older global versions, and any debt).

#include <string>

#include "common/refint.h"
#include "td/utils/Status.h"
#include "td/utils/int_types.h"
#include "td/utils/optional.h"
#include "vm/cells.h"

namespace tos {

struct AccountStorageStat {
  td::uint64 used_cells = 0;
  td::uint64 used_bits = 0;
  td::uint32 last_paid = 0;
  // Null when the account records no due payment.
  td::RefInt256 due_payment;
};

// From an Account cell (account$1 or account_none$0). An empty optional for a null
// root or account_none: a nonexistent account has no storage metadata. Fails, rather
// than throwing, on a malformed cell.
td::Result<td::optional<AccountStorageStat>> parse_account_storage_stat(td::Ref<vm::Cell> account_root);

// The "storage_stat" object of getAddressInformation and
// getExtendedAddressInformation:
//   {"@type":"storage.stat","used_cells":"<dec>","used_bits":"<dec>",
//    "last_paid":<uint32>,"due_payment":"<dec>"|null}
std::string account_storage_stat_json(const AccountStorageStat& stat);

}  // namespace tos
