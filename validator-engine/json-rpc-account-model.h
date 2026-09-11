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
#pragma once

// Account recognition, split out of the JSON-RPC server so it can be linked
// and tested without the node. It answers two questions about a code hash:
// which wallet layout it is, and which account model the JSON-RPC surface
// should report. Both depend only on the code a build carries, so keeping
// them here keeps them reachable from a unit test.

#include <string>

#include "td/utils/Slice.h"
#include "vm/cells.h"

namespace tos {

// Human-readable wallet name for a code hash, or "" when the code is not a
// wallet this build knows.
std::string detect_wallet_type(const vm::CellHash& code_hash);

// Account model reported for an account, given its code (may be null), its
// state string ("active"/"frozen"/"uninitialized") and the wallet type
// resolved for that code (may be empty).
std::string detect_account_model_for(const td::Ref<vm::Cell>& code_cell, td::Slice state_str,
                                     const std::string& wallet_type);

}  // namespace tos
