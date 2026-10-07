/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <vector>

#include "block/mc-config.h"
#include "vm/stack.hpp"

namespace block {

// The c7 used by a read-only get-method. Every value comes from the same account
// and masterchain snapshot; the caller supplies the seed for this execution.
td::Ref<vm::Tuple> prepare_get_method_c7(tos::UnixTime now, tos::LogicalTime lt, td::Ref<vm::CellSlice> address,
                                         const CurrencyCollection& balance, const ConfigInfo* config,
                                         td::Ref<vm::Cell> code, td::RefInt256 due_payment,
                                         const td::BitArray<256>& seed);

// Library collections in VM lookup order. Account libraries cease to be eligible
// from global version 15; the global collection remains eligible.
std::vector<td::Ref<vm::Cell>> get_method_libraries(const ConfigInfo& config, td::Ref<vm::Cell> account);

}  // namespace block
