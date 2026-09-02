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

// Pure parsers for chain data that the JSON-RPC server reads back from the
// liteserver. Everything here is reachable from an unauthenticated request
// and operates on cells that a contract author controls (account data,
// get-method results), so each function must return an error instead of
// letting a vm::VmError or vm::VmVirtError escape into the actor loop.
// They are free functions with no actor dependency so they can be unit
// tested with hostile inputs.

#include <string>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/stack.hpp"

namespace tos {

// Deserializes the serialized VM stack returned by liteServer.runSmcMethod.
// Fails, instead of throwing, when the BOC is malformed, the root or any
// nested cell is exotic (pruned branch, library, Merkle proof/update), or the
// stack encoding is invalid.
td::Result<td::Ref<vm::Stack>> parse_get_method_result_stack(td::Slice result_boc);

// Walks the `(Hashmap 8 PublicKey)` returned by a multisig's get_public_keys
// and renders each key as "ed25519:<hex>". Fails on malformed dictionary
// labels, exotic cells, and entries shorter than 256 bits.
td::Result<std::vector<std::string>> parse_multisig_public_keys(td::Ref<vm::Cell> dict_root);

// Reads start_at from a restricted wallet's data cell laid out as
// seqno(32) subwallet_id(32) public_key(256) start_at(32). Returns 0 when the
// cell is too short and fails when the root is exotic or null.
td::Result<td::uint32> parse_restricted_wallet_start_at(td::Ref<vm::Cell> data_cell);

}  // namespace tos
