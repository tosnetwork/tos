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
#include "json-rpc-server-parse.h"

#include "td/utils/SharedSlice.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

namespace tos {

namespace {

// Runs `f` and converts every VM-level exception into a td::Status so that
// nothing propagates into the actor scheduler.
template <class F>
auto guard_vm(F&& f) -> decltype(f()) {
  try {
    return f();
  } catch (vm::VmError& err) {
    return td::Status::Error(PSTRING() << "vm error: " << err.get_msg());
  } catch (vm::VmVirtError& err) {
    return td::Status::Error(PSTRING() << "vm virtualization error: " << err.get_msg());
  } catch (std::exception& err) {
    return td::Status::Error(PSTRING() << "exception: " << err.what());
  }
}

}  // namespace

td::Result<td::Ref<vm::Stack>> parse_get_method_result_stack(td::Slice result_boc) {
  return guard_vm([&]() -> td::Result<td::Ref<vm::Stack>> {
    TRY_RESULT_PREFIX(root, vm::std_boc_deserialize(result_boc), "result BOC parse error: ");
    if (root.is_null()) {
      return td::Status::Error("result BOC parse error: empty root");
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(root, special);
    if (special) {
      return td::Status::Error("result stack deserialize error: exotic root cell");
    }
    auto stk = td::make_ref<vm::Stack>();
    if (!stk.write().deserialize(cs)) {
      return td::Status::Error("result stack deserialize error");
    }
    return stk;
  });
}

td::Result<std::vector<std::string>> parse_multisig_public_keys(td::Ref<vm::Cell> dict_root) {
  return guard_vm([&]() -> td::Result<std::vector<std::string>> {
    std::vector<std::string> principals;
    if (dict_root.is_null()) {
      return principals;
    }
    vm::Dictionary dict(std::move(dict_root), 8);
    td::Status status;
    bool ok = dict.check_for_each([&](td::Ref<vm::CellSlice> cs, td::ConstBitPtr, int) {
      if (cs.is_null() || cs->size() < 256) {
        status = td::Status::Error("public key entry shorter than 256 bits");
        return false;
      }
      td::SecureString key(32);
      cs->prefetch_bytes(key.as_mutable_slice().ubegin(), td::narrow_cast<int>(key.size()));
      principals.push_back(PSTRING() << "ed25519:" << td::hex_encode(key.as_slice()));
      return true;
    });
    if (status.is_error()) {
      return std::move(status);
    }
    if (!ok) {
      return td::Status::Error("malformed public key dictionary");
    }
    return principals;
  });
}

td::Result<td::uint32> parse_restricted_wallet_start_at(td::Ref<vm::Cell> data_cell) {
  return guard_vm([&]() -> td::Result<td::uint32> {
    if (data_cell.is_null()) {
      return td::Status::Error("account has no data cell");
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(std::move(data_cell), special);
    if (special) {
      return td::Status::Error("data root is an exotic cell");
    }
    // seqno(32) + subwallet_id(32) + public_key(256) = 320 bits, then start_at(32)
    if (!cs.have(352)) {
      return td::uint32{0};
    }
    cs.advance(320);
    return static_cast<td::uint32>(cs.fetch_ulong(32));
  });
}

}  // namespace tos
