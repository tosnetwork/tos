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
#include "smc-envelope/GenericAccount.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

#include "json-rpc-server-fee.h"

namespace tos {

td::Result<td::Ref<vm::Cell>> build_query_external_message(const block::StdAddress& address,
                                                           const td::Ref<vm::Cell>& init_code,
                                                           const td::Ref<vm::Cell>& init_data,
                                                           td::Ref<vm::Cell> body) noexcept {
  return TRY_VM(([&]() -> td::Result<td::Ref<vm::Cell>> {
    if (body.is_null()) {
      return td::Status::Error("Failed to build external message: body is empty");
    }
    // addr_std carries an int8 workchain; a wider one does not encode.
    if (address.workchain < -128 || address.workchain > 127) {
      return td::Status::Error(PSTRING() << "workchain " << address.workchain
                                         << " is out of the addr_std int8 range [-128, 127]");
    }

    // ext_in_msg_info$10 src:addr_none$00 dest:addr_std$10 (no anycast) import_fee:0
    vm::CellBuilder cb;
    if (!(cb.store_long_bool(0b10, 2) && cb.store_long_bool(0b00, 2) && cb.store_long_bool(0b10, 2) &&
          cb.store_zeroes_bool(1) && cb.store_long_bool(address.workchain, 8) &&
          cb.store_bits_bool(address.addr.cbits(), 256) && cb.store_zeroes_bool(4))) {
      return td::Status::Error("Failed to build external message header");
    }

    if (init_code.not_null() || init_data.not_null()) {
      TRY_RESULT(init_state, tos::GenericAccount::get_init_state_checked(init_code, init_data));
      // just$1 right$1 ^StateInit
      if (!(cb.store_ones_bool(2) && cb.store_ref_bool(std::move(init_state)))) {
        return td::Status::Error("Failed to store StateInit in external message");
      }
    } else if (!cb.store_zeroes_bool(1)) {
      return td::Status::Error("Failed to store empty StateInit in external message");
    }

    // right$1 ^body
    if (!(cb.store_ones_bool(1) && cb.store_ref_bool(std::move(body)))) {
      return td::Status::Error("Failed to store external message body");
    }
    return cb.finalize();
  })());
}

td::Result<ExternalMessageEstimate> plan_external_message_estimate(
    const block::StdAddress& address, td::Ref<vm::Cell> body, const td::Ref<vm::Cell>& init_code,
    const td::Ref<vm::Cell>& init_data, bool account_active, const td::Ref<vm::Cell>& account_code,
    const td::Ref<vm::Cell>& account_data) {
  ExternalMessageEstimate estimate;
  if (account_active) {
    estimate.code = account_code;
    estimate.data = account_data;
  } else {
    estimate.code = init_code;
    estimate.data = init_data;
  }
  if (estimate.code.is_null()) {
    return td::Status::Error("estimateFee requires deploy init_code/init_data or an active account state");
  }
  TRY_RESULT_ASSIGN(estimate.message, build_query_external_message(address, init_code, init_data, std::move(body)));
  return estimate;
}

td::Result<td::int64> external_message_import_fee(const td::Ref<vm::Cell>& message, const block::MsgPrices& prices) {
  if (message.is_null()) {
    return td::Status::Error("external message is empty");
  }
  return TRY_VM(([&]() -> td::Result<td::int64> {
    // The same accounting as the executor's import of an inbound external
    // message: unpack ext_in_msg_info, then count everything after it with the
    // root cell and the bits it holds left out.
    auto cs = vm::load_cell_slice(message);
    if (block::gen::t_CommonMsgInfo.get_tag(cs) != block::gen::CommonMsgInfo::ext_in_msg_info) {
      return td::Status::Error("not an inbound external message");
    }
    block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
    if (!tlb::unpack(cs, info)) {
      return td::Status::Error("external message header does not unpack");
    }
    vm::CellStorageStat stat;
    TRY_RESULT(cell_info, stat.compute_used_storage(cs));
    (void)cell_info;
    if (stat.bits < cs.size() || stat.cells < 1) {
      return td::Status::Error("external message storage accounting is inconsistent");
    }
    const td::uint64 bits = stat.bits - cs.size();
    const td::uint64 cells = stat.cells - 1;
    const td::uint64 fee = prices.compute_fwd_ihr_fees(cells, bits, true).first;
    if (fee > static_cast<td::uint64>(std::numeric_limits<td::int64>::max())) {
      return td::Status::Error("import fee exceeds the signed 64-bit range");
    }
    return static_cast<td::int64>(fee);
  })());
}

}  // namespace tos
