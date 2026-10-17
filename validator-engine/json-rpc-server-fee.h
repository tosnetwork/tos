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

// The external message sendQuery submits, and what estimateFee prices for the same
// request. An estimate is only useful if it prices the message that is actually
// sent: the import fee an external message pays depends on every cell it carries
// beyond its root, so a StateInit the sent message does not carry, or a body laid
// out differently, changes the fee.

#include "block/block.h"
#include "block/mc-config.h"
#include "td/utils/Status.h"
#include "td/utils/int_types.h"
#include "vm/cells.h"

namespace tos {

// The external message sendQuery submits to `address`: ext_in_msg_info with no
// source and a zero import fee, then the StateInit by reference exactly when the
// request supplies init_code or init_data, then the body by reference.
td::Result<td::Ref<vm::Cell>> build_query_external_message(const block::StdAddress& address,
                                                           const td::Ref<vm::Cell>& init_code,
                                                           const td::Ref<vm::Cell>& init_data,
                                                           td::Ref<vm::Cell> body) noexcept;

// What estimateFee prices and emulates for one request.
struct ExternalMessageEstimate {
  // The message sendQuery submits for the same address, body, init_code and
  // init_data: its import fee is the estimate's in_fwd_fee.
  td::Ref<vm::Cell> message;
  // The code and data the compute phase runs: the account's own when it is
  // active (the executor ignores a StateInit then), otherwise the request's.
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
};

// Fails when the body is missing, when the StateInit or the message cannot be
// built, or when there is no code to run: an account that is not active and a
// request without init_code.
td::Result<ExternalMessageEstimate> plan_external_message_estimate(
    const block::StdAddress& address, td::Ref<vm::Cell> body, const td::Ref<vm::Cell>& init_code,
    const td::Ref<vm::Cell>& init_data, bool account_active, const td::Ref<vm::Cell>& account_code,
    const td::Ref<vm::Cell>& account_data);

// The import fee (in_fwd_fee) the executor charges for importing `message` as an
// inbound external message of an ordinary account: the forwarding price of every
// cell and bit beyond the root cell, which the lump price pays for. Fails on a
// message that is not an inbound external message, and on a fee that does not
// fit the signed 64-bit field it is served in.
td::Result<td::int64> external_message_import_fee(const td::Ref<vm::Cell>& message, const block::MsgPrices& prices);

}  // namespace tos
