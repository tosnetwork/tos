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

// The JSON-RPC codes a refused estimate travels under: a request the executor
// would reject (INVALID_ARGUMENT), and an account whose execution the estimate
// does not model (CONTRACT_KIND_UNSUPPORTED).
inline constexpr int kEstimateRejectedCode = -32602;
inline constexpr int kEstimateUnsupportedCode = -32006;

// The account an estimate is made against, in the terms the executor's compute
// phase decides by. An account that does not exist is uninitialized.
struct EstimateAccount {
  enum class Status { Uninitialized, Active, Frozen };
  Status status = Status::Uninitialized;
  // An active account's code and data.
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  // The hash of the StateInit a frozen account was frozen with.
  td::Bits256 frozen_state_hash = td::Bits256::zero();
};

// The configuration the executor's StateInit admission depends on.
struct EstimateRules {
  // ConfigParam 8. Before global version 8 an external message's StateInit
  // must hash to the address whatever the account's state, so a frozen account
  // cannot be unfrozen into a state other than its address.
  int global_version = 0;
  // ConfigParam 44 lists the address while the suspension is in force: the
  // executor does not deploy it.
  bool address_suspended = false;
};
inline constexpr int kExternalUnfreezeGlobalVersion = 8;

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

// Refuses, with kEstimateRejectedCode, every request the executor's compute
// phase skips as having no usable state, so that no fee is quoted for a
// message that would never execute:
//   * an uninitialized account and no StateInit, or a StateInit whose hash is
//     not the address;
//   * a frozen account and no StateInit, or a StateInit whose hash is not the
//     hash the account was frozen with;
//   * an active account and a StateInit whose hash is not the address;
//   * before global version 8, any StateInit whose hash is not the address;
//   * an uninitialized account whose address is suspended.
// Also refuses a request that leaves nothing to run (a StateInit without code
// for an account that is not active), and fails when the body is missing or the
// message cannot be built.
td::Result<ExternalMessageEstimate> plan_external_message_estimate(
    const block::StdAddress& address, td::Ref<vm::Cell> body, const td::Ref<vm::Cell>& init_code,
    const td::Ref<vm::Cell>& init_data, const EstimateAccount& account, const EstimateRules& rules);

// The import fee (in_fwd_fee) the executor charges for importing `message` as an
// inbound external message: the forwarding price of every cell and bit beyond
// the root cell, which the lump price pays for, and nothing for a special
// account. Refuses, with kEstimateRejectedCode, a message the executor does not
// import under `limits` (ConfigParam 43): deeper than the external message depth
// limit, more cells or bits beyond the root than the message limits, or Merkle
// proofs nested deeper than the executor allows. Fails on a message that is not
// an inbound external message, and on a fee that does not fit the signed 64-bit
// field it is served in.
td::Result<td::int64> external_message_import_fee(const td::Ref<vm::Cell>& message, const block::MsgPrices& prices,
                                                  bool special_account, const block::SizeLimitsConfig& limits);

// Refuses, with kEstimateUnsupportedCode, a workchain whose compute phase is not
// TVM: the executor charges such an account no import fee and runs its own
// engine, neither of which an estimate made by emulating TVM can price.
td::Status check_estimate_workchain(const block::WorkchainSet& workchains, tos::WorkchainId workchain);

}  // namespace tos
