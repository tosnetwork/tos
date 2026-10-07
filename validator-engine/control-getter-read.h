/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "auto/tl/tos_api.h"

#include "control-getter.h"

namespace tos::control_getter {
enum class ReadKind { Elector, Proposals, Proposal };
struct Request {
  ReadKind kind;
  std::vector<td::Bits256> wallets;
  td::Bits256 hash;
};
// Called on a worker, after admission and acquisition of one immutable state.
td::Result<td::BufferSlice> read(const Snapshot& snapshot, const Request& request);
td::Status validate_wallets(const std::vector<td::Bits256>& wallets);
}  // namespace tos::control_getter
