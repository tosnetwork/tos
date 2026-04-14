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

#include "json-rpc-server.h"

// Minimal shared includes — each .cpp adds its own heavy deps
#include "auto/tl/lite_api.h"
#include "tl-utils/lite-utils.hpp"
#include "block/block.h"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "td/utils/base64.h"
#include "td/utils/JsonBuilder.h"

namespace tos {

// ─── Shared: parse address parameter ────────────────────────────────────

td::Result<block::StdAddress> parse_address_param(td::JsonObject& params);

// ─── Shared: block ID JSON formatters ───────────────────────────────────

std::string format_block_id_json(const tos::lite_api::tosNode_blockIdExt& blk);
std::string format_zero_state_json(const tos::lite_api::tosNode_zeroStateIdExt& zs);

// ─── Shared: ParsedAccountState (declaration only) ──────────────────────

struct ParsedAccountState {
  td::int64 balance = 0;
  std::string state_str = "uninit";
  std::string code_b64;
  std::string data_b64;
  std::string frozen_hash;
  td::uint64 last_trans_lt = 0;
  std::string last_trans_hash_b64;
  td::uint32 sync_utime = 0;
  td::Ref<vm::Cell> code_cell;
  td::Ref<vm::Cell> data_cell;
  td::Ref<vm::Cell> extra_currencies_cell;
  td::Ref<vm::Cell> state_cell;
  tos::UnixTime storage_last_paid{0};
  block::StorageUsed storage_used;

  td::int32 blk_workchain = -1;
  td::int64 blk_shard = static_cast<td::int64>(0x8000000000000000ULL);
  td::uint32 blk_seqno = 0;
  std::string blk_root_hash_b64;
  std::string blk_file_hash_b64;

  // Parse account state from liteserver response
  static td::Result<ParsedAccountState> parse(
      tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
      const block::StdAddress& addr);

  // JSON serializers
  std::string to_address_info_json() const;
  std::string to_extended_info_json(const std::string& addr_str) const;
};

}  // namespace tos
