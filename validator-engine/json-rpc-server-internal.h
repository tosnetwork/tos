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

#include "json-rpc-explorer.h"
#include "json-rpc-server-fee.h"
#include "json-rpc-server-parse.h"
#include "json-rpc-server-runresult.h"
#include "json-rpc-server-storage.h"
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
struct ParsedAccountState;
inline constexpr std::size_t kExplorerResponseBudgetBytes = 192u << 20;
std::shared_ptr<http::BodyBudget::Reservation> reserve_explorer_response(std::size_t bytes);
std::string render_config_validator_set_json(int config_id, td::Ref<vm::Cell> param_cell);
std::string build_account_capability_json(const std::string& address, const ParsedAccountState& parsed,
                                          const std::string& account_model, const std::string& authorization_version,
                                          bool supports_sponsorship, bool include_sponsorship);
std::string build_wallet_json(bool is_wallet, td::int64 balance, const std::string& account_state,
                              const std::string& wallet_type, td::int64 seqno, td::uint64 last_lt,
                              const std::string& last_hash_b64, const std::string& observed_mc_block,
                              const std::string& observed_shard_block, td::int64 wallet_id = -1);

// ─── Shared: parse address parameter ────────────────────────────────────

td::Result<block::StdAddress> parse_address_param(td::JsonObject& params);

// ─── Shared: block ID JSON formatters ───────────────────────────────────

std::string format_zero_state_json(const tos::lite_api::tosNode_zeroStateIdExt& zs);

// ─── Shared: ParsedAccountState (declaration only) ──────────────────────

struct ParsedAccountState {
  // Reported as a number where the shape requires one; a balance wider
  // than this type saturates rather than wrapping to a negative.
  td::int64 balance = 0;
  // The same balance in full precision, for the fields carrying it as a
  // string. A Tomis amount is up to 2^120, so a 64-bit conversion is not
  // guaranteed to be exact.
  std::string balance_dec = "0";
  std::string state_str = "uninitialized";
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
  // The account's storage metadata, served as "storage_stat"; empty for an
  // account that does not exist.
  td::optional<AccountStorageStat> storage_stat;

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

// ─── Shared: wallet/account-model detection ───────────────────────────
// Defined in json-rpc-server-account-capability.cpp; called from
// json-rpc-server-send.cpp for capability auto-discovery.

std::string detect_wallet_type(const vm::CellHash& code_hash);
std::string detect_account_model(const ParsedAccountState& parsed,
                                 const std::string& wallet_type);
std::string detect_authorization_version(const std::string& wallet_type);

// ─── estimateFee: from the fetched state to the answer ─────────────────
// Defined in json-rpc-server-send.cpp. The handler fetches and verifies the
// account state and the config; everything it decides from them is here, so a
// test can hold the answer to the executor.

struct EstimateFeeRequest {
  block::StdAddress address;
  td::Ref<vm::Cell> body;
  // Null when the request leaves them out.
  td::Ref<vm::Cell> init_code;
  td::Ref<vm::Cell> init_data;
  bool ignore_chksig = true;
};

// The account in the executor's terms: active (with its code and data), frozen
// (with the hash it was frozen with), or uninitialized, which includes an
// account that does not exist.
td::Result<EstimateAccount> estimate_account_from(const ParsedAccountState& parsed);

// The `query.fees` result for `request` against `parsed` under `cfg` (with its
// library dictionary, null for none). Errors carry the JSON-RPC code they are
// answered with: kEstimateRejectedCode for a request the executor would reject,
// kEstimateUnsupportedCode for a workchain the estimate does not model, -32603
// otherwise. execution_time is the verified masterchain context time; account
// shard proofs can predate it and must not set admission or emulation time.
td::Result<std::string> estimate_external_message_fees(
    const EstimateFeeRequest& request, const ParsedAccountState& parsed, std::shared_ptr<const block::Config> cfg,
    td::Ref<vm::Cell> libraries_root, td::Ref<vm::Tuple> prev_blocks_info, tos::UnixTime execution_time);

// ─── Shared: AccountCapabilityContext ──────────────────────────────────

struct AccountCapabilityContext {
  block::StdAddress addr;
  std::string addr_str;
  ParsedAccountState parsed;
  std::string wallet_type;
  std::string account_model;
  std::string authorization_version;
};

}  // namespace tos
