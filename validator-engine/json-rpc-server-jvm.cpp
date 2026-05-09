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
#include "json-rpc-server-internal.h"

#include "auto/tl/lite_api.hpp"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "jvm/core/config-param.h"
#include "jvm/core/event-host.h"
#include "jvm/core/init.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/rpc.h"
#include "tl/tl_object_parse.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include <cctype>
#include <functional>
#include <vector>

namespace tos {
namespace {

constexpr td::int32 kJvmReceiptPageSize = 64;
constexpr std::uint64_t kJvmReceiptMaxScannedTransactions = 4096;
constexpr std::size_t kJvmReceiptMaxResults = 1024;

// Extract the per-contract wc=3 account address from a v2 jvm_callContract or
// jvm_getContractState request body.  Returns std::nullopt if the params are
// malformed or the field is absent.
std::optional<tos::StdSmcAddress> jvm_rpc_contract_address(
    const std::string& method, const std::string& params_json) {
  if (method == "jvm_callContract") {
    auto req = jvm_workchain::parse_jvm_call_contract_request(params_json);
    if (!req.has_value()) {
      return std::nullopt;
    }
    tos::StdSmcAddress addr;
    std::memcpy(addr.data(), req->contract_address.data(), 32);
    return addr;
  }
  if (method == "jvm_getContractState") {
    auto req = jvm_workchain::parse_jvm_get_contract_state_request(params_json);
    if (!req.has_value()) {
      return std::nullopt;
    }
    tos::StdSmcAddress addr;
    std::memcpy(addr.data(), req->contract_address.data(), 32);
    return addr;
  }
  return std::nullopt;
}

std::string jvm_rpc_hex_encode(td::Slice bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 + bytes.size() * 2);
  out += "0x";
  for (size_t i = 0; i < bytes.size(); ++i) {
    auto b = static_cast<unsigned char>(bytes[i]);
    out += kHex[(b >> 4) & 0x0f];
    out += kHex[b & 0x0f];
  }
  return out;
}

// True if the method needs the full-node to load the live per-account state
// (no `accountStateBoc` / legacy `executorStateBoc` in the params).
bool jvm_rpc_needs_live_account_state(const std::string& method,
                                      const std::string& params_json) {
  return (method == "jvm_callContract" || method == "jvm_getContractState")
      && params_json.find("\"accountStateBoc\"") == std::string::npos
      && params_json.find("\"executorStateBoc\"") == std::string::npos;
}

std::string jvm_rpc_hex_encode_bytes(const std::uint8_t* data,
                                     std::size_t size) {
  return jvm_rpc_hex_encode(
      td::Slice(reinterpret_cast<const char*>(data), size));
}

std::string jvm_rpc_contract_id_hex(
    const jvm_workchain::JvmContractId& contract_id) {
  return jvm_rpc_hex_encode_bytes(contract_id.data(), contract_id.size());
}

td::Result<vm::CellSlice> jvm_message_body_slice(td::Ref<vm::Cell> msg_cell) {
  if (msg_cell.is_null()) {
    return td::Status::Error("missing message cell");
  }
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) {
    return td::Status::Error("malformed message cell");
  }
  auto body = message.body.write();
  if (body.size() < 1) {
    return td::Status::Error("message body is empty");
  }
  auto in_ref = body.fetch_ulong(1);
  if (in_ref == 1) {
    if (!body.have_refs()) {
      return td::Status::Error("message body ref is missing");
    }
    return vm::load_cell_slice(body.fetch_ref());
  }
  return body;
}

td::Result<td::Ref<vm::Cell>> jvm_message_body_cell(
    td::Ref<vm::Cell> msg_cell,
    block::gen::CommonMsgInfo::Record_ext_out_msg_info* ext_info = nullptr) {
  if (msg_cell.is_null()) {
    return td::Status::Error("missing message cell");
  }
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) {
    return td::Status::Error("malformed event message cell");
  }
  if (block::gen::CommonMsgInfo().get_tag(*message.info)
      != block::gen::CommonMsgInfo::ext_out_msg_info) {
    return td::Status::Error("event message is not ext_out");
  }
  if (ext_info != nullptr && !tlb::csr_unpack(message.info, *ext_info)) {
    return td::Status::Error("malformed event ext_out info");
  }

  auto body = message.body.write();
  if (body.size() < 1) {
    return td::Status::Error("event message body is empty");
  }
  auto in_ref = body.fetch_ulong(1);
  if (in_ref == 1) {
    if (!body.have_refs()) {
      return td::Status::Error("event message body ref is missing");
    }
    return body.fetch_ref();
  }

  vm::CellBuilder cb;
  if (!cb.append_cellslice_bool(std::move(body))) {
    return td::Status::Error("event inline body cell build failed");
  }
  return cb.finalize();
}

bool jvm_transaction_matches_contract(
    td::Ref<vm::Cell> tx_root,
    const jvm_workchain::JvmContractId& /*contract_address*/) {
  // Under the account-native topology each contract is its own wc=3
  // account, so every transaction at the account already belongs to that
  // contract.  We still accept only inbound JVI2 call bodies so non-call
  // transactions (deploys, raw transfers) don't appear as receipts.
  block::gen::Transaction::Record tx;
  if (!tlb::unpack_cell(tx_root, tx)) {
    return false;
  }
  if (tx.r1.in_msg->prefetch_long(1) != -1) {
    return false;
  }
  auto in_msg = tx.r1.in_msg->prefetch_ref();
  if (in_msg.is_null()) {
    return false;
  }
  auto body_r = jvm_message_body_slice(std::move(in_msg));
  if (body_r.is_error()) {
    return false;
  }
  return jvm_workchain::parse_jvm_call_descriptor(body_r.move_as_ok()).is_ok();
}

std::uint64_t jvm_transaction_lt(td::Ref<vm::Cell> tx_root) {
  block::gen::Transaction::Record tx;
  if (!tlb::unpack_cell(tx_root, tx)) {
    return 0;
  }
  return tx.lt;
}

std::string jvm_receipt_event_json(
    const jvm_workchain::JvmEvent& event,
    const block::gen::CommonMsgInfo::Record_ext_out_msg_info& ext_info,
    td::Ref<vm::Cell> tx_root,
    const tos::lite_api::tosNode_blockIdExt& block_id,
    std::uint32_t log_index) {
  td::StringBuilder sb;
  sb << "{\"blockSeqno\":" << block_id.seqno_
     << ",\"blockHash\":\"" << jvm_rpc_hex_encode(block_id.root_hash_.as_slice()) << "\""
     << ",\"transactionLt\":\"" << jvm_transaction_lt(tx_root) << "\""
     << ",\"transactionHash\":\""
     << jvm_rpc_hex_encode(tx_root->get_hash(0).as_slice()) << "\""
     << ",\"logIndex\":" << log_index
     << ",\"createdLt\":\"" << ext_info.created_lt << "\""
     << ",\"createdAt\":" << ext_info.created_at
     << ",\"topics\":[";
  for (std::size_t i = 0; i < event.topics.size(); ++i) {
    if (i != 0) {
      sb << ",";
    }
    sb << "\"" << jvm_rpc_hex_encode_bytes(event.topics[i].data(),
                                           event.topics[i].size()) << "\"";
  }
  sb << "],\"data\":\"";
  if (event.data.empty()) {
    sb << "0x";
  } else {
    sb << jvm_rpc_hex_encode_bytes(event.data.data(), event.data.size());
  }
  sb << "\"}";
  return sb.as_cslice().str();
}

void append_jvm_receipts_from_transaction(
    td::Ref<vm::Cell> tx_root,
    const tos::lite_api::tosNode_blockIdExt& block_id,
    const jvm_workchain::JvmContractId& contract_id,
    std::vector<std::string>& receipts,
    std::size_t existing_receipt_count,
    bool& truncated) {
  if (truncated || !jvm_transaction_matches_contract(tx_root, contract_id)) {
    return;
  }

  block::gen::Transaction::Record tx;
  if (!tlb::unpack_cell(tx_root, tx) || tx.outmsg_cnt == 0) {
    return;
  }

  vm::Dictionary out_msgs{tx.r1.out_msgs, 15};
  std::uint32_t local_log_index = 0;
  for (int i = 0; i < tx.outmsg_cnt && i < (1 << 15); ++i) {
    if (existing_receipt_count + receipts.size() >= kJvmReceiptMaxResults) {
      truncated = true;
      return;
    }
    auto out_msg = out_msgs.lookup_ref(td::BitArray<15>{i});
    if (out_msg.is_null()) {
      continue;
    }

    block::gen::CommonMsgInfo::Record_ext_out_msg_info ext_info;
    auto body_cell_r = jvm_message_body_cell(out_msg, &ext_info);
    if (body_cell_r.is_error()) {
      continue;
    }
    auto event_r =
        jvm_workchain::decode_jvm_event_payload(body_cell_r.move_as_ok());
    if (event_r.is_error()) {
      continue;
    }
    receipts.push_back(jvm_receipt_event_json(
        event_r.move_as_ok(), ext_info, tx_root, block_id, local_log_index));
    ++local_log_index;
  }
}

std::string inject_account_state_boc(std::string params_json,
                                     const std::string& state_boc_hex) {
  auto pos = params_json.rfind('}');
  if (pos == std::string::npos) {
    return params_json;
  }
  auto before = pos;
  while (before > 0 &&
         std::isspace(static_cast<unsigned char>(params_json[before - 1]))) {
    --before;
  }
  const bool empty_object = before > 0 && params_json[before - 1] == '{';
  std::string field = empty_object ? "" : ",";
  field += "\"accountStateBoc\":\"" + state_boc_hex + "\"";
  params_json.insert(pos, field);
  return params_json;
}

// Round 42 MEDIUM fix: inject the live account's balance as a JSON-
// number `accountBalance` field.  `handle_jvm_call_contract` uses this
// to mirror the consensus affordability cap (`balance/gas_price`) —
// without it the live RPC simulation would diverge from on-chain
// execution any time the caller's balance is the binding constraint.
//
// Round 43 MEDIUM fix: insert the field at the START of the JSON
// object (right after `{`) instead of the end.  `json_get_number_str`
// returns the FIRST occurrence; appending let a malicious caller
// shadow the injected value with their own attacker-controlled
// `accountBalance` placed earlier in the request.  Inserting first
// means the parser always sees the injected value first.
//
// Round 43 LOW fix: take the balance as `td::uint64` so the call site
// can re-extract from the raw `RefInt256` and clamp 256-bit values
// that don't fit `int64` to UINT64_MAX (treated as "very high
// balance, no constraint") rather than letting `to_long()` return a
// negative sentinel that the old version clamped to zero.
std::string inject_account_balance(std::string params_json,
                                   std::uint64_t balance) {
  auto open = params_json.find('{');
  if (open == std::string::npos) {
    return params_json;
  }
  auto idx = open + 1;
  while (idx < params_json.size() &&
         std::isspace(static_cast<unsigned char>(params_json[idx]))) {
    ++idx;
  }
  // If the next non-whitespace char is `}`, the object is empty —
  // inject without a leading comma; otherwise inject with a trailing
  // comma so the existing first field still parses.
  const bool empty_object = idx < params_json.size() && params_json[idx] == '}';
  std::string field = "\"accountBalance\":" + std::to_string(balance);
  if (!empty_object) {
    field += ",";
  }
  params_json.insert(open + 1, field);
  return params_json;
}

// Round 43 LOW fix: extract the live account balance as a `uint64_t`.
// Pre-fix `ParsedAccountState::balance` (int64) silently lost the
// high bit, and `inject_account_balance` then clamped the resulting
// negative to 0 — so a balance > INT64_MAX was treated as "no hint",
// a behavior consensus did not match.
//
// Round 44 LOW fix: return `std::nullopt` when the balance overflows
// `uint64_t`.  Pre-Round-44 we returned `UINT64_MAX`, then RPC divided
// by `gas_price`; for huge balance + huge gas_price the quotient could
// fall below the admission floor and falsely reject locally even
// though consensus (which divides 256-bit `balance` by `gas_price`
// before clamping) computes a perfectly affordable amount.  Returning
// `nullopt` makes the validator-engine omit the `accountBalance`
// field; RPC then defers to `max_gas_per_tx` (balance-blind for the
// affordability cap).  This is a UX divergence from consensus, but a
// safe-side one: RPC will simulate at higher gas than consensus could
// afford only when the consensus cap is < kJvmAdmissionGasFloor, in
// which case consensus rejects pre-runtime — RPC is conservatively
// "balance-blind", not "balance-cap-bypass".
std::optional<std::uint64_t> extract_account_balance_uint64(
    const tos::lite_api::liteServer_accountState& account) {
  if (account.state_.empty()) {
    return 0;
  }
  auto state_r = vm::std_boc_deserialize(account.state_.as_slice());
  if (state_r.is_error()) {
    return 0;
  }
  auto state_cell = state_r.move_as_ok();
  block::gen::Account::Record_account ar;
  if (!tlb::unpack_cell(state_cell, ar)) {
    return 0;
  }
  block::gen::AccountStorage::Record storage;
  if (!tlb::csr_unpack(ar.storage, storage)) {
    return 0;
  }
  auto balance_cs = storage.balance.write();
  auto coins = block::tlb::t_Tomis.as_integer_skip(balance_cs);
  if (coins.is_null()) {
    return 0;
  }
  if (!coins->fits_bits(64, /*sign=*/false)) {
    return std::nullopt;  // overflow → omit `accountBalance` injection
  }
  return static_cast<std::uint64_t>(coins->to_long());
}

}  // namespace

void JsonRpcServer::handle_jvm_rpc_method(std::string method,
                                          std::string params_json,
                                          std::string req_id,
                                          td::Promise<HttpReturn> promise) {
  if (method == "jvm_getReceipts") {
    handle_jvm_get_receipts_rpc_method(
        std::move(params_json), std::move(req_id), std::move(promise));
    return;
  }

  struct Slot {
    td::Promise<HttpReturn> promise;
    std::string req_id;
    std::string method;
    std::string params_json;
    std::shared_ptr<const jvm_workchain::JvmComputeRuntime> runtime;
    bool settled{false};
  };

  auto slot = std::make_shared<Slot>();
  slot->promise = std::move(promise);
  slot->req_id = std::move(req_id);
  slot->method = std::move(method);
  slot->params_json = std::move(params_json);
  slot->runtime = jvm_workchain::current_jvm_compute_runtime();

  const std::string cors_origin = opts_.cors_origin;
  auto settle_error = [cors_origin](const std::shared_ptr<Slot>& s,
                                    int code,
                                    const std::string& message) {
    if (s->settled) {
      return;
    }
    s->settled = true;
    s->promise.set_value(JsonRpcServer::make_eth_json_error(
        code, message, s->req_id, cors_origin));
  };

  auto dispatch_with_config_and_params = [slot, settle_error, cors_origin](
      const jvm_workchain::JvmConfig& cfg,
      const std::string& params_json) mutable {
    if (slot->settled) {
      return;
    }
    auto result = jvm_workchain::handle_jvm_rpc(
        slot->method, params_json, slot->req_id, cfg,
        slot->runtime.get());
    if (!result.has_value()) {
      settle_error(slot, -32601,
                   PSTRING() << "Method not found: " << slot->method);
      return;
    }
    slot->settled = true;
    slot->promise.set_value(
        JsonRpcServer::make_raw_json_response(result->json, cors_origin));
  };

  auto do_query_config = [slot, settle_error, dispatch_with_config_and_params,
                          self_id = actor_id(this)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
    std::vector<td::int32> param_list = {jvm_workchain::kJvmConfigParam};
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
            0x10000, std::move(block_id), std::move(param_list)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(
            std::move(inner)),
        true);

    td::actor::send_closure(
        self_id, &JsonRpcServer::send_liteserver_query, std::move(query),
        td::PromiseCreator::lambda(
            [slot, settle_error, dispatch_with_config_and_params =
                 std::move(dispatch_with_config_and_params), self_id](
                td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "jvm ConfigParam 85 query failed: "
                               << R.error());
        return;
      }

      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "parse JVM configInfo: " << F.error());
        return;
      }
      auto f = F.move_as_ok();
      auto blk_id = tos::create_block_id(f->id_);
      auto state_r = block::check_extract_state_proof(
          blk_id, f->state_proof_.as_slice(), f->config_proof_.as_slice());
      if (state_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "JVM config state proof error: "
                               << state_r.error());
        return;
      }

      auto cfg_r = block::Config::extract_from_state(state_r.move_as_ok(), 0);
      if (cfg_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "JVM config extract error: "
                               << cfg_r.error());
        return;
      }
      auto cfg = cfg_r.move_as_ok();
      auto param_cell = cfg->get_config_param(jvm_workchain::kJvmConfigParam);
      if (param_cell.is_null()) {
        settle_error(slot, -32603, "JVM ConfigParam 85 not found");
        return;
      }

      auto jvm_cfg_r = jvm_workchain::parse_jvm_config_cell(param_cell);
      if (jvm_cfg_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "JVM ConfigParam 85 parse failed: "
                               << jvm_cfg_r.error());
        return;
      }
      auto jvm_cfg = jvm_cfg_r.move_as_ok();

      if (!jvm_rpc_needs_live_account_state(slot->method, slot->params_json)) {
        dispatch_with_config_and_params(jvm_cfg, slot->params_json);
        return;
      }

      // Each JVM contract is its own wc=3 account at a deterministic
      // 256-bit address (`derive_jvm_contract_address`).  Pull the address
      // from the request and load THAT account, not a singleton executor.
      auto contract_address_opt =
          jvm_rpc_contract_address(slot->method, slot->params_json);
      if (!contract_address_opt.has_value()) {
        settle_error(slot, -32602,
                     "JVM RPC missing or malformed contractAddress");
        return;
      }
      block::StdAddress account_addr(3, *contract_address_opt);
      auto account_inner = tos::serialize_tl_object(
          tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
              std::move(f->id_),
              tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                  account_addr.workchain, account_addr.addr)),
          true);
      auto account_query = tos::serialize_tl_object(
          tos::create_tl_object<tos::lite_api::liteServer_query>(
              std::move(account_inner)),
          true);

      td::actor::send_closure(
          self_id, &JsonRpcServer::send_liteserver_query,
          std::move(account_query),
          td::PromiseCreator::lambda(
              [slot, settle_error, dispatch_with_config_and_params =
                   std::move(dispatch_with_config_and_params),
               jvm_cfg = std::move(jvm_cfg), account_addr](
                  td::Result<td::BufferSlice> account_res) mutable {
        if (account_res.is_error()) {
          settle_error(slot, -32603,
                       PSTRING() << "JVM contract account state query failed: "
                                 << account_res.error());
          return;
        }
        auto account_r =
            tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
                account_res.move_as_ok(), true);
        if (account_r.is_error()) {
          settle_error(slot, -32603,
                       PSTRING() << "parse JVM contract account state: "
                                 << account_r.error());
          return;
        }
        auto account = account_r.move_as_ok();
        auto parsed_r = ParsedAccountState::parse(account, account_addr);
        if (parsed_r.is_error()) {
          settle_error(slot, -32603,
                       PSTRING() << "parse JVM contract account: "
                                 << parsed_r.error());
          return;
        }
        auto parsed = parsed_r.move_as_ok();
        if (parsed.data_cell.is_null()) {
          settle_error(slot, -32603, "JVM contract account has no data cell");
          return;
        }
        auto boc_r = vm::std_boc_serialize(parsed.data_cell, 0);
        if (boc_r.is_error()) {
          settle_error(slot, -32603,
                       PSTRING() << "serialize JVM contract account state BOC: "
                                 << boc_r.error());
          return;
        }
        auto params_with_state = inject_account_state_boc(
            slot->params_json, jvm_rpc_hex_encode(boc_r.ok().as_slice()));
        // Round 42: also forward the live balance so RPC simulation
        // applies the consensus `balance/gas_price` affordability cap.
        // Round 43: re-extract via `extract_account_balance_uint64`
        // which preserves the full 64 unsigned bits instead of using
        // `ParsedAccountState::balance` (int64) which silently lost
        // the high bit.
        // Round 44 LOW fix: skip injection when the balance overflows
        // `uint64_t`.  Otherwise the affordability cap divides
        // `UINT64_MAX / gas_price` and may falsely reject locally for
        // accounts whose true `balance / gas_price` is large enough.
        const auto live_balance =
            extract_account_balance_uint64(*account);
        if (live_balance.has_value()) {
            params_with_state =
                inject_account_balance(params_with_state, *live_balance);
        }
        dispatch_with_config_and_params(jvm_cfg, params_with_state);
      }));
    }));
  };

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(),
      true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(
          std::move(mc_inner)),
      true);

  send_liteserver_query(
      std::move(mc_query),
      [slot, settle_error, do_query_config = std::move(do_query_config)](
          td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      settle_error(slot, -32603,
                   PSTRING() << "jvm getMasterchainInfo failed: "
                             << R.error());
      return;
    }
    auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
        R.move_as_ok(), true);
    if (mc_r.is_error()) {
      settle_error(slot, -32603,
                   PSTRING() << "parse jvm getMasterchainInfo: "
                             << mc_r.error());
      return;
    }
    do_query_config(std::move(mc_r.move_as_ok()->last_));
  });
}

void JsonRpcServer::handle_jvm_get_receipts_rpc_method(
    std::string params_json,
    std::string req_id,
    td::Promise<HttpReturn> promise) {
  auto req = jvm_workchain::parse_jvm_get_receipts_request(params_json);
  if (!req.has_value()) {
    promise.set_value(make_eth_json_error(
        -32602, "invalid jvm_getReceipts params", req_id, opts_.cors_origin));
    return;
  }
  if (req->to_block != 0 && req->from_block > req->to_block) {
    promise.set_value(make_eth_json_error(
        -32602, "fromBlock must be <= toBlock", req_id, opts_.cors_origin));
    return;
  }

  struct Slot {
    td::Promise<HttpReturn> promise;
    std::string req_id;
    std::string cors_origin;
    jvm_workchain::JvmGetReceiptsRequest req;
    std::uint64_t to_block{0};
    std::uint64_t scanned{0};
    bool truncated{false};
    bool settled{false};
    std::vector<std::string> receipts;
  };

  auto slot = std::make_shared<Slot>();
  slot->promise = std::move(promise);
  slot->req_id = std::move(req_id);
  slot->cors_origin = opts_.cors_origin;
  slot->req = *req;
  slot->to_block = req->to_block;

  auto settle_error = [](const std::shared_ptr<Slot>& s,
                         int code,
                         const std::string& message) {
    if (s->settled) {
      return;
    }
    s->settled = true;
    s->promise.set_value(JsonRpcServer::make_eth_json_error(
        code, message, s->req_id, s->cors_origin));
  };

  auto finish = [](const std::shared_ptr<Slot>& s) {
    if (s->settled) {
      return;
    }
    s->settled = true;

    td::StringBuilder sb;
    sb << "{\"jsonrpc\":\"2.0\",\"id\":" << s->req_id
       << ",\"result\":{\"contractAddress\":\""
       << jvm_rpc_contract_id_hex(s->req.contract_address)
       << "\",\"fromBlock\":" << s->req.from_block
       << ",\"toBlock\":" << s->to_block
       << ",\"scannedTransactions\":" << s->scanned
       << ",\"truncated\":" << (s->truncated ? "true" : "false")
       << ",\"receipts\":[";
    for (std::size_t i = 0; i < s->receipts.size(); ++i) {
      if (i != 0) {
        sb << ",";
      }
      sb << s->receipts[i];
    }
    sb << "]}}";

    s->promise.set_value(JsonRpcServer::make_raw_json_response(
        sb.as_cslice().str(), s->cors_origin));
  };

  auto self_id = actor_id(this);
  auto fetch_page = std::make_shared<
      std::function<void(std::uint64_t, td::Bits256)>>();

  *fetch_page = [slot, self_id, settle_error, finish, fetch_page](
                    std::uint64_t from_lt,
                    td::Bits256 from_hash) mutable {
    if (slot->settled) {
      return;
    }
    if (from_lt == 0 || slot->scanned >= kJvmReceiptMaxScannedTransactions) {
      if (slot->scanned >= kJvmReceiptMaxScannedTransactions) {
        slot->truncated = true;
      }
      finish(slot);
      return;
    }

    tos::StdSmcAddress contract_addr;
    std::memcpy(contract_addr.data(), slot->req.contract_address.data(), 32);
    auto tx_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
            kJvmReceiptPageSize,
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                3, contract_addr),
            static_cast<td::int64>(from_lt), from_hash),
        true);
    auto tx_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(
            std::move(tx_inner)),
        true);

    td::actor::send_closure(
        self_id, &JsonRpcServer::send_liteserver_query, std::move(tx_query),
        td::PromiseCreator::lambda(
            [slot, settle_error, finish, fetch_page](
                td::Result<td::BufferSlice> tx_res) mutable {
      if (tx_res.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "JVM receipt transaction query failed: "
                               << tx_res.error());
        return;
      }
      auto list_r =
          tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
              tx_res.move_as_ok(), true);
      if (list_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "parse JVM receipt transactionList: "
                               << list_r.error());
        return;
      }
      auto list = list_r.move_as_ok();
      if (list->transactions_.empty()) {
        finish(slot);
        return;
      }

      auto roots_r =
          vm::std_boc_deserialize_multi(list->transactions_.as_slice());
      if (roots_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "deserialize JVM receipt transactions: "
                               << roots_r.error());
        return;
      }
      auto roots = roots_r.move_as_ok();

      bool saw_older_than_from = false;
      std::uint64_t next_lt = 0;
      td::Bits256 next_hash = td::Bits256::zero();
      const std::size_t n = std::min(roots.size(), list->ids_.size());
      for (std::size_t i = 0; i < n; ++i) {
        const auto& block_id = *list->ids_[i];
        const auto block_seqno = static_cast<std::uint64_t>(block_id.seqno_);
        if (slot->req.to_block == 0 &&
            (slot->to_block == 0 || block_seqno > slot->to_block)) {
          slot->to_block = block_seqno;
        }

        block::gen::Transaction::Record tx;
        if (tlb::unpack_cell(roots[i], tx)) {
          next_lt = tx.prev_trans_lt;
          next_hash = tx.prev_trans_hash;
        }

        ++slot->scanned;
        if (slot->req.from_block != 0 && block_seqno < slot->req.from_block) {
          saw_older_than_from = true;
          continue;
        }
        if (slot->req.to_block != 0 && block_seqno > slot->req.to_block) {
          continue;
        }

        std::vector<std::string> tx_receipts;
        append_jvm_receipts_from_transaction(
            roots[i], block_id, slot->req.contract_address, tx_receipts,
            slot->receipts.size(), slot->truncated);
        if (!tx_receipts.empty()) {
          slot->receipts.insert(slot->receipts.begin(), tx_receipts.begin(),
                                tx_receipts.end());
        }
        if (slot->truncated) {
          finish(slot);
          return;
        }
      }

      if (saw_older_than_from || next_lt == 0 ||
          slot->scanned >= kJvmReceiptMaxScannedTransactions) {
        if (slot->scanned >= kJvmReceiptMaxScannedTransactions) {
          slot->truncated = true;
        }
        finish(slot);
        return;
      }
      (*fetch_page)(next_lt, next_hash);
    }));
  };

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(),
      true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(
          std::move(mc_inner)),
      true);

  send_liteserver_query(
      std::move(mc_query),
      [slot, self_id, settle_error, finish, fetch_page](
          td::Result<td::BufferSlice> mc_res) mutable {
    if (mc_res.is_error()) {
      settle_error(slot, -32603,
                   PSTRING() << "jvm getMasterchainInfo failed: "
                             << mc_res.error());
      return;
    }
    auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
        mc_res.move_as_ok(), true);
    if (mc_r.is_error()) {
      settle_error(slot, -32603,
                   PSTRING() << "parse jvm getMasterchainInfo: "
                             << mc_r.error());
      return;
    }
    auto mc = mc_r.move_as_ok();

    tos::StdSmcAddress receipts_addr_inner;
    std::memcpy(receipts_addr_inner.data(),
                slot->req.contract_address.data(), 32);
    block::StdAddress account_addr(3, receipts_addr_inner);
    auto account_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(mc->last_),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                account_addr.workchain, account_addr.addr)),
        true);
    auto account_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(
            std::move(account_inner)),
        true);

    td::actor::send_closure(
        self_id, &JsonRpcServer::send_liteserver_query,
        std::move(account_query),
        td::PromiseCreator::lambda(
            [slot, account_addr, settle_error, finish, fetch_page](
                td::Result<td::BufferSlice> account_res) mutable {
      if (account_res.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "JVM contract account state query failed: "
                               << account_res.error());
        return;
      }
      auto account_r =
          tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              account_res.move_as_ok(), true);
      if (account_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "parse JVM contract account state: "
                               << account_r.error());
        return;
      }
      auto account = account_r.move_as_ok();
      auto parsed_r = ParsedAccountState::parse(account, account_addr);
      if (parsed_r.is_error()) {
        settle_error(slot, -32603,
                     PSTRING() << "parse JVM executor account: "
                               << parsed_r.error());
        return;
      }
      auto parsed = parsed_r.move_as_ok();
      if (parsed.last_trans_lt == 0) {
        finish(slot);
        return;
      }

      td::Bits256 last_hash = td::Bits256::zero();
      auto hash_decoded = td::base64_decode(parsed.last_trans_hash_b64);
      if (hash_decoded.is_error() || hash_decoded.ok().size() != 32) {
        settle_error(slot, -32603,
                     "JVM executor account has malformed last transaction hash");
        return;
      }
      last_hash.as_slice().copy_from(hash_decoded.ok());
      (*fetch_page)(parsed.last_trans_lt, last_hash);
    }));
  });
}

}  // namespace tos
