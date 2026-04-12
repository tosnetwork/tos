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
#include "json-rpc-server.h"

#include "auto/tl/lite_api.h"
#include "auto/tl/lite_api.hpp"
#include "tl/tl_object_parse.h"
#include "tl-utils/lite-utils.hpp"
#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"

namespace tos {

// ─── Actor lifecycle ──────────────────────────────────────────────────────

td::actor::ActorOwn<JsonRpcServer> JsonRpcServer::create(
    td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager) {
  return td::actor::create_actor<JsonRpcServer>("json-rpc", std::move(validator_manager));
}

JsonRpcServer::JsonRpcServer(
    td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager)
    : validator_manager_(std::move(validator_manager)) {
}

void JsonRpcServer::listen(td::IPAddress addr) {
  CHECK(http_.empty());
  auto callback = std::make_shared<HttpCallback>(actor_id(this));
  http_ = td::actor::create_actor<http::HttpServer>(
      PSTRING() << "JsonRPC@" << addr, addr, std::move(callback));
  LOG(WARNING) << "JSON-RPC server listening on " << addr;
}

// ─── HTTP callback ────────────────────────────────────────────────────────

JsonRpcServer::HttpCallback::HttpCallback(td::actor::ActorId<JsonRpcServer> server)
    : server_(std::move(server)) {
}

void JsonRpcServer::HttpCallback::receive_request(
    RequestPtr request, PayloadPtr payload, td::Promise<HttpReturn> promise) {
  td::actor::send_closure(server_, &JsonRpcServer::on_request,
                          std::move(request), std::move(payload), std::move(promise));
}

// ─── Request handling ─────────────────────────────────────────────────────

void JsonRpcServer::on_request(RequestPtr request, PayloadPtr payload,
                               td::Promise<HttpReturn> promise) {
  LOG(INFO) << "json-rpc: received " << request->method() << " " << request->url()
            << " payload_completed=" << payload->parse_completed()
            << " ready_bytes=" << payload->ready_bytes();

  if (request->method() != "POST") {
    promise.set_value(make_json_error(-32600, "Only POST method is supported", ""));
    return;
  }

  if (payload->parse_completed()) {
    auto body = payload->get_slice(1 << 20);
    process_body(std::move(body), "", std::move(promise));
  } else {
    // Body not yet fully received — register callback
    class BodyWaiter : public http::HttpPayload::Callback {
     public:
      BodyWaiter(td::actor::ActorId<JsonRpcServer> server, PayloadPtr payload,
                 td::Promise<HttpReturn> promise)
          : server_(server), payload_(std::move(payload)), promise_(std::move(promise)) {}
      void run(size_t) override {}
      void completed() override {
        auto body = payload_->get_slice(1 << 20);
        td::actor::send_closure(server_, &JsonRpcServer::process_body,
                                std::move(body), std::string(), std::move(promise_));
      }
     private:
      td::actor::ActorId<JsonRpcServer> server_;
      PayloadPtr payload_;
      td::Promise<HttpReturn> promise_;
    };
    payload->add_callback(std::make_unique<BodyWaiter>(
        actor_id(this), payload, std::move(promise)));
  }
}

void JsonRpcServer::process_body(td::BufferSlice body, std::string req_id,
                                 td::Promise<HttpReturn> promise) {
  if (body.empty()) {
    promise.set_value(make_json_error(-32700, "Empty request body", req_id));
    return;
  }

  auto json_r = td::json_decode(body.as_slice());
  if (json_r.is_error()) {
    promise.set_value(make_json_error(-32700, "Parse error: invalid JSON", req_id));
    return;
  }

  auto json = json_r.move_as_ok();
  if (json.type() != td::JsonValue::Type::Object) {
    promise.set_value(make_json_error(-32600, "Invalid request: expected JSON object", req_id));
    return;
  }

  auto &obj = json.get_object();

  // Extract request ID
  {
    auto id_val = obj.extract_field("id");
    if (id_val.type() == td::JsonValue::Type::String) {
      req_id = id_val.get_string().str();
    } else if (id_val.type() == td::JsonValue::Type::Number) {
      req_id = id_val.get_number().str();
    }
  }

  // Extract method
  auto method_r = obj.get_required_string_field("method");
  if (method_r.is_error()) {
    promise.set_value(make_json_error(-32600, "Missing or invalid 'method' field", req_id));
    return;
  }
  std::string method = method_r.move_as_ok();

  // Extract params (optional)
  auto params_val = obj.extract_field("params");
  if (params_val.type() == td::JsonValue::Type::Null) {
    params_val = td::JsonValue::make_object(td::JsonObject());
  }
  if (params_val.type() != td::JsonValue::Type::Object) {
    promise.set_value(make_json_error(-32602, "'params' must be an object", req_id));
    return;
  }

  dispatch_method(std::move(method), params_val.get_object(),
                  std::move(req_id), std::move(promise));
}

// ─── Method dispatch ──────────────────────────────────────────────────────

void JsonRpcServer::dispatch_method(std::string method, td::JsonObject &params,
                                    std::string req_id, td::Promise<HttpReturn> promise) {
  if (method == "sendBoc") {
    handle_sendBoc(params, std::move(req_id), std::move(promise));
  } else if (method == "getConfigParam") {
    handle_getConfigParam(params, std::move(req_id), std::move(promise));
  } else if (method == "getAddressInformation") {
    handle_getAddressInformation(params, std::move(req_id), std::move(promise));
  } else if (method == "getExtendedAddressInformation") {
    handle_getExtendedAddressInformation(params, std::move(req_id), std::move(promise));
  } else if (method == "runGetMethod") {
    handle_runGetMethod(params, std::move(req_id), std::move(promise));
  } else if (method == "getWalletInformation") {
    handle_getWalletInformation(params, std::move(req_id), std::move(promise));
  } else {
    promise.set_value(make_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
  }
}

// ─── Stub method handlers (to be implemented in subsequent steps) ─────────

void JsonRpcServer::handle_sendBoc(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise) {
  auto boc_r = params.get_required_string_field("boc");
  if (boc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'boc' parameter", req_id));
    return;
  }
  auto boc_b64 = boc_r.move_as_ok();
  auto decoded_r = td::base64_decode(boc_b64);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'boc'", req_id));
    return;
  }
  auto body = td::BufferSlice(decoded_r.move_as_ok());

  // Construct liteServer.sendMessage(body)
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(std::move(data), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(PSTRING() << "{\"status\":" << status->status_ << "}", req_id));
      });
}

void JsonRpcServer::handle_getConfigParam(td::JsonObject &params, std::string req_id,
                                          td::Promise<HttpReturn> promise) {
  auto config_id_r = params.get_required_int_field("config_id");
  if (config_id_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing or invalid 'config_id' parameter", req_id));
    return;
  }
  int config_id = config_id_r.ok();

  // Step 1: Get masterchain info to obtain latest block ID
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [config_id, req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo failed: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();

        // Step 2: Query config with the real block ID
        std::vector<td::int32> param_list = {config_id};
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
                0x10000, std::move(mc->last_), std::move(param_list)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [config_id, req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getConfigParam failed: " << R.error(), req_id));
            return;
          }
          auto data = R.move_as_ok();

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
              std::move(data), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse configInfo: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          // Extract config from proofs
          auto blk_id = tos::create_block_id(f->id_);
          auto state_r = block::check_extract_state_proof(
              blk_id, f->state_proof_.as_slice(), f->config_proof_.as_slice());
          if (state_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "state proof error: " << state_r.error(), req_id));
            return;
          }

          auto cfg_r = block::Config::extract_from_state(state_r.move_as_ok(), 0);
          if (cfg_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "config extract error: " << cfg_r.error(), req_id));
            return;
          }
          auto cfg = cfg_r.move_as_ok();

          auto param_cell = cfg->get_config_param(config_id);
          if (param_cell.is_null()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "config param " << config_id << " not found", req_id));
            return;
          }

          // Serialize cell to BOC, then base64
          auto boc_r = vm::std_boc_serialize(param_cell);
          if (boc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "BOC serialize error: " << boc_r.error(), req_id));
            return;
          }
          auto b64 = td::base64_encode(boc_r.ok().as_slice());

          promise.set_value(make_json_ok(
              PSTRING() << "{\"config\":{\"bytes\":" << td::JsonString(td::Slice(b64)) << "}}",
              req_id));
        }));
      });
}

// ─── Parsed account state (shared by getAddressInformation, getExtendedAddressInformation, getWalletInformation)

struct ParsedAccountState {
  td::int64 balance = 0;
  std::string state_str = "uninit";  // "active", "uninit", "frozen"
  std::string code_b64;
  std::string data_b64;
  std::string frozen_hash;
  td::uint64 last_trans_lt = 0;
  std::string last_trans_hash_b64;
  td::uint32 sync_utime = 0;
  td::Ref<vm::Cell> code_cell;  // for wallet detection

  static td::Result<ParsedAccountState> parse(
      tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
      const block::StdAddress& addr) {
    ParsedAccountState res;

    // Validate proof and extract last_trans_lt, last_trans_hash, gen_utime
    auto blk_id = tos::create_block_id(f->id_);
    auto shard_blk_id = tos::create_block_id(f->shardblk_);
    block::AccountState as;
    as.blk = blk_id;
    as.shard_blk = shard_blk_id;
    as.shard_proof = f->shard_proof_.clone();
    as.proof = f->proof_.clone();
    as.state = f->state_.clone();
    auto info_r = as.validate(blk_id, addr);
    if (info_r.is_ok()) {
      auto info = info_r.move_as_ok();
      res.last_trans_lt = info.last_trans_lt;
      res.last_trans_hash_b64 = td::base64_encode(info.last_trans_hash.as_slice());
      res.sync_utime = info.gen_utime;

      // Parse Account cell from validated root
      if (info.root.not_null()) {
        block::gen::Account::Record_account account;
        if (tlb::unpack_cell(info.root, account)) {
          block::gen::AccountStorage::Record storage;
          if (tlb::csr_unpack(account.storage, storage)) {
            auto balance_cs = storage.balance.write();
            auto coins = block::tlb::t_Tomis.as_integer_skip(balance_cs);
            if (coins.not_null()) res.balance = coins->to_long();

            auto tag = block::gen::t_AccountState.get_tag(*storage.state);
            if (tag == block::gen::AccountState::account_active) {
              res.state_str = "active";
              block::gen::AccountState::Record_account_active active;
              if (tlb::csr_unpack(storage.state, active)) {
                block::gen::StateInit::Record si;
                if (tlb::csr_unpack(active.x, si)) {
                  td::Ref<vm::Cell> data_cell;
                  si.code->prefetch_maybe_ref(res.code_cell);
                  si.data->prefetch_maybe_ref(data_cell);
                  if (res.code_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(res.code_cell);
                    if (boc.is_ok()) res.code_b64 = td::base64_encode(boc.ok().as_slice());
                  }
                  if (data_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(data_cell);
                    if (boc.is_ok()) res.data_b64 = td::base64_encode(boc.ok().as_slice());
                  }
                }
              }
            } else if (tag == block::gen::AccountState::account_frozen) {
              res.state_str = "frozen";
              block::gen::AccountState::Record_account_frozen frozen;
              if (tlb::csr_unpack(storage.state, frozen)) {
                res.frozen_hash = td::base64_encode(frozen.state_hash.as_slice());
              }
            }
          }
        }
      }
    }
    return res;
  }

  std::string to_address_info_json() const {
    return PSTRING()
        << "{\"@type\":\"raw.fullAccountState\""
        << ",\"balance\":" << td::JsonString(td::Slice(PSTRING() << balance))
        << ",\"code\":" << td::JsonString(td::Slice(code_b64))
        << ",\"data\":" << td::JsonString(td::Slice(data_b64))
        << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
        << ",\"lt\":\"" << last_trans_lt << "\""
        << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
        << ",\"block_id\":{\"@type\":\"tos.blockIdExt\",\"workchain\":-1,\"shard\":\"-9223372036854775808\",\"seqno\":0,\"root_hash\":\"\",\"file_hash\":\"\"}"
        << ",\"sync_utime\":" << sync_utime
        << ",\"extra_currencies\":[]"
        << ",\"state\":" << td::JsonString(td::Slice(state_str))
        << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash))
        << "}";
  }

  std::string to_extended_info_json(const std::string& addr_str) const {
    return PSTRING()
        << "{\"@type\":\"fullAccountState\""
        << ",\"address\":{\"@type\":\"accountAddress\",\"account_address\":"
        << td::JsonString(td::Slice(addr_str)) << "}"
        << ",\"balance\":" << balance
        << ",\"extra_currencies\":[]"
        << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
        << ",\"lt\":\"" << last_trans_lt << "\""
        << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
        << ",\"block_id\":{\"@type\":\"tos.blockIdExt\",\"workchain\":-1,\"shard\":\"-9223372036854775808\",\"seqno\":0,\"root_hash\":\"\",\"file_hash\":\"\"}"
        << ",\"sync_utime\":" << sync_utime
        << ",\"account_state\":{\"@type\":\"raw.accountState\""
        << ",\"code\":" << td::JsonString(td::Slice(code_b64))
        << ",\"data\":" << td::JsonString(td::Slice(data_b64))
        << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash)) << "}"
        << ",\"revision\":0}";
  }
};

// ─── Shared: fetch account state from liteserver ──────────────────────────

static td::Result<block::StdAddress> parse_address_param(td::JsonObject& params) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) return td::Status::Error("Missing 'address'");
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) return td::Status::Error("Invalid address");
  return addr;
}

// Sends getMasterchainInfo + getAccountState, then calls callback with parsed result
void JsonRpcServer::handle_getAddressInformation(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [addr, addr_str = std::move(addr_str), req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
          return;
        }
        auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc.error(), req_id));
          return;
        }
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, addr_str = std::move(addr_str), req_id = std::move(req_id),
                 promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id));
            return;
          }
          promise.set_value(make_json_ok(parsed.ok().to_address_info_json(), req_id));
        }));
      });
}

void JsonRpcServer::handle_getExtendedAddressInformation(td::JsonObject &params, std::string req_id,
                                                         td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [addr, addr_str = std::move(addr_str), req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
          return;
        }
        auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc.error(), req_id));
          return;
        }
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, addr_str = std::move(addr_str), req_id = std::move(req_id),
                 promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id));
            return;
          }
          promise.set_value(make_json_ok(parsed.ok().to_extended_info_json(addr_str), req_id));
        }));
      });
}

void JsonRpcServer::handle_runGetMethod(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  auto method_r = params.get_required_string_field("method");
  if (method_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'method'", req_id));
    return;
  }
  auto method_name = method_r.move_as_ok();
  td::int64 method_id = (td::crc16(td::Slice(method_name)) & 0xffff) | 0x10000;

  // Serialize empty stack as params
  vm::CellBuilder cb;
  vm::Stack stack;
  if (!stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }

  // Step 1: get latest mc block
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  auto params_boc = params_boc_r.move_as_ok();
  send_liteserver_query(std::move(mc_query),
      [addr, method_id, params_boc = std::move(params_boc),
       req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();

        // Step 2: runSmcMethod (mode=4 → return result)
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(mc->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                method_id, std::move(params_boc)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "runSmcMethod: " << R.error(), req_id));
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse runMethodResult: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          // Parse result stack
          std::string stack_json = "[]";
          if (!f->result_.empty()) {
            auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
            if (cell_r.is_ok()) {
              auto stk = td::make_ref<vm::Stack>();
              auto result_cell = cell_r.move_as_ok();
              vm::CellSlice cs = vm::load_cell_slice(result_cell);
              if (stk.write().deserialize(cs)) {
                // Convert stack to JSON array of ["num", "value"] entries
                td::StringBuilder sb;
                sb << "[";
                for (int i = 0; i < (int)stk->depth(); i++) {
                  if (i > 0) sb << ",";
                  auto& entry = stk->at(i);
                  if (entry.is_int()) {
                    auto val = entry.as_int();
                    sb << "[\"num\"," << td::JsonString(td::Slice(val->to_dec_string())) << "]";
                  } else if (entry.is_cell()) {
                    auto boc = vm::std_boc_serialize(entry.as_cell());
                    if (boc.is_ok()) {
                      sb << "[\"cell\",{\"bytes\":"
                         << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice())))
                         << "}]";
                    } else {
                      sb << "[\"unsupported\"]";
                    }
                  } else {
                    sb << "[\"unsupported\"]";
                  }
                }
                sb << "]";
                stack_json = sb.as_cslice().str();
              }
            }
          }

          auto result = PSTRING()
              << "{\"exit_code\":" << f->exit_code_
              << ",\"gas_used\":0"
              << ",\"stack\":" << stack_json << "}";

          promise.set_value(make_json_ok(result, req_id));
        }));
      });
}

// ─── Wallet info JSON builder ─────────────────────────────────────────────

static std::string build_wallet_json(bool is_wallet, td::int64 balance,
                                     const std::string& account_state,
                                     const std::string& wallet_type,
                                     td::int32 seqno,
                                     td::uint64 last_lt, const std::string& last_hash_b64) {
  td::StringBuilder sb;
  sb << "{\"wallet\":" << (is_wallet ? "true" : "false")
     << ",\"balance\":" << td::JsonString(td::Slice(PSTRING() << balance))
     << ",\"account_state\":" << td::JsonString(td::Slice(account_state))
     << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
     << ",\"lt\":\"" << last_lt << "\""
     << ",\"hash\":" << td::JsonString(td::Slice(last_hash_b64)) << "}";
  if (is_wallet) {
    sb << ",\"wallet_type\":" << td::JsonString(td::Slice(wallet_type));
    if (seqno >= 0) {
      sb << ",\"seqno\":" << seqno;
    } else {
      sb << ",\"seqno\":null";
    }
  } else {
    sb << ",\"wallet_type\":null,\"seqno\":null";
  }
  sb << "}";
  return sb.as_cslice().str();
}

// Known wallet code hashes → type name strings
static std::string detect_wallet_type(const vm::CellHash& code_hash) {
  static const std::map<std::string, std::string> known_wallets = {
    {"89c890a6c9b5a3828b38570a93dfc93c792ee9147933de8f21f5840ae19ab1aa", "wallet v1 r1"},
    {"27b5063ebdb6e5ecec073f57451a4be095eb68777496b65449b1b49fa09a43d9", "wallet v1 r2"},
    {"1f08ebe871907c8b60aa1bb9c22a54cb095d1dc0e007a3d7af827d1c4de23910", "wallet v1 r3"},
    {"8369fdda46a532a8302037d955d92d7a3308422eadf0074c497cecd209832c3a", "wallet v2 r1"},
    {"9264711341ab55499665d16b4589a148ed6ab8a4aed3ae9fcf805295eee7b927", "wallet v2 r2"},
    {"f475ec633ea8ec25b6872878b95996aeea061198bd1c86180d3984ea7e1e6fb4", "wallet v3 r1"},
    {"09be881beffe710d6bb4bd030a2506bef85c10ff1ac44df93b0b29282945916f", "wallet v3 r2"},
    {"6b5fd33048d2db82650b36f47ced9714a1c0b573aa08447e23f96629364dda2a", "wallet v4 r1"},
    {"288014a04d551904d623c826512ffeb16ad4df6130195ea537050b35207e5fc3", "wallet v4 r2"},
    {"7afa0eacbaf9e9eaa19ae93e61354540c9335b52f1add44e7a8e2d9089212b3e", "wallet v5 r1"},
    {"643a1ab8e96cb40b9cd92599ea295a591d6c12730d53ce77a447e1fc1c9a8b41", "nominator pool v1"},
    // tosctl verified hashes (may overlap; kept for belt-and-suspenders)
    {"84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599", "wallet v3 r2"},
    {"feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0", "wallet v4 r2"},
    {"20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f", "wallet v5 r1"},
  };
  auto hex = code_hash.to_hex();
  auto it = known_wallets.find(hex);
  return it != known_wallets.end() ? it->second : "";
}

void JsonRpcServer::handle_getWalletInformation(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [addr, req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();
        auto& block_id = mc->last_;
        auto saved_wc = block_id->workchain_;
        auto saved_shard = block_id->shard_;
        auto saved_seqno = block_id->seqno_;
        auto saved_root = block_id->root_hash_;
        auto saved_file = block_id->file_hash_;

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(block_id),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, block_id_wc = saved_wc, block_id_shard = saved_shard,
                 block_id_seqno = saved_seqno, block_id_root = saved_root,
                 block_id_file = saved_file,
                 req_id = std::move(req_id), self_id, promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id));
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();
          auto parsed_r = ParsedAccountState::parse(f, addr);
          if (parsed_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed_r.error(), req_id));
            return;
          }
          auto parsed = parsed_r.move_as_ok();

          // Detect wallet type from code hash
          std::string wallet_type;
          if (parsed.code_cell.not_null()) {
            wallet_type = detect_wallet_type(parsed.code_cell->get_hash(0));
          }
          bool is_wallet = !wallet_type.empty();

          if (!is_wallet) {
            promise.set_value(make_json_ok(
                build_wallet_json(false, parsed.balance, parsed.state_str, "",
                                  -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
                req_id));
            return;
          }

          // Is a wallet — query seqno via runGetMethod
          td::int64 method_id = (td::crc16(td::Slice("seqno")) & 0xffff) | 0x10000;
          vm::CellBuilder cb;
          vm::Stack empty_stack;
          empty_stack.serialize(cb);
          auto params_boc = vm::std_boc_serialize(cb.finalize());
          if (params_boc.is_error()) {
            promise.set_value(make_json_ok(
                build_wallet_json(true, parsed.balance, parsed.state_str, wallet_type,
                                  -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
                req_id));
            return;
          }

          auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
              block_id_wc, block_id_shard, block_id_seqno, block_id_root, block_id_file);
          auto run_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                  0x04, std::move(blk),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  method_id, params_boc.move_as_ok()),
              true);
          auto run_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(run_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(run_query),
              td::PromiseCreator::lambda(
                  [balance = parsed.balance, account_state = parsed.state_str,
                   last_lt = parsed.last_trans_lt, last_hash = parsed.last_trans_hash_b64,
                   wallet_type = std::move(wallet_type),
                   req_id = std::move(req_id), promise = std::move(promise)](
                      td::Result<td::BufferSlice> R) mutable {
            td::int32 seqno = -1;
            if (R.is_ok()) {
              auto rr = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                  R.move_as_ok(), true);
              if (rr.is_ok()) {
                auto rr_val = rr.move_as_ok();
                if (rr_val->exit_code_ == 0 && !rr_val->result_.empty()) {
                  auto cell = vm::std_boc_deserialize(rr_val->result_.as_slice());
                  if (cell.is_ok()) {
                    auto stk = td::make_ref<vm::Stack>();
                    auto result_cell = cell.move_as_ok();
                    vm::CellSlice cs = vm::load_cell_slice(result_cell);
                    if (stk.write().deserialize(cs) && stk->depth() > 0 && stk->at(0).is_int()) {
                      seqno = static_cast<td::int32>(stk->at(0).as_int()->to_long());
                    }
                  }
                }
              }
            }
            promise.set_value(make_json_ok(
                build_wallet_json(true, balance, account_state, wallet_type,
                                  seqno, last_lt, last_hash),
                req_id));
          }));
        }));
      });
}

// ─── Liteserver query forwarding ──────────────────────────────────────────

void JsonRpcServer::send_liteserver_query(td::BufferSlice query,
                                          td::Promise<td::BufferSlice> promise) {
  td::actor::send_closure(validator_manager_,
                          &validator::ValidatorManagerInterface::run_ext_query,
                          std::move(query), std::move(promise));
}

// ─── JSON response construction ───────────────────────────────────────────

JsonRpcServer::HttpReturn JsonRpcServer::make_json_ok(std::string result_json, std::string id) {
  std::string body = PSTRING()
      << "{\"ok\":true,\"jsonrpc\":\"2.0\",\"id\":" << td::JsonString(td::Slice(id))
      << ",\"result\":" << result_json << "}";

  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", "*"});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_json_error(int code, std::string message, std::string id) {
  std::string body = PSTRING()
      << "{\"ok\":false,\"jsonrpc\":\"2.0\",\"id\":" << td::JsonString(td::Slice(id))
      << ",\"error\":" << td::JsonString(td::Slice(message))
      << ",\"code\":" << code << "}";

  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", "*"});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

}  // namespace tos
