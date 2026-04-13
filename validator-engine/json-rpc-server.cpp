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
#include "block/mc-config.h"
#include "tos/lite-tl.hpp"
#include "vm/cells/MerkleProof.h"
#include "vm/boc.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"

namespace tos {

// ─── URL-decode + query-string → JSON helpers (for REST GET endpoints) ────

static int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static std::string url_decode(const std::string &src) {
  std::string out;
  out.reserve(src.size());
  for (size_t i = 0; i < src.size(); i++) {
    if (src[i] == '+') {
      out += ' ';
    } else if (src[i] == '%' && i + 2 < src.size()) {
      int hi = hex_digit(src[i + 1]);
      int lo = hex_digit(src[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out += static_cast<char>((hi << 4) | lo);
        i += 2;
      } else {
        out += src[i];
      }
    } else {
      out += src[i];
    }
  }
  return out;
}

// Convert "key1=val1&key2=val2" into a JSON object string: {"key1":"val1","key2":"val2"}
// All values are encoded as JSON strings; numeric coercion is handled by
// get_required_int_field / get_optional_int_field which parse from string values.
static std::string query_string_to_json(const std::string &qs) {
  if (qs.empty()) return "{}";
  td::StringBuilder sb;
  sb << "{";
  bool first = true;
  size_t pos = 0;
  while (pos < qs.size()) {
    auto amp = qs.find('&', pos);
    auto token = qs.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
    pos = amp == std::string::npos ? qs.size() : amp + 1;

    if (token.empty()) continue;
    auto eq = token.find('=');
    std::string key, value;
    if (eq == std::string::npos) {
      key = url_decode(token);
    } else {
      key = url_decode(token.substr(0, eq));
      value = url_decode(token.substr(eq + 1));
    }
    if (key.empty()) continue;

    if (!first) sb << ",";
    first = false;
    sb << td::JsonString(td::Slice(key)) << ":" << td::JsonString(td::Slice(value));
  }
  sb << "}";
  return sb.as_cslice().str();
}

// ─── Per-request timeout guard ────────────────────────────────────────────
//
// A tiny actor that wraps a td::Promise<td::BufferSlice> with a deadline.
// If deliver() is called before the alarm fires, the real promise gets the
// result and the guard self-destructs.  If the alarm fires first, the guard
// delivers a timeout error and any later deliver() call is a no-op.

class QueryTimeoutGuard final : public td::actor::Actor {
 public:
  QueryTimeoutGuard(td::Promise<td::BufferSlice> inner, double timeout_seconds)
      : inner_(std::move(inner)), timeout_seconds_(timeout_seconds) {
  }

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(timeout_seconds_);
  }

  void alarm() override {
    if (inner_) {
      LOG(WARNING) << "json-rpc: liteserver query timed out after " << timeout_seconds_ << "s";
      inner_.set_error(td::Status::Error(ErrorCode::timeout, "Request timeout"));
    }
    stop();
  }

  void deliver(td::Result<td::BufferSlice> result) {
    if (inner_) {
      inner_.set_result(std::move(result));
    }
    stop();
  }

 private:
  td::Promise<td::BufferSlice> inner_;
  double timeout_seconds_;
};

// ─── Actor lifecycle ──────────────────────────────────────────────────────

td::actor::ActorOwn<JsonRpcServer> JsonRpcServer::create(
    td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager,
    Options options) {
  return td::actor::create_actor<JsonRpcServer>("json-rpc", std::move(validator_manager),
                                                std::move(options));
}

JsonRpcServer::JsonRpcServer(
    td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager,
    Options options)
    : validator_manager_(std::move(validator_manager)), opts_(std::move(options)) {
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
  auto method = request->method();
  auto url = request->url();
  LOG(INFO) << "json-rpc: received " << method << " " << url
            << " payload_completed=" << payload->parse_completed()
            << " ready_bytes=" << payload->ready_bytes();

  // OPTIONS — CORS preflight on any path
  if (method == "OPTIONS") {
    promise.set_value(make_cors_preflight(opts_.cors_origin));
    return;
  }

  // GET /healthcheck — lightweight liveness probe (no liteserver dependency)
  if (method == "GET" && (url == "/healthcheck" || url == "/healthcheck/")) {
    promise.set_value(make_health_ok(opts_.cors_origin));
    return;
  }

  // GET /readyz — readiness probe (queries liteserver for sync state)
  if (method == "GET" && (url == "/readyz" || url == "/readyz/")) {
    handle_readyz(std::move(promise));
    return;
  }

  // ─── REST-style GET endpoints ────────────────────────────────────────────
  // Maps GET /methodName?param1=val1&param2=val2 to the same handlers as
  // POST JSON-RPC {"method":"methodName","params":{"param1":"val1",...}}.
  if (method == "GET") {
    auto path = url;
    auto query_pos = path.find('?');
    std::string query_string;
    if (query_pos != std::string::npos) {
      query_string = path.substr(query_pos + 1);
      path = path.substr(0, query_pos);
    }
    // Strip trailing slash for uniform matching
    if (path.size() > 1 && path.back() == '/') {
      path.pop_back();
    }

    // Map path to method name (only read-only, high-value endpoints)
    std::string rest_method;
    if (path == "/getMasterchainInfo")    rest_method = "getMasterchainInfo";
    else if (path == "/getAddressInformation")  rest_method = "getAddressInformation";
    else if (path == "/getAddressBalance")      rest_method = "getAddressBalance";
    else if (path == "/getAddressState")        rest_method = "getAddressState";
    else if (path == "/getWalletInformation")   rest_method = "getWalletInformation";
    else if (path == "/getTransactions")        rest_method = "getTransactions";
    else if (path == "/getConfigParam")         rest_method = "getConfigParam";
    else if (path == "/packAddress")            rest_method = "packAddress";
    else if (path == "/unpackAddress")          rest_method = "unpackAddress";
    else if (path == "/detectAddress")          rest_method = "detectAddress";
    else if (path == "/lookupBlock")            rest_method = "lookupBlock";
    else if (path == "/shards")                 rest_method = "shards";
    else if (path == "/getBlockHeader")         rest_method = "getBlockHeader";
    else if (path == "/getBlockTransactions")   rest_method = "getBlockTransactions";
    else if (path == "/getExtendedAddressInformation") rest_method = "getExtendedAddressInformation";

    if (!rest_method.empty()) {
      // Build a JSON object from query parameters, parse it, and dispatch
      auto json_str = query_string_to_json(query_string);
      auto buf = td::BufferSlice(json_str);
      auto json_r = td::json_decode(buf.as_slice());
      if (json_r.is_error()) {
        promise.set_value(make_json_error(-32602, "Invalid query parameters", "null",
                                          opts_.cors_origin));
        return;
      }
      auto json_val = json_r.move_as_ok();
      if (json_val.type() != td::JsonValue::Type::Object) {
        promise.set_value(make_json_error(-32602, "Invalid query parameters", "null",
                                          opts_.cors_origin));
        return;
      }
      dispatch_method(std::move(rest_method), json_val.get_object(),
                      "null", std::move(promise));
      return;
    }

    // Unknown GET path
    promise.set_value(make_text_response(404, "Not Found",
                                         "Unknown endpoint",
                                         opts_.cors_origin));
    return;
  }

  // Only POST is allowed for JSON-RPC beyond this point
  if (method != "POST") {
    promise.set_value(make_text_response(405, "Method Not Allowed",
                                         "Only POST, GET, and OPTIONS are supported",
                                         opts_.cors_origin));
    return;
  }

  // Accept POST on /jsonRPC (canonical) and any other path (backward compat)
  // Future: restrict to /jsonRPC only after migration period

  if (payload->parse_completed()) {
    auto body = payload->get_slice(1 << 20);
    process_body(std::move(body), "", std::move(promise));
  } else {
    // Body not yet fully received — register callback.
    // IMPORTANT: completed() must NOT call payload_->get_slice() directly,
    // because it runs inside HttpPayload::parse() which holds mutex_.
    // get_slice() also takes mutex_ → deadlock on the same thread.
    // Instead, send an actor message to read the body outside the lock.
    class BodyWaiter : public http::HttpPayload::Callback {
     public:
      BodyWaiter(td::actor::ActorId<JsonRpcServer> server, PayloadPtr payload,
                 td::Promise<HttpReturn> promise)
          : server_(server), payload_(std::move(payload)), promise_(std::move(promise)) {}
      void run(size_t) override {}
      void completed() override {
        // Do NOT read payload here (mutex deadlock). Defer to actor scheduler.
        td::actor::send_closure(server_, &JsonRpcServer::on_body_ready,
                                std::move(payload_), std::move(promise_));
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

void JsonRpcServer::on_body_ready(PayloadPtr payload, td::Promise<HttpReturn> promise) {
  // Safe to call get_slice() here — we are in the actor scheduler, NOT inside
  // HttpPayload::parse()'s mutex. This breaks the deadlock chain.
  auto body = payload->get_slice(1 << 20);
  process_body(std::move(body), "", std::move(promise));
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
  if (json.type() == td::JsonValue::Type::Array) {
    promise.set_value(make_json_error(-32600, "Batch requests are not supported", req_id));
    return;
  }
  if (json.type() != td::JsonValue::Type::Object) {
    promise.set_value(make_json_error(-32600, "Invalid request: expected JSON object", req_id));
    return;
  }

  auto &obj = json.get_object();

  // Extract request ID — store as JSON literal to preserve type in response
  // (JSON-RPC 2.0 requires echoing the id type exactly)
  {
    auto id_val = obj.extract_field("id");
    if (id_val.type() == td::JsonValue::Type::String) {
      req_id = PSTRING() << td::JsonString(td::Slice(id_val.get_string()));
    } else if (id_val.type() == td::JsonValue::Type::Number) {
      req_id = id_val.get_number().str();  // numeric literal, no quotes
    } else {
      req_id = "null";
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
  // Write-method gate: reject send-family methods in readonly mode
  if (opts_.readonly &&
      (method == "sendBoc" || method == "sendBocReturnHash" || method == "sendQuery")) {
    promise.set_value(make_json_error(-32601,
        "Write methods are disabled (server is in readonly mode)", req_id));
    return;
  }

  // Existing methods
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
  // Block/chain read APIs
  } else if (method == "getMasterchainInfo") {
    handle_getMasterchainInfo(params, std::move(req_id), std::move(promise));
  } else if (method == "lookupBlock") {
    handle_lookupBlock(params, std::move(req_id), std::move(promise));
  } else if (method == "shards") {
    handle_shards(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockHeader") {
    handle_getBlockHeader(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockTransactions") {
    handle_getBlockTransactions(params, std::move(req_id), std::move(promise));
  } else if (method == "getTransactions") {
    handle_getTransactions(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockTransactionsExt") {
    handle_getBlockTransactionsExt(params, std::move(req_id), std::move(promise));
  // Send family
  } else if (method == "sendBocReturnHash") {
    handle_sendBocReturnHash(params, std::move(req_id), std::move(promise));
  } else if (method == "sendQuery") {
    handle_sendQuery(params, std::move(req_id), std::move(promise));
  // Convenience / address APIs
  } else if (method == "getAddressBalance") {
    handle_getAddressBalance(params, std::move(req_id), std::move(promise));
  } else if (method == "getAddressState") {
    handle_getAddressState(params, std::move(req_id), std::move(promise));
  } else if (method == "packAddress") {
    handle_packAddress(params, std::move(req_id), std::move(promise));
  } else if (method == "unpackAddress") {
    handle_unpackAddress(params, std::move(req_id), std::move(promise));
  } else if (method == "detectAddress") {
    handle_detectAddress(params, std::move(req_id), std::move(promise));
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

  // Block ID from liteserver response (for real block_id in JSON)
  td::int32 blk_workchain = -1;
  td::int64 blk_shard = static_cast<td::int64>(0x8000000000000000ULL);
  td::uint32 blk_seqno = 0;
  std::string blk_root_hash_b64;
  std::string blk_file_hash_b64;

  static td::Result<ParsedAccountState> parse(
      tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
      const block::StdAddress& addr) {
    ParsedAccountState res;

    // Capture block ID from the liteserver response
    if (f->id_) {
      res.blk_workchain = f->id_->workchain_;
      res.blk_shard = f->id_->shard_;
      res.blk_seqno = f->id_->seqno_;
      res.blk_root_hash_b64 = td::base64_encode(f->id_->root_hash_.as_slice());
      res.blk_file_hash_b64 = td::base64_encode(f->id_->file_hash_.as_slice());
    }

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
        << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
        << ",\"workchain\":" << blk_workchain
        << ",\"shard\":\"" << blk_shard << "\""
        << ",\"seqno\":" << blk_seqno
        << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
        << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
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
        << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
        << ",\"workchain\":" << blk_workchain
        << ",\"shard\":\"" << blk_shard << "\""
        << ",\"seqno\":" << blk_seqno
        << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
        << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
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

          // Build block_id from liteserver response
          std::string block_id_json = "null";
          if (f->id_) {
            block_id_json = PSTRING()
                << "{\"@type\":\"ton.blockIdExt\""
                << ",\"workchain\":" << f->id_->workchain_
                << ",\"shard\":\"" << f->id_->shard_ << "\""
                << ",\"seqno\":" << f->id_->seqno_
                << ",\"root_hash\":\"" << td::base64_encode(f->id_->root_hash_.as_slice()) << "\""
                << ",\"file_hash\":\"" << td::base64_encode(f->id_->file_hash_.as_slice()) << "\""
                << "}";
          }

          auto result = PSTRING()
              << "{\"gas_used\":0"
              << ",\"stack\":" << stack_json
              << ",\"exit_code\":" << f->exit_code_
              << ",\"last_transaction_id\":null"
              << ",\"block_id\":" << block_id_json
              << "}";

          promise.set_value(make_json_ok(result, req_id));
        }));
      });
}

// ─── Wallet info JSON builder ─────────────────────────────────────────────

static std::string build_wallet_json(bool is_wallet, td::int64 balance,
                                     const std::string& account_state,
                                     const std::string& wallet_type,
                                     td::int32 seqno,
                                     td::uint64 last_lt, const std::string& last_hash_b64,
                                     td::int64 wallet_id = -1) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"query.fees\""
     << ",\"wallet\":" << (is_wallet ? "true" : "false")
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
    if (wallet_id >= 0) {
      sb << ",\"wallet_id\":" << wallet_id;
    } else {
      sb << ",\"wallet_id\":null";
    }
  } else {
    sb << ",\"wallet_type\":null,\"seqno\":null,\"wallet_id\":null";
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

// ─── Block ID JSON formatter (shared by block/chain APIs) ────────────

static std::string format_block_id_json(const tos::lite_api::tosNode_blockIdExt& blk) {
  return PSTRING()
      << "{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << blk.workchain_
      << ",\"shard\":\"" << blk.shard_ << "\""
      << ",\"seqno\":" << blk.seqno_
      << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash_.as_slice()) << "\""
      << "}";
}

static std::string format_zero_state_json(const tos::lite_api::tosNode_zeroStateIdExt& zs) {
  return PSTRING()
      << "{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << zs.workchain_
      << ",\"shard\":\"-9223372036854775808\""
      << ",\"seqno\":0"
      << ",\"root_hash\":\"" << td::base64_encode(zs.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(zs.file_hash_.as_slice()) << "\""
      << "}";
}

// ─── getMasterchainInfo ──────────────────────────────────────────────

void JsonRpcServer::handle_getMasterchainInfo(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
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
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();
        auto result = PSTRING()
            << "{\"@type\":\"blocks.masterchainInfo\""
            << ",\"last\":" << format_block_id_json(*mc->last_)
            << ",\"state_root_hash\":\"" << td::base64_encode(mc->state_root_hash_.as_slice()) << "\""
            << ",\"init\":" << format_zero_state_json(*mc->init_)
            << "}";
        promise.set_value(make_json_ok(result, req_id));
      });
}

// ─── lookupBlock ─────────────────────────────────────────────────────

void JsonRpcServer::handle_lookupBlock(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  if (wc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'workchain'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();

  auto shard_r = params.get_required_string_field("shard");
  if (shard_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'shard'", req_id));
    return;
  }
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);

  // Determine lookup mode: seqno (1), lt (2), or utime (4)
  td::int32 mode = 0;
  td::int32 seqno = 0;
  td::int64 lt = 0;
  td::int32 utime = 0;

  auto seqno_r = params.get_optional_int_field("seqno");
  if (seqno_r.is_ok() && seqno_r.ok() > 0) {
    mode = 1;
    seqno = static_cast<td::int32>(seqno_r.ok());
  }
  if (mode == 0) {
    auto lt_r = params.get_optional_string_field("lt");
    if (lt_r.is_ok() && !lt_r.ok().empty()) {
      mode = 2;
      lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);
    }
  }
  if (mode == 0) {
    auto utime_r = params.get_optional_int_field("utime");
    if (utime_r.is_ok() && utime_r.ok() > 0) {
      mode = 4;
      utime = static_cast<td::int32>(utime_r.ok());
    }
  }
  if (mode == 0) {
    // Default to seqno lookup if none specified
    auto seqno2_r = params.get_optional_int_field("seqno");
    if (seqno2_r.is_ok()) {
      mode = 1;
      seqno = static_cast<td::int32>(seqno2_r.ok());
    } else {
      promise.set_value(make_json_error(-32602,
          "Must provide 'seqno', 'lt', or 'utime'", req_id));
      return;
    }
  }

  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
      workchain, shard, seqno);
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          mode, std::move(block_id), lt, utime),
      true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_lookupBlockResult>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();
        promise.set_value(make_json_ok(format_block_id_json(*lb->id_), req_id));
      });
}

// ─── shards ──────────────────────────────────────────────────────────

void JsonRpcServer::handle_shards(td::JsonObject &params, std::string req_id,
                                  td::Promise<HttpReturn> promise) {
  auto seqno_r = params.get_required_int_field("seqno");
  if (seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'seqno'", req_id));
    return;
  }
  td::int32 seqno = seqno_r.ok();

  // Step 1: lookup the masterchain block by seqno
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
      -1, static_cast<td::int64>(-1LL << 63), seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_lookupBlockResult>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();

        // Step 2: get all shards info for this MC block
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAllShardsInfo>(
                std::move(lb->id_)),
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
                PSTRING() << "getAllShardsInfo: " << R.error(), req_id));
            return;
          }
          auto si_r = tos::fetch_tl_object<tos::lite_api::liteServer_allShardsInfo>(
              R.move_as_ok(), true);
          if (si_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse allShardsInfo: " << si_r.error(), req_id));
            return;
          }
          auto si = si_r.move_as_ok();

          // Parse shard hashes from data BOC
          auto root_r = vm::std_boc_deserialize(si->data_.as_slice());
          if (root_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "deserialize shard data: " << root_r.error(), req_id));
            return;
          }

          block::ShardConfig sc;
          if (!sc.unpack(root_r.move_as_ok())) {
            promise.set_value(make_json_error(-32603,
                "failed to parse shard configuration", req_id));
            return;
          }

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.shards\",\"shards\":[";
          bool first = true;
          sc.process_shard_hashes([&](block::McShardHash& sh) -> int {
            if (!first) sb << ",";
            first = false;
            auto& blk = sh.blk_;
            sb << "{\"@type\":\"ton.blockIdExt\""
               << ",\"workchain\":" << blk.id.workchain
               << ",\"shard\":\"" << blk.id.shard << "\""
               << ",\"seqno\":" << blk.id.seqno
               << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash.as_slice()) << "\""
               << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash.as_slice()) << "\""
               << "}";
            return 0;  // continue
          });
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getBlockHeader ──────────────────────────────────────────────────

void JsonRpcServer::handle_getBlockHeader(td::JsonObject &params, std::string req_id,
                                          td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  // Step 1: lookupBlock to resolve full block ID
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_lookupBlockResult>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: getBlockHeader
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getBlockHeader>(
                std::move(resolved_id), 0),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getBlockHeader: " << R.error(), req_id));
            return;
          }
          auto hdr_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (hdr_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockHeader: " << hdr_r.error(), req_id));
            return;
          }
          auto hdr = hdr_r.move_as_ok();

          // Parse header proof to extract block info fields
          auto proof_root_r = vm::std_boc_deserialize(hdr->header_proof_.as_slice());
          if (proof_root_r.is_error()) {
            // Return just the block ID and raw proof if parsing fails
            auto result = PSTRING()
                << "{\"@type\":\"blocks.header\",\"id\":" << id_json
                << ",\"header_proof\":\"" << td::base64_encode(hdr->header_proof_.as_slice()) << "\"}";
            promise.set_value(make_json_ok(result, req_id));
            return;
          }

          auto virt_r = vm::MerkleProof::virtualize(proof_root_r.move_as_ok());
          if (virt_r.is_error()) {
            auto result = PSTRING()
                << "{\"@type\":\"blocks.header\",\"id\":" << id_json
                << ",\"header_proof\":\"" << td::base64_encode(hdr->header_proof_.as_slice()) << "\"}";
            promise.set_value(make_json_ok(result, req_id));
            return;
          }
          auto virt_root = virt_r.move_as_ok();

          // Parse Block structure from virtual root
          block::gen::Block::Record blk;
          block::gen::BlockInfo::Record info;
          bool parsed = tlb::unpack_cell(virt_root, blk) &&
                        tlb::unpack_cell(blk.info, info);

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.header\",\"id\":" << id_json;
          if (parsed) {
            sb << ",\"global_id\":" << blk.global_id
               << ",\"version\":" << info.version
               << ",\"after_merge\":" << (info.after_merge ? "true" : "false")
               << ",\"before_split\":" << (info.before_split ? "true" : "false")
               << ",\"after_split\":" << (info.after_split ? "true" : "false")
               << ",\"want_merge\":" << (info.want_merge ? "true" : "false")
               << ",\"want_split\":" << (info.want_split ? "true" : "false")
               << ",\"validator_list_hash_short\":" << info.gen_validator_list_hash_short
               << ",\"catchain_seqno\":" << info.gen_catchain_seqno
               << ",\"min_ref_mc_seqno\":" << info.min_ref_mc_seqno
               << ",\"is_key_block\":" << (info.key_block ? "true" : "false")
               << ",\"prev_key_block_seqno\":" << info.prev_key_block_seqno
               << ",\"start_lt\":\"" << info.start_lt << "\""
               << ",\"end_lt\":\"" << info.end_lt << "\""
               << ",\"gen_utime\":" << info.gen_utime;
          }
          sb << "}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getBlockTransactions ────────────────────────────────────────────────

void JsonRpcServer::handle_getBlockTransactions(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  td::int32 count = 40;
  auto count_r = params.get_optional_int_field("count");
  if (count_r.is_ok() && count_r.ok() > 0) {
    count = std::min(static_cast<td::int32>(count_r.ok()), static_cast<td::int32>(256));
  }

  // Parse optional after_lt and after_hash for pagination
  td::int64 after_lt = 0;
  td::Bits256 after_account = td::Bits256::zero();
  td::int32 mode = 0x07;  // account + lt + hash in results
  auto after_lt_r = params.get_optional_string_field("after_lt");
  auto after_hash_r = params.get_optional_string_field("after_hash");
  if (after_lt_r.is_ok() && !after_lt_r.ok().empty()) {
    after_lt = std::strtoll(after_lt_r.ok().c_str(), nullptr, 10);
    mode |= 0x80;  // AFTER_MASK — use after cursor
    if (after_hash_r.is_ok() && !after_hash_r.ok().empty()) {
      auto hash_decoded = td::base64_decode(after_hash_r.ok());
      if (hash_decoded.is_ok() && hash_decoded.ok().size() == 32) {
        after_account.as_slice().copy_from(hash_decoded.ok());
      }
    }
  }

  // Step 1: lookup block
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [req_id = std::move(req_id), self_id, count, mode, after_lt, after_account,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_lookupBlockResult>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: list block transactions
        tos::tl_object_ptr<tos::lite_api::liteServer_transactionId3> after;
        if (mode & 0x80) {
          after = tos::create_tl_object<tos::lite_api::liteServer_transactionId3>(
              after_account, after_lt);
        }

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_listBlockTransactions>(
                std::move(resolved_id), mode, count, std::move(after),
                false, false),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "listBlockTransactions: " << R.error(), req_id));
            return;
          }
          auto bt_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockTransactions>(
              R.move_as_ok(), true);
          if (bt_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockTransactions: " << bt_r.error(), req_id));
            return;
          }
          auto bt = bt_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.transactions\""
             << ",\"id\":" << id_json
             << ",\"req_count\":" << bt->req_count_
             << ",\"incomplete\":" << (bt->incomplete_ ? "true" : "false")
             << ",\"transactions\":[";
          for (size_t i = 0; i < bt->ids_.size(); i++) {
            if (i > 0) sb << ",";
            auto& tid = bt->ids_[i];
            sb << "{\"@type\":\"blocks.shortTxId\"";
            if (tid->mode_ & 0x01) {
              sb << ",\"account\":\"" << tid->account_.to_hex() << "\"";
            }
            if (tid->mode_ & 0x02) {
              sb << ",\"lt\":\"" << tid->lt_ << "\"";
            }
            if (tid->mode_ & 0x04) {
              sb << ",\"hash\":\"" << td::base64_encode(tid->hash_.as_slice()) << "\"";
            }
            sb << "}";
          }
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getBlockTransactionsExt ─────────────────────────────────────────────
// Returns full transaction BOCs per block (richer than getBlockTransactions)

void JsonRpcServer::handle_getBlockTransactionsExt(td::JsonObject &params, std::string req_id,
                                                   td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  td::int32 count = 40;
  auto count_r = params.get_optional_int_field("count");
  if (count_r.is_ok() && count_r.ok() > 0) {
    count = std::min(static_cast<td::int32>(count_r.ok()), static_cast<td::int32>(256));
  }

  // Parse optional after_lt and after_hash for pagination
  td::int64 after_lt = 0;
  td::Bits256 after_account = td::Bits256::zero();
  td::int32 mode = 0x07;  // account + lt + hash
  auto after_lt_r = params.get_optional_string_field("after_lt");
  auto after_hash_r = params.get_optional_string_field("after_hash");
  if (after_lt_r.is_ok() && !after_lt_r.ok().empty()) {
    after_lt = std::strtoll(after_lt_r.ok().c_str(), nullptr, 10);
    mode |= 0x80;  // AFTER_MASK
    if (after_hash_r.is_ok() && !after_hash_r.ok().empty()) {
      auto hash_decoded = td::base64_decode(after_hash_r.ok());
      if (hash_decoded.is_ok() && hash_decoded.ok().size() == 32) {
        after_account.as_slice().copy_from(hash_decoded.ok());
      }
    }
  }

  // Step 1: lookup block
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [req_id = std::move(req_id), self_id, count, mode, after_lt, after_account,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_lookupBlockResult>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: list block transactions (extended)
        tos::tl_object_ptr<tos::lite_api::liteServer_transactionId3> after;
        if (mode & 0x80) {
          after = tos::create_tl_object<tos::lite_api::liteServer_transactionId3>(
              after_account, after_lt);
        }

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_listBlockTransactionsExt>(
                std::move(resolved_id), mode, count, std::move(after),
                false, false),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "listBlockTransactionsExt: " << R.error(), req_id));
            return;
          }
          auto bt_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockTransactionsExt>(
              R.move_as_ok(), true);
          if (bt_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockTransactionsExt: " << bt_r.error(), req_id));
            return;
          }
          auto bt = bt_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.transactionsExt\""
             << ",\"id\":" << id_json
             << ",\"req_count\":" << bt->req_count_
             << ",\"incomplete\":" << (bt->incomplete_ ? "true" : "false")
             << ",\"transactions\":[";

          // Parse individual transactions from the BOC
          if (!bt->transactions_.empty()) {
            auto roots_r = vm::std_boc_deserialize_multi(bt->transactions_.as_slice());
            if (roots_r.is_ok()) {
              auto roots = roots_r.move_as_ok();
              for (size_t i = 0; i < roots.size(); i++) {
                if (i > 0) sb << ",";
                sb << "{\"@type\":\"raw.transaction\"";

                // Serialize individual transaction as base64 BOC
                auto boc_r = vm::std_boc_serialize(roots[i]);
                if (boc_r.is_ok()) {
                  sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
                }

                // Extract basic fields from Transaction TLB
                block::gen::Transaction::Record tx;
                if (tlb::unpack_cell(roots[i], tx)) {
                  sb << ",\"account\":\"" << tx.account_addr.to_hex() << "\""
                     << ",\"lt\":\"" << tx.lt << "\""
                     << ",\"utime\":" << tx.now;
                  auto hash = roots[i]->get_hash(0);
                  sb << ",\"hash\":\"" << td::base64_encode(hash.as_slice()) << "\"";
                }
                sb << "}";
              }
            }
          }

          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getTransactions ────────────────────────────────────────────────────

void JsonRpcServer::handle_getTransactions(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  td::int32 limit = 10;
  auto limit_r = params.get_optional_int_field("limit");
  if (limit_r.is_ok() && limit_r.ok() > 0) {
    limit = std::min(static_cast<td::int32>(limit_r.ok()), static_cast<td::int32>(100));
  }

  // lt and hash are required for getTransactions
  auto lt_r = params.get_required_string_field("lt");
  if (lt_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'lt'", req_id));
    return;
  }
  td::int64 lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);

  auto hash_r = params.get_required_string_field("hash");
  if (hash_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'hash'", req_id));
    return;
  }
  td::Bits256 hash;
  auto hash_decoded = td::base64_decode(hash_r.ok());
  if (hash_decoded.is_error() || hash_decoded.ok().size() != 32) {
    // Try hex decode
    auto hex_r = td::hex_decode(td::Slice(hash_r.ok()));
    if (hex_r.is_error() || hex_r.ok().size() != 32) {
      promise.set_value(make_json_error(-32602,
          "Invalid 'hash' (expected base64 or hex, 32 bytes)", req_id));
      return;
    }
    hash.as_slice().copy_from(hex_r.ok());
  } else {
    hash.as_slice().copy_from(hash_decoded.ok());
  }

  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
          limit,
          tos::create_tl_object<tos::lite_api::liteServer_accountId>(
              addr.workchain, addr.addr),
          lt, hash),
      true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getTransactions: " << R.error(), req_id));
          return;
        }
        auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
            R.move_as_ok(), true);
        if (tl_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse transactionList: " << tl_r.error(), req_id));
          return;
        }
        auto tl = tl_r.move_as_ok();

        // Parse individual transactions from the BOC chain
        td::StringBuilder sb;
        sb << "{\"@type\":\"blocks.transactions\""
           << ",\"transactions\":[";

        if (!tl->transactions_.empty()) {
          auto root_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
          if (root_r.is_ok()) {
            auto roots = root_r.move_as_ok();
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              if (i > 0) sb << ",";
              sb << "{\"@type\":\"raw.transaction\"";
              sb << ",\"block_id\":" << format_block_id_json(*tl->ids_[i]);
              // Serialize individual transaction as base64 BOC for client parsing
              auto boc_r = vm::std_boc_serialize(roots[i]);
              if (boc_r.is_ok()) {
                sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
              }
              // Extract basic identifying fields from Transaction TLB
              block::gen::Transaction::Record tx;
              if (tlb::unpack_cell(roots[i], tx)) {
                sb << ",\"lt\":\"" << tx.lt << "\""
                   << ",\"utime\":" << tx.now;
                auto hash = roots[i]->get_hash(0);
                sb << ",\"hash\":\"" << td::base64_encode(hash.as_slice()) << "\"";
              }
              sb << "}";
            }
          }
        }

        sb << "]}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
      });
}

// ─── sendBocReturnHash ──────────────────────────────────────────────────

void JsonRpcServer::handle_sendBocReturnHash(td::JsonObject &params, std::string req_id,
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
  auto decoded = decoded_r.move_as_ok();

  // Compute the external message hash before sending
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded));
  std::string msg_hash_b64;
  if (cell_r.is_ok()) {
    auto hash = cell_r.ok()->get_hash(0);
    msg_hash_b64 = td::base64_encode(hash.as_slice());
  }

  auto body = td::BufferSlice(std::move(decoded));
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), msg_hash_b64 = std::move(msg_hash_b64),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            std::move(data), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"status\":" << status->status_
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
}

// ─── sendQuery ──────────────────────────────────────────────────────────
// Build external message from address + body + optional init, then send

void JsonRpcServer::handle_sendQuery(td::JsonObject &params, std::string req_id,
                                     td::Promise<HttpReturn> promise) {
  // Parse destination address
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Parse message body (base64 BOC)
  auto body_r = params.get_required_string_field("body");
  if (body_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'body'", req_id));
    return;
  }
  auto body_decoded_r = td::base64_decode(body_r.ok());
  if (body_decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid base64 in 'body'", req_id));
    return;
  }
  auto body_cell_r = vm::std_boc_deserialize(td::Slice(body_decoded_r.ok()));
  if (body_cell_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid BOC in 'body'", req_id));
    return;
  }
  auto body_cell = body_cell_r.move_as_ok();

  // Parse optional init_code and init_data
  td::Ref<vm::Cell> init_code, init_data;
  auto code_r = params.get_optional_string_field("init_code");
  if (code_r.is_ok() && !code_r.ok().empty()) {
    auto dec = td::base64_decode(code_r.ok());
    if (dec.is_ok()) {
      auto cell = vm::std_boc_deserialize(td::Slice(dec.ok()));
      if (cell.is_ok()) init_code = cell.move_as_ok();
    }
  }
  auto data_r = params.get_optional_string_field("init_data");
  if (data_r.is_ok() && !data_r.ok().empty()) {
    auto dec = td::base64_decode(data_r.ok());
    if (dec.is_ok()) {
      auto cell = vm::std_boc_deserialize(td::Slice(dec.ok()));
      if (cell.is_ok()) init_data = cell.move_as_ok();
    }
  }

  // Build external inbound message
  // Message = message$_ info:CommonMsgInfo init:(Maybe (Either StateInit ^StateInit)) body:(Either X ^X)
  vm::CellBuilder cb;

  // CommonMsgInfo: ext_in_msg_info$10 src:MsgAddressExt dest:MsgAddressInt import_fee:Grams
  cb.store_long(0b10, 2);    // ext_in_msg_info tag
  cb.store_long(0b00, 2);    // addr_none for src (MsgAddressExt)
  // dest: addr_std$10 anycast:(Maybe Anycast) workchain:int8 address:bits256
  cb.store_long(0b10, 2);    // addr_std tag
  cb.store_long(0, 1);       // no anycast
  cb.store_long(addr.workchain, 8);
  cb.store_bits(addr.addr.cbits(), 256);
  cb.store_long(0, 4);       // import_fee: 0 grams (VarUInteger 16, len=0)

  // init: Maybe (Either StateInit ^StateInit)
  bool has_init = init_code.not_null() || init_data.not_null();
  if (has_init) {
    cb.store_long(1, 1);     // Maybe: present
    cb.store_long(1, 1);     // Either: right (^StateInit, as ref)
    // Build StateInit cell
    vm::CellBuilder si_cb;
    si_cb.store_long(0, 1);  // split_depth: nothing
    si_cb.store_long(0, 1);  // special: nothing
    if (init_code.not_null()) {
      si_cb.store_long(1, 1);
      si_cb.store_ref(init_code);
    } else {
      si_cb.store_long(0, 1);
    }
    if (init_data.not_null()) {
      si_cb.store_long(1, 1);
      si_cb.store_ref(init_data);
    } else {
      si_cb.store_long(0, 1);
    }
    si_cb.store_long(0, 1);  // library: empty HashmapE
    cb.store_ref(si_cb.finalize());
  } else {
    cb.store_long(0, 1);     // Maybe: absent
  }

  // body: Either X ^X — store as ref to avoid overflow
  cb.store_long(1, 1);       // Either: right (^X, as ref)
  cb.store_ref(body_cell);

  auto msg_cell = cb.finalize();
  auto msg_boc_r = vm::std_boc_serialize(msg_cell);
  if (msg_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "Failed to serialize message", req_id));
    return;
  }

  // Compute message hash
  auto msg_hash_b64 = td::base64_encode(msg_cell->get_hash(0).as_slice());

  auto body_buf = td::BufferSlice(msg_boc_r.ok().as_slice());
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(body_buf)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), msg_hash_b64 = std::move(msg_hash_b64),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "sendMessage failed: " << R.error(), req_id));
          return;
        }
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            R.move_as_ok(), true);
        if (status_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse sendMsgStatus: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"status\":" << status->status_
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
}

// ─── readyz (readiness probe) ───────────────────────────────────────────
// Queries getMasterchainInfoExt to determine sync state.
// Returns structured JSON: {"ready":true/false,"sync_lag_seconds":N,"last_block_utime":N,"node_time":N}

void JsonRpcServer::handle_readyz(td::Promise<HttpReturn> promise) {
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfoExt>(0), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  auto threshold = opts_.readyz_threshold;
  auto cors = opts_.cors_origin;
  send_liteserver_query(std::move(query),
      [promise = std::move(promise), threshold, cors](td::Result<td::BufferSlice> R) mutable {
        auto make_readyz_response = [&](int status_code, std::string status_text, std::string body) -> HttpReturn {
          auto response = http::HttpResponse::create("HTTP/1.1", status_code,
              std::move(status_text), false, false).move_as_ok();
          response->add_header({"Content-Type", "application/json"});
          response->add_header({"Access-Control-Allow-Origin", cors});
          response->add_header({"Transfer-Encoding", "Chunked"});
          response->complete_parse_header();
          auto payload = response->create_empty_payload().move_as_ok();
          payload->add_chunk(td::BufferSlice(std::move(body)));
          payload->complete_parse();
          return {std::move(response), std::move(payload)};
        };

        if (R.is_error()) {
          promise.set_value(make_readyz_response(503, "Service Unavailable",
              PSTRING() << "{\"ready\":false,\"error\":"
                        << td::JsonString(td::Slice(PSTRING() << R.error())) << "}"));
          return;
        }

        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfoExt>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_readyz_response(503, "Service Unavailable",
              "{\"ready\":false,\"error\":\"parse error\"}"));
          return;
        }
        auto mc = mc_r.move_as_ok();

        td::int32 last_utime = mc->last_utime_;
        td::int32 now = mc->now_;
        td::int32 sync_lag = now > last_utime ? now - last_utime : 0;
        bool ready = sync_lag < threshold;

        auto body = PSTRING()
            << "{\"ready\":" << (ready ? "true" : "false")
            << ",\"sync_lag_seconds\":" << sync_lag
            << ",\"last_block_utime\":" << last_utime
            << ",\"node_time\":" << now
            << ",\"last_block\":" << format_block_id_json(*mc->last_)
            << "}";

        promise.set_value(make_readyz_response(
            ready ? 200 : 503,
            ready ? "OK" : "Service Unavailable",
            std::move(body)));
      });
}

// ─── getAddressBalance ──────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressBalance(td::JsonObject &params, std::string req_id,
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
                [addr, req_id = std::move(req_id), promise = std::move(promise)](
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
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id));
            return;
          }
          promise.set_value(make_json_ok(
              PSTRING() << "\"" << parsed.ok().balance << "\"", req_id));
        }));
      });
}

// ─── getAddressState ────────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressState(td::JsonObject &params, std::string req_id,
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
                [addr, req_id = std::move(req_id), promise = std::move(promise)](
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
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id));
            return;
          }
          auto state_json = PSTRING() << td::JsonString(td::Slice(parsed.ok().state_str));
          promise.set_value(make_json_ok(state_json, req_id));
        }));
      });
}

// ─── packAddress ────────────────────────────────────────────────────────

void JsonRpcServer::handle_packAddress(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  // Parse raw address (workchain:hex)
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid raw address", req_id));
    return;
  }

  // Pack into user-friendly base64url form (bounceable, no testnet flag)
  addr.bounceable = true;
  addr.testnet = false;
  auto packed = addr.rserialize(true);  // base64url
  if (packed.empty()) {
    promise.set_value(make_json_error(-32603, "Failed to serialize address", req_id));
    return;
  }

  auto packed_json = PSTRING() << td::JsonString(td::Slice(packed));
  promise.set_value(make_json_ok(packed_json, req_id));
}

// ─── unpackAddress ──────────────────────────────────────────────────────

void JsonRpcServer::handle_unpackAddress(td::JsonObject &params, std::string req_id,
                                         td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  // Parse user-friendly address
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  // Return raw form: workchain:hex_hash
  auto raw = PSTRING() << addr.workchain << ":" << addr.addr.to_hex();
  auto raw_json = PSTRING() << td::JsonString(td::Slice(raw));
  promise.set_value(make_json_ok(raw_json, req_id));
}

// ─── detectAddress ──────────────────────────────────────────────────────

void JsonRpcServer::handle_detectAddress(td::JsonObject &params, std::string req_id,
                                         td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  auto raw = PSTRING() << addr.workchain << ":" << addr.addr.to_hex();

  // Generate user-friendly forms
  auto gen_friendly = [&](bool bounceable, bool testnet) -> std::string {
    block::StdAddress a = addr;
    a.bounceable = bounceable;
    a.testnet = testnet;
    return a.rserialize(true);  // base64url
  };

  auto bounceable = gen_friendly(true, false);
  auto non_bounceable = gen_friendly(false, false);
  auto bounceable_test = gen_friendly(true, true);
  auto non_bounceable_test = gen_friendly(false, true);

  td::StringBuilder sb;
  sb << "{\"raw_form\":" << td::JsonString(td::Slice(raw))
     << ",\"bounceable\":{\"b64\":" << td::JsonString(td::Slice(bounceable))
     << ",\"b64url\":" << td::JsonString(td::Slice(bounceable)) << "}"
     << ",\"non_bounceable\":{\"b64\":" << td::JsonString(td::Slice(non_bounceable))
     << ",\"b64url\":" << td::JsonString(td::Slice(non_bounceable)) << "}"
     << ",\"given_type\":" << td::JsonString(td::Slice(
          addr.bounceable ? "friendly_bounceable" : "friendly_non_bounceable"))
     << ",\"test_only\":" << (addr.testnet ? "true" : "false")
     << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

// ─── Liteserver query forwarding ──────────────────────────────────────────

void JsonRpcServer::send_liteserver_query(td::BufferSlice query,
                                          td::Promise<td::BufferSlice> promise) {
  if (opts_.request_timeout > 0) {
    auto guard = td::actor::create_actor<QueryTimeoutGuard>(
        "rpc-timeout", std::move(promise), opts_.request_timeout);
    auto guard_id = guard.release();
    // The guard actor self-destructs via stop() after either deliver() or alarm().
    // send_closure to a stopped actor is a safe no-op.
    promise = td::PromiseCreator::lambda(
        [guard_id](td::Result<td::BufferSlice> result) mutable {
          td::actor::send_closure(guard_id, &QueryTimeoutGuard::deliver, std::move(result));
        });
  }
  td::actor::send_closure(validator_manager_,
                          &validator::ValidatorManagerInterface::run_ext_query,
                          std::move(query), std::move(promise));
}

// ─── JSON response construction ───────────────────────────────────────────

JsonRpcServer::HttpReturn JsonRpcServer::make_json_ok(std::string result_json, std::string id,
                                                      const std::string& cors_origin) {
  if (id.empty()) id = "null";
  std::string body = PSTRING()
      << "{\"ok\":true,\"jsonrpc\":\"2.0\",\"id\":" << id
      << ",\"result\":" << result_json << "}";

  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_json_error(int code, std::string message, std::string id,
                                                         const std::string& cors_origin) {
  if (id.empty()) id = "null";
  std::string body = PSTRING()
      << "{\"ok\":false,\"jsonrpc\":\"2.0\",\"id\":" << id
      << ",\"error\":" << td::JsonString(td::Slice(message))
      << ",\"code\":" << code << "}";

  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_health_ok(const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "text/plain"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice("OK"));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_cors_preflight(const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 204, "No Content", false, false).move_as_ok();
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Access-Control-Allow-Methods", "POST, GET, OPTIONS"});
  response->add_header({"Access-Control-Allow-Headers", "Content-Type"});
  response->add_header({"Access-Control-Max-Age", "86400"});
  response->add_header({"Content-Length", "0"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_text_response(int status_code,
                                                            std::string status_text,
                                                            std::string body,
                                                            const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", status_code,
                                             std::move(status_text), false, false).move_as_ok();
  response->add_header({"Content-Type", "text/plain"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(std::move(body)));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

}  // namespace tos
